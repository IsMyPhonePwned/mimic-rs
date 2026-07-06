//! DNG analyzer: CVE-2025-43300, CVE-2025-21043, tile configuration (elegant-bouncer style).
//! See https://github.com/msuiche/elegant-bouncer/blob/5fed0880a33ca1309bf6f40bad1b4c54676ac453/src/dng.rs

use crate::result::{AnalysisResult, DngTileConfig, FileComprehension, Threat, TrustLevel};
use crate::dng::jpeg_lossless::sof3_component_count;
use crate::dng::tiff::{
    read_tiff_header, read_short_tag, read_long_tag, read_long_array, read_sub_ifd_offsets,
    walk_ifd, opcode_list_count,
    Endian, TAG_COMPRESSION, TAG_JPEG_INTERCHANGE_FORMAT, TAG_SAMPLES_PER_PIXEL,
    TAG_STRIP_OFFSETS, TAG_SUB_IFD, TAG_IMAGE_WIDTH, TAG_IMAGE_HEIGHT,
    TAG_TILE_WIDTH, TAG_TILE_HEIGHT, TAG_TILE_OFFSETS, TAG_TILE_BYTE_COUNTS,
    TAG_OPCODE_LIST_1, TAG_OPCODE_LIST_2, TAG_OPCODE_LIST_3,
    COMPRESSION_JPEG, validate_entry_bounds, IfdEntry, TYPE_UNDEFINED,
};

const CVE_2025_43300_ID: &str = "CVE-2025-43300";
const CVE_2025_43300_DESC: &str =
    "DNG SamplesPerPixel vs JPEG Lossless SOF3 component count mismatch (Apple RawCamera.bundle heap overflow)";
const CVE_2025_43300_REF: &str = "https://www.cve.org/CVERecord?id=CVE-2025-43300";

const CVE_2025_21043_ID: &str = "CVE-2025-21043";
const CVE_2025_21043_DESC: &str = "DNG excessive opcode count causing OOB write";
const CVE_2025_21043_REF: &str = "https://github.com/msuiche/elegant-bouncer";

const TILE_CONFIG_ID: &str = "DNG-TILE-CONFIG";
const TILE_CONFIG_DESC: &str = "DNG tile configuration vulnerability (invalid tile count/dimensions)";
const TILE_CONFIG_REF: &str = "https://github.com/msuiche/elegant-bouncer";

/// Maximum opcode count in opcode list; above this is CVE-2025-21043.
const MAX_OPCODE_COUNT: u32 = 1_000_000;

/// Maximum bytes to scan for SOF3 (avoid reading huge strips).
const MAX_JPEG_SCAN: usize = 1024 * 1024;

/// Tile info collected from IFD/SubIFD for validation.
#[derive(Default)]
struct TileInfo {
    width: Option<u32>,
    height: Option<u32>,
    tile_width: Option<u32>,
    tile_height: Option<u32>,
    tile_offsets: Vec<u32>,
    tile_byte_counts: Vec<u32>,
    is_compressed: bool,
}

/// Analyze raw bytes as a DNG (or TIFF) file. Returns analysis result with comprehension and verdict.
/// Detects CVE-2025-43300, CVE-2025-21043, and tile configuration issues (elegant-bouncer style).
pub fn analyze_dng(data: &[u8]) -> AnalysisResult {
    let size = data.len();
    let mut comprehension = FileComprehension {
        format: "DNG/TIFF".to_string(),
        details: Vec::new(),
        warnings: Vec::new(),
        extraction_rtf: None,
        extraction_dng_tile: None,
    };

    let (bo, ifd0_offset) = match read_tiff_header(data) {
        Some(h) => h,
        None => {
            comprehension.details.push("Not a valid TIFF/DNG header".to_string());
            return AnalysisResult::suspicious(comprehension, Some(size));
        }
    };

    comprehension
        .details
        .push(format!("TIFF endian: {:?}, IFD0 at {}", bo, ifd0_offset));

    let mut threats = Vec::new();
    let mut tile_info = TileInfo::default();
    let mut has_excessive_opcodes = false;

    let Some(ifd_iter) = walk_ifd(bo, data, ifd0_offset) else {
        comprehension.warnings.push("Invalid or empty IFD0".to_string());
        return AnalysisResult::suspicious(comprehension, Some(size));
    };

    for (entry, _next) in ifd_iter {
        if let Some(issue) = validate_entry_bounds(data.len(), entry) {
            comprehension.warnings.push(issue);
        }

        if matches!(entry.tag, TAG_OPCODE_LIST_1 | TAG_OPCODE_LIST_2 | TAG_OPCODE_LIST_3) {
            if entry.field_type != TYPE_UNDEFINED {
                comprehension.warnings.push(format!(
                    "OpcodeList tag=0x{:04x} has unexpected field_type={} (expected UNDEFINED={})",
                    entry.tag, entry.field_type, TYPE_UNDEFINED
                ));
            }
            if let Some(count) = opcode_list_count(data, entry) {
                if count > MAX_OPCODE_COUNT {
                    has_excessive_opcodes = true;
                    comprehension.warnings.push(format!(
                        "CVE-2025-21043: Excessive opcode count {} in tag 0x{:04X} (max {})",
                        count, entry.tag, MAX_OPCODE_COUNT
                    ));
                }
            }
        }
        collect_tile_and_compression(bo, data, &entry, &mut tile_info);

        if entry.tag == TAG_SUB_IFD {
            let Some(sub_offsets) = read_sub_ifd_offsets(bo, data, entry) else {
                continue;
            };
            comprehension
                .details
                .push(format!("SubIFD count: {}", sub_offsets.len()));

            for &sub_offset in &sub_offsets {
                if let Some(t) = check_subifd_cve_2025_43300(bo, data, sub_offset) {
                    threats.push(t);
                }
                if let Some(sub_iter) = walk_ifd(bo, data, sub_offset) {
                    for (e, _) in sub_iter {
                        if let Some(issue) = validate_entry_bounds(data.len(), e) {
                            comprehension.warnings.push(issue);
                        }
                        if matches!(e.tag, TAG_OPCODE_LIST_1 | TAG_OPCODE_LIST_2 | TAG_OPCODE_LIST_3) {
                            if let Some(count) = opcode_list_count(data, e) {
                                if count > MAX_OPCODE_COUNT {
                                    has_excessive_opcodes = true;
                                }
                            }
                        }
                        collect_tile_and_compression(bo, data, &e, &mut tile_info);
                    }
                }
            }
        }
    }

    if has_excessive_opcodes {
        threats.push(Threat {
            id: CVE_2025_21043_ID.to_string(),
            description: CVE_2025_21043_DESC.to_string(),
            reference: Some(CVE_2025_21043_REF.to_string()),
            trust: TrustLevel::High,
        });
    }

    if !tile_info.tile_offsets.is_empty() || !tile_info.tile_byte_counts.is_empty() {
        let validation_reason = validate_tile_info(&tile_info);
        let (expected_tiles, tiles_h, tiles_v) = tile_grid_summary(&tile_info);
        let summary = format_tile_config_summary(&tile_info, expected_tiles, tiles_h, tiles_v, validation_reason.as_deref());
        comprehension.details.push(summary);
        comprehension.extraction_dng_tile = Some(DngTileConfig {
            image_width: tile_info.width,
            image_height: tile_info.height,
            tile_width: tile_info.tile_width,
            tile_height: tile_info.tile_height,
            tile_offsets_count: tile_info.tile_offsets.len(),
            tile_byte_counts_count: tile_info.tile_byte_counts.len(),
            is_compressed: tile_info.is_compressed,
            expected_tiles,
            tiles_horizontal: tiles_h,
            tiles_vertical: tiles_v,
            validation_reason: validation_reason.clone(),
        });
        if let Some(detail) = validation_reason {
            comprehension.warnings.push(format!("DNG-TILE-CONFIG: {}", detail));
            threats.push(Threat {
                id: TILE_CONFIG_ID.to_string(),
                description: format!("{} — {}", TILE_CONFIG_DESC, detail),
                reference: Some(TILE_CONFIG_REF.to_string()),
                trust: TrustLevel::Low,
            });
        }
    }

    if !threats.is_empty() {
        return AnalysisResult::malicious(threats, comprehension, Some(size));
    }

    if !comprehension.warnings.is_empty() {
        let (id, desc) = if comprehension
            .warnings
            .iter()
            .any(|w| w.contains("OpcodeList tag=0x"))
        {
            (
                "DNG-OPCODELIST-TYPE-MISMATCH",
                "DNG OpcodeList has unexpected TIFF field type (crafted DNG parser attack surface)",
            )
        } else {
            (
                "TIFF-STRUCTURE-ANOMALY",
                "TIFF/DNG structural anomaly (unexpected or inconsistent metadata)",
            )
        };

        let threat = Threat {
            id: id.to_string(),
            description: desc.to_string(),
            reference: Some("https://project-zero.issues.chromium.org/issues/442423708".to_string()),
            trust: TrustLevel::High,
        };
        return AnalysisResult::malicious(vec![threat], comprehension, Some(size));
    }

    AnalysisResult::benign(comprehension, Some(size))
}

/// Collect tile dimensions/offsets and compression from one IFD entry into TileInfo.
fn collect_tile_and_compression(
    bo: Endian,
    data: &[u8],
    entry: &IfdEntry,
    tile: &mut TileInfo,
) {
    match entry.tag {
        TAG_COMPRESSION => {
            if let Some(c) = read_short_tag(bo, data, *entry) {
                if c == COMPRESSION_JPEG {
                    tile.is_compressed = true;
                }
            }
        }
        TAG_IMAGE_WIDTH => {
            tile.width = read_long_tag(bo, data, *entry);
        }
        TAG_IMAGE_HEIGHT => {
            tile.height = read_long_tag(bo, data, *entry);
        }
        TAG_TILE_WIDTH => {
            tile.tile_width = read_long_tag(bo, data, *entry);
        }
        TAG_TILE_HEIGHT => {
            tile.tile_height = read_long_tag(bo, data, *entry);
        }
        TAG_TILE_OFFSETS => {
            if let Some(v) = read_long_array(bo, data, *entry) {
                tile.tile_offsets = v;
            }
        }
        TAG_TILE_BYTE_COUNTS => {
            if let Some(v) = read_long_array(bo, data, *entry) {
                tile.tile_byte_counts = v;
            }
        }
        _ => {}
    }
}

/// Validate tile configuration (elegant-bouncer logic; cdng_lossless_jpeg_unpack style).
/// Returns Some(detail_string) when invalid (for FP analysis); None when valid.
fn validate_tile_info(tile: &TileInfo) -> Option<String> {
    let (width, height, tile_width, tile_height) = match (
        tile.width,
        tile.height,
        tile.tile_width,
        tile.tile_height,
    ) {
        (Some(w), Some(h), Some(tw), Some(th)) => (w, h, tw, th),
        _ => return None,
    };

    if width == 0 || height == 0 || tile_width == 0 || tile_height == 0 {
        return Some(format!(
            "invalid dimensions: width={} height={} tile_width={} tile_height={} (zero not allowed)",
            width, height, tile_width, tile_height
        ));
    }

    const LIMIT: u32 = 0xFFFE_7960;
    if width > LIMIT || height > LIMIT || tile_width > LIMIT || tile_height > LIMIT {
        return Some(format!(
            "dimension overflow: width={} height={} tile_width={} tile_height={} (limit=0x{:X})",
            width, height, tile_width, tile_height, LIMIT
        ));
    }

    let tiles_horizontal = (width + tile_width - 1) / tile_width;
    let mut tiles_vertical = (height + tile_height - 1) / tile_height;
    if tile.is_compressed {
        tiles_vertical >>= 1;
    }
    let expected_tiles = tiles_horizontal * tiles_vertical;
    let actual_tile_count = tile.tile_offsets.len() as u32;

    if tile.tile_offsets.len() != tile.tile_byte_counts.len() {
        return Some(format!(
            "tile_offsets.len()={} != tile_byte_counts.len()={}",
            tile.tile_offsets.len(),
            tile.tile_byte_counts.len()
        ));
    }
    if actual_tile_count != expected_tiles {
        return Some(format!(
            "tile count mismatch: expected {} ({}x{} grid, compressed={}) but got {} tiles; width={} height={} tile_w={} tile_h={}",
            expected_tiles,
            tiles_horizontal,
            tiles_vertical,
            tile.is_compressed,
            actual_tile_count,
            width,
            height,
            tile_width,
            tile_height
        ));
    }
    if ((actual_tile_count >> 5) & 0x1FF_FFFF) >= 0x271 {
        return Some(format!(
            "suspicious tile count: actual_tiles={} ((count>>5)&0x1FFFFFF={} >= 0x271)",
            actual_tile_count,
            (actual_tile_count >> 5) & 0x1FF_FFFF
        ));
    }
    None
}

/// Compute expected tile count and grid (tiles_horizontal, tiles_vertical) from dimensions.
/// Returns (expected_tiles, tiles_horizontal, tiles_vertical) when all four dimensions present.
fn tile_grid_summary(tile: &TileInfo) -> (Option<u32>, Option<u32>, Option<u32>) {
    let (width, height, tile_width, tile_height) = match (
        tile.width,
        tile.height,
        tile.tile_width,
        tile.tile_height,
    ) {
        (Some(w), Some(h), Some(tw), Some(th)) if w > 0 && h > 0 && tw > 0 && th > 0 => (w, h, tw, th),
        _ => return (None, None, None),
    };
    let tiles_h = (width + tile_width - 1) / tile_width;
    let mut tiles_v = (height + tile_height - 1) / tile_height;
    if tile.is_compressed {
        tiles_v >>= 1;
    }
    (Some(tiles_h * tiles_v), Some(tiles_h), Some(tiles_v))
}

/// Human-readable one-line summary of tile config for details list (FP triage).
fn format_tile_config_summary(
    tile: &TileInfo,
    expected_tiles: Option<u32>,
    tiles_h: Option<u32>,
    tiles_v: Option<u32>,
    validation_reason: Option<&str>,
) -> String {
    let dims = match (tile.width, tile.height, tile.tile_width, tile.tile_height) {
        (Some(w), Some(h), Some(tw), Some(th)) => format!("image {}x{}, tile {}x{}", w, h, tw, th),
        _ => "image/tile dimensions partial or missing".to_string(),
    };
    let counts = format!(
        "offsets={}, byte_counts={}, compressed={}",
        tile.tile_offsets.len(),
        tile.tile_byte_counts.len(),
        tile.is_compressed
    );
    let grid = match (expected_tiles, tiles_h, tiles_v) {
        (Some(e), Some(h), Some(v)) => format!(" | grid {}x{} => expected {} tiles", h, v, e),
        _ => String::new(),
    };
    let validation = validation_reason
        .map(|r| format!(" | validation: {}", r))
        .unwrap_or_else(|| " | validation: ok".to_string());
    format!("DNG tile config: {} | {} {}{}", dims, counts, grid, validation)
}

/// Check one SubIFD for CVE-2025-43300: Compression=7, SamplesPerPixel vs SOF3 component count mismatch.
fn check_subifd_cve_2025_43300(
    bo: Endian,
    data: &[u8],
    ifd_offset: u32,
) -> Option<Threat> {
    let mut samples_per_pixel: Option<u16> = None;
    let mut compression: Option<u16> = None;
    let mut jpeg_offset: Option<u32> = None;

    let iter = walk_ifd(bo, data, ifd_offset)?;
    for (entry, _) in iter {
        match entry.tag {
            TAG_SAMPLES_PER_PIXEL => {
                samples_per_pixel = read_short_tag(bo, data, entry);
            }
            TAG_COMPRESSION => {
                compression = read_short_tag(bo, data, entry);
            }
            TAG_STRIP_OFFSETS => {
                jpeg_offset = read_long_tag(bo, data, entry);
            }
            TAG_JPEG_INTERCHANGE_FORMAT => {
                jpeg_offset = read_long_tag(bo, data, entry);
            }
            _ => {}
        }
    }

    let compression = compression?;
    if compression != COMPRESSION_JPEG {
        return None;
    }

    let jpeg_start = jpeg_offset? as usize;
    if jpeg_start >= data.len() {
        return None;
    }

    let scan_len = (data.len() - jpeg_start).min(MAX_JPEG_SCAN);
    let jpeg_slice = &data[jpeg_start..jpeg_start + scan_len];
    let sof3_components = sof3_component_count(jpeg_slice)?;

    let spp = samples_per_pixel?;
    if spp == 2 && sof3_components == 1 {
        return Some(Threat {
            id: CVE_2025_43300_ID.to_string(),
            description: CVE_2025_43300_DESC.to_string(),
            reference: Some(CVE_2025_43300_REF.to_string()),
            trust: TrustLevel::High,
        });
    }

    None
}

