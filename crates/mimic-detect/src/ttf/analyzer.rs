//! TTF/OTF analyzer: CVE-2023-41990 (Operation Triangulation – ADJUST instruction).
//! Scans fpgm, prep, and glyf bytecode for undocumented Apple-only opcodes 0x8F/0x90.
//! See https://github.com/msuiche/elegant-bouncer/blob/main/src/ttf.rs

use crate::result::{AnalysisResult, FileComprehension, Threat, TrustLevel};
use crate::ttf::bytecode::contains_adjust_instruction;
use crate::ttf::parser::{get_table, table_bytes, is_ttf};

const CVE_2023_41990_ID: &str = "CVE-2023-41990";
const CVE_2023_41990_DESC: &str =
    "Undocumented Apple-only TrueType ADJUST instruction (Operation Triangulation)";
const CVE_2023_41990_REF: &str = "https://securelist.com/operation-triangulation-the-last-hardware-mystery/111669/";

const CVE_2025_27363_ID: &str = "CVE-2025-27363";
const CVE_2025_27363_DESC: &str =
    "FreeType OOB write in GX/variable font subglyph parsing (signed short→unsigned wraparound)";
const CVE_2025_27363_REF: &str = "https://www.cve.org/CVERecord?id=CVE-2025-27363";

/// True if table header (first 64 bytes) contains a 2-byte big-endian value in 0x8000..0xFFFF (negative as i16).
/// FreeType CVE-2025-27363: signed short "limit" used as allocation size → wraparound → OOB write; count/limit live in header.
fn has_negative_i16_be_in_table(bytes: &[u8]) -> bool {
    let limit = bytes.len().min(64);
    let mut i = 0;
    while i + 2 <= limit {
        let u = u16::from_be_bytes([bytes[i], bytes[i + 1]]);
        if u >= 0x8000 {
            return true;
        }
        i += 2;
    }
    false
}

/// Analyze TTF/OTF for CVE-2023-41990 (ADJUST in fpgm, prep, or glyf) and CVE-2025-27363 (GX/var).
pub fn analyze_ttf(data: &[u8]) -> AnalysisResult {
    let size = data.len();
    let mut comprehension = FileComprehension {
        format: "TTF/OTF".to_string(),
        details: Vec::new(),
        warnings: Vec::new(),
        extraction_rtf: None,
        extraction_dng_tile: None,
    };

    if !is_ttf(data) {
        comprehension
            .details
            .push("Not a valid TTF/OTF SFNT (bad magic)".to_string());
        return AnalysisResult::benign(comprehension, Some(size));
    }

    comprehension.details.push("TTF/OTF SFNT with table directory".to_string());

    // CVE-2025-27363: FreeType GX/variable font subglyph parsing – signed short used as size → wraparound.
    // Tables that trigger the vulnerable path: gvar (variable), fvar, feat, mort, morx (GX).
    const GX_VAR_TABLES: &[[u8; 4]] = &[*b"gvar", *b"fvar", *b"feat", *b"mort", *b"morx"];
    for tag in GX_VAR_TABLES {
        if let Some(tbl) = get_table(data, tag) {
            if let Some(bytes) = table_bytes(data, &tbl) {
                if has_negative_i16_be_in_table(bytes) {
                    comprehension.warnings.push(format!(
                        "GX/variable table {:?} contains value that could trigger FreeType CVE-2025-27363 (signed short wraparound)",
                        std::str::from_utf8(tag).unwrap_or("?")
                    ));
                    return AnalysisResult::malicious(
                        vec![Threat {
                            id: CVE_2025_27363_ID.to_string(),
                            description: CVE_2025_27363_DESC.to_string(),
                            reference: Some(CVE_2025_27363_REF.to_string()),
                            trust: TrustLevel::High,
                        }],
                        comprehension,
                        Some(size),
                    );
                }
            }
        }
    }

    if let Some(fpgm) = get_table(data, b"fpgm") {
        if let Some(bytes) = table_bytes(data, &fpgm) {
            comprehension.details.push(format!("fpgm table: {} bytes", bytes.len()));
            if contains_adjust_instruction(bytes) {
                comprehension.warnings.push(
                    "ADJUST instruction (0x8F/0x90) found in fpgm – Operation Triangulation".to_string(),
                );
                return AnalysisResult::malicious(
                    vec![Threat {
                        id: CVE_2023_41990_ID.to_string(),
                        description: CVE_2023_41990_DESC.to_string(),
                        reference: Some(CVE_2023_41990_REF.to_string()),
                        trust: TrustLevel::High,
                    }],
                    comprehension,
                    Some(size),
                );
            }
        }
    }

    if let Some(prep) = get_table(data, b"prep") {
        if let Some(bytes) = table_bytes(data, &prep) {
            comprehension.details.push(format!("prep table: {} bytes", bytes.len()));
            if contains_adjust_instruction(bytes) {
                comprehension.warnings.push(
                    "ADJUST instruction (0x8F/0x90) found in prep – Operation Triangulation".to_string(),
                );
                return AnalysisResult::malicious(
                    vec![Threat {
                        id: CVE_2023_41990_ID.to_string(),
                        description: CVE_2023_41990_DESC.to_string(),
                        reference: Some(CVE_2023_41990_REF.to_string()),
                        trust: TrustLevel::High,
                    }],
                    comprehension,
                    Some(size),
                );
            }
        }
    }

    if let (Some(maxp), Some(loca), Some(glyf)) = (
        get_table(data, b"maxp"),
        get_table(data, b"loca"),
        get_table(data, b"glyf"),
    ) {
        let maxp_bytes = match table_bytes(data, &maxp) {
            Some(b) if b.len() >= 6 => b,
            _ => return AnalysisResult::benign(comprehension, Some(size)),
        };
        let num_glyphs = u16::from_be_bytes([maxp_bytes[4], maxp_bytes[5]]) as usize;
        if num_glyphs > 0xFFFF {
            return AnalysisResult::benign(comprehension, Some(size));
        }
        let loca_bytes = match table_bytes(data, &loca) {
            Some(b) => b,
            None => return AnalysisResult::benign(comprehension, Some(size)),
        };
        let glyf_base = glyf.offset as usize;
        let glyf_end = glyf_base.saturating_add(glyf.length as usize);

        for glyf_id in 0..num_glyphs {
            let loca_entry = glyf_id * 2;
            if loca_entry + 2 > loca_bytes.len() {
                break;
            }
            let glyf_offset_short = u16::from_be_bytes([loca_bytes[loca_entry], loca_bytes[loca_entry + 1]]);
            let start = glyf_base + (glyf_offset_short as usize) * 2;
            if start + 10 > data.len() || start >= glyf_end {
                continue;
            }
            let num_contours = i16::from_be_bytes([data[start], data[start + 1]]);
            if num_contours < 0 {
                continue;
            }
            let num_contours = num_contours as usize;
            let mut off = start + 10;
            for _ in 0..num_contours {
                if off + 2 > data.len() {
                    break;
                }
                let n_pts = u16::from_be_bytes([data[off], data[off + 1]]) as usize;
                off += 2;
                if off + n_pts * 2 > data.len() {
                    break;
                }
                off += n_pts * 2;
            }
            if off + 2 > data.len() {
                continue;
            }
            let instr_len = u16::from_be_bytes([data[off], data[off + 1]]) as usize;
            off += 2;
            if off + instr_len > data.len() || off + instr_len > glyf_end {
                continue;
            }
            let instr = &data[off..off + instr_len];
            if contains_adjust_instruction(instr) {
                comprehension.warnings.push(format!(
                    "ADJUST instruction (0x8F/0x90) found in glyf id {} – Operation Triangulation",
                    glyf_id
                ));
                return AnalysisResult::malicious(
                    vec![Threat {
                        id: CVE_2023_41990_ID.to_string(),
                        description: CVE_2023_41990_DESC.to_string(),
                        reference: Some(CVE_2023_41990_REF.to_string()),
                        trust: TrustLevel::High,
                    }],
                    comprehension,
                    Some(size),
                );
            }
        }
    }

    AnalysisResult::benign(comprehension, Some(size))
}

