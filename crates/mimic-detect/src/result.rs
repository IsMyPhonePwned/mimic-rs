//! Analysis result types: file comprehension and maliciousness verdict.

#[cfg(feature = "serde")]
use serde::Serialize;

/// High-level verdict after analyzing a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub enum Verdict {
    /// File appears benign; no known exploit patterns detected.
    Benign,
    /// Suspicious patterns (e.g. metadata inconsistencies) but not clearly malicious.
    Suspicious,
    /// File matches a known exploit pattern and could be malicious.
    Malicious,
}

/// Trust level for a detector: higher trust = fewer expected false positives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
pub enum TrustLevel {
    /// Reliable signal; low expected false positive rate.
    High,
    /// May produce many false positives; triage recommended.
    Low,
}

/// A detected threat (CVE or exploit pattern).
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct Threat {
    /// Short identifier (e.g. "CVE-2025-43300").
    pub id: String,
    /// Human-readable description.
    pub description: String,
    /// Optional reference (Project Zero issue, advisory, etc.).
    pub reference: Option<String>,
    /// Detector trust level (high = reliable, low = may have many FP).
    pub trust: TrustLevel,
}

/// Per-object extraction info (oleid-style) for RTF embedded objects.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct RtfObjectInfo {
    /// 1-based index.
    pub index: usize,
    /// OLE/COM class name if present (e.g. "Word.Document.8", "file").
    pub objclass: Option<String>,
    /// "embed" or "ocx".
    pub kind: String,
    /// Raw payload size in bytes.
    pub size: usize,
    /// If payload contains OLE, list of stream/storage names (root entries).
    pub ole_entries: Option<Vec<String>>,
    /// URLs/links extracted from payload (e.g. file://, http(s)://, WebDAV paths).
    pub links: Option<Vec<String>>,
}

/// Structured RTF extraction summary (oleid-style) for analysis.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct RtfExtraction {
    pub object_count: usize,
    pub objects: Vec<RtfObjectInfo>,
}

/// DNG/TIFF tile configuration observed in IFD(s), for FP triage and reporting.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct DngTileConfig {
    /// Image width (ImageWidth tag).
    pub image_width: Option<u32>,
    /// Image height (ImageLength tag).
    pub image_height: Option<u32>,
    /// Tile width (TileWidth tag).
    pub tile_width: Option<u32>,
    /// Tile height (TileLength tag).
    pub tile_height: Option<u32>,
    /// Number of TileOffsets entries.
    pub tile_offsets_count: usize,
    /// Number of TileByteCounts entries.
    pub tile_byte_counts_count: usize,
    /// Compression=7 (JPEG) was seen in this IFD chain.
    pub is_compressed: bool,
    /// Expected tile count from grid (only when all dimensions present).
    pub expected_tiles: Option<u32>,
    /// Tiles in horizontal direction (only when dimensions present).
    pub tiles_horizontal: Option<u32>,
    /// Tiles in vertical direction (only when dimensions present; may be halved for compressed).
    pub tiles_vertical: Option<u32>,
    /// If validation failed, the reason (e.g. count mismatch, zero dimensions).
    pub validation_reason: Option<String>,
}

/// Detailed comprehension of the file (format-specific facts).
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct FileComprehension {
    /// Format identifier (e.g. "DNG", "TIFF").
    pub format: String,
    /// Format-specific details (e.g. TIFF endianness, IFD count, tags found).
    pub details: Vec<String>,
    /// Any parsing warnings (truncation, unknown tags, etc.).
    pub warnings: Vec<String>,
    /// RTF-only: structured extraction (embedded objects, OLE streams) for oleid-style analysis.
    pub extraction_rtf: Option<RtfExtraction>,
    /// DNG/TIFF-only: tile configuration when tile tags are present (for DNG-TILE-CONFIG FP triage).
    pub extraction_dng_tile: Option<DngTileConfig>,
}

/// Result of analyzing a file for exploit patterns.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct AnalysisResult {
    /// Overall verdict.
    pub verdict: Verdict,
    /// Detected threats (empty if benign).
    pub threats: Vec<Threat>,
    /// Detailed file comprehension.
    pub comprehension: FileComprehension,
    /// Size of the input in bytes (if known).
    pub size_bytes: Option<usize>,
}

impl AnalysisResult {
    /// Create a benign result with comprehension.
    pub fn benign(comprehension: FileComprehension, size_bytes: Option<usize>) -> Self {
        Self {
            verdict: Verdict::Benign,
            threats: Vec::new(),
            comprehension,
            size_bytes,
        }
    }

    /// Create a malicious result with threats and comprehension.
    pub fn malicious(
        threats: Vec<Threat>,
        comprehension: FileComprehension,
        size_bytes: Option<usize>,
    ) -> Self {
        Self {
            verdict: Verdict::Malicious,
            threats,
            comprehension,
            size_bytes,
        }
    }

    /// Create a suspicious result (no concrete threat but anomalies).
    pub fn suspicious(
        comprehension: FileComprehension,
        size_bytes: Option<usize>,
    ) -> Self {
        Self {
            verdict: Verdict::Suspicious,
            threats: Vec::new(),
            comprehension,
            size_bytes,
        }
    }
}
