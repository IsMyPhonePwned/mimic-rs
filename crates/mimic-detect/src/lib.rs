//! # mimic
//!
//! Library to detect files that look normal but are crafted to exploit parsing
//! vulnerabilities in tools that process them (e.g. DNG in Apple RawCamera, Samsung Quram).
//!
//! Designed for **high throughput**: thousands of files per second via slice-based parsing,
//! minimal allocations, and optional parallel batch analysis with the `parallel` feature.
//!
//! ## Supported formats and threats
//!
//! - **DNG (Digital Negative)**  
//!   - [CVE-2025-43300](https://www.cve.org/CVERecord?id=CVE-2025-43300): Apple RawCamera.bundle heap overflow  
//!     (SamplesPerPixel vs JPEG Lossless SOF3 component count mismatch).  
//!   - Related: [Project Zero 442423708](https://project-zero.issues.chromium.org/issues/442423708)  
//!     (Android/Samsung Quram DNG in-the-wild exploit); detection heuristics can be extended.
//!
//! - **RTF (Rich Text Format)**  
//!   - [CVE-2025-21298](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-21298): Windows OLE Pres stream UAF (zero-click RCE).  
//!   - [CVE-2026-21509](https://blog.synapticsystems.de/apt28-geofencing-as-a-targeting-signal-cve-2026-21509/):  
//!     Microsoft Office security feature bypass via malformed embedded OLE (`\object` / `\objdata`).
//!
//! - **TTF/OTF (TrueType/OpenType)**  
//!   - [CVE-2025-27363](https://www.cve.org/CVERecord?id=CVE-2025-27363): FreeType GX/variable font subglyph OOB (signed short wraparound).  
//!   - [CVE-2023-41990](https://securelist.com/operation-triangulation-the-last-hardware-mystery/111669/):  
//!     Undocumented Apple-only ADJUST instruction (Operation Triangulation; opcodes 0x8F/0x90 in fpgm, prep, glyf).
//!
//! - **PDF**  
//!   - [EXPMON 328131](https://pub.expmon.com/analysis/328131/) (heuristic): Adobe Acrobat Reader PDF JavaScript abuse (`util.readFileIntoStream`, `RSS.addFeed`, or obfuscated `SOAP`/`streamDecode`/`stringFromStream` chains as in [Haifei Li, Apr 2026](https://justhaifei1.blogspot.com/2026/04/expmon-detected-sophisticated-zero-day-adobe-reader.html)).
//!
//! - **RAR**  
//!   - [CVE-2025-8088](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/):  
//!     WinRAR path traversal via Alternate Data Streams (ADS); malicious files hidden in ADS, extracted to arbitrary paths (e.g. Startup folder).
//!
//! - **ZIP**  
//!   - [CVE-2026-0866](https://github.com/bombadil-systems/zombie-zip) (Zombie ZIP): archive declares Method=0 (stored) while payload is DEFLATE-compressed; evades AV scanners that trust the method field.
//!
//! ## Example
//!
//! ```no_run
//! use mimic_detect::{analyze, Verdict};
//!
//! let bytes = std::fs::read("photo.dng").unwrap();
//! let result = analyze(&bytes);
//! match result.verdict {
//!     Verdict::Malicious => println!("Threats: {:?}", result.threats),
//!     Verdict::Suspicious => println!("Warnings: {:?}", result.comprehension.warnings),
//!     Verdict::Benign => {}
//! }
//! ```
//!
//! ## Throughput
//!
//! - Use `analyze(&[u8])` on in-memory buffers (e.g. from `mmap` or a queue).
//! - For many files, use the `parallel` feature and your own `rayon` pool, or iterate
//!   over paths and call `analyze` from a thread pool.

mod result;
pub mod dng;
pub mod pdf;
pub mod rar;
pub mod rtf;
pub mod ttf;
pub mod zip;

#[cfg(target_arch = "wasm32")]
mod wasm;

pub use result::{AnalysisResult, DngTileConfig, FileComprehension, Threat, TrustLevel, Verdict};
pub use dng::analyze_dng;
pub use pdf::analyze_pdf;
pub use rar::analyze_rar;
pub use rtf::analyze_rtf;
pub use ttf::analyze_ttf;
pub use zip::analyze_zip;

/// File type hint for routing (by extension or magic).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum FileType {
    Dng,
    Rtf,
    Ttf,
    Pdf,
    Rar,
    Zip,
    Unknown,
}

impl FileType {
    /// Preferred extension for this type (e.g. "dng", "rtf"); `None` for Unknown.
    pub fn extension(self) -> Option<&'static str> {
        match self {
            FileType::Dng => Some("dng"),
            FileType::Rtf => Some("rtf"),
            FileType::Ttf => Some("ttf"),
            FileType::Pdf => Some("pdf"),
            FileType::Rar => Some("rar"),
            FileType::Zip => Some("zip"),
            FileType::Unknown => None,
        }
    }
    /// Short label for display (e.g. "DNG", "RTF").
    pub fn label(self) -> &'static str {
        match self {
            FileType::Dng => "DNG/TIFF",
            FileType::Rtf => "RTF",
            FileType::Ttf => "TTF/OTF",
            FileType::Pdf => "PDF",
            FileType::Rar => "RAR",
            FileType::Zip => "ZIP",
            FileType::Unknown => "unknown",
        }
    }
}

/// Detect file type from magic bytes (no extension needed).
/// Use this to guess format when the path has no extension or to validate content.
#[inline]
pub fn detect_file_type(data: &[u8]) -> FileType {
    if data.len() >= 8
        && ((data[0] == 0x49 && data[1] == 0x49) || (data[0] == 0x4D && data[1] == 0x4D))
        && ((data[2] == 0x2A && data[3] == 0x00) || (data[2] == 0x00 && data[3] == 0x2A))
    {
        return FileType::Dng;
    }
    if rtf::is_rtf(data) {
        return FileType::Rtf;
    }
    if ttf::is_ttf(data) {
        return FileType::Ttf;
    }
    if pdf::is_pdf(data) {
        return FileType::Pdf;
    }
    if rar::is_rar(data) {
        return FileType::Rar;
    }
    if zip::is_zip(data) {
        return FileType::Zip;
    }
    FileType::Unknown
}

/// Analyze file bytes and return a detailed result (comprehension + verdict + threats).
/// Dispatches by format: DNG/TIFF, RTF, TTF/OTF (CVE-2023-41990), PDF, or unknown.
#[inline]
pub fn analyze(data: &[u8]) -> AnalysisResult {
    match detect_file_type(data) {
        FileType::Dng => dng::analyze_dng(data),
        FileType::Rtf => rtf::analyze_rtf(data),
        FileType::Ttf => ttf::analyze_ttf(data),
        FileType::Pdf => pdf::analyze_pdf(data),
        FileType::Rar => rar::analyze_rar(data),
        FileType::Zip => zip::analyze_zip(data),
        FileType::Unknown => AnalysisResult::benign(
            FileComprehension {
                format: "unknown".to_string(),
                details: vec!["No recognized format".to_string()],
                warnings: Vec::new(),
                extraction_rtf: None,
                extraction_dng_tile: None,
            },
            Some(data.len()),
        ),
    }
}

/// Result of analyzing one item in a batch (path or index + analysis result).
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct BatchItem<T> {
    pub path_or_id: T,
    pub result: AnalysisResult,
}

/// Analyze many buffers in sequence. For parallel throughput, enable the `parallel` feature
/// and use `rayon::prelude::*` with `paths.par_iter().map(|(id, bytes)| (id.clone(), analyze(bytes)))`.
pub fn analyze_batch<I, B>(items: I) -> Vec<BatchItem<B>>
where
    I: IntoIterator<Item = (B, Vec<u8>)>,
    B: Clone,
{
    items
        .into_iter()
        .map(|(path_or_id, bytes)| BatchItem {
            path_or_id,
            result: analyze(&bytes),
        })
        .collect()
}

#[cfg(test)]
mod tests;

