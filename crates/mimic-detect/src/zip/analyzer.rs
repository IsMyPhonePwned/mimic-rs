//! Zombie ZIP detection: Method=0 (stored) with DEFLATE payload (CVE-2026-0866).

use crate::result::{AnalysisResult, FileComprehension, Threat, TrustLevel};

/// ZIP local file header signature: PK\x03\x04.
const LOCAL_HEADER_SIG: &[u8] = b"PK\x03\x04";

/// Compression method: 0 = stored, 8 = deflate.
const METHOD_STORED: u16 = 0;
const METHOD_DEFLATE: u16 = 8;

/// Minimum local header size: sig(4) + version(2) + flags(2) + method(2) + modtime(2) + moddate(2)
/// + crc(4) + compressed_size(4) + uncompressed_size(4) + fn_len(2) + extra_len(2) = 30.
const LOCAL_HEADER_MIN: usize = 30;

/// Check if data starts with a ZIP local file header (or has one early for SFX).
#[inline]
pub fn is_zip(data: &[u8]) -> bool {
    if data.len() < LOCAL_HEADER_MIN {
        return false;
    }
    data[0..4] == LOCAL_HEADER_SIG[..]
}

/// Returns true if the given slice looks like DEFLATE-compressed data (zlib wrapper or raw deflate).
fn looks_like_deflate(data: &[u8]) -> bool {
    if data.len() < 2 {
        return false;
    }
    // Zlib wrapper: first byte 0x78, second byte CMF/flags (e.g. 0x01, 0x5E, 0x9C, 0xDA).
    if data[0] == 0x78 && (data[1] == 0x01 || data[1] == 0x5E || data[1] == 0x9C || data[1] == 0xDA) {
        return true;
    }
    // Other zlib CM (compression method) values with 0x78 (e.g. 0x78 0x20 .. 0x78 0xFF).
    if data[0] == 0x78 && data.len() >= 2 {
        return true;
    }
    // Raw DEFLATE: bit 0 = BFINAL, bits 1-2 = BTYPE (01 = fixed, 10 = dynamic).
    // (b0 & 0x06) == 0x02 => BTYPE 01 (fixed), 0x04 => BTYPE 10 (dynamic).
    let b0 = data[0];
    if (b0 & 0x06) == 0x02 || (b0 & 0x06) == 0x04 {
        return true;
    }
    false
}

/// Find the first local file header and return (offset, method, compressed_size, data_start).
/// data_start is the offset where the compressed payload begins (after name + extra).
fn first_local_header(data: &[u8]) -> Option<(usize, u16, u32, usize)> {
    let mut off = 0usize;
    let end = data.len().saturating_sub(LOCAL_HEADER_MIN);
    while off <= end {
        if data[off..off + 4] != LOCAL_HEADER_SIG[..] {
            off += 1;
            continue;
        }
        let method = u16::from_le_bytes([data[off + 8], data[off + 9]]);
        let compressed_size = u32::from_le_bytes([
            data[off + 18],
            data[off + 19],
            data[off + 20],
            data[off + 21],
        ]) as usize;
        let fn_len = u16::from_le_bytes([data[off + 26], data[off + 27]]) as usize;
        let extra_len = u16::from_le_bytes([data[off + 28], data[off + 29]]) as usize;
        let data_start = off + LOCAL_HEADER_MIN + fn_len + extra_len;
        if data_start + compressed_size > data.len() {
            return None;
        }
        return Some((off, method, compressed_size as u32, data_start));
    }
    None
}

const CVE_2026_0866_ID: &str = "CVE-2026-0866";
const CVE_2026_0866_DESC: &str =
    "Zombie ZIP: archive declares Method=0 (stored) while payload is DEFLATE-compressed (AV evasion)";
const CVE_2026_0866_REF: &str = "https://github.com/bombadil-systems/zombie-zip";

/// Analyze ZIP for Zombie ZIP (method mismatch) — CVE-2026-0866.
pub fn analyze_zip(data: &[u8]) -> AnalysisResult {
    let size = data.len();
    let mut comprehension = FileComprehension {
        format: "ZIP".to_string(),
        details: Vec::new(),
        warnings: Vec::new(),
        extraction_rtf: None,
        extraction_dng_tile: None,
    };

    let (header_off, method, compressed_size, data_start) = match first_local_header(data) {
        Some(x) => x,
        None => {
            if data.len() >= 4 && data[0..4] == LOCAL_HEADER_SIG[..] {
                comprehension
                    .details
                    .push("ZIP local header found but structure invalid or truncated".to_string());
            } else {
                comprehension
                    .details
                    .push("Not a valid ZIP (no PK\\x03\\x04 local header)".to_string());
            }
            return AnalysisResult::benign(comprehension, Some(size));
        }
    };

    comprehension.details.push(format!(
        "ZIP local header at offset {}, compression method {}",
        header_off,
        method
    ));

    if method != METHOD_STORED {
        comprehension.details.push(format!(
            "Method is {} (not stored); no Zombie ZIP",
            if method == METHOD_DEFLATE { "deflate" } else { "other" }
        ));
        return AnalysisResult::benign(comprehension, Some(size));
    }

    if compressed_size == 0 {
        return AnalysisResult::benign(comprehension, Some(size));
    }

    let payload = &data[data_start..data_start + compressed_size as usize];
    if !looks_like_deflate(payload) {
        comprehension.details.push(
            "Method=0 (stored) and payload does not look like DEFLATE; benign".to_string(),
        );
        return AnalysisResult::benign(comprehension, Some(size));
    }

    comprehension.warnings.push(
        "Zombie ZIP: declared stored but payload appears DEFLATE-compressed".to_string(),
    );
    let threat = Threat {
        id: CVE_2026_0866_ID.to_string(),
        description: CVE_2026_0866_DESC.to_string(),
        reference: Some(CVE_2026_0866_REF.to_string()),
        trust: TrustLevel::High,
    };
    AnalysisResult::malicious(vec![threat], comprehension, Some(size))
}
