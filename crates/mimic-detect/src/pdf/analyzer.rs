//! PDF analysis: Adobe Acrobat JavaScript exploit / fingerprinting patterns.
//!
//! Heuristic for PDFs matching the EXPMON public analysis 328131 and related reporting
//! (privileged `util` / `SOAP` Acrobat JS APIs abused for exfiltration and remote staging).
//! References:
//! - <https://justhaifei1.blogspot.com/2026/04/expmon-detected-sophisticated-zero-day-adobe-reader.html>
//! - <https://pub.expmon.com/analysis/328131/>

use crate::result::{AnalysisResult, FileComprehension, Threat, TrustLevel};

/// PDF magic: %PDF (first 4 bytes after optional whitespace).
const PDF_MAGIC: &[u8] = b"%PDF";

/// Do not scan entire multi-gigabyte PDFs byte-by-byte for patterns.
const MAX_PATTERN_SCAN: usize = 32 * 1024 * 1024;

#[inline]
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return needle.is_empty();
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[inline]
fn contains_ascii_ci(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return needle.is_empty();
    }
    haystack.windows(needle.len()).any(|w| {
        w.iter()
            .zip(needle.iter())
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
    })
}

/// True when bytes match known plain or obfuscated Acrobat JS exploit indicators.
fn looks_like_acrobat_reader_exfil_pdf(data: &[u8]) -> bool {
    let scan = if data.len() > MAX_PATTERN_SCAN {
        &data[..MAX_PATTERN_SCAN]
    } else {
        data
    };

    // Reported in-the-clear API names (EXPMON / Haifei Li analysis, April 2026).
    if contains_ascii_ci(scan, b"readFileIntoStream") {
        return true;
    }
    if contains_ascii_ci(scan, b"RSS.addFeed") {
        return true;
    }

    // Obfuscated sample chain: SOAP["stre"+…+"mD"+…+"cod"+…](util["str"+…+"mFromStr"+…+"ng"](getField(…)…
    // Distinctive together; unlikely in benign PDFs.
    if contains(scan, b"SOAP[")
        && contains(scan, b"mFromStr")
        && contains(scan, b"ngFromStr")
    {
        return true;
    }

    false
}

const THREAT_ID: &str = "EXPMON-328131";
const THREAT_DESC: &str = "Adobe Acrobat Reader PDF JavaScript abuse (privileged util/SOAP APIs, exfiltration / remote staging pattern; EXPMON analysis 328131)";
const THREAT_REF: &str = "https://pub.expmon.com/analysis/328131/";

/// Check if data looks like a PDF.
#[inline]
pub fn is_pdf(data: &[u8]) -> bool {
    if data.len() < PDF_MAGIC.len() {
        return false;
    }
    data[0..PDF_MAGIC.len()] == *PDF_MAGIC
}

/// Analyze PDF for Acrobat JS exploit / fingerprinting heuristics.
pub fn analyze_pdf(data: &[u8]) -> AnalysisResult {
    let size = data.len();
    let mut comprehension = FileComprehension {
        format: "PDF".to_string(),
        details: Vec::new(),
        warnings: Vec::new(),
        extraction_rtf: None,
        extraction_dng_tile: None,
    };

    if !is_pdf(data) {
        comprehension
            .details
            .push("Not a valid PDF (missing %PDF)".to_string());
        return AnalysisResult::benign(comprehension, Some(size));
    }

    comprehension.details.push("PDF document".to_string());

    if looks_like_acrobat_reader_exfil_pdf(data) {
        comprehension.warnings.push(
            "Acrobat JavaScript pattern consistent with EXPMON 328131 / Adobe Reader exploit reporting"
                .to_string(),
        );
        let threat = Threat {
            id: THREAT_ID.to_string(),
            description: THREAT_DESC.to_string(),
            reference: Some(THREAT_REF.to_string()),
            trust: TrustLevel::Low,
        };
        return AnalysisResult::malicious(vec![threat], comprehension, Some(size));
    }

    AnalysisResult::benign(comprehension, Some(size))
}
