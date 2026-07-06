//! Unit tests for mimic-detect.

use super::*;

#[test]
fn detect_file_type_unknown_empty() {
    assert_eq!(detect_file_type(b""), FileType::Unknown);
}

#[test]
fn detect_file_type_pdf() {
    let data = b"%PDF-1.4 minimal";
    assert_eq!(detect_file_type(data), FileType::Pdf);
}

#[test]
fn detect_file_type_rtf() {
    let data = b"{\\rtf1\\ansi minimal}";
    assert_eq!(detect_file_type(data), FileType::Rtf);
}

#[test]
fn detect_file_type_dng_tiff_little_endian() {
    let data = [0x49u8, 0x49, 0x2A, 0x00, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(detect_file_type(&data), FileType::Dng);
}

#[test]
fn analyze_unknown_benign() {
    let data = b"not a known format";
    let result = analyze(data);
    assert_eq!(result.verdict, Verdict::Benign);
    assert_eq!(result.comprehension.format, "unknown");
}

#[test]
fn analyze_pdf_benign() {
    let data = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF";
    let result = analyze(data);
    assert_eq!(result.verdict, Verdict::Benign);
    assert_eq!(result.comprehension.format, "PDF");
}

/// Minimal PDF body matching obfuscated SOAP + util stream API fragments (EXPMON 328131-style).
#[test]
fn analyze_pdf_expmon_obfuscated_malicious() {
    let mut v = b"%PDF-1.4\n".to_vec();
    v.extend_from_slice(b"SOAP[\"stre");
    v.extend_from_slice(b"...");
    v.extend_from_slice(b"mFromStr");
    v.extend_from_slice(b"...");
    v.extend_from_slice(b"ngFromStr");
    let result = analyze(&v);
    assert_eq!(result.verdict, Verdict::Malicious);
    assert!(result.threats.iter().any(|t| t.id == "EXPMON-328131"));
}

#[test]
fn analyze_pdf_readfile_plain_malicious() {
    let data = b"%PDF-1.4\n/readFileIntoStream";
    let result = analyze(data);
    assert_eq!(result.verdict, Verdict::Malicious);
}

#[test]
fn analyze_pdf_rss_addfeed_plain_malicious() {
    let data = b"%PDF-1.4\nRSS.addFeed(";
    let result = analyze(data);
    assert_eq!(result.verdict, Verdict::Malicious);
}

/// When the EXPMON sample is present next to the workspace (../testdata/pdf), assert detection.
#[test]
fn analyze_pdf_expmon_sample_file_if_present() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/pdf/65dca34b04416f9a113f09718cbe51e11fd58e7287b7863e37f393ed4d25dde7");
    if !path.exists() {
        return;
    }
    let data = std::fs::read(&path).expect("read sample");
    let result = analyze(&data);
    assert_eq!(result.verdict, Verdict::Malicious);
    assert!(result.threats.iter().any(|t| t.id == "EXPMON-328131"));
}

#[test]
fn file_type_extension() {
    assert_eq!(FileType::Pdf.extension(), Some("pdf"));
    assert_eq!(FileType::Rtf.extension(), Some("rtf"));
    assert_eq!(FileType::Unknown.extension(), None);
}

/// Minimal ZIP local header: method=0 (stored), 1-byte filename "a", payload 0x78 0x9C (zlib magic).
fn minimal_zombie_zip() -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"PK\x03\x04");           // sig
    v.extend_from_slice(&[0x0a, 0x00]);           // version
    v.extend_from_slice(&[0x00, 0x00]);           // flags
    v.extend_from_slice(&[0x00, 0x00]);           // method = 0 (stored)
    v.extend_from_slice(&[0x00; 8]);              // mod time/date (10-13) + crc (14-17)
    v.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]); // compressed size = 2 (18-21)
    v.extend_from_slice(&[0x00; 4]);              // uncompressed size (22-25)
    v.extend_from_slice(&[0x01, 0x00]);           // fn len = 1
    v.extend_from_slice(&[0x00, 0x00]);           // extra len = 0
    v.push(b'a');                                 // filename
    v.push(0x78);                                 // zlib magic
    v.push(0x9C);
    v
}

#[test]
fn detect_file_type_zip() {
    let data = minimal_zombie_zip();
    assert_eq!(detect_file_type(&data), FileType::Zip);
}

#[test]
fn analyze_zombie_zip_malicious() {
    let data = minimal_zombie_zip();
    let result = analyze(&data);
    assert_eq!(result.verdict, Verdict::Malicious);
    assert!(result.threats.iter().any(|t| t.id == "CVE-2026-0866"));
}

/// Zombie ZIP with raw DEFLATE (BTYPE=01 fixed), e.g. real method_mismatch.zip payload starts with 0x8b.
#[test]
fn analyze_zombie_zip_raw_deflate_fixed() {
    let mut v = Vec::new();
    v.extend_from_slice(b"PK\x03\x04");
    v.extend_from_slice(&[0x14, 0x00, 0x00, 0x00]); // version, flags
    v.extend_from_slice(&[0x00, 0x00]);             // method = 0 stored
    v.extend_from_slice(&[0x00; 8]);
    v.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]); // compressed size = 2
    v.extend_from_slice(&[0x00; 4]);
    v.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
    v.push(b'a');
    v.push(0x8b); // raw DEFLATE: BFINAL=1, BTYPE=01 (fixed)
    v.push(0x30);
    let result = analyze(&v);
    assert_eq!(result.verdict, Verdict::Malicious);
    assert!(result.threats.iter().any(|t| t.id == "CVE-2026-0866"));
}

#[test]
fn analyze_zip_method_deflate_benign() {
    // ZIP with method=8 (deflate) — not Zombie ZIP.
    let mut v = Vec::new();
    v.extend_from_slice(b"PK\x03\x04");           // sig (4)
    v.extend_from_slice(&[0x0a, 0x00]);           // version (2)
    v.extend_from_slice(&[0x00, 0x00]);           // flags (2)
    v.extend_from_slice(&[0x08, 0x00]);           // method = 8 deflate (2)
    v.extend_from_slice(&[0x00; 8]);              // mod time/date (8)
    v.extend_from_slice(&[0x00; 4]);             // crc (4)
    v.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]); // compressed size (4)
    v.extend_from_slice(&[0x00; 4]);              // uncompressed (4)
    v.extend_from_slice(&[0x01, 0x00]);           // fn len (2)
    v.extend_from_slice(&[0x00, 0x00]);          // extra len (2) -> 30 bytes
    v.push(b'a');                                 // filename
    v.push(0x78);
    v.push(0x9C);
    let result = analyze(&v);
    assert_eq!(result.verdict, Verdict::Benign);
}
