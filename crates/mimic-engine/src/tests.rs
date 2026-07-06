//! Unit tests for mimic-engine.

use super::*;
use mimic_core::{ScanConfig, Verdict};

#[test]
fn scanner_no_matcher_returns_clean() {
    let config = ScanConfig::default();
    let scanner = FileScanner::new(&config, None, None, None);
    let data = b"clean content";
    let result = scanner.scan_bytes("test.txt", data);
    assert_eq!(result.scan_verdict.verdict, Verdict::Clean);
    assert!(result.scan_verdict.signature_threats.is_empty());
    assert!(!result.sha256.is_empty());
    assert!(!result.md5.is_empty());
}
