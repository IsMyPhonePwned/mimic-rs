//! Unit tests for mimic-browser.

use super::*;

#[test]
fn scanner_new_and_stats() {
    let scanner = BrowserScanner::new();
    let stats = scanner.get_stats_internal();
    assert_eq!(stats.total, 0);
}

#[test]
fn scanner_load_hdb_and_scan() {
    let mut scanner = BrowserScanner::new();
    let test_data = b"test malware content for browser";
    let md5 = compute_md5(test_data);
    let size = test_data.len();

    let hdb = format!("{}:{}:Browser.Test.HDB\n", md5, size);
    scanner.load_database("test.hdb", hdb.as_bytes()).unwrap();
    scanner.finalize();

    let result_json = scanner.scan_file("test.bin", test_data).unwrap();
    let result: ScanResult = serde_json::from_str(&result_json).unwrap();
    assert_eq!(result.verdict, "INFECTED");
    assert_eq!(result.threats.len(), 1);
    assert_eq!(result.threats[0].name, "Browser.Test.HDB");
}

#[test]
fn scanner_clean_file() {
    let mut scanner = BrowserScanner::new();
    let hdb = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:10:Dummy.Sig\n";
    scanner.load_database("test.hdb", hdb).unwrap();
    scanner.finalize();

    let result_json = scanner.scan_file("clean.txt", b"harmless").unwrap();
    let result: ScanResult = serde_json::from_str(&result_json).unwrap();
    assert_eq!(result.verdict, "CLEAN");
    assert!(result.threats.is_empty());
}

#[test]
fn scanner_reset() {
    let mut scanner = BrowserScanner::new();
    scanner.load_database("test.hdb", b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:1:Test\n").unwrap();
    scanner.reset();
    let stats = scanner.get_stats_internal();
    assert_eq!(stats.total, 0);
}

#[test]
fn yara_lite_parse_and_scan() {
    let rules = crate::yara_lite::parse_yara_lite(
        r#"rule Hello { strings: $a = "Hello" condition: any of them }"#,
    )
    .unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].name, "Hello");
    assert_eq!(rules[0].patterns.len(), 1);
    assert_eq!(rules[0].patterns[0], b"Hello");

    let matches = crate::yara_lite::scan_yara_lite(&rules, b"xxx Hello world");
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].0, "Hello");
    assert!(crate::yara_lite::scan_yara_lite(&rules, b"nope").is_empty());
}

#[test]
fn yara_lite_sample_rules() {
    let sample = r#"rule SuspiciousExecutable {
  strings:
    $magic_elf = { 7f 45 4c 46 }
    $magic_pe = "MZ"
  condition: any of them
}"#;
    let rules = crate::yara_lite::parse_yara_lite(sample).unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].patterns.len(), 2);
    assert_eq!(rules[0].patterns[0], [0x7f, 0x45, 0x4c, 0x46]);
    assert_eq!(rules[0].patterns[1], b"MZ");

    let matches = crate::yara_lite::scan_yara_lite(&rules, b"MZ\x90\x00");
    assert_eq!(matches.len(), 1);
}
