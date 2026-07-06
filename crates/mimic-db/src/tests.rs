//! Unit tests for mimic-db.

use super::*;
use mimic_core::{ScanResult, ScanVerdict};

fn make_clean_result(path: &str, size: u64) -> ScanResult {
    ScanResult {
        path: path.to_string(),
        size_bytes: size,
        sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        md5: "d41d8cd98f00b204e9800998ecf8427e".to_string(),
        scan_verdict: ScanVerdict::clean(),
        scan_duration_us: 100,
        error: None,
    }
}

#[test]
fn db_create_session_and_insert() {
    let db = MimicDb::open_memory().unwrap();
    let id = db.create_session("test-path").unwrap();
    assert!(!id.is_empty());

    let result = make_clean_result("/tmp/foo.bin", 42);
    db.insert_result(&id, &result).unwrap();

    let records = db.get_session_records(&id, 10, 0).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].path, "/tmp/foo.bin");
    assert_eq!(records[0].verdict, "CLEAN");
}

#[test]
fn db_sessions_list() {
    let db = MimicDb::open_memory().unwrap();
    db.create_session("scan-1").unwrap();
    db.create_session("scan-2").unwrap();

    let sessions = db.get_sessions(10).unwrap();
    assert!(sessions.len() >= 2);
}

#[test]
fn db_stats() {
    let db = MimicDb::open_memory().unwrap();
    let _stats = db.get_stats().unwrap();
}
