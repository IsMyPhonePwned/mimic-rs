//! ClamAV-compatible and matcher unit tests (loaded as matcher::tests).

use super::*;
use crate::cdb_db::CdbDb;
use md5::Digest as Md5Digest;

fn md5_hex(data: &[u8]) -> String {
    format!("{:x}", md5::Md5::digest(data))
}

fn sha256_hex(data: &[u8]) -> String {
    format!("{:x}", sha2::Sha256::digest(data))
}

/// MD5 hash signature: file that matches the loaded HDB entry is detected.
#[test]
fn test_clamav_hash_md5_match() {
    let data = b"sample malware content for hash test";
    let md5 = md5_hex(data);
    let sha = sha256_hex(data);
    let size = data.len() as u64;

    let mut hash_db = HashDb::new();
    let hdb = format!("{}:{}:Test.Malware.MD5\n", md5, size);
    hash_db.load_hdb(hdb.as_bytes());

    let matcher = SignatureMatcher::new(
        hash_db,
        BodyDb::new(),
        LdbDb::new(),
        CdbDb::new(),
        0,
    );
    let threats = matcher.scan(data, &md5, &sha, size);

    let hash_threats: Vec<_> = threats
        .iter()
        .filter(|t| t.signature_type == "hash-md5")
        .collect();
    assert_eq!(hash_threats.len(), 1, "expected one MD5 threat");
    assert_eq!(hash_threats[0].name, "Test.Malware.MD5");
}

/// SHA256 hash signature: file that matches the loaded HSB entry is detected.
#[test]
fn test_clamav_hash_sha256_match() {
    let data = b"another sample for sha256 signature";
    let md5 = md5_hex(data);
    let sha = sha256_hex(data);
    let size = data.len() as u64;

    let mut hash_db = HashDb::new();
    let hsb = format!("{}:{}:Test.Malware.SHA256\n", sha, size);
    hash_db.load_hsb(hsb.as_bytes());

    let matcher = SignatureMatcher::new(
        hash_db,
        BodyDb::new(),
        LdbDb::new(),
        CdbDb::new(),
        0,
    );
    let threats = matcher.scan(data, &md5, &sha, size);

    let sha_threats: Vec<_> = threats
        .iter()
        .filter(|t| t.signature_type == "hash-sha256")
        .collect();
    assert_eq!(sha_threats.len(), 1, "expected one SHA256 threat");
    assert_eq!(sha_threats[0].name, "Test.Malware.SHA256");
}

/// NDB body signature: content containing the hex pattern is detected.
#[test]
fn test_clamav_body_ndb_match() {
    let ndb = b"Test.Signature.NDB:0:*:deadbeef\n";
    let mut body_db = BodyDb::new();
    body_db.load_ndb(ndb);
    body_db.finalize_automaton();

    let mut data = vec![0u8; 64];
    data.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    data.extend_from_slice(b"tail");

    let hash_db = HashDb::new();
    let md5 = md5_hex(&data);
    let sha = sha256_hex(&data);
    let size = data.len() as u64;

    let matcher = SignatureMatcher::new(
        hash_db,
        body_db,
        LdbDb::new(),
        CdbDb::new(),
        0,
    );
    let threats = matcher.scan(&data, &md5, &sha, size);

    let ndb_threats: Vec<_> = threats
        .iter()
        .filter(|t| t.signature_type == "body-ndb")
        .collect();
    assert_eq!(ndb_threats.len(), 1, "expected one NDB body threat");
    assert_eq!(ndb_threats[0].name, "Test.Signature.NDB");
}

/// LDB logical signature: one subsig, target 0 (any); content with pattern matches.
#[test]
fn test_clamav_ldb_match() {
    let ldb = b"Test.Signature.LDB;0;0;deadbeef\n";
    let mut ldb_db = LdbDb::new();
    ldb_db.load_ldb(ldb);
    ldb_db.finalize_automaton();

    let mut data = vec![0x00u8; 32];
    data.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    data.extend_from_slice(&[0xff; 16]);

    let hash_db = HashDb::new();
    let body_db = BodyDb::new();
    let md5 = md5_hex(&data);
    let sha = sha256_hex(&data);
    let size = data.len() as u64;

    let matcher = SignatureMatcher::new(
        hash_db,
        body_db,
        ldb_db,
        CdbDb::new(),
        0,
    );
    let threats = matcher.scan(&data, &md5, &sha, size);

    let ldb_threats: Vec<_> = threats
        .iter()
        .filter(|t| t.signature_type == "logical-ldb")
        .collect();
    assert_eq!(ldb_threats.len(), 1, "expected one LDB threat");
    assert_eq!(ldb_threats[0].name, "Test.Signature.LDB");
}

/// Clean content and empty matcher: no threats.
#[test]
fn test_clamav_no_match() {
    let data = b"clean file content";
    let md5 = md5_hex(data);
    let sha = sha256_hex(data);
    let size = data.len() as u64;

    let matcher = SignatureMatcher::new(
        HashDb::new(),
        BodyDb::new(),
        LdbDb::new(),
        CdbDb::new(),
        0,
    );
    let threats = matcher.scan(data, &md5, &sha, size);
    assert!(threats.is_empty(), "clean content should yield no threats");
}

/// False-positive whitelist: MD5 in .fp is not reported even if in .hdb.
#[test]
fn test_clamav_fp_whitelist_md5() {
    let data = b"whitelisted content";
    let md5 = md5_hex(data);
    let sha = sha256_hex(data);
    let size = data.len() as u64;

    let mut hash_db = HashDb::new();
    hash_db.load_hdb(format!("{}:{}:Test.Malware\n", md5, size).as_bytes());
    hash_db.load_fp(format!("{}:{}:Whitelist.Name\n", md5, size).as_bytes());

    let matcher = SignatureMatcher::new(
        hash_db,
        BodyDb::new(),
        LdbDb::new(),
        CdbDb::new(),
        0,
    );
    let threats = matcher.scan(data, &md5, &sha, size);

    let hash_threats: Vec<_> = threats
        .iter()
        .filter(|t| t.signature_type == "hash-md5")
        .collect();
    assert!(
        hash_threats.is_empty(),
        "FP whitelist should suppress MD5 match, got {:?}",
        threats
    );
}

/// False-positive whitelist: SHA256 in .sfp suppresses SHA256 match.
#[test]
fn test_clamav_fp_whitelist_sha256() {
    let data = b"sha256 whitelisted content";
    let md5 = md5_hex(data);
    let sha = sha256_hex(data);
    let size = data.len() as u64;

    let mut hash_db = HashDb::new();
    hash_db.load_hsb(format!("{}:{}:Test.Malware.SHA\n", sha, size).as_bytes());
    hash_db.load_sfp(format!("{}:{}:FP.SHA\n", sha, size).as_bytes());

    let matcher = SignatureMatcher::new(hash_db, BodyDb::new(), LdbDb::new(), CdbDb::new(), 0);
    let threats = matcher.scan(data, &md5, &sha, size);
    assert!(threats.iter().all(|t| t.signature_type != "hash-sha256"),
        "SFP whitelist should suppress SHA256 match");
}

/// NDB wildcard pattern with ?? bytes matches correctly.
#[test]
fn test_clamav_ndb_wildcard_match() {
    let ndb = b"Test.Wildcard.NDB:0:*:de??beef\n";
    let mut body_db = BodyDb::new();
    body_db.load_ndb(ndb);
    body_db.finalize_automaton();

    let mut data = vec![0u8; 32];
    data.extend_from_slice(&[0xde, 0x42, 0xbe, 0xef]);
    data.extend_from_slice(b"tail");

    let hash_db = HashDb::new();
    let md5 = md5_hex(&data);
    let sha = sha256_hex(&data);
    let size = data.len() as u64;

    let matcher = SignatureMatcher::new(hash_db, body_db, LdbDb::new(), CdbDb::new(), 0);
    let threats = matcher.scan(&data, &md5, &sha, size);
    let ndb_threats: Vec<_> = threats.iter().filter(|t| t.signature_type == "body-ndb").collect();
    assert_eq!(ndb_threats.len(), 1, "expected wildcard NDB match");
    assert_eq!(ndb_threats[0].name, "Test.Wildcard.NDB");
}

/// NDB with specific offset: signature only matches at an absolute byte offset.
#[test]
fn test_clamav_ndb_absolute_offset() {
    let ndb = b"Test.Offset.NDB:0:8:cafebabe\n";
    let mut body_db = BodyDb::new();
    body_db.load_ndb(ndb);
    body_db.finalize_automaton();

    let mut data_match = vec![0u8; 8];
    data_match.extend_from_slice(&[0xca, 0xfe, 0xba, 0xbe]);
    data_match.extend_from_slice(&[0u8; 8]);

    let md5 = md5_hex(&data_match);
    let sha = sha256_hex(&data_match);
    let size = data_match.len() as u64;

    let matcher = SignatureMatcher::new(HashDb::new(), body_db, LdbDb::new(), CdbDb::new(), 0);
    let threats = matcher.scan(&data_match, &md5, &sha, size);
    assert!(!threats.is_empty(), "pattern at correct offset should match");
}

/// NDB: pattern NOT present should yield no threats.
#[test]
fn test_clamav_ndb_no_match() {
    let ndb = b"Test.Missing.NDB:0:*:deadbeef\n";
    let mut body_db = BodyDb::new();
    body_db.load_ndb(ndb);
    body_db.finalize_automaton();

    let data = b"this file does not contain the pattern at all";
    let md5 = md5_hex(data);
    let sha = sha256_hex(data);
    let size = data.len() as u64;

    let matcher = SignatureMatcher::new(HashDb::new(), body_db, LdbDb::new(), CdbDb::new(), 0);
    let threats = matcher.scan(data, &md5, &sha, size);
    assert!(threats.is_empty(), "no pattern match should yield zero threats");
}

/// NDB target 0 (any) must not run on Ascii/HTML/Mail to avoid false positives on source/text.
#[test]
fn test_clamav_ndb_target_any_skips_ascii() {
    let ndb = b"Test.NDB.Any:0:*:deadbeef\n";
    let mut body_db = BodyDb::new();
    body_db.load_ndb(ndb);
    body_db.finalize_automaton();

    let mut data = vec![b'A'; 200];
    data.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    data.extend_from_slice(&[b'B'; 200]);

    let md5 = md5_hex(&data);
    let sha = sha256_hex(&data);
    let size = data.len() as u64;

    let matcher = SignatureMatcher::new(HashDb::new(), body_db, LdbDb::new(), CdbDb::new(), 0);
    let threats = matcher.scan(&data, &md5, &sha, size);
    let ndb_threats: Vec<_> = threats.iter().filter(|t| t.signature_type == "body-ndb").collect();
    assert!(ndb_threats.is_empty(), "NDB target 0 must not match on Ascii (avoids FP on C source etc.)");
}

/// LDB with AND logic: two subsigs must both match.
#[test]
fn test_clamav_ldb_and_logic() {
    let ldb = b"Test.LDB.AND;0;(0&1);deadbeef;cafebabe\n";
    let mut ldb_db = LdbDb::new();
    ldb_db.load_ldb(ldb);
    ldb_db.finalize_automaton();

    let mut data = vec![0x00u8; 16];
    data.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    data.extend_from_slice(&[0u8; 8]);
    data.extend_from_slice(&[0xca, 0xfe, 0xba, 0xbe]);
    data.extend_from_slice(&[0xffu8; 8]);

    let md5 = md5_hex(&data);
    let sha = sha256_hex(&data);
    let size = data.len() as u64;

    let matcher = SignatureMatcher::new(HashDb::new(), BodyDb::new(), ldb_db, CdbDb::new(), 0);
    let threats = matcher.scan(&data, &md5, &sha, size);
    let ldb_t: Vec<_> = threats.iter().filter(|t| t.signature_type == "logical-ldb").collect();
    assert_eq!(ldb_t.len(), 1, "both subsigs present -> LDB match");
    assert_eq!(ldb_t[0].name, "Test.LDB.AND");
}

/// LDB with AND logic: only one subsig present — should NOT match.
#[test]
fn test_clamav_ldb_and_partial_no_match() {
    let ldb = b"Test.LDB.AND.Partial;0;(0&1);deadbeef;cafebabe\n";
    let mut ldb_db = LdbDb::new();
    ldb_db.load_ldb(ldb);
    ldb_db.finalize_automaton();

    let mut data = vec![0x00u8; 16];
    data.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    data.extend_from_slice(&[0xffu8; 16]);

    let md5 = md5_hex(&data);
    let sha = sha256_hex(&data);
    let size = data.len() as u64;

    let matcher = SignatureMatcher::new(HashDb::new(), BodyDb::new(), ldb_db, CdbDb::new(), 0);
    let threats = matcher.scan(&data, &md5, &sha, size);
    assert!(threats.is_empty(), "partial LDB match (AND) should not trigger");
}

/// LDB with OR logic: either subsig triggers the rule.
#[test]
fn test_clamav_ldb_or_logic() {
    let ldb = b"Test.LDB.OR;0;(0|1);deadbeef;cafebabe\n";
    let mut ldb_db = LdbDb::new();
    ldb_db.load_ldb(ldb);
    ldb_db.finalize_automaton();

    let mut data = vec![0x00u8; 16];
    data.extend_from_slice(&[0xca, 0xfe, 0xba, 0xbe]);
    data.extend_from_slice(&[0xffu8; 8]);

    let md5 = md5_hex(&data);
    let sha = sha256_hex(&data);
    let size = data.len() as u64;

    let matcher = SignatureMatcher::new(HashDb::new(), BodyDb::new(), ldb_db, CdbDb::new(), 0);
    let threats = matcher.scan(&data, &md5, &sha, size);
    let ldb_t: Vec<_> = threats.iter().filter(|t| t.signature_type == "logical-ldb").collect();
    assert_eq!(ldb_t.len(), 1, "OR logic: one subsig should suffice");
}

/// Multiple NDB signatures: both alert on same file.
#[test]
fn test_clamav_multiple_ndb_matches() {
    let ndb = b"Malware.A:0:*:deadbeef\nMalware.B:0:*:cafebabe\n";
    let mut body_db = BodyDb::new();
    body_db.load_ndb(ndb);
    body_db.finalize_automaton();

    let mut data = vec![0u8; 8];
    data.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    data.extend_from_slice(&[0u8; 4]);
    data.extend_from_slice(&[0xca, 0xfe, 0xba, 0xbe]);
    data.extend_from_slice(&[0u8; 4]);

    let md5 = md5_hex(&data);
    let sha = sha256_hex(&data);
    let size = data.len() as u64;

    let matcher = SignatureMatcher::new(HashDb::new(), body_db, LdbDb::new(), CdbDb::new(), 0);
    let threats = matcher.scan(&data, &md5, &sha, size);
    let names: Vec<&str> = threats.iter().map(|t| t.name.as_str()).collect();
    assert!(names.contains(&"Malware.A"), "expected Malware.A");
    assert!(names.contains(&"Malware.B"), "expected Malware.B");
}

/// HDB hash mismatch: different content should not match.
#[test]
fn test_clamav_hash_md5_no_match() {
    let data_sig = b"signed content";
    let md5_sig = md5_hex(data_sig);
    let size_sig = data_sig.len() as u64;

    let mut hash_db = HashDb::new();
    hash_db.load_hdb(format!("{}:{}:Test.Malware.Only\n", md5_sig, size_sig).as_bytes());

    let data_other = b"completely different content";
    let md5_other = md5_hex(data_other);
    let sha_other = sha256_hex(data_other);
    let size_other = data_other.len() as u64;

    let matcher = SignatureMatcher::new(hash_db, BodyDb::new(), LdbDb::new(), CdbDb::new(), 0);
    let threats = matcher.scan(data_other, &md5_other, &sha_other, size_other);
    assert!(threats.is_empty(), "different content should not match HDB sig");
}

/// PE section MD5 matching via MDB.
#[test]
fn test_clamav_mdb_pe_section() {
    let section_data = b"fake PE section data for MDB test !!";
    let section_md5 = md5_hex(section_data);
    let section_size = section_data.len() as u64;

    let mdb = format!("{}:{}:Test.MDB.Section\n", section_size, section_md5);
    let mut hash_db = HashDb::new();
    hash_db.load_mdb(mdb.as_bytes());

    let pe = build_minimal_pe(section_data);
    let md5 = md5_hex(&pe);
    let sha = sha256_hex(&pe);
    let size = pe.len() as u64;

    let matcher = SignatureMatcher::new(hash_db, BodyDb::new(), LdbDb::new(), CdbDb::new(), 0);
    let threats = matcher.scan(&pe, &md5, &sha, size);
    let mdb_threats: Vec<_> = threats.iter().filter(|t| t.signature_type == "pe-section-md5").collect();
    assert_eq!(mdb_threats.len(), 1, "MDB should match PE section");
    assert_eq!(mdb_threats[0].name, "Test.MDB.Section");
}

/// Multiple signature types matching at once (hash + body + LDB).
#[test]
fn test_clamav_multi_engine_match() {
    let mut data = vec![0x00u8; 16];
    data.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    data.extend_from_slice(&[0xffu8; 16]);

    let md5 = md5_hex(&data);
    let sha = sha256_hex(&data);
    let size = data.len() as u64;

    let mut hash_db = HashDb::new();
    hash_db.load_hdb(format!("{}:{}:Hash.Match\n", md5, size).as_bytes());

    let mut body_db = BodyDb::new();
    body_db.load_ndb(b"Body.Match:0:*:deadbeef\n");
    body_db.finalize_automaton();

    let mut ldb_db = LdbDb::new();
    ldb_db.load_ldb(b"LDB.Match;0;0;deadbeef\n");
    ldb_db.finalize_automaton();

    let matcher = SignatureMatcher::new(hash_db, body_db, ldb_db, CdbDb::new(), 0);
    let threats = matcher.scan(&data, &md5, &sha, size);

    let sig_types: Vec<&str> = threats.iter().map(|t| t.signature_type.as_str()).collect();
    assert!(sig_types.contains(&"hash-md5"), "expected hash-md5 match");
    assert!(sig_types.contains(&"body-ndb"), "expected body-ndb match");
    assert!(sig_types.contains(&"logical-ldb"), "expected logical-ldb match");
}

/// Loader round-trip: write temp signature files, load, scan, detect.
/// Use binary prefix so file type is Any (NDB target 0 runs); pure ASCII would skip NDB.
#[test]
#[cfg(feature = "native")]
fn test_clamav_loader_roundtrip() {
    let mut test_data = vec![0u8; 200];
    test_data.extend_from_slice(b"EICAR-like test content for loader roundtrip");
    let md5 = md5_hex(&test_data);
    let sha = sha256_hex(&test_data);
    let size = test_data.len() as u64;

    let dir = std::env::temp_dir().join("mimic_test_loader");
    let _ = std::fs::create_dir_all(&dir);

    let hdb_path = dir.join("test_roundtrip.hdb");
    std::fs::write(&hdb_path, format!("{}:{}:Loader.Test.HDB\n", md5, size)).unwrap();

    let ndb_path = dir.join("test_roundtrip.ndb");
    let hex_pattern = hex::encode(b"EICAR-like");
    std::fs::write(&ndb_path, format!("Loader.Test.NDB:0:*:{}\n", hex_pattern)).unwrap();

    let paths = vec![dir.to_str().unwrap().to_string()];
    let (matcher, stats) = crate::loader::load_databases(&paths).unwrap();

    assert!(matcher.stats().md5_sigs >= 1, "expected at least 1 MD5 sig");
    assert!(matcher.stats().body_fixed_sigs >= 1, "expected at least 1 NDB sig");
    assert!(!stats.is_empty(), "expected source stats");

    let threats = matcher.scan(&test_data, &md5, &sha, size);
    assert!(threats.iter().any(|t| t.name == "Loader.Test.HDB"), "expected HDB match from loader");
    assert!(threats.iter().any(|t| t.name == "Loader.Test.NDB"), "expected NDB match from loader");

    let _ = std::fs::remove_dir_all(&dir);
}

/// MatcherStats total count and Display formatting.
#[test]
fn test_matcher_stats_display() {
    let matcher = SignatureMatcher::new(HashDb::new(), BodyDb::new(), LdbDb::new(), CdbDb::new(), 42);
    let stats = matcher.stats();
    assert_eq!(stats.bytecode_sigs, 42);
    assert_eq!(stats.total_signatures(), 42);
    let display = format!("{}", stats);
    assert!(display.contains("42 bytecode"), "display should contain bytecode count");
}

/// LDB count modifier: subsig must match MORE THAN N times.
#[test]
fn test_clamav_ldb_count_modifier_gt() {
    // Require subsig 0 to appear more than 3 times (i.e. at least 4)
    let ldb = b"Test.Count.GT;0;0>3;deadbeef\n";
    let mut ldb_db = LdbDb::new();
    ldb_db.load_ldb(ldb);
    ldb_db.finalize_automaton();

    // Data with pattern appearing exactly 3 times → should NOT match
    let mut data_3 = vec![0u8; 16];
    for _ in 0..3 {
        data_3.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        data_3.extend_from_slice(&[0u8; 4]);
    }
    let matcher_3 = SignatureMatcher::new(HashDb::new(), BodyDb::new(), ldb_db, CdbDb::new(), 0);
    let threats_3 = matcher_3.scan(&data_3, &md5_hex(&data_3), &sha256_hex(&data_3), data_3.len() as u64);
    assert!(threats_3.iter().all(|t| t.name != "Test.Count.GT"),
        "3 occurrences should NOT satisfy >3");

    // Data with pattern appearing 4 times → SHOULD match
    let mut ldb_db2 = LdbDb::new();
    ldb_db2.load_ldb(b"Test.Count.GT;0;0>3;deadbeef\n");
    ldb_db2.finalize_automaton();

    let mut data_4 = vec![0u8; 16];
    for _ in 0..4 {
        data_4.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        data_4.extend_from_slice(&[0u8; 4]);
    }
    let matcher_4 = SignatureMatcher::new(HashDb::new(), BodyDb::new(), ldb_db2, CdbDb::new(), 0);
    let threats_4 = matcher_4.scan(&data_4, &md5_hex(&data_4), &sha256_hex(&data_4), data_4.len() as u64);
    assert!(threats_4.iter().any(|t| t.name == "Test.Count.GT"),
        "4 occurrences should satisfy >3");
}

/// LDB count modifier =0 acts as negation: subsig must NOT appear.
#[test]
fn test_clamav_ldb_count_modifier_eq_zero() {
    // Rule: subsig 0 must match AND subsig 1 must NOT match (=0)
    let ldb = b"Test.Count.Neg;0;0&1=0;deadbeef;cafebabe\n";
    let mut ldb_db = LdbDb::new();
    ldb_db.load_ldb(ldb);
    ldb_db.finalize_automaton();

    // Data with only subsig 0 → matches (subsig 1 absent, satisfying =0)
    let mut data = vec![0u8; 16];
    data.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    data.extend_from_slice(&[0u8; 16]);
    let matcher = SignatureMatcher::new(HashDb::new(), BodyDb::new(), ldb_db, CdbDb::new(), 0);
    let threats = matcher.scan(&data, &md5_hex(&data), &sha256_hex(&data), data.len() as u64);
    assert!(threats.iter().any(|t| t.name == "Test.Count.Neg"),
        "subsig 0 present + subsig 1 absent (=0) should match");

    // Data with both subsigs → should NOT match (subsig 1 present violates =0)
    let mut ldb_db2 = LdbDb::new();
    ldb_db2.load_ldb(b"Test.Count.Neg;0;0&1=0;deadbeef;cafebabe\n");
    ldb_db2.finalize_automaton();

    let mut data_both = vec![0u8; 16];
    data_both.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    data_both.extend_from_slice(&[0u8; 4]);
    data_both.extend_from_slice(&[0xca, 0xfe, 0xba, 0xbe]);
    data_both.extend_from_slice(&[0u8; 16]);
    let matcher2 = SignatureMatcher::new(HashDb::new(), BodyDb::new(), ldb_db2, CdbDb::new(), 0);
    let threats2 = matcher2.scan(&data_both, &md5_hex(&data_both), &sha256_hex(&data_both), data_both.len() as u64);
    assert!(threats2.iter().all(|t| t.name != "Test.Count.Neg"),
        "subsig 1 present should violate =0");
}

/// LDB FileSize constraint: rule only matches within the specified file size range.
#[test]
fn test_clamav_ldb_filesize_constraint() {
    let ldb = b"Test.FileSize;Target:0,FileSize:100-200;0;deadbeef\n";
    let mut ldb_db = LdbDb::new();
    ldb_db.load_ldb(ldb);
    ldb_db.finalize_automaton();

    // 50-byte file (below min) → no match
    let mut data_small = vec![0u8; 42];
    data_small.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    data_small.extend_from_slice(&[0u8; 4]);
    let matcher = SignatureMatcher::new(HashDb::new(), BodyDb::new(), ldb_db, CdbDb::new(), 0);
    let threats = matcher.scan(&data_small, &md5_hex(&data_small), &sha256_hex(&data_small), data_small.len() as u64);
    assert!(threats.iter().all(|t| t.name != "Test.FileSize"),
        "file below min FileSize should not match");

    // 150-byte file (within range) → match
    let mut ldb_db2 = LdbDb::new();
    ldb_db2.load_ldb(b"Test.FileSize;Target:0,FileSize:100-200;0;deadbeef\n");
    ldb_db2.finalize_automaton();

    let mut data_ok = vec![0u8; 142];
    data_ok.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    data_ok.extend_from_slice(&[0u8; 4]);
    let matcher2 = SignatureMatcher::new(HashDb::new(), BodyDb::new(), ldb_db2, CdbDb::new(), 0);
    let threats2 = matcher2.scan(&data_ok, &md5_hex(&data_ok), &sha256_hex(&data_ok), data_ok.len() as u64);
    assert!(threats2.iter().any(|t| t.name == "Test.FileSize"),
        "file within FileSize range should match");
}

/// LDB nested parenthesized expression: ((0|1)&2) parses correctly.
#[test]
fn test_clamav_ldb_nested_parens() {
    let ldb = b"Test.Nested;0;((0|1)&2);deadbeef;cafebabe;f00dcafe\n";
    let mut ldb_db = LdbDb::new();
    ldb_db.load_ldb(ldb);
    ldb_db.finalize_automaton();

    // Data with subsig 1 and subsig 2 (no subsig 0) → (0|1)=true, 2=true → match
    let mut data = vec![0u8; 16];
    data.extend_from_slice(&[0xca, 0xfe, 0xba, 0xbe]); // subsig 1
    data.extend_from_slice(&[0u8; 4]);
    data.extend_from_slice(&[0xf0, 0x0d, 0xca, 0xfe]); // subsig 2
    data.extend_from_slice(&[0u8; 16]);
    let matcher = SignatureMatcher::new(HashDb::new(), BodyDb::new(), ldb_db, CdbDb::new(), 0);
    let threats = matcher.scan(&data, &md5_hex(&data), &sha256_hex(&data), data.len() as u64);
    assert!(threats.iter().any(|t| t.name == "Test.Nested"),
        "((0|1)&2) with subsigs 1+2 should match");

    // Data with only subsig 1 (no subsig 2) → (0|1)=true, 2=false → no match
    let mut ldb_db2 = LdbDb::new();
    ldb_db2.load_ldb(b"Test.Nested;0;((0|1)&2);deadbeef;cafebabe;f00dcafe\n");
    ldb_db2.finalize_automaton();

    let mut data_no2 = vec![0u8; 16];
    data_no2.extend_from_slice(&[0xca, 0xfe, 0xba, 0xbe]);
    data_no2.extend_from_slice(&[0u8; 24]);
    let matcher2 = SignatureMatcher::new(HashDb::new(), BodyDb::new(), ldb_db2, CdbDb::new(), 0);
    let threats2 = matcher2.scan(&data_no2, &md5_hex(&data_no2), &sha256_hex(&data_no2), data_no2.len() as u64);
    assert!(threats2.iter().all(|t| t.name != "Test.Nested"),
        "((0|1)&2) without subsig 2 should not match");
}

/// LDB block count: ((0|1|2)>5) requires total matches across subsigs > 5.
#[test]
fn test_clamav_ldb_block_count() {
    let ldb = b"Test.BlockCount;0;(0|1)>5;deadbeef;cafebabe\n";
    let mut ldb_db = LdbDb::new();
    ldb_db.load_ldb(ldb);
    ldb_db.finalize_automaton();

    // 3 of subsig 0, 2 of subsig 1 → total 5, not >5 → no match
    let mut data_5 = vec![0u8; 8];
    for _ in 0..3 {
        data_5.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        data_5.extend_from_slice(&[0u8; 4]);
    }
    for _ in 0..2 {
        data_5.extend_from_slice(&[0xca, 0xfe, 0xba, 0xbe]);
        data_5.extend_from_slice(&[0u8; 4]);
    }
    let matcher = SignatureMatcher::new(HashDb::new(), BodyDb::new(), ldb_db, CdbDb::new(), 0);
    let threats = matcher.scan(&data_5, &md5_hex(&data_5), &sha256_hex(&data_5), data_5.len() as u64);
    assert!(threats.iter().all(|t| t.name != "Test.BlockCount"),
        "total 5 should NOT satisfy (0|1)>5");

    // 4 of subsig 0, 3 of subsig 1 → total 7 > 5 → match
    let mut ldb_db2 = LdbDb::new();
    ldb_db2.load_ldb(b"Test.BlockCount;0;(0|1)>5;deadbeef;cafebabe\n");
    ldb_db2.finalize_automaton();

    let mut data_7 = vec![0u8; 8];
    for _ in 0..4 {
        data_7.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        data_7.extend_from_slice(&[0u8; 4]);
    }
    for _ in 0..3 {
        data_7.extend_from_slice(&[0xca, 0xfe, 0xba, 0xbe]);
        data_7.extend_from_slice(&[0u8; 4]);
    }
    let matcher2 = SignatureMatcher::new(HashDb::new(), BodyDb::new(), ldb_db2, CdbDb::new(), 0);
    let threats2 = matcher2.scan(&data_7, &md5_hex(&data_7), &sha256_hex(&data_7), data_7.len() as u64);
    assert!(threats2.iter().any(|t| t.name == "Test.BlockCount"),
        "total 7 should satisfy (0|1)>5");
}

/// LDB diversity requirement: (0|1|2)>2,3 needs total > 2 AND 3 distinct subsigs.
#[test]
fn test_clamav_ldb_count_diversity() {
    let ldb = b"Test.Diversity;0;(0|1|2)>2,3;deadbeef;cafebabe;f00dcafe\n";
    let mut ldb_db = LdbDb::new();
    ldb_db.load_ldb(ldb);
    ldb_db.finalize_automaton();

    // Only 2 distinct subsigs match (subsig 0 twice, subsig 1 once → total 3 > 2 but only 2 distinct)
    let mut data_2diff = vec![0u8; 8];
    data_2diff.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    data_2diff.extend_from_slice(&[0u8; 4]);
    data_2diff.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    data_2diff.extend_from_slice(&[0u8; 4]);
    data_2diff.extend_from_slice(&[0xca, 0xfe, 0xba, 0xbe]);
    data_2diff.extend_from_slice(&[0u8; 16]);
    let matcher = SignatureMatcher::new(HashDb::new(), BodyDb::new(), ldb_db, CdbDb::new(), 0);
    let threats = matcher.scan(&data_2diff, &md5_hex(&data_2diff), &sha256_hex(&data_2diff), data_2diff.len() as u64);
    assert!(threats.iter().all(|t| t.name != "Test.Diversity"),
        "2 distinct subsigs should NOT satisfy ,3 diversity requirement");

    // All 3 distinct subsigs match → should trigger
    let mut ldb_db2 = LdbDb::new();
    ldb_db2.load_ldb(b"Test.Diversity;0;(0|1|2)>2,3;deadbeef;cafebabe;f00dcafe\n");
    ldb_db2.finalize_automaton();

    let mut data_3diff = vec![0u8; 8];
    data_3diff.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    data_3diff.extend_from_slice(&[0u8; 4]);
    data_3diff.extend_from_slice(&[0xca, 0xfe, 0xba, 0xbe]);
    data_3diff.extend_from_slice(&[0u8; 4]);
    data_3diff.extend_from_slice(&[0xf0, 0x0d, 0xca, 0xfe]);
    data_3diff.extend_from_slice(&[0u8; 16]);
    let matcher2 = SignatureMatcher::new(HashDb::new(), BodyDb::new(), ldb_db2, CdbDb::new(), 0);
    let threats2 = matcher2.scan(&data_3diff, &md5_hex(&data_3diff), &sha256_hex(&data_3diff), data_3diff.len() as u64);
    assert!(threats2.iter().any(|t| t.name == "Test.Diversity"),
        "3 distinct subsigs with total > 2 should satisfy (0|1|2)>2,3");
}

/// Build a minimal valid PE file with one section containing the given data.
fn build_minimal_pe(section_data: &[u8]) -> Vec<u8> {
    let mut pe = Vec::new();

    pe.extend_from_slice(b"MZ");
    pe.extend_from_slice(&[0u8; 62]);
    pe[0x3C] = 64;

    pe.extend_from_slice(b"PE\0\0");

    pe.extend_from_slice(&[0x4C, 0x01]);
    pe.extend_from_slice(&1u16.to_le_bytes());
    pe.extend_from_slice(&[0u8; 12]);
    let opt_size: u16 = 0;
    pe.extend_from_slice(&opt_size.to_le_bytes());
    pe.extend_from_slice(&[0x02, 0x01]);

    let section_table_offset = pe.len();
    pe.extend_from_slice(b".text\0\0\0");
    pe.extend_from_slice(&(section_data.len() as u32).to_le_bytes());
    pe.extend_from_slice(&[0x00, 0x10, 0x00, 0x00]);
    pe.extend_from_slice(&(section_data.len() as u32).to_le_bytes());
    let raw_data_ptr = (section_table_offset + 40) as u32;
    pe.extend_from_slice(&raw_data_ptr.to_le_bytes());
    pe.extend_from_slice(&[0u8; 16]);

    pe.extend_from_slice(section_data);

    pe
}
