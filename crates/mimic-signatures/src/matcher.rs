/// Unified signature matcher combining all ClamAV signature databases.
///
/// Scan phases (ordered by speed — fastest first):
///   1. Whole-file hash lookup (O(1) — instant)
///   2. Body pattern matching (NDB — single AC pass + atom-verified wildcards)
///   3. Logical signatures (LDB — AC + target-type-filtered evaluation)
///   4. PE section hash matching (MDB/MSB — only for PE files)

use crate::body_db::BodyDb;
use crate::cdb_db::CdbDb;
use crate::hash_db::HashDb;
use crate::ldb_db::{detect_file_type, LdbDb};
use mimic_core::{ThreatInfo, ThreatSeverity};

pub struct SignatureMatcher {
    pub hash_db: HashDb,
    pub body_db: BodyDb,
    pub ldb_db: LdbDb,
    pub cdb_db: CdbDb,
    pub bytecode_count: u64,
}

impl SignatureMatcher {
    pub fn new(
        hash_db: HashDb,
        body_db: BodyDb,
        ldb_db: LdbDb,
        cdb_db: CdbDb,
        bytecode_count: u64,
    ) -> Self {
        Self {
            hash_db,
            body_db,
            ldb_db,
            cdb_db,
            bytecode_count,
        }
    }

    pub fn stats(&self) -> MatcherStats {
        MatcherStats {
            md5_sigs: self.hash_db.md5_count(),
            sha256_sigs: self.hash_db.sha256_count(),
            mdb_sigs: self.hash_db.mdb_count(),
            msb_sigs: self.hash_db.msb_count(),
            fp_sigs: self.hash_db.fp_count(),
            body_fixed_sigs: self.body_db.fixed_count(),
            body_wildcard_sigs: self.body_db.wildcard_count(),
            ldb_sigs: self.ldb_db.count(),
            cdb_sigs: self.cdb_db.count(),
            bytecode_sigs: self.bytecode_count as usize,
        }
    }

    /// Scan file data through all signature phases.
    pub fn scan(
        &self,
        data: &[u8],
        md5_hex: &str,
        sha256_hex: &str,
        file_size: u64,
    ) -> Vec<ThreatInfo> {
        let mut threats = Vec::new();

        // Detect file type once — shared by NDB and LDB phases
        let file_type = detect_file_type(data);

        // 1. Whole-file hash matching (O(1))
        if let Some(entry) = self.hash_db.match_md5(md5_hex, file_size) {
            threats.push(ThreatInfo {
                name: entry.name.clone(),
                signature_type: "hash-md5".to_string(),
                severity: ThreatSeverity::High,
                match_reason: Some("Whole-file MD5 hash matched a known malware signature.".to_string()),
            });
        }
        if let Some(entry) = self.hash_db.match_sha256(sha256_hex, file_size) {
            threats.push(ThreatInfo {
                name: entry.name.clone(),
                signature_type: "hash-sha256".to_string(),
                severity: ThreatSeverity::High,
                match_reason: Some("Whole-file SHA-256 hash matched a known malware signature.".to_string()),
            });
        }

        // 2. Body pattern matching (NDB — AC + atom wildcards, single pass)
        let body_matches = self.body_db.scan(data, file_type);
        for name in body_matches {
            threats.push(ThreatInfo {
                name,
                signature_type: "body-ndb".to_string(),
                severity: ThreatSeverity::High,
                match_reason: Some("A byte-pattern in the file body matched this signature.".to_string()),
            });
        }

        // 3. Logical signatures (LDB — pre-filtered by target type)
        let ldb_matches = self.ldb_db.scan(data, file_type);
        for name in ldb_matches {
            threats.push(ThreatInfo {
                name,
                signature_type: "logical-ldb".to_string(),
                severity: ThreatSeverity::High,
                match_reason: Some("A logical signature (combination of patterns/conditions) matched.".to_string()),
            });
        }

        // 4. PE section hash matching (MDB/MSB) — only for PE files
        if (self.hash_db.mdb_count() > 0 || self.hash_db.msb_count() > 0) && is_pe(data) {
            let section_threats = scan_pe_sections(data, &self.hash_db);
            threats.extend(section_threats);
        }

        threats
    }
}

#[derive(Debug, Clone)]
pub struct MatcherStats {
    pub md5_sigs: usize,
    pub sha256_sigs: usize,
    pub mdb_sigs: usize,
    pub msb_sigs: usize,
    pub fp_sigs: usize,
    pub body_fixed_sigs: usize,
    pub body_wildcard_sigs: usize,
    pub ldb_sigs: usize,
    pub cdb_sigs: usize,
    pub bytecode_sigs: usize,
}

impl MatcherStats {
    pub fn total_signatures(&self) -> u64 {
        (self.md5_sigs
            + self.sha256_sigs
            + self.mdb_sigs
            + self.msb_sigs
            + self.body_fixed_sigs
            + self.body_wildcard_sigs
            + self.ldb_sigs
            + self.cdb_sigs
            + self.bytecode_sigs) as u64
    }
}

impl std::fmt::Display for MatcherStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "signatures loaded: {} MD5, {} SHA256, {} MDB, {} MSB, {} FP, {} NDB-fixed, {} NDB-wildcard, {} LDB, {} CDB, {} bytecode (total: {})",
            self.md5_sigs, self.sha256_sigs, self.mdb_sigs, self.msb_sigs,
            self.fp_sigs, self.body_fixed_sigs, self.body_wildcard_sigs,
            self.ldb_sigs, self.cdb_sigs, self.bytecode_sigs,
            self.total_signatures()
        )
    }
}

fn is_pe(data: &[u8]) -> bool {
    data.len() > 64 && data[0] == b'M' && data[1] == b'Z'
}

fn scan_pe_sections(data: &[u8], hash_db: &HashDb) -> Vec<ThreatInfo> {
    let mut threats = Vec::new();

    if data.len() < 64 {
        return threats;
    }

    let pe_offset =
        u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    if pe_offset + 4 > data.len() || &data[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return threats;
    }

    let coff_offset = pe_offset + 4;
    if coff_offset + 20 > data.len() {
        return threats;
    }

    let num_sections =
        u16::from_le_bytes([data[coff_offset + 2], data[coff_offset + 3]]) as usize;
    let opt_header_size =
        u16::from_le_bytes([data[coff_offset + 16], data[coff_offset + 17]]) as usize;
    let section_table_offset = coff_offset + 20 + opt_header_size;

    for i in 0..num_sections {
        let entry_offset = section_table_offset + i * 40;
        if entry_offset + 40 > data.len() {
            break;
        }

        let raw_size = u32::from_le_bytes([
            data[entry_offset + 16],
            data[entry_offset + 17],
            data[entry_offset + 18],
            data[entry_offset + 19],
        ]) as usize;

        let raw_ptr = u32::from_le_bytes([
            data[entry_offset + 20],
            data[entry_offset + 21],
            data[entry_offset + 22],
            data[entry_offset + 23],
        ]) as usize;

        if raw_ptr == 0 || raw_size == 0 || raw_ptr + raw_size > data.len() {
            continue;
        }

        let section_data = &data[raw_ptr..raw_ptr + raw_size];
        let section_size = raw_size as u64;

        if hash_db.mdb_count() > 0 {
            let md5 = compute_md5(section_data);
            if let Some(entry) = hash_db.match_section_md5(&md5, section_size) {
                threats.push(ThreatInfo {
                    name: entry.name.clone(),
                    signature_type: "pe-section-md5".to_string(),
                    severity: ThreatSeverity::High,
                    match_reason: Some("A PE section's MD5 hash matched a known malware section.".to_string()),
                });
            }
        }

        if hash_db.msb_count() > 0 {
            let sha256 = compute_sha256(section_data);
            if let Some(entry) = hash_db.match_section_sha256(&sha256, section_size) {
                threats.push(ThreatInfo {
                    name: entry.name.clone(),
                    signature_type: "pe-section-sha256".to_string(),
                    severity: ThreatSeverity::High,
                    match_reason: Some("A PE section's SHA-256 hash matched a known malware section.".to_string()),
                });
            }
        }
    }

    threats
}

fn compute_md5(data: &[u8]) -> String {
    use md5::Digest;
    format!("{:x}", md5::Md5::digest(data))
}

fn compute_sha256(data: &[u8]) -> String {
    use sha2::Digest;
    format!("{:x}", sha2::Sha256::digest(data))
}

// ---------------------------------------------------------------------------
// ClamAV scanning tests: ensure signature matching works end-to-end
// ---------------------------------------------------------------------------

#[cfg(test)]
#[path = "matcher_tests.rs"]
mod tests;
