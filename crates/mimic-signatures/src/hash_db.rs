/// Hash-based signature databases:
///   .hdb = MD5, .hsb = SHA256, .mdb/.msb = PE section hashes,
///   .fp/.sfp = false-positive whitelists.
///
/// ClamAV format:
///   .hdb: `HexHash:FileSize:MalwareName`
///   .hsb: `HexHash:FileSize:MalwareName`  (SHA1 or SHA256 depending on length)
///   .mdb: `PESectionSize:MD5:MalwareName`
///   .msb: `PESectionSize:SHA256:MalwareName`
///
/// We store hashes in HashMaps for O(1) lookup — the fastest possible matching.

use std::collections::HashMap;
use tracing::debug;

#[derive(Debug, Clone)]
pub struct HashEntry {
    pub name: String,
    pub file_size: Option<u64>,
}

#[derive(Debug, Default)]
pub struct HashDb {
    /// MD5 hex -> threat name (whole-file)
    md5_map: HashMap<String, HashEntry>,
    /// SHA256 hex -> threat name (whole-file)
    sha256_map: HashMap<String, HashEntry>,
    /// PE section MD5 hex -> (section_size, threat_name)
    mdb_map: HashMap<String, HashEntry>,
    /// PE section SHA256 hex -> (section_size, threat_name)
    msb_map: HashMap<String, HashEntry>,
    /// MD5 false-positive whitelist
    fp_md5: HashMap<String, String>,
    /// SHA256 false-positive whitelist
    fp_sha256: HashMap<String, String>,
}

impl HashDb {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn md5_count(&self) -> usize {
        self.md5_map.len()
    }

    pub fn sha256_count(&self) -> usize {
        self.sha256_map.len()
    }

    pub fn fp_count(&self) -> usize {
        self.fp_md5.len() + self.fp_sha256.len()
    }

    pub fn mdb_count(&self) -> usize {
        self.mdb_map.len()
    }

    pub fn msb_count(&self) -> usize {
        self.msb_map.len()
    }

    /// Merge another HashDb into this one (e.g. from parallel load). Later entries override on key collision.
    pub fn merge(&mut self, other: HashDb) {
        self.md5_map.reserve(other.md5_map.len());
        self.sha256_map.reserve(other.sha256_map.len());
        self.mdb_map.reserve(other.mdb_map.len());
        self.msb_map.reserve(other.msb_map.len());
        self.fp_md5.reserve(other.fp_md5.len());
        self.fp_sha256.reserve(other.fp_sha256.len());
        self.md5_map.extend(other.md5_map);
        self.sha256_map.extend(other.sha256_map);
        self.mdb_map.extend(other.mdb_map);
        self.msb_map.extend(other.msb_map);
        self.fp_md5.extend(other.fp_md5);
        self.fp_sha256.extend(other.fp_sha256);
    }

    /// Load a .hdb file (MD5 hashes). Format: `MD5:Size:Name`
    pub fn load_hdb(&mut self, data: &[u8]) {
        let text = match std::str::from_utf8(data) {
            Ok(t) => t,
            Err(_) => return,
        };
        let mut count = 0u64;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.splitn(3, ':').collect();
            if parts.len() < 3 {
                continue;
            }
            let hash = parts[0].to_lowercase();
            let size = parts[1].parse::<u64>().ok();
            let name = parts[2].to_string();
            self.md5_map.insert(hash, HashEntry { name, file_size: size });
            count += 1;
        }
        debug!(count, "loaded .hdb MD5 signatures");
    }

    /// Load a .hsb file (SHA256/SHA1 hashes). Format: `Hash:Size:Name`
    pub fn load_hsb(&mut self, data: &[u8]) {
        let text = match std::str::from_utf8(data) {
            Ok(t) => t,
            Err(_) => return,
        };
        let mut count = 0u64;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.splitn(3, ':').collect();
            if parts.len() < 3 {
                continue;
            }
            let hash = parts[0].to_lowercase();
            let size = parts[1].parse::<u64>().ok();
            let name = parts[2].to_string();

            if hash.len() == 64 {
                self.sha256_map.insert(hash, HashEntry { name, file_size: size });
            } else if hash.len() == 32 {
                self.md5_map.insert(hash, HashEntry { name, file_size: size });
            }
            count += 1;
        }
        debug!(count, "loaded .hsb hash signatures");
    }

    /// Load a .fp (false positive whitelist by MD5). Format: `MD5:Size:Name`
    pub fn load_fp(&mut self, data: &[u8]) {
        let text = match std::str::from_utf8(data) {
            Ok(t) => t,
            Err(_) => return,
        };
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.splitn(3, ':').collect();
            if parts.len() >= 3 {
                self.fp_md5.insert(parts[0].to_lowercase(), parts[2].to_string());
            }
        }
    }

    /// Load a .sfp (false positive whitelist by SHA256). Format: `SHA256:Size:Name`
    pub fn load_sfp(&mut self, data: &[u8]) {
        let text = match std::str::from_utf8(data) {
            Ok(t) => t,
            Err(_) => return,
        };
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.splitn(3, ':').collect();
            if parts.len() >= 3 {
                let hash = parts[0].to_lowercase();
                if hash.len() == 64 {
                    self.fp_sha256.insert(hash, parts[2].to_string());
                } else if hash.len() == 32 {
                    self.fp_md5.insert(hash, parts[2].to_string());
                }
            }
        }
    }

    /// Load a .mdb file (PE section MD5 hashes). Format: `SectionSize:MD5:Name`
    pub fn load_mdb(&mut self, data: &[u8]) {
        let text = match std::str::from_utf8(data) {
            Ok(t) => t,
            Err(_) => return,
        };
        let mut count = 0u64;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.splitn(3, ':').collect();
            if parts.len() < 3 {
                continue;
            }
            let size = parts[0].parse::<u64>().ok();
            let hash = parts[1].to_lowercase();
            let name = parts[2].to_string();
            if hash.len() == 32 {
                self.mdb_map.insert(hash, HashEntry { name, file_size: size });
                count += 1;
            }
        }
        debug!(count, "loaded .mdb PE section MD5 signatures");
    }

    /// Load a .msb file (PE section SHA256 hashes). Format: `SectionSize:SHA256:Name`
    pub fn load_msb(&mut self, data: &[u8]) {
        let text = match std::str::from_utf8(data) {
            Ok(t) => t,
            Err(_) => return,
        };
        let mut count = 0u64;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.splitn(3, ':').collect();
            if parts.len() < 3 {
                continue;
            }
            let size = parts[0].parse::<u64>().ok();
            let hash = parts[1].to_lowercase();
            let name = parts[2].to_string();
            if hash.len() == 64 {
                self.msb_map.insert(hash, HashEntry { name, file_size: size });
                count += 1;
            }
        }
        debug!(count, "loaded .msb PE section SHA256 signatures");
    }

    /// Match a PE section by its MD5 hash and size.
    pub fn match_section_md5(&self, md5: &str, section_size: u64) -> Option<&HashEntry> {
        self.mdb_map.get(md5).filter(|entry| {
            entry.file_size.is_none() || entry.file_size == Some(section_size)
        })
    }

    /// Match a PE section by its SHA256 hash and size.
    pub fn match_section_sha256(&self, sha256: &str, section_size: u64) -> Option<&HashEntry> {
        self.msb_map.get(sha256).filter(|entry| {
            entry.file_size.is_none() || entry.file_size == Some(section_size)
        })
    }

    /// Look up by MD5 hash (hex, lowercase). Returns None if whitelisted.
    pub fn match_md5(&self, md5: &str, file_size: u64) -> Option<&HashEntry> {
        if self.fp_md5.contains_key(md5) {
            return None;
        }
        self.md5_map.get(md5).filter(|entry| {
            entry.file_size.is_none() || entry.file_size == Some(file_size)
        })
    }

    /// Look up by SHA256 hash (hex, lowercase). Returns None if whitelisted.
    pub fn match_sha256(&self, sha256: &str, file_size: u64) -> Option<&HashEntry> {
        if self.fp_sha256.contains_key(sha256) {
            return None;
        }
        self.sha256_map.get(sha256).filter(|entry| {
            entry.file_size.is_none() || entry.file_size == Some(file_size)
        })
    }
}
