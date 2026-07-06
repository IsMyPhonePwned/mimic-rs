/// Container metadata signature database (.cdb).
///
/// ClamAV .cdb format:
///   `VirusName:ContainerType:ContainerSize:FileNameREGEX:FileSizeInContainer:FileSizeReal:IsEncrypted:FilePos:Res1:Res2[:MinFL[:MaxFL]]`
///
/// Matching is done against filenames inside archive containers.
/// For standalone file scanning this is a limited match (filename-based only).

use tracing::debug;

#[derive(Debug, Clone)]
pub struct CdbSignature {
    pub name: String,
    pub container_type: String,
    pub filename_regex: Option<String>,
}

#[derive(Default)]
pub struct CdbDb {
    sigs: Vec<CdbSignature>,
}

impl CdbDb {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn count(&self) -> usize {
        self.sigs.len()
    }

    pub fn merge(&mut self, other: CdbDb) {
        self.sigs.reserve(other.sigs.len());
        self.sigs.extend(other.sigs);
    }

    /// Load a .cdb file. Format: `Name:CType:CSize:FileNameREGEX:...`
    pub fn load_cdb(&mut self, data: &[u8]) {
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
            let parts: Vec<&str> = line.splitn(10, ':').collect();
            if parts.len() < 4 {
                continue;
            }
            let name = parts[0].to_string();
            let container_type = parts[1].to_string();
            let filename_regex = if parts[3] == "*" {
                None
            } else {
                Some(parts[3].to_string())
            };
            self.sigs.push(CdbSignature {
                name,
                container_type,
                filename_regex,
            });
            count += 1;
        }
        debug!(count, total = self.sigs.len(), "loaded .cdb container metadata signatures");
    }

    /// Match against a filename (e.g. from inside an archive). Simple substring check.
    pub fn scan_filename(&self, filename: &str) -> Vec<String> {
        let lower = filename.to_lowercase();
        let mut matches = Vec::new();
        for sig in &self.sigs {
            if let Some(ref pattern) = sig.filename_regex {
                if lower.contains(&pattern.to_lowercase()) {
                    matches.push(sig.name.clone());
                }
            }
        }
        matches
    }
}
