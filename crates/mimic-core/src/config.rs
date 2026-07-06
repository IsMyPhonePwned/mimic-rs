use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    /// Number of parallel scanning threads (0 = auto-detect from CPU count).
    pub threads: usize,
    /// Maximum file size to scan in bytes (files larger are skipped). 0 = no limit.
    pub max_file_size: u64,
    /// Path(s) to ClamAV signature databases (.cvd, .cld, .hdb, .hsb, .ndb).
    pub signature_paths: Vec<String>,
    /// Enable mimic advanced exploit detection.
    pub enable_mimic: bool,
    /// Enable ClamAV signature scanning.
    pub enable_signatures: bool,
    /// Enable sandboxed subprocess scanning.
    pub enable_sandbox: bool,
    /// File extensions to scan (empty = scan all).
    pub extensions: Vec<String>,
    /// Recurse into subdirectories.
    pub recursive: bool,
    /// Path(s) to WASM plugin files or directories containing .wasm files.
    pub plugin_paths: Vec<String>,
    /// Path(s) to YARA rule files or directories containing .yar/.yara files.
    pub yara_paths: Vec<String>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            threads: 0,
            max_file_size: 256 * 1024 * 1024,
            signature_paths: Vec::new(),
            enable_mimic: true,
            enable_signatures: true,
            enable_sandbox: false,
            extensions: Vec::new(),
            recursive: true,
            plugin_paths: Vec::new(),
            yara_paths: Vec::new(),
        }
    }
}
