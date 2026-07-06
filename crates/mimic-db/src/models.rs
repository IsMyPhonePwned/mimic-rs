use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSession {
    pub id: String,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub scan_path: String,
    pub total_files: u64,
    pub infected: u64,
    pub suspicious: u64,
    pub clean: u64,
    pub errors: u64,
    pub total_bytes: u64,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRecord {
    pub id: String,
    pub session_id: String,
    pub path: String,
    pub sha256: String,
    pub md5: String,
    pub size_bytes: u64,
    pub verdict: String,
    pub threats_json: String,
    pub scan_duration_us: u64,
    pub scanned_at: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbStats {
    pub total_sessions: u64,
    pub total_files_scanned: u64,
    pub total_infected: u64,
    pub total_suspicious: u64,
    pub total_bytes_scanned: u64,
    pub unique_hashes: u64,
    pub top_threats: Vec<(String, u64)>,
}
