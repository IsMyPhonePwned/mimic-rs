use mimic_core::MimicError;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtConfig {
    pub api_key: String,
    /// Only perform hash lookup (no file upload). Default: true.
    pub hash_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtLookupResult {
    pub sha256: String,
    pub found: bool,
    pub positives: Option<u32>,
    pub total: Option<u32>,
    pub scan_date: Option<String>,
    pub permalink: Option<String>,
    /// Top engine detections (engine_name -> detection_name)
    pub detections: Vec<(String, String)>,
}

pub struct VtClient {
    config: VtConfig,
    http: reqwest::Client,
}

impl VtClient {
    pub fn new(config: VtConfig) -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap_or_default();
        Self { config, http }
    }

    /// Look up a file hash on VirusTotal. Returns None if the API key is empty.
    pub async fn lookup_hash(&self, sha256: &str) -> Result<VtLookupResult, MimicError> {
        if self.config.api_key.is_empty() {
            return Err(MimicError::Engine("VirusTotal API key is empty".into()));
        }

        let url = format!("https://www.virustotal.com/api/v3/files/{sha256}");
        debug!(sha256, "VirusTotal hash lookup");

        let resp = self
            .http
            .get(&url)
            .header("x-apikey", &self.config.api_key)
            .send()
            .await
            .map_err(|e| MimicError::Engine(format!("VT request failed: {e}")))?;

        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            debug!(sha256, "hash not found on VirusTotal");
            return Ok(VtLookupResult {
                sha256: sha256.to_string(),
                found: false,
                positives: None,
                total: None,
                scan_date: None,
                permalink: None,
                detections: Vec::new(),
            });
        }

        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            warn!(status = %status, body = %body, "VT API error");
            return Err(MimicError::Engine(format!("VT API error {status}: {body}")));
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| MimicError::Engine(format!("VT response parse error: {e}")))?;

        let attrs = &body["data"]["attributes"];
        let stats = &attrs["last_analysis_stats"];
        let positives = stats["malicious"].as_u64().unwrap_or(0)
            + stats["suspicious"].as_u64().unwrap_or(0);
        let total = stats["malicious"].as_u64().unwrap_or(0)
            + stats["undetected"].as_u64().unwrap_or(0)
            + stats["suspicious"].as_u64().unwrap_or(0)
            + stats["harmless"].as_u64().unwrap_or(0);

        let scan_date = attrs["last_analysis_date"]
            .as_i64()
            .map(|ts| {
                chrono::DateTime::<chrono::Utc>::from_timestamp(ts, 0)
                    .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                    .unwrap_or_default()
            });

        let permalink = Some(format!(
            "https://www.virustotal.com/gui/file/{sha256}"
        ));

        let mut detections = Vec::new();
        if let Some(results) = attrs["last_analysis_results"].as_object() {
            for (engine, result) in results {
                if let Some(cat) = result["category"].as_str() {
                    if cat == "malicious" || cat == "suspicious" {
                        let det = result["result"].as_str().unwrap_or("unknown");
                        detections.push((engine.clone(), det.to_string()));
                    }
                }
            }
        }
        detections.sort_by(|a, b| a.0.cmp(&b.0));

        info!(
            sha256,
            positives,
            total,
            detections = detections.len(),
            "VT lookup complete"
        );

        Ok(VtLookupResult {
            sha256: sha256.to_string(),
            found: true,
            positives: Some(positives as u32),
            total: Some(total as u32),
            scan_date,
            permalink,
            detections,
        })
    }
}
