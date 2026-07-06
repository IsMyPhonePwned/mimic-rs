/// Single-file scanner: hash computation + signature matching + YARA + WASM plugins.
/// Mimic-detect (exploit detection) runs only when loaded as a WASM plugin (e.g. mimic_detect.wasm).
/// When `mimic_detect` is loaded, native `mimic_detect::analyze` enriches generic plugin threats with
/// CVE / advisory id, description, and reference (same logic as the WASM `scan` entry point).

use mimic_core::{MimicThreat, ScanConfig, ScanResult, ScanVerdict, Verdict};
use mimic_detect::{analyze as mimic_analyze, Verdict as MimicVerdict};
use mimic_signatures::SignatureMatcher;
use mimic_wasm::WasmPluginEngine;
use crate::yara::YaraEngine;
use std::time::Instant;
use tracing::debug;

const MIMIC_DETECT_PLUGIN: &str = "mimic_detect";

/// Replace generic `plugin:mimic_detect` threats with structured ids from native analysis.
fn enrich_mimic_detect_threats(data: &[u8], verdict: &mut ScanVerdict) {
    let ar = mimic_analyze(data);
    if ar.threats.is_empty() {
        return;
    }
    verdict
        .mimic_threats
        .retain(|t| !t.id.starts_with("plugin:mimic_detect"));
    for t in ar.threats {
        verdict.mimic_threats.push(MimicThreat {
            id: t.id,
            description: t.description,
            reference: t.reference,
        });
    }
    match ar.verdict {
        MimicVerdict::Malicious => {
            if verdict.verdict == Verdict::Clean {
                verdict.verdict = Verdict::Infected;
            }
        }
        MimicVerdict::Suspicious => {
            if verdict.verdict == Verdict::Clean {
                verdict.verdict = Verdict::Suspicious;
            }
        }
        MimicVerdict::Benign => {}
    }
}

pub struct FileScanner<'a> {
    config: &'a ScanConfig,
    matcher: Option<&'a SignatureMatcher>,
    wasm_plugins: Option<&'a WasmPluginEngine>,
    yara_engine: Option<&'a YaraEngine>,
}

impl<'a> FileScanner<'a> {
    pub fn new(
        config: &'a ScanConfig,
        matcher: Option<&'a SignatureMatcher>,
        wasm_plugins: Option<&'a WasmPluginEngine>,
        yara_engine: Option<&'a YaraEngine>,
    ) -> Self {
        Self { config, matcher, wasm_plugins, yara_engine }
    }

    pub fn scan_bytes(&self, path: &str, data: &[u8]) -> ScanResult {
        let start = Instant::now();

        if self.config.max_file_size > 0 && data.len() as u64 > self.config.max_file_size {
            return ScanResult {
                path: path.to_string(),
                size_bytes: data.len() as u64,
                sha256: String::new(),
                md5: String::new(),
                scan_verdict: ScanVerdict {
                    verdict: Verdict::Error,
                    signature_threats: Vec::new(),
                    mimic_threats: Vec::new(),
                    yara_matches: Vec::new(),
                },
                scan_duration_us: start.elapsed().as_micros() as u64,
                error: Some("file exceeds max size".into()),
            };
        }

        let md5_hex = compute_md5(data);
        let sha256_hex = compute_sha256(data);

        let mut result = self.run_analysis(path, data, &md5_hex, &sha256_hex);
        result.scan_duration_us = start.elapsed().as_micros() as u64;
        result
    }

    /// Scan with pre-computed hashes (used in sandbox mode to avoid double-hashing).
    pub fn scan_bytes_with_hashes(&self, path: &str, data: &[u8], md5: &str, sha256: &str) -> ScanResult {
        let start = Instant::now();
        let mut result = self.run_analysis(path, data, md5, sha256);
        result.scan_duration_us = start.elapsed().as_micros() as u64;
        result
    }

    fn run_analysis(&self, path: &str, data: &[u8], md5_hex: &str, sha256_hex: &str) -> ScanResult {
        let file_size = data.len() as u64;
        let mut verdict = ScanVerdict::clean();

        // Phase 1: ClamAV signature matching (hash + body patterns)
        if self.config.enable_signatures {
            if let Some(matcher) = self.matcher {
                debug!(path = %path, "scan phase: ClamAV signatures");
                let sig_threats = matcher.scan(data, md5_hex, sha256_hex, file_size);
                if !sig_threats.is_empty() {
                    debug!(path = %path, count = sig_threats.len(), "ClamAV signatures matched");
                    verdict.verdict = Verdict::Infected;
                    verdict.signature_threats = sig_threats;
                }
            }
        }

        // Phase 2: YARA-X rule matching
        if let Some(yara) = self.yara_engine {
            debug!(path = %path, "scan phase: YARA");
            let yara_verdict = yara.scan(data);
            verdict.merge(yara_verdict);
        }

        // Phase 3: WASM plugins (include mimic_detect.wasm for exploit detection)
        if let Some(wasm) = self.wasm_plugins {
            let n = wasm.plugin_count();
            debug!(path = %path, plugin_count = n, "scan phase: WASM plugins");
            let plugin_verdict = wasm.scan(data);
            verdict.merge(plugin_verdict);
            if wasm
                .plugin_names()
                .iter()
                .any(|name| name == MIMIC_DETECT_PLUGIN)
            {
                enrich_mimic_detect_threats(data, &mut verdict);
            }
        }

        ScanResult {
            path: path.to_string(),
            size_bytes: file_size,
            sha256: sha256_hex.to_string(),
            md5: md5_hex.to_string(),
            scan_verdict: verdict,
            scan_duration_us: 0,
            error: None,
        }
    }
}

fn compute_md5(data: &[u8]) -> String {
    use md5::Digest;
    format!("{:x}", md5::Md5::digest(data))
}

fn compute_sha256(data: &[u8]) -> String {
    use sha2::Digest;
    format!("{:x}", sha2::Sha256::digest(data))
}
