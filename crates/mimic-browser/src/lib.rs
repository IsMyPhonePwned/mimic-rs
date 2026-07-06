//! # mimic-browser
//!
//! In-browser file scanner powered by the Mimic ClamAV-compatible signature engine,
//! compiled to WebAssembly. Allows loading `.hdb`, `.hsb`, `.ndb`, `.ldb`, `.mdb`,
//! `.msb`, `.fp`, `.sfp`, `.cvd`, `.cld` signature databases and scanning files
//! entirely client-side. Includes a minimal YARA-like rule engine (subset) for the browser.

mod yara_lite;

use mimic_detect::{analyze, Verdict as MimicVerdict};
use mimic_signatures::body_db::BodyDb;
use mimic_signatures::cdb_db::CdbDb;
use mimic_signatures::cvd::extract_cvd;
use mimic_signatures::hash_db::HashDb;
use mimic_signatures::ldb_db::LdbDb;
use mimic_signatures::SignatureMatcher;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

/// Accumulates signature databases during loading, then builds a finalized
/// `SignatureMatcher` for scanning. Optionally holds compiled YARA-like rules (subset).
#[wasm_bindgen]
pub struct BrowserScanner {
    hash_db: HashDb,
    body_db: BodyDb,
    ldb_db: LdbDb,
    cdb_db: CdbDb,
    bytecode_count: u64,
    matcher: Option<SignatureMatcher>,
    yara_rules: Option<Vec<yara_lite::YaraLiteRule>>,
}

#[derive(Serialize, Deserialize)]
pub struct ScanResult {
    pub filename: String,
    pub size: u64,
    pub md5: String,
    pub sha256: String,
    pub threats: Vec<ThreatResult>,
    pub verdict: String,
}

#[derive(Serialize, Deserialize)]
pub struct ThreatResult {
    pub name: String,
    pub sig_type: String,
    /// Human-readable "Why did it match?" explanation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

#[derive(Serialize)]
pub struct LoadStats {
    pub md5_sigs: usize,
    pub sha256_sigs: usize,
    pub mdb_sigs: usize,
    pub msb_sigs: usize,
    pub fp_sigs: usize,
    pub ndb_fixed: usize,
    pub ndb_wildcard: usize,
    pub ldb_sigs: usize,
    pub cdb_sigs: usize,
    pub bytecode_sigs: usize,
    pub total: u64,
}

fn compute_md5(data: &[u8]) -> String {
    use md5::Digest;
    format!("{:x}", md5::Md5::digest(data))
}

fn compute_sha256(data: &[u8]) -> String {
    use sha2::Digest;
    format!("{:x}", sha2::Sha256::digest(data))
}

#[wasm_bindgen]
impl BrowserScanner {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            hash_db: HashDb::new(),
            body_db: BodyDb::new(),
            ldb_db: LdbDb::new(),
            cdb_db: CdbDb::new(),
            bytecode_count: 0,
            matcher: None,
            yara_rules: None,
        }
    }

    /// Compile and set YARA-like rules from source string (subset: strings + "any of them").
    /// Returns JSON: { "rule_count": N } or { "error": "..." }.
    #[wasm_bindgen(js_name = setYaraRules)]
    pub fn set_yara_rules(&mut self, source: &str) -> String {
        match yara_lite::parse_yara_lite(source) {
            Ok(rules) => {
                let count = rules.len();
                self.yara_rules = Some(rules);
                serde_json::json!({ "rule_count": count }).to_string()
            }
            Err(e) => serde_json::json!({ "error": e }).to_string(),
        }
    }

    /// Return number of loaded YARA rules (0 if none).
    #[wasm_bindgen(js_name = getYaraRuleCount)]
    pub fn get_yara_rule_count(&self) -> usize {
        self.yara_rules.as_ref().map(|r| r.len()).unwrap_or(0)
    }

    /// Clear YARA rules only.
    #[wasm_bindgen(js_name = clearYaraRules)]
    pub fn clear_yara_rules(&mut self) {
        self.yara_rules = None;
    }

    /// Run only YARA rules on data (no ClamAV). Returns JSON array of match objects: [{ "rule": "...", "namespace": "..." }].
    #[wasm_bindgen(js_name = scanYaraOnly)]
    pub fn scan_yara_only(&self, data: &[u8]) -> String {
        let matches = match &self.yara_rules {
            Some(rules) => yara_lite::scan_yara_lite(rules, data),
            None => Vec::new(),
        };
        let out: Vec<serde_json::Value> = matches
            .into_iter()
            .map(|(rule, ns)| serde_json::json!({ "rule": rule, "namespace": ns }))
            .collect();
        serde_json::to_string(&out).unwrap_or_else(|_| "[]".to_string())
    }

    /// Load a signature database file. Pass the filename and raw bytes.
    /// Supports: .hdb, .hsb, .ndb, .ldb, .ldu, .mdb, .msb, .fp, .sfp, .cdb, .cbc, .cvd, .cld
    #[wasm_bindgen(js_name = loadDatabase)]
    pub fn load_database(&mut self, filename: &str, data: &[u8]) -> Result<String, JsValue> {
        self.matcher = None; // invalidate the finalized matcher

        let ext = filename
            .rsplit('.')
            .next()
            .unwrap_or("")
            .to_lowercase();

        match ext.as_str() {
            "cvd" | "cld" => {
                let entries = extract_cvd(data).map_err(|e| JsValue::from_str(&e.to_string()))?;
                for entry in entries {
                    let inner_ext = entry
                        .filename
                        .rsplit('.')
                        .next()
                        .unwrap_or("")
                        .to_lowercase();
                    self.load_by_ext(&inner_ext, &entry.data);
                }
            }
            other => {
                self.load_by_ext(other, data);
            }
        }

        let stats = self.get_stats_internal();
        serde_json::to_string(&stats).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Finalize the scanner (builds Aho-Corasick search automatons).
    /// Called automatically on first scan, but can be called explicitly for
    /// progress feedback.
    pub fn finalize(&mut self) {
        let mut body_db = std::mem::replace(&mut self.body_db, BodyDb::new());
        let mut ldb_db = std::mem::replace(&mut self.ldb_db, LdbDb::new());
        body_db.finalize_automaton();
        ldb_db.finalize_automaton();

        self.matcher = Some(SignatureMatcher::new(
            std::mem::replace(&mut self.hash_db, HashDb::new()),
            body_db,
            ldb_db,
            std::mem::replace(&mut self.cdb_db, CdbDb::new()),
            self.bytecode_count,
        ));
    }

    /// Scan a file. Returns JSON with results (ClamAV + mimic-detect; VT is done in JS).
    #[wasm_bindgen(js_name = scanFile)]
    pub fn scan_file(&mut self, filename: &str, data: &[u8]) -> Result<String, JsValue> {
        if self.matcher.is_none() {
            self.finalize();
        }
        let matcher = self.matcher.as_ref().unwrap();

        let md5 = compute_md5(data);
        let sha256 = compute_sha256(data);
        let size = data.len() as u64;

        let mut threats: Vec<ThreatResult> = matcher
            .scan(data, &md5, &sha256, size)
            .into_iter()
            .map(|t| ThreatResult {
                name: t.name,
                sig_type: t.signature_type,
                why: t.match_reason,
            })
            .collect();

        // mimic-detect: exploit detection (DNG, RTF, TTF, PDF, RAR)
        let mimic_result = analyze(data);
        if matches!(mimic_result.verdict, MimicVerdict::Malicious | MimicVerdict::Suspicious) {
            for t in &mimic_result.threats {
                let why = match &t.reference {
                    Some(r) => Some(format!("{} See: {}", t.description, r)),
                    None => Some(t.description.clone()),
                };
                threats.push(ThreatResult {
                    name: format!("{} — {}", t.id, t.description),
                    sig_type: "mimic-detect".to_string(),
                    why,
                });
            }
        }

        // YARA-like: run compiled rules if any
        if let Some(ref rules) = self.yara_rules {
            for (rule_name, ns) in yara_lite::scan_yara_lite(rules, data) {
                threats.push(ThreatResult {
                    name: format!("{}::{}", ns, rule_name),
                    sig_type: "yara".to_string(),
                    why: Some("A YARA rule string or condition matched in the file.".to_string()),
                });
            }
        }

        let verdict = if threats.is_empty() {
            "CLEAN".to_string()
        } else {
            "INFECTED".to_string()
        };

        let result = ScanResult {
            filename: filename.to_string(),
            size,
            md5,
            sha256,
            verdict,
            threats,
        };

        serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Get current signature statistics as JSON.
    #[wasm_bindgen(js_name = getStats)]
    pub fn get_stats(&self) -> String {
        if let Some(ref m) = self.matcher {
            let s = m.stats();
            let stats = LoadStats {
                md5_sigs: s.md5_sigs,
                sha256_sigs: s.sha256_sigs,
                mdb_sigs: s.mdb_sigs,
                msb_sigs: s.msb_sigs,
                fp_sigs: s.fp_sigs,
                ndb_fixed: s.body_fixed_sigs,
                ndb_wildcard: s.body_wildcard_sigs,
                ldb_sigs: s.ldb_sigs,
                cdb_sigs: s.cdb_sigs,
                bytecode_sigs: s.bytecode_sigs,
                total: s.total_signatures(),
            };
            return serde_json::to_string(&stats).unwrap_or_default();
        }
        serde_json::to_string(&self.get_stats_internal()).unwrap_or_default()
    }

    /// Reset the scanner, clearing all loaded databases and YARA rules.
    pub fn reset(&mut self) {
        self.hash_db = HashDb::new();
        self.body_db = BodyDb::new();
        self.ldb_db = LdbDb::new();
        self.cdb_db = CdbDb::new();
        self.bytecode_count = 0;
        self.matcher = None;
        self.yara_rules = None;
    }
}

impl BrowserScanner {
    fn load_by_ext(&mut self, ext: &str, data: &[u8]) {
        match ext {
            "hdb" => self.hash_db.load_hdb(data),
            "hsb" => self.hash_db.load_hsb(data),
            "mdb" => self.hash_db.load_mdb(data),
            "msb" => self.hash_db.load_msb(data),
            "ndb" => self.body_db.load_ndb(data),
            "ldb" | "ldu" => self.ldb_db.load_ldb(data),
            "cdb" => self.cdb_db.load_cdb(data),
            "fp" => self.hash_db.load_fp(data),
            "sfp" => self.hash_db.load_sfp(data),
            "cbc" => {
                self.bytecode_count += count_bytecode_sigs(data);
            }
            _ => {}
        }
    }

    fn get_stats_internal(&self) -> LoadStats {
        LoadStats {
            md5_sigs: self.hash_db.md5_count(),
            sha256_sigs: self.hash_db.sha256_count(),
            mdb_sigs: self.hash_db.mdb_count(),
            msb_sigs: self.hash_db.msb_count(),
            fp_sigs: self.hash_db.fp_count(),
            ndb_fixed: self.body_db.fixed_count(),
            ndb_wildcard: self.body_db.wildcard_count(),
            ldb_sigs: self.ldb_db.count(),
            cdb_sigs: self.cdb_db.count(),
            bytecode_sigs: self.bytecode_count as usize,
            total: (self.hash_db.md5_count()
                + self.hash_db.sha256_count()
                + self.hash_db.mdb_count()
                + self.hash_db.msb_count()
                + self.body_db.fixed_count()
                + self.body_db.wildcard_count()
                + self.ldb_db.count()
                + self.cdb_db.count()
                + self.bytecode_count as usize) as u64,
        }
    }
}

fn count_bytecode_sigs(data: &[u8]) -> u64 {
    let text = match std::str::from_utf8(data) {
        Ok(t) => t,
        Err(_) => return 0,
    };
    text.lines()
        .filter(|l| {
            let l = l.trim();
            !l.is_empty() && !l.starts_with('#')
        })
        .count() as u64
}

#[cfg(test)]
mod tests;
