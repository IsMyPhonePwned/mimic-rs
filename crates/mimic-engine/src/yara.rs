/// YARA-X rule compilation and scanning.

use mimic_core::{MimicError, ScanVerdict, Verdict, YaraMatch};
use std::path::Path;
use tracing::{debug, info, warn};

pub struct YaraEngine {
    rules: yara_x::Rules,
}

impl YaraEngine {
    /// Compile YARA rules from a list of file/directory paths.
    /// When paths is empty, returns an engine with no rules (YARA "loaded" but 0 rules).
    pub fn new(paths: &[String]) -> Result<Option<Self>, MimicError> {
        if paths.is_empty() {
            debug!("No YARA paths configured, initializing YARA with empty rules (enabled by default)");
            let rules = yara_x::Compiler::new().build();
            return Ok(Some(Self { rules }));
        }

        info!(
            path_count = paths.len(),
            paths = ?paths,
            "Loading YARA rules"
        );

        let mut compiler = yara_x::Compiler::new();
        let mut rule_count = 0usize;

        for path_str in paths {
            let path = Path::new(path_str);
            if !path.exists() {
                warn!(path = %path.display(), "YARA path does not exist, skipping");
                continue;
            }
            if path.is_file() {
                rule_count += load_rule_file(&mut compiler, path)?;
            } else if path.is_dir() {
                info!(dir = %path.display(), "Scanning directory for YARA rule files (.yar, .yara)");
                rule_count += load_rule_dir(&mut compiler, path)?;
            }
        }

        if rule_count == 0 {
            warn!("No YARA rules loaded from given paths, using empty rules");
        }

        info!(rule_count, "Compiling YARA rules");
        let rules = compiler.build();
        info!(rule_count, "YARA-X rules compiled successfully");
        Ok(Some(Self { rules }))
    }

    /// Scan file bytes against compiled YARA rules.
    pub fn scan(&self, data: &[u8]) -> ScanVerdict {
        let mut scanner = yara_x::Scanner::new(&self.rules);
        match scanner.scan(data) {
            Ok(results) => {
                let matches: Vec<YaraMatch> = results
                    .matching_rules()
                    .map(|rule| YaraMatch {
                        rule: rule.identifier().to_string(),
                        namespace: rule.namespace().to_string(),
                        tags: rule.tags().map(|t| t.identifier().to_string()).collect(),
                    })
                    .collect();

                if matches.is_empty() {
                    ScanVerdict::clean()
                } else {
                    ScanVerdict {
                        verdict: Verdict::Infected,
                        signature_threats: Vec::new(),
                        mimic_threats: Vec::new(),
                        yara_matches: matches,
                    }
                }
            }
            Err(e) => {
                tracing::debug!(error = %e, "YARA scan error");
                ScanVerdict::clean()
            }
        }
    }
}

fn load_rule_file(compiler: &mut yara_x::Compiler, path: &Path) -> Result<usize, MimicError> {
    let source = std::fs::read_to_string(path).map_err(|e| {
        MimicError::Engine(format!("failed to read YARA file {}: {}", path.display(), e))
    })?;
    let size = source.len();
    match compiler.add_source(source.as_str()) {
        Ok(_) => {
            info!(
                path = %path.display(),
                size_bytes = size,
                "Loaded YARA rule file"
            );
            Ok(1)
        }
        Err(e) => {
            warn!(
                path = %path.display(),
                error = %e,
                "Failed to compile YARA rule file, skipping"
            );
            Ok(0)
        }
    }
}

fn load_rule_dir(compiler: &mut yara_x::Compiler, dir: &Path) -> Result<usize, MimicError> {
    let mut count = 0;
    let mut skipped = 0;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if ext == "yar" || ext == "yara" {
                count += load_rule_file(compiler, &path)?;
            } else {
                skipped += 1;
                debug!(
                    path = %path.display(),
                    ext = ext,
                    "Skipping non-YARA file in rules directory"
                );
            }
        }
    }
    if skipped > 0 {
        debug!(dir = %dir.display(), skipped, "Skipped non-.yar/.yara files");
    }
    Ok(count)
}
