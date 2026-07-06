/// Database loader: reads .cvd/.cld containers and individual signature files,
/// building a unified SignatureMatcher. Uses maximum parallelism: CVD containers are
/// first extracted, then ALL individual signature data units (from CVDs and standalone)
/// are parsed in parallel across all CPU cores.
///
/// Supported types: .hdb, .hsb, .mdb, .msb, .ndb, .ldb, .ldu, .cdb, .fp, .sfp, .cbc

use crate::body_db::BodyDb;
use crate::cdb_db::CdbDb;
use crate::cvd::extract_cvd;
use crate::hash_db::HashDb;
use crate::ldb_db::LdbDb;
use crate::matcher::SignatureMatcher;
use indicatif::{ProgressBar, ProgressStyle};
use mimic_core::MimicError;
use rayon::prelude::*;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{info, warn};

const SIGNATURE_EXTENSIONS: &[&str] = &[
    "cvd", "cld", "hdb", "hsb", "mdb", "msb", "ndb", "ldb", "ldu", "cdb", "fp", "sfp", "cbc",
];

fn is_signature_extension(ext: &str) -> bool {
    SIGNATURE_EXTENSIONS.contains(&ext)
}

/// Per-unit parse result (one per individual signature data blob).
struct ParsedSigs {
    source: String,
    hash_db: HashDb,
    body_db: BodyDb,
    ldb_db: LdbDb,
    cdb_db: CdbDb,
    bytecode_count: u64,
}

impl ParsedSigs {
    fn new(source: &str) -> Self {
        Self {
            source: source.to_string(),
            hash_db: HashDb::new(),
            body_db: BodyDb::new(),
            ldb_db: LdbDb::new(),
            cdb_db: CdbDb::new(),
            bytecode_count: 0,
        }
    }

    fn sig_count(&self) -> u64 {
        (self.hash_db.md5_count()
            + self.hash_db.sha256_count()
            + self.hash_db.mdb_count()
            + self.hash_db.msb_count()
            + self.body_db.fixed_count()
            + self.body_db.wildcard_count()
            + self.ldb_db.count()
            + self.cdb_db.count()) as u64
            + self.bytecode_count
    }
}

/// A flat work unit: one signature data blob to parse.
struct SigUnit {
    source: String,
    ext: String,
    data: Vec<u8>,
}

fn collect_signature_paths(paths: &[String]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for path_str in paths {
        let path = Path::new(path_str);
        if !path.exists() {
            continue;
        }
        if path.is_file() {
            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_lowercase();
            if is_signature_extension(&ext) {
                out.push(path.to_path_buf());
            }
        } else if path.is_dir() {
            if let Ok(entries) = std::fs::read_dir(path) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if p.is_file() {
                        let ext = p
                            .extension()
                            .and_then(|e| e.to_str())
                            .unwrap_or("")
                            .to_lowercase();
                        if is_signature_extension(&ext) {
                            out.push(p);
                        }
                    }
                }
            }
        }
    }
    out
}

/// Per-source-file signature count for the summary.
#[derive(Debug, Clone)]
pub struct SourceStats {
    pub name: String,
    pub sig_count: u64,
}

/// Load all signature databases from a list of paths (files or directories).
/// Returns (SignatureMatcher, per-source stats).
pub fn load_databases(
    paths: &[String],
) -> Result<(SignatureMatcher, Vec<SourceStats>), MimicError> {
    info!(
        path_count = paths.len(),
        paths = ?paths,
        "Loading ClamAV signature databases (parallel)"
    );

    for path_str in paths {
        let path = Path::new(path_str);
        if !path.exists() {
            warn!(path = %path.display(), "ClamAV path does not exist, skipping");
        }
    }

    let all_files = collect_signature_paths(paths);
    if all_files.is_empty() {
        let matcher = SignatureMatcher::new(
            HashDb::new(),
            BodyDb::new(),
            LdbDb::new(),
            CdbDb::new(),
            0,
        );
        return Ok((matcher, Vec::new()));
    }

    // Single 0–100% progress bar across all loading phases
    let pb = ProgressBar::new(100);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {pos:>3}% {msg}")
            .unwrap()
            .progress_chars("=> "),
    );
    pb.enable_steady_tick(std::time::Duration::from_millis(120));

    // Phase 1 (0–5%): read all database files in parallel
    pb.set_position(0);
    pb.set_message(format!("Reading {} database files...", all_files.len()));

    let files_data: Vec<(PathBuf, Vec<u8>)> = all_files
        .par_iter()
        .filter_map(|path| std::fs::read(path).ok().map(|data| (path.clone(), data)))
        .collect();

    pb.set_position(5);

    // Phase 2 (5–15%): extract CVD/CLD containers → flatten into SigUnits
    pb.set_message("Extracting CVD containers...");

    let all_units: Vec<SigUnit> = files_data
        .par_iter()
        .flat_map_iter(|(path, data)| flatten_file(path, data))
        .collect();

    let num_units = all_units.len();
    pb.set_position(15);
    pb.set_message(format!("Parsing {} signature units...", num_units));

    // Phase 3 (15–80%): parse ALL units in parallel
    let parsed_counter = AtomicU64::new(0);
    let num_units_u64 = num_units.max(1) as u64;

    let results: Vec<ParsedSigs> = all_units
        .par_iter()
        .map(|unit| {
            let mut sigs = ParsedSigs::new(&unit.source);
            load_by_ext(&unit.ext, &unit.data, &mut sigs);
            let done = parsed_counter.fetch_add(1, Ordering::Relaxed) + 1;
            pb.set_position(15 + (done * 65 / num_units_u64));
            sigs
        })
        .collect();

    pb.set_position(80);

    // Phase 4 (80–90%): merge parsed results
    pb.set_message("Merging databases...");

    let mut hash_db = HashDb::new();
    let mut body_db = BodyDb::new();
    let mut ldb_db = LdbDb::new();
    let mut cdb_db = CdbDb::new();
    let mut bytecode_count = 0u64;
    let mut source_counts: HashMap<String, u64> = HashMap::new();

    let num_results = results.len();
    for (i, r) in results.into_iter().enumerate() {
        let cnt = r.sig_count();
        *source_counts.entry(r.source).or_insert(0) += cnt;
        hash_db.merge(r.hash_db);
        body_db.merge(r.body_db);
        ldb_db.merge(r.ldb_db);
        cdb_db.merge(r.cdb_db);
        bytecode_count += r.bytecode_count;
        if i % 8 == 0 {
            pb.set_position(80 + ((i as u64) * 10 / num_results.max(1) as u64));
        }
    }

    pb.set_position(90);

    // Phase 5 (90–100%): build Aho-Corasick automatons + eligible sets IN PARALLEL
    pb.set_message("Building search automata...");
    std::thread::scope(|s| {
        let h1 = s.spawn(|| body_db.finalize_automaton());
        let h2 = s.spawn(|| ldb_db.finalize_automaton());
        h1.join().ok();
        h2.join().ok();
    });
    pb.set_position(100);

    pb.finish_and_clear();

    let matcher = SignatureMatcher::new(hash_db, body_db, ldb_db, cdb_db, bytecode_count);
    let stats = matcher.stats();
    info!(%stats, "ClamAV signature databases loaded successfully");

    let mut source_stats: Vec<SourceStats> = source_counts
        .into_iter()
        .map(|(name, sig_count)| SourceStats { name, sig_count })
        .collect();
    source_stats.sort_by(|a, b| b.sig_count.cmp(&a.sig_count));

    Ok((matcher, source_stats))
}

/// Flatten a top-level file into individual SigUnits.
fn flatten_file(path: &Path, data: &[u8]) -> Vec<SigUnit> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    let source_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("?")
        .to_string();

    match ext.as_str() {
        "cvd" | "cld" => match extract_cvd(data) {
            Ok(entries) => entries
                .into_iter()
                .filter_map(|entry| {
                    let inner_ext = entry
                        .filename
                        .rsplit('.')
                        .next()
                        .unwrap_or("")
                        .to_lowercase();
                    if inner_ext.is_empty() {
                        return None;
                    }
                    Some(SigUnit {
                        source: source_name.clone(),
                        ext: inner_ext,
                        data: entry.data,
                    })
                })
                .collect(),
            Err(e) => {
                warn!(path = %path.display(), error = %e, "Failed to extract CVD");
                Vec::new()
            }
        },
        _ => {
            vec![SigUnit {
                source: source_name,
                ext,
                data: data.to_vec(),
            }]
        }
    }
}

fn load_by_ext(ext: &str, data: &[u8], sigs: &mut ParsedSigs) {
    match ext {
        "hdb" => sigs.hash_db.load_hdb(data),
        "hsb" => sigs.hash_db.load_hsb(data),
        "mdb" => sigs.hash_db.load_mdb(data),
        "msb" => sigs.hash_db.load_msb(data),
        "ndb" => sigs.body_db.load_ndb(data),
        "ldb" | "ldu" => sigs.ldb_db.load_ldb(data),
        "cdb" => sigs.cdb_db.load_cdb(data),
        "fp" => sigs.hash_db.load_fp(data),
        "sfp" => sigs.hash_db.load_sfp(data),
        "cbc" => {
            sigs.bytecode_count += count_bytecode_sigs(data);
        }
        _ => {}
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
