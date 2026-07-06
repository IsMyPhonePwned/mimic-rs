//! # Mimic CLI
//!
//! Command-line interface for the Mimic antivirus engine. Supports default scan mode
//! (file or directory), recursive scanning with progress bar, and a `serve` subcommand
//! for the web dashboard and REST API. Options: `-d` ClamAV DBs, `-y` YARA rules,
//! `--plugin` WASM plugins, `--vt-key` VirusTotal, `--sandbox` for worker isolation,
//! `--db-file` for SQLite persistence. See `mimic --help` and `mimic serve --help`.

use clap::{Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use mimic_core::{ScanConfig, ScanResult, Verdict};
use mimic_db::MimicDb;
use mimic_engine::MimicEngine;
use mimic_sandbox::worker::run_worker_loop;
use mimic_vt::VtConfig;
use mimic_web::{build_router, AppState};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use tracing::error;
use walkdir::WalkDir;

/// Filenames that trigger the built-in VirusTotal plugin (load with: --plugin path/mimic-vt.wasm).
/// Cargo produces mimic_vt.wasm from the crate name; both are accepted.
const VT_PLUGIN_FILENAMES: &[&str] = &["mimic-vt.wasm", "mimic_vt.wasm"];

/// Splits plugin list into WASM paths (for the engine) and whether the VT built-in plugin is requested.
/// A path whose filename is "mimic-vt.wasm" or "mimic_vt.wasm" enables the built-in VT client; it is not passed to the WASM loader.
fn split_plugins(plugins: &[String]) -> (Vec<String>, bool) {
    let mut wasm_paths = Vec::new();
    let mut vt_requested = false;
    for p in plugins {
        let path = Path::new(p.trim());
        let is_vt = path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| VT_PLUGIN_FILENAMES.iter().any(|v| n.eq_ignore_ascii_case(v)))
            .unwrap_or(false);
        if is_vt {
            vt_requested = true;
        } else {
            wasm_paths.push(p.clone());
        }
    }
    (wasm_paths, vt_requested)
}

#[derive(Parser)]
#[command(
    name = "mimic",
    about = "Mimic — Next-generation antivirus engine",
    long_about = "High-speed parallel file scanner with ClamAV signatures, YARA rules, VirusTotal lookups, and advanced exploit detection."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// File or directory to scan (for default scan mode).
    path: Option<String>,

    /// Recurse into subdirectories.
    #[arg(short, long)]
    recursive: bool,

    /// ClamAV signature database paths. Repeatable.
    #[arg(short = 'd', long = "db", value_name = "PATH")]
    databases: Vec<String>,

    /// YARA rule files or directories. Repeatable.
    #[arg(short = 'y', long = "yara", value_name = "PATH")]
    yara: Vec<String>,

    /// Number of scanning threads (0 = auto).
    #[arg(short = 'j', long = "threads", default_value = "0")]
    threads: usize,

    /// Maximum file size in MB (0 = no limit).
    #[arg(long = "max-size", default_value = "256")]
    max_size_mb: u64,

    /// File extensions to scan (comma-separated).
    #[arg(short, long, default_value = "")]
    extensions: String,

    /// Output as JSON.
    #[arg(long)]
    json: bool,

    /// Only show infected/suspicious files.
    #[arg(short, long)]
    quiet: bool,

    /// Disable mimic advanced exploit detection.
    #[arg(long = "no-mimic")]
    no_mimic: bool,

    /// Disable ClamAV signature scanning.
    #[arg(long = "no-signatures")]
    no_signatures: bool,

    /// WASM plugins (file or directory). Use path/mimic-vt.wasm for VirusTotal. Repeatable.
    #[arg(long = "plugin", value_name = "PATH")]
    plugins: Vec<String>,

    /// Enable sandboxed scanning: each file is read in a separate hardened subprocess.
    #[arg(long = "sandbox")]
    sandbox: bool,

    /// VirusTotal API key for hash lookups (hash-only, no file upload).
    #[arg(long = "vt-key", value_name = "KEY", env = "MIMIC_VT_KEY")]
    vt_key: Option<String>,

    /// SQLite database path for persisting results.
    #[arg(long = "db-file", value_name = "PATH", default_value = "mimic.db")]
    db_file: String,

    /// Run as sandboxed worker (internal).
    #[arg(long = "sandbox-worker", hide = true)]
    sandbox_worker: bool,

    /// Verbose output (-v, -vv, -vvv).
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the web UI and REST API server.
    Serve {
        /// Listen address (same option name as mimic-mcp --listen for compatibility).
        #[arg(long = "listen", default_value = "0.0.0.0:8080")]
        listen: String,

        /// ClamAV signature database path(s). Repeatable. Overrides global -d/--db when set.
        #[arg(long = "db", value_name = "PATH")]
        clamav_db: Vec<String>,

        /// Wipe all sessions and scan records from the database before starting (keeps schema).
        #[arg(long = "clean-db")]
        clean_db: bool,

        /// WASM plugin file(s) or directory; use path/mimic-vt.wasm for VirusTotal. Repeatable. Overrides global --plugin when set.
        #[arg(long = "plugin", value_name = "PATH")]
        plugins: Vec<String>,

        /// VirusTotal API key for hash lookups. Overrides global --vt-key when set.
        #[arg(long = "vt-key", value_name = "KEY", env = "MIMIC_VT_KEY")]
        vt_key: Option<String>,

        /// Verbose output (-v, -vv, -vvv). Overrides global -v when set after serve.
        #[arg(short, long, action = clap::ArgAction::Count)]
        verbose: u8,
    },
}

fn main() {
    let cli = Cli::parse();

    if cli.sandbox_worker {
        // Worker process: init tracing so sandbox logs go to stderr (--verbose has no effect yet)
        init_tracing(1); // default to -v level so worker lifecycle is visible
        if let Err(e) = run_worker_loop() {
            eprintln!("sandbox worker error: {e}");
            std::process::exit(1);
        }
        return;
    }

    let verbose = match &cli.command {
        Some(Commands::Serve { verbose, .. }) => cli.verbose + verbose,
        None => cli.verbose,
    };
    init_tracing(verbose);

    match &cli.command {
        Some(Commands::Serve {
            listen,
            clamav_db,
            clean_db,
            plugins,
            vt_key: serve_vt_key,
            ..
        }) => run_server(&cli, listen, clamav_db, *clean_db, plugins, serve_vt_key.as_deref()),
        None => run_scan(&cli),
    }
}

fn build_config(cli: &Cli) -> ScanConfig {
    build_config_with_signature_paths(cli, cli.databases.clone())
}

fn build_config_with_signature_paths(cli: &Cli, signature_paths: Vec<String>) -> ScanConfig {
    let (wasm_paths, _) = split_plugins(&cli.plugins);
    build_config_serve(cli, signature_paths, wasm_paths)
}

fn build_config_serve(
    cli: &Cli,
    signature_paths: Vec<String>,
    plugin_paths: Vec<String>,
) -> ScanConfig {
    ScanConfig {
        threads: cli.threads,
        max_file_size: cli.max_size_mb * 1024 * 1024,
        signature_paths,
        enable_mimic: !cli.no_mimic,
        enable_signatures: !cli.no_signatures,
        enable_sandbox: cli.sandbox,
        extensions: parse_extensions(&cli.extensions),
        recursive: cli.recursive,
        plugin_paths,
        yara_paths: cli.yara.clone(),
    }
}

fn run_scan(cli: &Cli) {
    let scan_path_str = match &cli.path {
        Some(p) => p.clone(),
        None => {
            eprintln!("Error: no scan path provided. Use: mimic <PATH>");
            std::process::exit(1);
        }
    };

    let config = build_config(cli);

    let engine = match MimicEngine::new(config) {
        Ok(e) => e,
        Err(e) => {
            error!(error = %e, "failed to initialize engine");
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    };

    if !cli.quiet
        && !cli.json
        && cli.no_signatures
        && cli.plugins.is_empty()
    {
        eprintln!(
            "[!] Warning: --no-signatures and no --plugin: WASM exploit detection (mimic-detect) is not loaded. \
Build with: cargo build --release --target wasm32-unknown-unknown -p mimic-detect \
then add: --plugin target/wasm32-unknown-unknown/release/mimic_detect.wasm"
        );
    }

    let db = MimicDb::open(Path::new(&cli.db_file)).ok();

    if let Some(stats) = engine.matcher_stats() {
        if !cli.quiet && !cli.json {
            eprintln!("[*] {stats}");
        }
    }

    let scan_path = Path::new(&scan_path_str);
    if !scan_path.exists() {
        eprintln!("Error: path not found: {scan_path_str}");
        std::process::exit(1);
    }

    let start = Instant::now();
    let start_wall = chrono::Utc::now();
    let files = collect_files(scan_path, cli.recursive, &engine.config().extensions);
    let file_count = files.len() as u64;
    let dir_count = count_scanned_directories(&files);

    if !cli.quiet && !cli.json {
        eprintln!("[*] collected {} files to scan", file_count);
    }

    let session_id = db.as_ref().and_then(|d| d.create_session(&scan_path_str).ok());

    let (tx, rx) = crossbeam_channel::unbounded::<ScanResult>();

    let show_progress = !cli.json && !cli.quiet && file_count > 1;
    let pb = if show_progress {
        let pb = ProgressBar::new(file_count);
        pb.set_style(
            ProgressStyle::with_template(
                "{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} ({percent}%) {wide_msg}"
            )
            .unwrap()
            .progress_chars("=>-"),
        );
        pb.enable_steady_tick(std::time::Duration::from_millis(100));
        Some(pb)
    } else {
        None
    };

    let json_output = cli.json;
    let quiet_output = cli.quiet;
    let db_ref = db.map(Arc::new);
    let db_collector = db_ref.clone();
    let sid = session_id.clone();

    let collector = std::thread::spawn(move || {
        let mut total = 0u64;
        let mut infected = 0u64;
        let mut suspicious = 0u64;
        let mut errors = 0u64;
        let mut clean = 0u64;
        let mut total_bytes = 0u64;

        for result in rx {
            total += 1;
            total_bytes += result.size_bytes;
            match result.scan_verdict.verdict {
                Verdict::Infected => infected += 1,
                Verdict::Suspicious => suspicious += 1,
                Verdict::Error => errors += 1,
                Verdict::Clean => clean += 1,
            }

            if let Some(ref pb) = pb {
                let short = result.path.rsplit('/').next().unwrap_or(&result.path);
                pb.set_message(short.to_string());
                pb.inc(1);
            }

            if let (Some(ref db), Some(ref sid)) = (&db_collector, &sid) {
                let _ = db.insert_result(sid, &result);
            }

            print_result(&result, json_output, quiet_output);
        }

        if let Some(pb) = pb {
            pb.finish_and_clear();
        }

        (total, infected, suspicious, clean, errors, total_bytes)
    });

    engine.scan_files_parallel(files, tx);

    let (total, infected, suspicious, clean, errors, total_bytes) = collector.join().unwrap();
    let elapsed = start.elapsed();

    if let (Some(db), Some(sid)) = (&db_ref, &session_id) {
        let _ = db.finish_session(
            sid,
            total,
            infected,
            suspicious,
            clean,
            errors,
            total_bytes,
            elapsed.as_millis() as u64,
        );
    }

    if !cli.json {
        print_scan_summary(
            &engine,
            dir_count,
            total,
            infected,
            total_bytes,
            elapsed,
            start_wall,
            session_id.is_some(),
            &cli.db_file,
        );
    }

    if infected > 0 {
        std::process::exit(1);
    }
}

fn run_server(
    cli: &Cli,
    listen: &str,
    clamav_db: &[String],
    clean_db: bool,
    plugins: &[String],
    serve_vt_key: Option<&str>,
) {
    let vt_key = serve_vt_key.or(cli.vt_key.as_deref());
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async {
        let signature_paths = if clamav_db.is_empty() {
            cli.databases.clone()
        } else {
            clamav_db.to_vec()
        };
        let effective_plugins = if plugins.is_empty() {
            cli.plugins.as_slice()
        } else {
            plugins
        };
        let (wasm_paths, vt_requested) = split_plugins(effective_plugins);
        let config = build_config_serve(cli, signature_paths, wasm_paths);
        let engine = MimicEngine::new(config).expect("engine init");

        let db = MimicDb::open(Path::new(&cli.db_file)).expect("database open");
        if clean_db {
            db.clean().expect("clean database");
        }

        let vt_config = if vt_requested {
            vt_key.map(|key| VtConfig {
                api_key: key.to_string(),
                hash_only: true,
            })
        } else {
            None
        };

        let state = AppState::new(engine, db, vt_config);
        let app = build_router(state);

        eprintln!("[*] Mimic web UI: http://{listen}");
        eprintln!("[*] REST API:     http://{listen}/api/");

        let listener = tokio::net::TcpListener::bind(listen)
            .await
            .expect("bind failed");
        axum::serve(listener, app).await.expect("server error");
    });
}

fn print_result(result: &ScanResult, json: bool, quiet: bool) {
    if quiet && result.scan_verdict.verdict == Verdict::Clean {
        return;
    }

    if json {
        if let Ok(j) = serde_json::to_string(result) {
            println!("{j}");
        }
        return;
    }

    let icon = match result.scan_verdict.verdict {
        Verdict::Infected => "INFECTED",
        Verdict::Suspicious => "SUSPICIOUS",
        Verdict::Clean => "OK",
        Verdict::Error => "ERROR",
    };

    let duration = if result.scan_duration_us > 1000 {
        format!("{:.1}ms", result.scan_duration_us as f64 / 1000.0)
    } else {
        format!("{}us", result.scan_duration_us)
    };

    println!("{icon}: {} ({} bytes, {duration})", result.path, result.size_bytes);

    for threat in &result.scan_verdict.signature_threats {
        println!("  [sig] {} ({})", threat.name, threat.signature_type);
        if let Some(ref reason) = threat.match_reason {
            println!("    why: {reason}");
        }
    }
    for threat in &result.scan_verdict.mimic_threats {
        println!("  [mimic] {}: {}", threat.id, threat.description);
        if let Some(ref r) = threat.reference {
            println!("    ref: {r}");
        }
    }
    for m in &result.scan_verdict.yara_matches {
        let tags = if m.tags.is_empty() {
            String::new()
        } else {
            format!(" [{}]", m.tags.join(", "))
        };
        println!("  [yara] {}::{}{}", m.namespace, m.rule, tags);
    }
    if let Some(ref e) = result.error {
        println!("  error: {e}");
    }
}

fn collect_files(path: &Path, recursive: bool, extensions: &[String]) -> Vec<PathBuf> {
    let mut files = Vec::new();

    if path.is_file() {
        files.push(path.to_path_buf());
        return files;
    }

    let walker = if recursive {
        WalkDir::new(path).into_iter()
    } else {
        WalkDir::new(path).max_depth(1).into_iter()
    };

    for entry in walker.filter_map(|e| e.ok()) {
        let p = entry.path();
        if !p.is_file() {
            continue;
        }
        if !extensions.is_empty() {
            let ext = p
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_lowercase();
            if ext.is_empty() || !extensions.iter().any(|e| e == &ext) {
                continue;
            }
        }
        files.push(p.to_path_buf());
    }

    files
}

fn count_scanned_directories(files: &[PathBuf]) -> u64 {
    let dirs: HashSet<_> = files
        .iter()
        .filter_map(|p| p.parent().map(|d| d.to_path_buf()))
        .collect();
    dirs.len() as u64
}

fn print_scan_summary(
    engine: &MimicEngine,
    scanned_dirs: u64,
    scanned_files: u64,
    infected_files: u64,
    data_scanned_bytes: u64,
    elapsed: std::time::Duration,
    start_wall: chrono::DateTime<chrono::Utc>,
    results_saved: bool,
    db_file: &str,
) {
    let end_wall = start_wall + chrono::Duration::from_std(elapsed).unwrap_or_default();
    let known_viruses = engine
        .matcher_stats_detailed()
        .map(|s| s.total_signatures())
        .unwrap_or(0);

    let data_str = if data_scanned_bytes >= 1024 * 1024 {
        format!("{:.2} MiB", data_scanned_bytes as f64 / 1_048_576.0)
    } else {
        format!("{:.2} KiB", data_scanned_bytes as f64 / 1024.0)
    };

    let secs = elapsed.as_secs();
    let time_str = if secs >= 60 {
        format!(
            "{:.3} sec ({} m {} s)",
            elapsed.as_secs_f64(),
            secs / 60,
            secs % 60
        )
    } else {
        format!("{:.3} sec", elapsed.as_secs_f64())
    };

    eprintln!();
    eprintln!("----------- MIMIC SCAN SUMMARY -----------");
    eprintln!("Known viruses: {}", known_viruses);

    let src_stats = engine.source_stats();
    if !src_stats.is_empty() {
        for ss in src_stats {
            eprintln!("  {}: {} sigs", ss.name, ss.sig_count);
        }
    }

    eprintln!("Engine version: {}", env!("CARGO_PKG_VERSION"));
    eprintln!("Scanned directories: {}", scanned_dirs);
    eprintln!("Scanned files: {}", scanned_files);
    eprintln!("Infected files: {}", infected_files);
    eprintln!("Data scanned: {}", data_str);
    eprintln!("Time: {}", time_str);
    eprintln!(
        "Start Date: {}",
        start_wall.format("%Y:%m:%d %H:%M:%S")
    );
    eprintln!(
        "End Date:   {}",
        end_wall.format("%Y:%m:%d %H:%M:%S")
    );
    if results_saved {
        eprintln!("Results saved to: {}", db_file);
    }
    eprintln!("---------------------------------------------");
}

fn parse_extensions(s: &str) -> Vec<String> {
    if s.is_empty() {
        return Vec::new();
    }
    s.split(',')
        .map(|e| e.trim().to_lowercase())
        .filter(|e| !e.is_empty())
        .collect()
}

/// EnvFilter that sets only mimic crates to the given level; other crates are at WARN to avoid flooding (e.g. wasmtime TRACE).
fn mimic_only_filter(level: &str) -> tracing_subscriber::EnvFilter {
    let directives = [
        "mimic_cli",
        "mimic_engine",
        "mimic_sandbox",
        "mimic_signatures",
        "mimic_wasm",
        "mimic_core",
        "mimic_db",
        "mimic_detect",
        "mimic_vt",
        "mimic_web",
    ]
    .iter()
    .map(|crate_| format!("{}={}", crate_, level))
    .collect::<Vec<_>>()
    .join(",");
    // Default everything else to warn so dependencies (e.g. wasmtime) don't flood at trace
    tracing_subscriber::EnvFilter::new(format!("{},warn", directives))
}

fn init_tracing(verbosity: u8) {
    let filter = match verbosity {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| {
            if verbosity >= 3 {
                mimic_only_filter(filter)
            } else {
                tracing_subscriber::EnvFilter::new(filter)
            }
        });

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();
}
