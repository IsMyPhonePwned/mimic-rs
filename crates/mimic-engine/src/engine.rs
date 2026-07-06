/// The main Mimic engine: loads databases, configures thread pool, scans files in parallel.
/// Two modes:
///   - In-process (default): rayon thread pool, fastest, no process isolation
///   - Sandboxed: pool of hardened subprocess workers, each file scanned in a separate
///     process with seccomp/seatbelt/privilege-drop

use mimic_core::{ScanConfig, ScanResult, MimicError, ScanVerdict};
use mimic_signatures::{load_databases, SignatureMatcher, MatcherStats, SourceStats};
use mimic_wasm::WasmPluginEngine;
use mimic_sandbox::{WorkerPool, WorkerRequest, SandboxPolicy};
use crate::scanner::FileScanner;
use crate::yara::YaraEngine;
use rayon::prelude::*;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{info, warn, debug};
use crossbeam_channel::Sender;

pub struct MimicEngine {
    config: ScanConfig,
    matcher: Option<Arc<SignatureMatcher>>,
    source_stats: Vec<SourceStats>,
    wasm_plugins: Option<Arc<WasmPluginEngine>>,
    yara_engine: Option<Arc<YaraEngine>>,
    pool: rayon::ThreadPool,
    worker_pool: Option<Arc<WorkerPool>>,
}

impl MimicEngine {
    pub fn new(config: ScanConfig) -> Result<Self, MimicError> {
        let (matcher, source_stats) = if config.enable_signatures && !config.signature_paths.is_empty() {
            info!("loading ClamAV signature databases...");
            let (m, ss) = load_databases(&config.signature_paths)?;
            let stats = m.stats();
            info!(%stats, "signature matcher ready");
            (Some(Arc::new(m)), ss)
        } else {
            (None, Vec::new())
        };

        let num_threads = if config.threads == 0 {
            num_cpus()
        } else {
            config.threads
        };

        let mut wasm_plugins = WasmPluginEngine::new();
        for path_str in &config.plugin_paths {
            let path = Path::new(path_str);
            if path.is_dir() {
                wasm_plugins.load_dir(path)?;
            } else if path.is_file() {
                wasm_plugins.load_file(path)?;
            }
        }
        let wasm_plugins = if wasm_plugins.plugin_count() > 0 {
            info!(count = wasm_plugins.plugin_count(), "WASM plugins loaded");
            Some(Arc::new(wasm_plugins))
        } else {
            None
        };

        let yara_engine = YaraEngine::new(&config.yara_paths)?
            .map(Arc::new);

        // Spawn sandboxed worker pool if enabled
        let worker_pool = if config.enable_sandbox {
            let bin = std::env::current_exe()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "mimic".to_string());
            let policy = SandboxPolicy::default();
            info!(workers = num_threads, "spawning sandboxed worker process pool");
            Some(Arc::new(WorkerPool::new(&bin, num_threads, &policy)?))
        } else {
            None
        };

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(num_threads)
            .thread_name(|i| format!("mimic-scan-{i}"))
            .build()
            .map_err(|e| MimicError::Engine(format!("thread pool init failed: {e}")))?;

        info!(
            threads = num_threads,
            sandbox = config.enable_sandbox,
            "mimic engine initialized"
        );

        Ok(Self {
            config,
            matcher,
            source_stats,
            wasm_plugins,
            yara_engine,
            pool,
            worker_pool,
        })
    }

    pub fn scan_file(&self, path: &Path) -> ScanResult {
        if let Some(ref wp) = self.worker_pool {
            let worker_slot = 0;
            debug!(
                path = %path.display(),
                worker_slot = worker_slot,
                worker_count = wp.worker_count(),
                "scan_file: using sandboxed worker"
            );
            let result = self.scan_file_sandboxed(wp, path, 0);
            // Run full analysis in-process (same as scan_parallel_sandboxed).
            if result.error.is_none() && !result.sha256.is_empty() {
                match read_file_fast(path) {
                    Ok(data) => {
                        let scanner = self.make_scanner();
                        let mut full = scanner.scan_bytes_with_hashes(
                            &result.path,
                            &data,
                            &result.md5,
                            &result.sha256,
                        );
                        full.scan_duration_us = result.scan_duration_us;
                        return full;
                    }
                    Err(e) => {
                        warn!(path = %path.display(), error = %e, "re-read after sandbox failed");
                    }
                }
            }
            return result;
        }
        let scanner = self.make_scanner();
        match std::fs::read(path) {
            Ok(data) => scanner.scan_bytes(&path.display().to_string(), &data),
            Err(e) => {
                warn!(path = %path.display(), error = %e, "failed to read file");
                error_result(&path.display().to_string(), &format!("read error: {e}"))
            }
        }
    }

    pub fn scan_bytes(&self, path: &str, data: &[u8]) -> ScanResult {
        self.make_scanner().scan_bytes(path, data)
    }

    /// Scan files in parallel, streaming results to a channel.
    /// Uses sandboxed subprocesses when enable_sandbox is true, otherwise in-process rayon.
    pub fn scan_files_parallel(
        &self,
        files: Vec<PathBuf>,
        tx: Sender<ScanResult>,
    ) {
        if let Some(ref wp) = self.worker_pool {
            self.scan_parallel_sandboxed(files, tx, wp);
        } else {
            self.scan_parallel_inprocess(files, tx);
        }
    }

    /// In-process parallel scanning via rayon (fast path, no isolation).
    fn scan_parallel_inprocess(&self, files: Vec<PathBuf>, tx: Sender<ScanResult>) {
        let config = &self.config;
        let matcher = &self.matcher;
        let wasm = &self.wasm_plugins;
        let yara = &self.yara_engine;

        self.pool.install(|| {
            files.par_iter().for_each(|path| {
                let scanner = FileScanner::new(config, matcher.as_deref(), wasm.as_deref(), yara.as_deref());
                let result = match read_file_fast(path) {
                    Ok(data) => scanner.scan_bytes(&path.display().to_string(), &data),
                    Err(e) => {
                        debug!(path = %path.display(), error = %e, "skipping file");
                        error_result(&path.display().to_string(), &format!("read error: {e}"))
                    }
                };
                let _ = tx.send(result);
            });
        });
    }

    /// Sandboxed parallel scanning: distribute files across worker processes via rayon.
    /// Each rayon thread picks a worker from the pool and sends the file path over IPC.
    /// The worker reads the file, computes hashes; then the parent runs analysis phases
    /// (signatures, YARA, mimic, WASM) in-process on the returned data.
    fn scan_parallel_sandboxed(&self, files: Vec<PathBuf>, tx: Sender<ScanResult>, wp: &Arc<WorkerPool>) {
        info!(
            file_count = files.len(),
            worker_count = wp.worker_count(),
            "scanning files in sandboxed worker pool"
        );
        let counter = AtomicU64::new(0);
        let config = &self.config;
        let matcher = &self.matcher;
        let wasm = &self.wasm_plugins;
        let yara = &self.yara_engine;

        self.pool.install(|| {
            files.par_iter().for_each(|path| {
                let idx = counter.fetch_add(1, Ordering::Relaxed) as usize;
                let worker_slot = idx % wp.worker_count();
                debug!(path = %path.display(), index = idx, worker_slot = worker_slot, "sandboxed scan");
                let result = self.scan_file_sandboxed(wp, path, idx);

                // The sandboxed worker only reads and hashes.
                // Run the analysis phases in-process on the data from the worker.
                let result = if result.error.is_none() && !result.sha256.is_empty() {
                    match read_file_fast(path) {
                        Ok(data) => {
                            let scanner = FileScanner::new(config, matcher.as_deref(), wasm.as_deref(), yara.as_deref());
                            let mut full = scanner.scan_bytes_with_hashes(
                                &result.path,
                                &data,
                                &result.md5,
                                &result.sha256,
                            );
                            full.scan_duration_us = result.scan_duration_us;
                            full
                        }
                        Err(_) => result,
                    }
                } else {
                    result
                };

                let _ = tx.send(result);
            });
        });
    }

    fn scan_file_sandboxed(&self, wp: &WorkerPool, path: &Path, index: usize) -> ScanResult {
        let worker_slot = index % wp.worker_count();
        let start = std::time::Instant::now();
        debug!(
            path = %path.display(),
            file_index = index,
            worker_slot = worker_slot,
            worker_count = wp.worker_count(),
            max_size = self.config.max_file_size,
            "sending to worker"
        );
        let req = WorkerRequest {
            id: index as u64,
            file_path: path.display().to_string(),
            max_size: self.config.max_file_size,
        };

        match wp.scan_file(index, &req) {
            Ok(resp) => {
                let elapsed_ms = start.elapsed().as_millis();
                if let Some(err) = resp.error {
                    debug!(
                        path = %path.display(),
                        file_index = index,
                        worker_slot = worker_slot,
                        error = %err,
                        elapsed_ms = elapsed_ms,
                        "worker returned error"
                    );
                    ScanResult {
                        path: resp.file_path,
                        size_bytes: resp.size,
                        sha256: resp.sha256,
                        md5: resp.md5,
                        scan_verdict: ScanVerdict::error(),
                        scan_duration_us: start.elapsed().as_micros() as u64,
                        error: Some(err),
                    }
                } else {
                    debug!(
                        path = %path.display(),
                        file_index = index,
                        worker_slot = worker_slot,
                        size = resp.size,
                        elapsed_ms = elapsed_ms,
                        "worker returned data"
                    );
                    ScanResult {
                        path: resp.file_path,
                        size_bytes: resp.size,
                        sha256: resp.sha256,
                        md5: resp.md5,
                        scan_verdict: ScanVerdict::clean(),
                        scan_duration_us: start.elapsed().as_micros() as u64,
                        error: None,
                    }
                }
            }
            Err(e) => {
                warn!(
                    path = %path.display(),
                    file_index = index,
                    worker_slot = worker_slot,
                    error = %e,
                    "sandboxed scan failed"
                );
                error_result(&path.display().to_string(), &format!("sandbox error: {e}"))
            }
        }
    }

    pub fn scan_files_collect(&self, files: Vec<PathBuf>) -> Vec<ScanResult> {
        let (tx, rx) = crossbeam_channel::unbounded();
        let collector = std::thread::spawn(move || rx.iter().collect::<Vec<_>>());
        self.scan_files_parallel(files, tx);
        collector.join().unwrap()
    }

    pub fn config(&self) -> &ScanConfig {
        &self.config
    }

    pub fn matcher_stats(&self) -> Option<String> {
        self.matcher.as_ref().map(|m| m.stats().to_string())
    }

    /// Detailed matcher stats (for scan summary: known viruses count, etc.).
    pub fn matcher_stats_detailed(&self) -> Option<MatcherStats> {
        self.matcher.as_ref().map(|m| m.stats())
    }

    /// Per-source-file signature counts (e.g. main.cvd: 2M, daily.cld: 1.5M).
    pub fn source_stats(&self) -> &[SourceStats] {
        &self.source_stats
    }

    /// Names of loaded WASM plugins (for API / dashboard).
    pub fn wasm_plugin_names(&self) -> Vec<String> {
        self.wasm_plugins
            .as_ref()
            .map(|w| w.plugin_names())
            .unwrap_or_default()
    }

    /// Whether YARA rules are loaded and active.
    pub fn yara_loaded(&self) -> bool {
        self.yara_engine.is_some()
    }

    /// Whether ClamAV signature databases are loaded.
    pub fn signatures_loaded(&self) -> bool {
        self.matcher.is_some()
    }

    /// Whether sandboxed worker processes are used for file analysis.
    pub fn sandbox_enabled(&self) -> bool {
        self.worker_pool.is_some()
    }

    fn make_scanner(&self) -> FileScanner<'_> {
        FileScanner::new(
            &self.config,
            self.matcher.as_deref(),
            self.wasm_plugins.as_deref(),
            self.yara_engine.as_deref(),
        )
    }
}

fn error_result(path: &str, msg: &str) -> ScanResult {
    ScanResult {
        path: path.to_string(),
        size_bytes: 0,
        sha256: String::new(),
        md5: String::new(),
        scan_verdict: ScanVerdict::error(),
        scan_duration_us: 0,
        error: Some(msg.to_string()),
    }
}

fn read_file_fast(path: &Path) -> Result<Vec<u8>, std::io::Error> {
    let metadata = std::fs::metadata(path)?;
    let size = metadata.len();
    // Use mmap for files >= 256 KiB to reduce allocation and copy (faster on large scans).
    if size < 262_144 {
        return std::fs::read(path);
    }
    let file = std::fs::File::open(path)?;
    let mmap = unsafe { memmap2::Mmap::map(&file)? };
    Ok(mmap.to_vec())
}

fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}
