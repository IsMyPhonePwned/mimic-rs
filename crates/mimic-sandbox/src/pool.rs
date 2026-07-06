/// Pool of sandboxed worker processes for parallel file scanning.
/// Each worker is a long-lived subprocess with hardened security (seccomp, seatbelt,
/// privilege drop). Files are distributed round-robin across workers.

use crate::policy::SandboxPolicy;
use crate::worker::{SandboxedWorker, WorkerRequest, WorkerResponse};
use mimic_core::MimicError;
use std::sync::Mutex;
use tracing::{debug, info, warn};

pub struct WorkerPool {
    workers: Vec<Mutex<SandboxedWorker>>,
}

impl WorkerPool {
    /// Spawn `n` sandboxed worker processes.
    pub fn new(worker_bin: &str, n: usize, policy: &SandboxPolicy) -> Result<Self, MimicError> {
        let n = n.max(1);
        info!(
            worker_bin = %worker_bin,
            count = n,
            drop_uid = policy.drop_uid,
            drop_gid = policy.drop_gid,
            max_memory_mb = policy.max_memory_bytes / (1024 * 1024),
            timeout_secs = policy.timeout_secs,
            "spawning sandboxed worker pool"
        );
        let mut workers = Vec::with_capacity(n);
        for i in 0..n {
            match SandboxedWorker::spawn(worker_bin, policy) {
                Ok(w) => {
                    debug!(worker_index = i, "worker process spawned");
                    workers.push(Mutex::new(w));
                }
                Err(e) => {
                    warn!(worker_index = i, error = %e, "failed to spawn worker");
                    // Clean up already-spawned workers
                    for (j, w) in workers.iter().enumerate() {
                        if let Ok(mut w) = w.lock() {
                            debug!(worker_index = j, "killing worker during cleanup");
                            w.kill();
                        }
                    }
                    return Err(e);
                }
            }
        }
        info!(count = workers.len(), "worker pool ready");
        Ok(Self { workers })
    }

    pub fn worker_count(&self) -> usize {
        self.workers.len()
    }

    /// Send a scan request to a specific worker (by index % pool_size).
    pub fn scan_file(&self, index: usize, request: &WorkerRequest) -> Result<WorkerResponse, MimicError> {
        let slot = index % self.workers.len();
        debug!(
            request_id = request.id,
            slot = slot,
            path = %request.file_path,
            max_size = request.max_size,
            "dispatching scan to worker"
        );
        let mut worker = self.workers[slot].lock().map_err(|e| {
            MimicError::Sandbox(format!("worker lock poisoned: {e}"))
        })?;
        let response = worker.scan_file(request)?;
        debug!(
            request_id = response.id,
            path = %response.file_path,
            size = response.size,
            error = ?response.error,
            "worker response received"
        );
        Ok(response)
    }

    pub fn shutdown(&self) {
        info!(count = self.workers.len(), "shutting down worker pool");
        for (i, w) in self.workers.iter().enumerate() {
            if let Ok(mut w) = w.lock() {
                debug!(worker_index = i, "killing worker");
                w.kill();
            }
        }
    }
}

impl Drop for WorkerPool {
    fn drop(&mut self) {
        self.shutdown();
    }
}
