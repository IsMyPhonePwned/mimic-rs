/// Sandboxed worker: spawns a child process with reduced privileges that performs
/// the actual file scanning. Communication via stdin/stdout JSON.
///
/// Architecture:
///   Parent (mimic-engine) ---[stdin JSON]--> Child (mimic-sandbox worker)
///   Parent <--[stdout JSON]--- Child
///
/// The child process:
/// 1. Applies security hardening (resource limits, privilege drop, seccomp/seatbelt)
/// 2. Reads WorkerRequest from stdin
/// 3. Performs scan (reads file, computes hashes, returns raw data for engine)
/// 4. Writes WorkerResponse to stdout

use serde::{Deserialize, Serialize};
use mimic_core::MimicError;
use crate::policy::SandboxPolicy;
use crate::hardening;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use tracing::{debug, info, warn};

#[derive(Debug, Serialize, Deserialize)]
pub struct WorkerRequest {
    pub id: u64,
    pub file_path: String,
    pub max_size: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WorkerResponse {
    pub id: u64,
    pub file_path: String,
    pub size: u64,
    pub md5: String,
    pub sha256: String,
    pub data_b64: Option<String>,
    pub error: Option<String>,
}

pub struct SandboxedWorker {
    child: Child,
}

impl SandboxedWorker {
    /// Spawn a sandboxed worker subprocess.
    pub fn spawn(worker_bin: &str, policy: &SandboxPolicy) -> Result<Self, MimicError> {
        let mut cmd = Command::new(worker_bin);
        cmd.arg("--sandbox-worker")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());

        #[cfg(target_os = "macos")]
        if policy.enable_seatbelt {
            let profile = policy.seatbelt_profile();
            cmd.env("MIMIC_SANDBOX_PROFILE", &profile);
        }

        cmd.env("MIMIC_DROP_UID", policy.drop_uid.to_string());
        cmd.env("MIMIC_DROP_GID", policy.drop_gid.to_string());
        cmd.env("MIMIC_TIMEOUT", policy.timeout_secs.to_string());
        cmd.env("MIMIC_MAX_MEM", policy.max_memory_bytes.to_string());
        cmd.env("MIMIC_SECCOMP", if policy.enable_seccomp { "1" } else { "0" });
        cmd.env("MIMIC_SEATBELT", if policy.enable_seatbelt { "1" } else { "0" });

        let child = cmd.spawn().map_err(|e| {
            MimicError::Sandbox(format!("failed to spawn worker: {e}"))
        })?;

        info!(pid = ?child.id(), bin = %worker_bin, "sandboxed worker process spawned");
        Ok(Self { child })
    }

    pub fn scan_file(&mut self, request: &WorkerRequest) -> Result<WorkerResponse, MimicError> {
        let stdin = self.child.stdin.as_mut().ok_or_else(|| {
            MimicError::Sandbox("worker stdin not available".into())
        })?;

        let req_json = serde_json::to_string(request)?;
        debug!(request_id = request.id, path = %request.file_path, "sending request to worker");
        writeln!(stdin, "{}", req_json).map_err(|e| {
            MimicError::Sandbox(format!("failed to write to worker: {e}"))
        })?;
        stdin.flush().map_err(|e| {
            MimicError::Sandbox(format!("failed to flush worker stdin: {e}"))
        })?;

        let stdout = self.child.stdout.as_mut().ok_or_else(|| {
            MimicError::Sandbox("worker stdout not available".into())
        })?;

        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        reader.read_line(&mut line).map_err(|e| {
            MimicError::Sandbox(format!("failed to read from worker: {e}"))
        })?;

        let response: WorkerResponse = serde_json::from_str(line.trim())?;
        debug!(
            request_id = response.id,
            size = response.size,
            has_error = response.error.is_some(),
            "received response from worker"
        );
        Ok(response)
    }

    pub fn kill(&mut self) {
        if let Err(e) = self.child.kill() {
            warn!(error = %e, "failed to kill sandbox worker");
        }
    }
}

impl Drop for SandboxedWorker {
    fn drop(&mut self) {
        self.kill();
    }
}

/// Entry point for the worker subprocess. Applies hardening, then loops on stdin requests.
pub fn run_worker_loop() -> Result<(), MimicError> {
    let policy = SandboxPolicy {
        drop_uid: env_u32("MIMIC_DROP_UID"),
        drop_gid: env_u32("MIMIC_DROP_GID"),
        timeout_secs: env_u64("MIMIC_TIMEOUT", 30),
        max_memory_bytes: env_u64("MIMIC_MAX_MEM", 512 * 1024 * 1024),
        enable_seccomp: std::env::var("MIMIC_SECCOMP").unwrap_or_default() == "1",
        enable_seatbelt: std::env::var("MIMIC_SEATBELT").unwrap_or_default() == "1",
        ..Default::default()
    };

    info!(
        drop_uid = policy.drop_uid,
        drop_gid = policy.drop_gid,
        timeout_secs = policy.timeout_secs,
        max_memory_mb = policy.max_memory_bytes / (1024 * 1024),
        seccomp = policy.enable_seccomp,
        seatbelt = policy.enable_seatbelt,
        "sandbox worker started, applying hardening"
    );

    if let Err(e) = hardening::apply_hardening(&policy) {
        warn!(error = %e, "some hardening measures failed");
    }

    info!("sandbox worker ready, reading requests from stdin");
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let reader = BufReader::new(stdin.lock());

    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let request: WorkerRequest = match serde_json::from_str::<WorkerRequest>(&line) {
            Ok(r) => {
                debug!(request_id = r.id, path = %r.file_path, "worker received request");
                r
            }
            Err(e) => {
                warn!(error = %e, "worker received invalid JSON request");
                let resp = WorkerResponse {
                    id: 0,
                    file_path: String::new(),
                    size: 0,
                    md5: String::new(),
                    sha256: String::new(),
                    data_b64: None,
                    error: Some(format!("invalid request: {e}")),
                };
                let mut out = stdout.lock();
                let _ = writeln!(out, "{}", serde_json::to_string(&resp).unwrap_or_default());
                let _ = out.flush();
                continue;
            }
        };

        let response = process_request(&request);
        debug!(
            request_id = response.id,
            path = %response.file_path,
            size = response.size,
            error = ?response.error,
            "worker sending response"
        );
        let mut out = stdout.lock();
        let _ = writeln!(out, "{}", serde_json::to_string(&response)?);
        let _ = out.flush();
    }

    info!("sandbox worker stdin closed, exiting");
    Ok(())
}

fn process_request(request: &WorkerRequest) -> WorkerResponse {
    match std::fs::read(&request.file_path) {
        Ok(data) => {
            if request.max_size > 0 && data.len() as u64 > request.max_size {
                debug!(
                    request_id = request.id,
                    path = %request.file_path,
                    size = data.len(),
                    max_size = request.max_size,
                    "file exceeds max size, skipping content"
                );
                WorkerResponse {
                    id: request.id,
                    file_path: request.file_path.clone(),
                    size: data.len() as u64,
                    md5: String::new(),
                    sha256: String::new(),
                    data_b64: None,
                    error: Some("file exceeds max size".into()),
                }
            } else {
                let md5_hash = format!("{:x}", <md5::Md5 as md5::Digest>::digest(&data));
                let sha256_hash = format!("{:x}", <sha2::Sha256 as sha2::Digest>::digest(&data));
                debug!(
                    request_id = request.id,
                    path = %request.file_path,
                    size = data.len(),
                    "file read and hashed"
                );

                WorkerResponse {
                    id: request.id,
                    file_path: request.file_path.clone(),
                    size: data.len() as u64,
                    md5: md5_hash,
                    sha256: sha256_hash,
                    data_b64: None,
                    error: None,
                }
            }
        }
        Err(e) => {
            debug!(
                request_id = request.id,
                path = %request.file_path,
                error = %e,
                "file read failed"
            );
            WorkerResponse {
                id: request.id,
                file_path: request.file_path.clone(),
                size: 0,
                md5: String::new(),
                sha256: String::new(),
                data_b64: None,
                error: Some(format!("read error: {e}")),
            }
        }
    }
}

fn env_u32(name: &str) -> u32 {
    std::env::var(name).ok().and_then(|s| s.parse().ok()).unwrap_or(0)
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name).ok().and_then(|s| s.parse().ok()).unwrap_or(default)
}
