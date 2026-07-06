//! # mimic-sandbox
//!
//! Sandboxed worker processes for secure file reading. Each worker is a long-lived
//! subprocess that applies **SandboxPolicy**: resource limits (RLIMIT_AS, RLIMIT_CPU),
//! privilege drop (setuid/setgid to nobody), and optionally **seccomp-bpf** (Linux)
//! or **seatbelt** (macOS). The **WorkerPool** distributes file paths to workers;
//! workers return file content and hashes over JSON on stdin/stdout.

pub mod hardening;
pub mod policy;
pub mod pool;
pub mod worker;

pub use policy::SandboxPolicy;
pub use pool::WorkerPool;
pub use worker::{SandboxedWorker, WorkerRequest, WorkerResponse};

#[cfg(test)]
mod tests;
