/// Security hardening: resource limits, privilege drop, OS sandboxing.

use mimic_core::MimicError;
use tracing::{info, warn, debug};
use crate::policy::SandboxPolicy;

/// Apply all available security hardening for the worker process.
pub fn apply_hardening(policy: &SandboxPolicy) -> Result<(), MimicError> {
    info!(
        max_memory_mb = policy.max_memory_bytes / (1024 * 1024),
        timeout_secs = policy.timeout_secs,
        "applying security hardening"
    );

    match policy.apply_resource_limits() {
        Ok(()) => debug!("resource limits (RLIMIT_AS, RLIMIT_CPU) applied"),
        Err(e) => warn!(error = %e, "resource limits failed (non-root?)"),
    }

    match policy.apply_privilege_drop() {
        Ok(()) => info!(uid = policy.drop_uid, gid = policy.drop_gid, "privileges dropped"),
        Err(e) => warn!(error = %e, "privilege drop failed (not running as root?)"),
    }

    #[cfg(target_os = "linux")]
    if policy.enable_seccomp {
        match apply_seccomp_filter() {
            Ok(()) => info!("seccomp-bpf filter applied"),
            Err(e) => warn!(error = %e, "seccomp filter failed"),
        }
    }

    #[cfg(target_os = "macos")]
    if policy.enable_seatbelt {
        debug!(profile_len = policy.seatbelt_profile().len(), "seatbelt profile prepared");
        info!("seatbelt sandbox configured (applied via sandbox-exec on spawn)");
    }

    info!("security hardening applied");
    Ok(())
}

/// Apply seccomp-bpf on Linux: restrict syscalls to read/write/mmap/brk/exit.
#[cfg(target_os = "linux")]
fn apply_seccomp_filter() -> Result<(), MimicError> {
    use seccompiler::{SeccompAction, SeccompFilter, SeccompRule};
    use std::collections::BTreeMap;

    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();

    // Allow only the syscalls needed for file scanning
    let allowed = [
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_close,
        libc::SYS_fstat,
        libc::SYS_mmap,
        libc::SYS_mprotect,
        libc::SYS_munmap,
        libc::SYS_brk,
        libc::SYS_openat,
        libc::SYS_lseek,
        libc::SYS_getpid,
        libc::SYS_exit_group,
        libc::SYS_futex,
        libc::SYS_clock_gettime,
        libc::SYS_sched_yield,
        libc::SYS_getrandom,
        libc::SYS_sigaltstack,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
    ];

    for nr in &allowed {
        rules.insert(*nr, vec![SeccompRule::new(vec![]).map_err(|e| {
            MimicError::Sandbox(format!("seccomp rule: {e}"))
        })?]);
    }

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Errno(libc::EPERM as u32),
        SeccompAction::Allow,
        std::env::consts::ARCH.try_into().map_err(|_| {
            MimicError::Sandbox("unsupported arch for seccomp".into())
        })?,
    )
    .map_err(|e| MimicError::Sandbox(format!("seccomp filter: {e}")))?;

    let bpf_prog = seccompiler::SeccompFilter::try_into(filter)
        .map_err(|e| MimicError::Sandbox(format!("seccomp compile: {e}")))?;

    seccompiler::apply_filter(&bpf_prog)
        .map_err(|e| MimicError::Sandbox(format!("seccomp apply: {e}")))?;

    Ok(())
}
