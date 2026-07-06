use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxPolicy {
    /// Drop to this UID inside the worker (0 = don't drop).
    pub drop_uid: u32,
    /// Drop to this GID inside the worker (0 = don't drop).
    pub drop_gid: u32,
    /// Temporary directory the worker is allowed to read from.
    pub allowed_read_dir: Option<String>,
    /// Maximum wall-clock seconds per file scan before kill.
    pub timeout_secs: u64,
    /// Maximum memory in bytes (RSS limit via setrlimit).
    pub max_memory_bytes: u64,
    /// Enable seccomp syscall filtering on Linux.
    pub enable_seccomp: bool,
    /// Enable macOS seatbelt sandbox.
    pub enable_seatbelt: bool,
}

impl Default for SandboxPolicy {
    fn default() -> Self {
        Self {
            drop_uid: 65534,
            drop_gid: 65534,
            allowed_read_dir: None,
            timeout_secs: 30,
            max_memory_bytes: 512 * 1024 * 1024,
            enable_seccomp: true,
            enable_seatbelt: true,
        }
    }
}

impl SandboxPolicy {
    #[cfg(target_os = "macos")]
    pub fn seatbelt_profile(&self) -> String {
        let read_clause = if let Some(ref dir) = self.allowed_read_dir {
            format!(
                r#"(allow file-read* (subpath "{}"))"#,
                dir
            )
        } else {
            String::new()
        };

        format!(
            r#"(version 1)
(deny default)
(allow process-exec)
(allow process-fork)
(allow sysctl-read)
(allow mach-lookup)
{read_clause}
(allow file-read* (subpath "/usr/lib") (subpath "/System") (subpath "/dev/urandom"))
(allow file-write* (subpath "/dev/null"))
"#
        )
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub fn apply_privilege_drop(&self) -> Result<(), mimic_core::MimicError> {
        use nix::unistd::{setgid, setuid, Gid, Uid};

        if self.drop_gid > 0 {
            setgid(Gid::from_raw(self.drop_gid))
                .map_err(|e| mimic_core::MimicError::Sandbox(format!("setgid failed: {e}")))?;
        }
        if self.drop_uid > 0 {
            setuid(Uid::from_raw(self.drop_uid))
                .map_err(|e| mimic_core::MimicError::Sandbox(format!("setuid failed: {e}")))?;
        }
        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    pub fn apply_privilege_drop(&self) -> Result<(), mimic_core::MimicError> {
        Ok(())
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub fn apply_resource_limits(&self) -> Result<(), mimic_core::MimicError> {
        use nix::sys::resource::{setrlimit, Resource};
        if self.max_memory_bytes > 0 {
            setrlimit(Resource::RLIMIT_AS, self.max_memory_bytes, self.max_memory_bytes)
                .map_err(|e| mimic_core::MimicError::Sandbox(format!("setrlimit AS failed: {e}")))?;
        }
        if self.timeout_secs > 0 {
            setrlimit(Resource::RLIMIT_CPU, self.timeout_secs, self.timeout_secs)
                .map_err(|e| mimic_core::MimicError::Sandbox(format!("setrlimit CPU failed: {e}")))?;
        }
        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    pub fn apply_resource_limits(&self) -> Result<(), mimic_core::MimicError> {
        Ok(())
    }
}
