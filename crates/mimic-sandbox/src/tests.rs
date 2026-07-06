//! Unit tests for mimic-sandbox.

use super::*;

#[test]
fn sandbox_policy_default() {
    let p = SandboxPolicy::default();
    assert_eq!(p.drop_uid, 65534);
    assert_eq!(p.drop_gid, 65534);
    assert!(p.enable_seccomp);
    assert!(p.timeout_secs > 0);
    assert!(p.max_memory_bytes > 0);
}

#[test]
#[cfg(target_os = "macos")]
fn sandbox_policy_seatbelt_profile_contains_deny() {
    let p = SandboxPolicy::default();
    let profile = p.seatbelt_profile();
    assert!(profile.contains("(deny default)"));
    assert!(profile.contains("(version 1)"));
}
