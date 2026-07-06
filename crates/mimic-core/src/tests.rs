//! Unit tests for mimic-core.

use super::*;

#[test]
fn verdict_display() {
    assert_eq!(Verdict::Clean.to_string(), "CLEAN");
    assert_eq!(Verdict::Infected.to_string(), "INFECTED");
    assert_eq!(Verdict::Suspicious.to_string(), "SUSPICIOUS");
    assert_eq!(Verdict::Error.to_string(), "ERROR");
}

#[test]
fn scan_config_default() {
    let c = ScanConfig::default();
    assert_eq!(c.threads, 0);
    assert!(c.enable_mimic);
    assert!(c.enable_signatures);
    assert!(!c.enable_sandbox);
    assert_eq!(c.max_file_size, 256 * 1024 * 1024);
}

#[test]
fn scan_verdict_clean() {
    let v = ScanVerdict::clean();
    assert_eq!(v.verdict, Verdict::Clean);
    assert!(v.signature_threats.is_empty());
    assert!(v.mimic_threats.is_empty());
    assert!(v.yara_matches.is_empty());
}

#[test]
fn scan_verdict_merge_infected_wins() {
    let mut a = ScanVerdict::clean();
    let mut b = ScanVerdict::clean();
    b.verdict = Verdict::Infected;
    b.signature_threats.push(ThreatInfo {
        name: "Test.Sig".into(),
        signature_type: "body-ndb".into(),
        severity: ThreatSeverity::High,
        match_reason: None,
    });
    a.merge(b);
    assert_eq!(a.verdict, Verdict::Infected);
    assert_eq!(a.signature_threats.len(), 1);
}
