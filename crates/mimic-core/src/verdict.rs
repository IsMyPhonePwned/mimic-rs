use serde::{Deserialize, Serialize};
use crate::threat::ThreatSeverity;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Clean,
    Infected,
    Suspicious,
    Error,
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Clean => write!(f, "CLEAN"),
            Self::Infected => write!(f, "INFECTED"),
            Self::Suspicious => write!(f, "SUSPICIOUS"),
            Self::Error => write!(f, "ERROR"),
        }
    }
}

/// A ClamAV-style signature match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatInfo {
    pub name: String,
    pub signature_type: String,
    pub severity: ThreatSeverity,
    /// Human-readable explanation of why this signature matched ("Why did it match?").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_reason: Option<String>,
}

/// A threat detected by mimic (CVE-based exploit detection).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MimicThreat {
    pub id: String,
    pub description: String,
    pub reference: Option<String>,
}

/// A YARA rule match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraMatch {
    pub rule: String,
    pub namespace: String,
    pub tags: Vec<String>,
}

/// Per-scan verdict: which scanner found what.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanVerdict {
    pub verdict: Verdict,
    pub signature_threats: Vec<ThreatInfo>,
    pub mimic_threats: Vec<MimicThreat>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub yara_matches: Vec<YaraMatch>,
}

impl ScanVerdict {
    pub fn clean() -> Self {
        Self {
            verdict: Verdict::Clean,
            signature_threats: Vec::new(),
            mimic_threats: Vec::new(),
            yara_matches: Vec::new(),
        }
    }

    pub fn error() -> Self {
        Self {
            verdict: Verdict::Error,
            signature_threats: Vec::new(),
            mimic_threats: Vec::new(),
            yara_matches: Vec::new(),
        }
    }

    pub fn merge(&mut self, other: ScanVerdict) {
        self.signature_threats.extend(other.signature_threats);
        self.mimic_threats.extend(other.mimic_threats);
        self.yara_matches.extend(other.yara_matches);
        self.verdict = match (self.verdict, other.verdict) {
            (Verdict::Infected, _) | (_, Verdict::Infected) => Verdict::Infected,
            (Verdict::Suspicious, _) | (_, Verdict::Suspicious) => Verdict::Suspicious,
            (Verdict::Error, _) | (_, Verdict::Error) => Verdict::Error,
            _ => Verdict::Clean,
        };
    }
}

/// Full scan result for a single file, with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub path: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub md5: String,
    pub scan_verdict: ScanVerdict,
    pub scan_duration_us: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}
