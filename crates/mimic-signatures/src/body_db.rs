/// Body-based signature database (.ndb) — optimized with atom extraction.
///
/// ClamAV .ndb format: `MalwareName:TargetType:Offset:HexSignature[:min_flevel[:max_flevel]]`
///
/// Optimizations:
/// 1. Fixed hex patterns compiled into a single Aho-Corasick automaton (as before).
/// 2. Wildcard patterns now have their longest fixed byte-run ("atom") extracted and
///    added to the same AC automaton.  Full pattern verification happens only when the
///    atom fires, turning O(data_len × num_wildcards) into O(AC_pass + hits × verify).
/// 3. Target-type filtering: NDB sigs with a specific target type (PE, ELF, …) are
///    skipped when scanning a file of a different type.

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, AhoCorasickKind};
use tracing::debug;
use crate::ldb_db::TargetType;

#[derive(Debug, Clone)]
pub struct NdbSignature {
    pub name: String,
    pub target_type: u8,
    pub offset: NdbOffset,
    pub pattern_bytes: Vec<u8>,
    pub has_wildcards: bool,
    pub wildcard_mask: Option<Vec<bool>>,
}

#[derive(Debug, Clone)]
pub enum NdbOffset {
    Any,
    Absolute(usize),
    EndMinus(usize),
    Unsupported(String),
}

struct NdbAtomWildcard {
    sig: NdbSignature,
    atom_offset: usize,
}

pub struct BodyDb {
    automaton: Option<AhoCorasick>,
    /// Fixed-pattern NDB sigs (AC indices 0..fixed_count)
    ac_sigs: Vec<NdbSignature>,
    /// Accumulation buffer for fixed AC patterns (cleared after finalize)
    ac_patterns: Vec<Vec<u8>>,
    /// Accumulation buffer for raw wildcard sigs (consumed by finalize)
    wildcard_sigs: Vec<NdbSignature>,

    // Post-finalize:
    fixed_count: usize,
    atom_wildcards: Vec<NdbAtomWildcard>,
    linear_wildcards: Vec<NdbSignature>,
}

impl BodyDb {
    pub fn new() -> Self {
        Self {
            automaton: None,
            ac_sigs: Vec::new(),
            ac_patterns: Vec::new(),
            wildcard_sigs: Vec::new(),
            fixed_count: 0,
            atom_wildcards: Vec::new(),
            linear_wildcards: Vec::new(),
        }
    }

    /// Build the Aho-Corasick automaton with wildcard atom extraction.
    /// Call once after all loads/merges.
    pub fn finalize_automaton(&mut self) {
        // Extract atoms from wildcard sigs
        let mut atom_patterns: Vec<Vec<u8>> = Vec::new();
        self.atom_wildcards = Vec::new();
        self.linear_wildcards = Vec::new();

        for sig in std::mem::take(&mut self.wildcard_sigs) {
            if let Some(ref mask) = sig.wildcard_mask {
                if let Some((atom_start, atom_len)) = extract_atom(mask) {
                    atom_patterns
                        .push(sig.pattern_bytes[atom_start..atom_start + atom_len].to_vec());
                    self.atom_wildcards.push(NdbAtomWildcard {
                        sig,
                        atom_offset: atom_start,
                    });
                    continue;
                }
            }
            self.linear_wildcards.push(sig);
        }

        self.fixed_count = self.ac_patterns.len();

        debug!(
            fixed = self.fixed_count,
            atom_wildcards = self.atom_wildcards.len(),
            linear_wildcards = self.linear_wildcards.len(),
            "NDB: building unified Aho-Corasick automaton"
        );

        // Unified AC: fixed patterns + atom patterns
        let mut all_patterns = std::mem::take(&mut self.ac_patterns);
        all_patterns.extend(atom_patterns);

        if all_patterns.is_empty() {
            self.automaton = None;
        } else {
            self.automaton = AhoCorasickBuilder::new()
                .kind(Some(AhoCorasickKind::ContiguousNFA))
                .prefilter(false)
                .build(&all_patterns)
                .ok();
        }
    }

    pub fn merge(&mut self, other: BodyDb) {
        self.ac_patterns.reserve(other.ac_patterns.len());
        self.ac_sigs.reserve(other.ac_sigs.len());
        self.wildcard_sigs.reserve(other.wildcard_sigs.len());
        self.ac_patterns.extend(other.ac_patterns);
        self.ac_sigs.extend(other.ac_sigs);
        self.wildcard_sigs.extend(other.wildcard_sigs);
    }

    pub fn fixed_count(&self) -> usize {
        self.ac_sigs.len()
    }

    pub fn wildcard_count(&self) -> usize {
        self.atom_wildcards.len() + self.linear_wildcards.len()
    }

    /// Load an .ndb file.
    pub fn load_ndb(&mut self, data: &[u8]) {
        let text = match std::str::from_utf8(data) {
            Ok(t) => t,
            Err(_) => return,
        };

        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let parts: Vec<&str> = line.splitn(6, ':').collect();
            if parts.len() < 4 {
                continue;
            }

            let name = parts[0].to_string();
            let target_type = parts[1].parse::<u8>().unwrap_or(0);
            let offset = parse_offset(parts[2]);
            let hex_sig = parts[3];

            let has_wildcards = hex_sig.contains('?')
                || hex_sig.contains('*')
                || hex_sig.contains('{')
                || hex_sig.contains('(');

            if has_wildcards {
                if let Some((bytes, mask)) = parse_wildcard_hex(hex_sig) {
                    self.wildcard_sigs.push(NdbSignature {
                        name,
                        target_type,
                        offset,
                        pattern_bytes: bytes,
                        has_wildcards: true,
                        wildcard_mask: Some(mask),
                    });
                }
            } else if let Some(bytes) = parse_hex_string(hex_sig) {
                if bytes.len() >= 2 {
                    self.ac_patterns.push(bytes.clone());
                    self.ac_sigs.push(NdbSignature {
                        name,
                        target_type,
                        offset,
                        pattern_bytes: bytes,
                        has_wildcards: false,
                        wildcard_mask: None,
                    });
                }
            }
        }

        debug!(
            fixed = self.ac_sigs.len(),
            wildcard = self.wildcard_sigs.len(),
            "loaded .ndb body signatures"
        );
    }

    /// Scan file bytes against all NDB body signatures, with target-type filtering.
    pub fn scan(&self, data: &[u8], file_type: TargetType) -> Vec<String> {
        let mut matches = Vec::new();

        if let Some(ref ac) = self.automaton {
            for mat in ac.find_overlapping_iter(data) {
                let pat_id = mat.pattern().as_usize();

                if pat_id < self.fixed_count {
                    // Fixed NDB match
                    let sig = &self.ac_sigs[pat_id];
                    if ndb_target_ok(sig.target_type, file_type)
                        && check_offset(&sig.offset, mat.start(), data.len())
                    {
                        matches.push(sig.name.clone());
                    }
                } else {
                    // Wildcard atom hit — verify full pattern
                    let wc_idx = pat_id - self.fixed_count;
                    if wc_idx < self.atom_wildcards.len() {
                        let wc = &self.atom_wildcards[wc_idx];
                        if ndb_target_ok(wc.sig.target_type, file_type) {
                            let atom_pos = mat.start();
                            if atom_pos >= wc.atom_offset {
                                let start = atom_pos - wc.atom_offset;
                                if start + wc.sig.pattern_bytes.len() <= data.len() {
                                    if verify_wildcard_at(
                                        data,
                                        start,
                                        &wc.sig.pattern_bytes,
                                        wc.sig.wildcard_mask.as_deref().unwrap_or(&[]),
                                    ) && check_offset(&wc.sig.offset, start, data.len())
                                    {
                                        matches.push(wc.sig.name.clone());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Linear wildcards (un-atomizable, rare)
        for sig in &self.linear_wildcards {
            if ndb_target_ok(sig.target_type, file_type) {
                if match_wildcard(
                    data,
                    &sig.pattern_bytes,
                    sig.wildcard_mask.as_deref(),
                    &sig.offset,
                ) {
                    matches.push(sig.name.clone());
                }
            }
        }

        matches.sort_unstable();
        matches.dedup();
        matches
    }
}

impl Default for BodyDb {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Target-type filtering for NDB
// ---------------------------------------------------------------------------

/// NDB target type 0 (any): match only non-text types, same as LDB.
/// ClamAV uses text normalization for Ascii/HTML/Mail we don't implement, so
/// running "any" rules on text causes false positives (e.g. C source flagged).
#[inline]
fn ndb_target_ok(rule_target: u8, file_type: TargetType) -> bool {
    if rule_target == 0 {
        return !matches!(file_type, TargetType::Ascii | TargetType::HTML | TargetType::Mail);
    }
    TargetType::from_u8(rule_target) == file_type
}

// ---------------------------------------------------------------------------
// Atom extraction
// ---------------------------------------------------------------------------

fn extract_atom(mask: &[bool]) -> Option<(usize, usize)> {
    let mut best_start = 0;
    let mut best_len = 0usize;
    let mut cur_start = 0;
    let mut cur_len = 0usize;

    for (i, &fixed) in mask.iter().enumerate() {
        if fixed {
            if cur_len == 0 {
                cur_start = i;
            }
            cur_len += 1;
            if cur_len > best_len {
                best_start = cur_start;
                best_len = cur_len;
            }
        } else {
            cur_len = 0;
        }
    }

    if best_len >= 2 {
        Some((best_start, best_len))
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Wildcard matching
// ---------------------------------------------------------------------------

#[inline]
fn verify_wildcard_at(data: &[u8], start: usize, pattern: &[u8], mask: &[bool]) -> bool {
    if mask.is_empty() {
        return false;
    }
    for i in 0..pattern.len() {
        if i < mask.len() && mask[i] && data[start + i] != pattern[i] {
            return false;
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Parsing / offset helpers
// ---------------------------------------------------------------------------

fn parse_offset(s: &str) -> NdbOffset {
    if s == "*" {
        return NdbOffset::Any;
    }
    if let Ok(n) = s.parse::<usize>() {
        return NdbOffset::Absolute(n);
    }
    if let Some(rest) = s.strip_prefix("EOF-") {
        if let Ok(n) = rest.parse::<usize>() {
            return NdbOffset::EndMinus(n);
        }
    }
    NdbOffset::Unsupported(s.to_string())
}

fn check_offset(offset: &NdbOffset, found_at: usize, file_len: usize) -> bool {
    match offset {
        NdbOffset::Any | NdbOffset::Unsupported(_) => true,
        NdbOffset::Absolute(n) => found_at == *n,
        NdbOffset::EndMinus(n) => {
            if file_len >= *n {
                found_at >= file_len - *n
            } else {
                false
            }
        }
    }
}

fn parse_hex_string(hex: &str) -> Option<Vec<u8>> {
    let clean: String = hex.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if clean.len() % 2 != 0 {
        return None;
    }
    hex::decode(&clean).ok()
}

fn parse_wildcard_hex(hex: &str) -> Option<(Vec<u8>, Vec<bool>)> {
    let cleaned: String = hex
        .chars()
        .filter(|c| c.is_ascii_hexdigit() || *c == '?')
        .collect();
    if cleaned.len() % 2 != 0 {
        return None;
    }

    let mut bytes = Vec::with_capacity(cleaned.len() / 2);
    let mut mask = Vec::with_capacity(cleaned.len() / 2);

    for chunk in cleaned.as_bytes().chunks(2) {
        if chunk == b"??" {
            bytes.push(0);
            mask.push(false);
        } else {
            let s = std::str::from_utf8(chunk).ok()?;
            let b = u8::from_str_radix(s, 16).ok()?;
            bytes.push(b);
            mask.push(true);
        }
    }

    Some((bytes, mask))
}

fn match_wildcard(
    data: &[u8],
    pattern: &[u8],
    mask: Option<&[bool]>,
    offset: &NdbOffset,
) -> bool {
    let mask = match mask {
        Some(m) => m,
        None => return false,
    };
    if pattern.len() > data.len() {
        return false;
    }

    let (start, end) = match offset {
        NdbOffset::Absolute(n) => (*n, *n + 1),
        NdbOffset::EndMinus(n) => {
            let s = data.len().saturating_sub(*n);
            (s, data.len().saturating_sub(pattern.len()) + 1)
        }
        _ => (0, data.len().saturating_sub(pattern.len()) + 1),
    };

    for pos in start..end {
        if pos + pattern.len() > data.len() {
            break;
        }
        let mut matched = true;
        for i in 0..pattern.len() {
            if mask[i] && data[pos + i] != pattern[i] {
                matched = false;
                break;
            }
        }
        if matched {
            return true;
        }
    }
    false
}
