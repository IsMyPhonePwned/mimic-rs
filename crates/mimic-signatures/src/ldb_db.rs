/// Logical signature database (.ldb/.ldu) — optimized for high-speed scanning.
///
/// ClamAV .ldb format:
///   `SignatureName;TargetDescriptionBlock;LogicalExpression;Subsig0;Subsig1;...`
///
/// Optimizations over naive O(N×M) approach:
/// 1. Rules pre-partitioned by ClamAV target type — only eligible rules for the
///    detected file type are processed.  For text/HTML/mail files this means zero work.
/// 2. Wildcard subsig "atoms" — the longest contiguous fixed-byte run is extracted
///    from each wildcard pattern and inserted into the Aho-Corasick automaton.
///    Full pattern verification happens only on atom hits, eliminating the linear
///    O(data_len × num_wildcards) brute-force scan.
/// 3. Flat subsig bitset with pre-computed offsets — one Vec<bool> per scan instead
///    of Vec<Vec<bool>> (saves ~321K inner-Vec allocations per file).
/// 4. Eligible-rule bitmaps pre-computed at finalize() — zero per-scan set building.

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, AhoCorasickKind};
use tracing::debug;

// ---------------------------------------------------------------------------
// Target types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TargetType {
    Any = 0,
    PE = 1,
    OLE2 = 2,
    HTML = 3,
    Mail = 4,
    Graphics = 5,
    ELF = 6,
    Ascii = 7,
    MachO = 9,
    PDF = 10,
    Flash = 11,
    Java = 12,
}

const NUM_TARGET_SLOTS: usize = 13;

impl TargetType {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::PE,
            2 => Self::OLE2,
            3 => Self::HTML,
            4 => Self::Mail,
            5 => Self::Graphics,
            6 => Self::ELF,
            7 => Self::Ascii,
            9 => Self::MachO,
            10 => Self::PDF,
            11 => Self::Flash,
            12 => Self::Java,
            _ => Self::Any,
        }
    }
}

/// Detect file type from magic bytes / content heuristics.
pub fn detect_file_type(data: &[u8]) -> TargetType {
    if data.len() < 4 {
        return TargetType::Any;
    }

    if data.len() > 64 && data[0] == b'M' && data[1] == b'Z' {
        let pe_off = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
        if pe_off + 4 <= data.len() && &data[pe_off..pe_off + 4] == b"PE\0\0" {
            return TargetType::PE;
        }
    }

    if &data[..4] == b"\x7FELF" {
        return TargetType::ELF;
    }

    let m32 = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if matches!(m32, 0xFEEDFACE | 0xFEEDFACF | 0xCEFAEDFE | 0xCFFAEDFE | 0xCAFEBABE) {
        return TargetType::MachO;
    }

    if data.starts_with(b"%PDF") {
        return TargetType::PDF;
    }

    if m32 == 0xBEBAFECA {
        return TargetType::Java;
    }

    if data.len() >= 8 && &data[..8] == b"\xD0\xCF\x11\xE0\xA1\xB2\x1A\xE1" {
        return TargetType::OLE2;
    }

    if (data.starts_with(b"FWS") || data.starts_with(b"CWS") || data.starts_with(b"ZWS"))
        && data.len() > 8
    {
        return TargetType::Flash;
    }

    if data.starts_with(b"\x89PNG")
        || data.starts_with(b"\xFF\xD8\xFF")
        || data.starts_with(b"GIF8")
        || data.starts_with(b"BM")
        || data.starts_with(b"II\x2A\x00")
        || data.starts_with(b"MM\x00\x2A")
    {
        return TargetType::Graphics;
    }

    let check_len = data.len().min(1024);
    let prefix = &data[..check_len];

    if has_html_tag(prefix) {
        return TargetType::HTML;
    }

    if prefix.starts_with(b"From ")
        || prefix.starts_with(b"Return-Path:")
        || prefix.starts_with(b"Received:")
        || prefix.starts_with(b"MIME-Version:")
    {
        return TargetType::Mail;
    }

    if is_mostly_text(prefix) {
        return TargetType::Ascii;
    }

    TargetType::Any
}

fn has_html_tag(data: &[u8]) -> bool {
    let lower: Vec<u8> = data.iter().map(|b| b.to_ascii_lowercase()).collect();
    lower.windows(5).any(|w| w == b"<html")
        || lower.windows(6).any(|w| w == b"<head>")
        || lower.windows(7).any(|w| w == b"<!docty")
        || lower.windows(7).any(|w| w == b"<script")
}

fn is_mostly_text(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    let printable = data
        .iter()
        .filter(|&&b| b >= 0x20 || b == b'\n' || b == b'\r' || b == b'\t')
        .count();
    (printable * 100 / data.len()) > 90
}

/// Whether a rule targeting `rule_target` should fire on a file of type `file_type`.
/// ASCII/HTML/Mail rules require ClamAV text normalization we don't implement, so we
/// skip them.  "Any" (target 0) rules are restricted to non-text types to avoid noise.
#[inline]
fn target_matches(rule_target: TargetType, file_type: TargetType) -> bool {
    match rule_target {
        TargetType::Any => {
            !matches!(file_type, TargetType::Ascii | TargetType::HTML | TargetType::Mail)
        }
        TargetType::Ascii | TargetType::HTML | TargetType::Mail => false,
        _ => rule_target == file_type,
    }
}

// ---------------------------------------------------------------------------
// Count operators for LDB logic expressions.
// ClamAV format: A>X,Y  where X = count threshold, Y = min distinct subsigs.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
enum CountOp {
    /// more than X total matches; optionally at least Y distinct subsigs.
    Gt(u32, u32),
    /// fewer than X total matches; optionally at least Y distinct subsigs.
    Lt(u32, u32),
    /// exactly X total matches; optionally at least Y distinct subsigs.
    Eq(u32, u32),
}

// ---------------------------------------------------------------------------
// Logic expression tree
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum LogicNode {
    Leaf(usize),
    And(Box<LogicNode>, Box<LogicNode>),
    Or(Box<LogicNode>, Box<LogicNode>),
    /// Post-fix count modifier on a sub-expression.
    Count(Box<LogicNode>, CountOp),
}

impl LogicNode {
    #[inline]
    fn evaluate(&self, counts: &[u32]) -> bool {
        match self {
            LogicNode::Leaf(idx) => counts.get(*idx).copied().unwrap_or(0) > 0,
            LogicNode::And(l, r) => l.evaluate(counts) && r.evaluate(counts),
            LogicNode::Or(l, r) => l.evaluate(counts) || r.evaluate(counts),
            LogicNode::Count(inner, op) => {
                let total = inner.match_count(counts);
                let unique = inner.unique_count(counts);
                match op {
                    CountOp::Gt(n, min_diff) => {
                        total > *n && (*min_diff == 0 || unique >= *min_diff)
                    }
                    CountOp::Lt(n, min_diff) => {
                        total < *n && (*min_diff == 0 || unique >= *min_diff)
                    }
                    CountOp::Eq(n, min_diff) => {
                        total == *n && (*min_diff == 0 || unique >= *min_diff)
                    }
                }
            }
        }
    }

    /// Total match count across all leaf subsigs in the subtree.
    /// For AND nodes, returns 0 if the boolean condition isn't met (both sides
    /// must have matches for the AND block to contribute counts).
    fn match_count(&self, counts: &[u32]) -> u32 {
        match self {
            LogicNode::Leaf(idx) => counts.get(*idx).copied().unwrap_or(0),
            LogicNode::And(l, r) => {
                if l.evaluate(counts) && r.evaluate(counts) {
                    l.match_count(counts).saturating_add(r.match_count(counts))
                } else {
                    0
                }
            }
            LogicNode::Or(l, r) => {
                l.match_count(counts).saturating_add(r.match_count(counts))
            }
            LogicNode::Count(inner, _) => inner.match_count(counts),
        }
    }

    /// Number of distinct leaf subsigs that matched at least once.
    fn unique_count(&self, counts: &[u32]) -> u32 {
        match self {
            LogicNode::Leaf(idx) => {
                if counts.get(*idx).copied().unwrap_or(0) > 0 { 1 } else { 0 }
            }
            LogicNode::And(l, r) | LogicNode::Or(l, r) => {
                l.unique_count(counts).saturating_add(r.unique_count(counts))
            }
            LogicNode::Count(inner, _) => inner.unique_count(counts),
        }
    }
}

// ---------------------------------------------------------------------------
// Internal data structures
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct LdbRule {
    name: String,
    target_type: TargetType,
    logic: LogicNode,
    subsig_count: usize,
    min_filesize: u64,
    max_filesize: u64,
}

struct RawWildcard {
    rule_idx: usize,
    local_idx: usize,
    pattern: Vec<u8>,
    mask: Vec<bool>,
}

struct AtomWildcard {
    rule_idx: usize,
    local_idx: usize,
    pattern: Vec<u8>,
    mask: Vec<bool>,
    atom_offset: usize,
}

// ---------------------------------------------------------------------------
// LdbDb
// ---------------------------------------------------------------------------

pub struct LdbDb {
    rules: Vec<LdbRule>,

    // --- Accumulation phase (populated by load_ldb / merge) ---
    raw_fixed_patterns: Vec<Vec<u8>>,
    raw_fixed_map: Vec<(usize, usize)>, // (rule_idx, local_subsig_idx)
    raw_wildcards: Vec<RawWildcard>,

    // --- Post-finalize ---
    subsig_offsets: Vec<usize>,
    total_subsigs: usize,
    automaton: Option<AhoCorasick>,
    fixed_count: usize,
    fixed_map: Vec<(usize, usize)>,
    atom_wildcards: Vec<AtomWildcard>,
    linear_wildcards: Vec<RawWildcard>,
    // [target_type_val] → sorted list of eligible rule indices
    eligible_rules: Vec<Vec<usize>>,
    // [target_type_val] → indices into linear_wildcards
    eligible_linear_wc: Vec<Vec<usize>>,
    // [target_type_val][rule_idx] → eligible?
    eligible_bitmap: Vec<Vec<bool>>,
}

impl LdbDb {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            raw_fixed_patterns: Vec::new(),
            raw_fixed_map: Vec::new(),
            raw_wildcards: Vec::new(),
            subsig_offsets: Vec::new(),
            total_subsigs: 0,
            automaton: None,
            fixed_count: 0,
            fixed_map: Vec::new(),
            atom_wildcards: Vec::new(),
            linear_wildcards: Vec::new(),
            eligible_rules: Vec::new(),
            eligible_linear_wc: Vec::new(),
            eligible_bitmap: Vec::new(),
        }
    }

    pub fn count(&self) -> usize {
        self.rules.len()
    }

    pub fn merge(&mut self, other: LdbDb) {
        let rule_offset = self.rules.len();

        self.rules.reserve(other.rules.len());
        self.raw_fixed_patterns.reserve(other.raw_fixed_patterns.len());
        self.raw_fixed_map.reserve(other.raw_fixed_map.len());
        self.raw_wildcards.reserve(other.raw_wildcards.len());

        self.rules.extend(other.rules);
        self.raw_fixed_patterns.extend(other.raw_fixed_patterns);
        for (ri, li) in other.raw_fixed_map {
            self.raw_fixed_map.push((ri + rule_offset, li));
        }
        for mut wc in other.raw_wildcards {
            wc.rule_idx += rule_offset;
            self.raw_wildcards.push(wc);
        }
    }

    /// Build the Aho-Corasick automaton (with wildcard atom extraction) and
    /// pre-compute per-target-type eligible rule sets.  Call once after all merges.
    pub fn finalize_automaton(&mut self) {
        let num_rules = self.rules.len();
        if num_rules == 0 {
            return;
        }

        // 1. Flat subsig offsets
        self.subsig_offsets = Vec::with_capacity(num_rules);
        let mut off = 0usize;
        for rule in &self.rules {
            self.subsig_offsets.push(off);
            off += rule.subsig_count;
        }
        self.total_subsigs = off;

        // 2. Atom extraction from wildcard subsigs
        let mut atom_patterns: Vec<Vec<u8>> = Vec::new();
        self.atom_wildcards = Vec::new();
        self.linear_wildcards = Vec::new();

        for wc in std::mem::take(&mut self.raw_wildcards) {
            if let Some((atom_start, atom_len)) = extract_atom(&wc.mask) {
                atom_patterns.push(wc.pattern[atom_start..atom_start + atom_len].to_vec());
                self.atom_wildcards.push(AtomWildcard {
                    rule_idx: wc.rule_idx,
                    local_idx: wc.local_idx,
                    pattern: wc.pattern,
                    mask: wc.mask,
                    atom_offset: atom_start,
                });
            } else {
                self.linear_wildcards.push(wc);
            }
        }

        // 3. Build unified AC: [0..fixed_count) = fixed subsigs,
        //    [fixed_count..) = wildcard atom patterns
        self.fixed_count = self.raw_fixed_patterns.len();
        self.fixed_map = std::mem::take(&mut self.raw_fixed_map);
        let mut all_patterns = std::mem::take(&mut self.raw_fixed_patterns);
        all_patterns.extend(atom_patterns);

        debug!(
            fixed = self.fixed_count,
            atom_wildcards = self.atom_wildcards.len(),
            linear_wildcards = self.linear_wildcards.len(),
            total_ac_patterns = all_patterns.len(),
            "LDB: building unified Aho-Corasick automaton"
        );

        if !all_patterns.is_empty() {
            self.automaton = AhoCorasickBuilder::new()
                .kind(Some(AhoCorasickKind::ContiguousNFA))
                .prefilter(false)
                .build(&all_patterns)
                .ok();
        }

        // 4. Pre-compute eligible sets for every target type value
        self.eligible_rules = vec![Vec::new(); NUM_TARGET_SLOTS];
        self.eligible_linear_wc = vec![Vec::new(); NUM_TARGET_SLOTS];
        self.eligible_bitmap = vec![vec![false; num_rules]; NUM_TARGET_SLOTS];

        for ft_val in 0..NUM_TARGET_SLOTS {
            let ft = TargetType::from_u8(ft_val as u8);
            for (i, rule) in self.rules.iter().enumerate() {
                if target_matches(rule.target_type, ft) {
                    self.eligible_rules[ft_val].push(i);
                    self.eligible_bitmap[ft_val][i] = true;
                }
            }
            for (i, wc) in self.linear_wildcards.iter().enumerate() {
                if self.eligible_bitmap[ft_val]
                    .get(wc.rule_idx)
                    .copied()
                    .unwrap_or(false)
                {
                    self.eligible_linear_wc[ft_val].push(i);
                }
            }
        }

        let max_eligible = self.eligible_rules.iter().map(|v| v.len()).max().unwrap_or(0);
        debug!(
            total_rules = num_rules,
            total_subsigs = self.total_subsigs,
            max_eligible_for_any_type = max_eligible,
            "LDB: finalized eligible sets"
        );
    }

    /// Load an .ldb or .ldu file.
    pub fn load_ldb(&mut self, data: &[u8]) {
        let text = match std::str::from_utf8(data) {
            Ok(t) => t,
            Err(_) => return,
        };

        let mut count = 0u64;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let parts: Vec<&str> = line.splitn(4, ';').collect();
            if parts.len() < 4 {
                continue;
            }

            let name = parts[0].to_string();
            let (target_type, min_filesize, max_filesize) = parse_tdb(parts[1]);
            let logic_str = parts[2];
            let subsigs_str = parts[3];

            let subsig_hexes: Vec<&str> = subsigs_str.split(';').collect();
            if subsig_hexes.is_empty() {
                continue;
            }

            let rule_index = self.rules.len();
            let subsig_count = subsig_hexes.len();

            const MIN_PATTERN_LEN: usize = 4;

            for (local_idx, hex_sig) in subsig_hexes.iter().enumerate() {
                let hex_sig = hex_sig.trim();
                if hex_sig.is_empty() {
                    continue;
                }

                let has_wildcards = hex_sig.contains('?')
                    || hex_sig.contains('*')
                    || hex_sig.contains('{')
                    || hex_sig.contains('(');

                if has_wildcards {
                    if let Some((bytes, mask)) = parse_wildcard_hex(hex_sig) {
                        if bytes.len() >= MIN_PATTERN_LEN {
                            self.raw_wildcards.push(RawWildcard {
                                rule_idx: rule_index,
                                local_idx,
                                pattern: bytes,
                                mask,
                            });
                        }
                    }
                } else if let Some(bytes) = parse_hex_string(hex_sig) {
                    if bytes.len() >= MIN_PATTERN_LEN {
                        self.raw_fixed_map.push((rule_index, local_idx));
                        self.raw_fixed_patterns.push(bytes);
                    }
                }
            }

            let logic = parse_logic_expr(logic_str, subsig_count);

            self.rules.push(LdbRule {
                name,
                target_type,
                logic,
                subsig_count,
                min_filesize,
                max_filesize,
            });
            count += 1;
        }

        debug!(count, total = self.rules.len(), "loaded .ldb logical signatures");
    }

    /// Scan file bytes against LDB rules, filtered by the detected file type.
    pub fn scan(&self, data: &[u8], file_type: TargetType) -> Vec<String> {
        if self.rules.is_empty() || self.total_subsigs == 0 {
            return Vec::new();
        }

        let ft_idx = file_type as u8 as usize;
        if ft_idx >= self.eligible_rules.len() {
            return Vec::new();
        }

        let eligible = &self.eligible_rules[ft_idx];
        if eligible.is_empty() {
            return Vec::new();
        }

        let bitmap = &self.eligible_bitmap[ft_idx];
        let file_size = data.len() as u64;

        // Flat subsig match counts (u32 for count-modifier support)
        let mut subsig_counts = vec![0u32; self.total_subsigs];

        // Phase 1: Aho-Corasick (fixed subsigs + wildcard atoms, single pass)
        if let Some(ref ac) = self.automaton {
            for mat in ac.find_overlapping_iter(data) {
                let pat_id = mat.pattern().as_usize();

                if pat_id < self.fixed_count {
                    let (rule_idx, local_idx) = self.fixed_map[pat_id];
                    if bitmap[rule_idx] {
                        let slot = self.subsig_offsets[rule_idx] + local_idx;
                        subsig_counts[slot] = subsig_counts[slot].saturating_add(1);
                    }
                } else {
                    let wc_idx = pat_id - self.fixed_count;
                    let wc = &self.atom_wildcards[wc_idx];
                    if bitmap[wc.rule_idx] {
                        let atom_pos = mat.start();
                        if atom_pos >= wc.atom_offset {
                            let start = atom_pos - wc.atom_offset;
                            if start + wc.pattern.len() <= data.len()
                                && verify_wildcard_at(data, start, &wc.pattern, &wc.mask)
                            {
                                let slot = self.subsig_offsets[wc.rule_idx] + wc.local_idx;
                                subsig_counts[slot] = subsig_counts[slot].saturating_add(1);
                            }
                        }
                    }
                }
            }
        }

        // Phase 2: linear wildcards (un-atomizable patterns, typically < 1%)
        if ft_idx < self.eligible_linear_wc.len() {
            for &wc_idx in &self.eligible_linear_wc[ft_idx] {
                let wc = &self.linear_wildcards[wc_idx];
                let count = count_wildcard_linear(data, &wc.pattern, &wc.mask);
                if count > 0 {
                    let slot = self.subsig_offsets[wc.rule_idx] + wc.local_idx;
                    subsig_counts[slot] = subsig_counts[slot].saturating_add(count);
                }
            }
        }

        // Phase 3: evaluate logic + count constraints for eligible rules
        let mut matches = Vec::new();
        for &rule_idx in eligible {
            let rule = &self.rules[rule_idx];

            if rule.min_filesize > 0 && file_size < rule.min_filesize {
                continue;
            }
            if rule.max_filesize > 0 && file_size > rule.max_filesize {
                continue;
            }

            let off = self.subsig_offsets[rule_idx];
            if rule.logic.evaluate(&subsig_counts[off..off + rule.subsig_count]) {
                matches.push(rule.name.clone());
            }
        }

        matches
    }
}

impl Default for LdbDb {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Atom extraction
// ---------------------------------------------------------------------------

/// Find the longest contiguous run of fixed bytes (mask == true) in a wildcard
/// pattern.  Returns (start_offset, length) if at least 2 fixed bytes exist.
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

/// Verify a wildcard pattern at a specific position (used after atom AC hit).
#[inline]
fn verify_wildcard_at(data: &[u8], start: usize, pattern: &[u8], mask: &[bool]) -> bool {
    for i in 0..pattern.len() {
        if mask[i] && data[start + i] != pattern[i] {
            return false;
        }
    }
    true
}

/// Count all positions where the linear wildcard pattern matches.
fn count_wildcard_linear(data: &[u8], pattern: &[u8], mask: &[bool]) -> u32 {
    if pattern.len() > data.len() {
        return 0;
    }
    let end = data.len() - pattern.len() + 1;
    let mut count = 0u32;
    for pos in 0..end {
        if verify_wildcard_at(data, pos, pattern, mask) {
            count = count.saturating_add(1);
        }
    }
    count
}

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

/// Parse the Target Description Block, extracting target type and filesize range.
fn parse_tdb(tdb: &str) -> (TargetType, u64, u64) {
    let mut target = TargetType::Any;
    let mut min_fs = 0u64;
    let mut max_fs = 0u64;
    let mut found_target = false;

    for part in tdb.split(',') {
        let part = part.trim();
        if let Some(val) = part.strip_prefix("Target:") {
            if let Ok(n) = val.trim().parse::<u8>() {
                target = TargetType::from_u8(n);
                found_target = true;
            }
        } else if let Some(val) = part.strip_prefix("FileSize:") {
            if let Some((lo, hi)) = val.split_once('-') {
                min_fs = lo.trim().parse().unwrap_or(0);
                max_fs = hi.trim().parse().unwrap_or(0);
            }
        }
    }

    if !found_target {
        let first = tdb.split(|c: char| c == ':' || c == ',').next().unwrap_or("");
        if let Ok(n) = first.trim().parse::<u8>() {
            target = TargetType::from_u8(n);
        }
    }

    (target, min_fs, max_fs)
}

// ---------------------------------------------------------------------------
// Recursive descent parser for ClamAV LDB logical expressions.
//
// Grammar:
//   expr     = or_expr
//   or_expr  = and_expr ('|' and_expr)*
//   and_expr = unary ('&' unary)*
//   unary    = atom [count_mod]
//   atom     = '(' expr ')' | NUMBER
//   count_mod = ('>' | '<' | '=') NUMBER [',' NUMBER]
// ---------------------------------------------------------------------------

fn parse_logic_expr(s: &str, max_subsigs: usize) -> LogicNode {
    let mut parser = LogicParser {
        bytes: s.as_bytes(),
        pos: 0,
        max_subsigs,
    };
    parser.parse_expr()
}

struct LogicParser<'a> {
    bytes: &'a [u8],
    pos: usize,
    max_subsigs: usize,
}

impl<'a> LogicParser<'a> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn advance(&mut self) {
        if self.pos < self.bytes.len() {
            self.pos += 1;
        }
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.advance();
        }
    }

    fn parse_u32(&mut self) -> u32 {
        self.skip_ws();
        let start = self.pos;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.advance();
        }
        if self.pos == start {
            return 0;
        }
        std::str::from_utf8(&self.bytes[start..self.pos])
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    }

    fn parse_expr(&mut self) -> LogicNode {
        self.parse_or_expr()
    }

    fn parse_or_expr(&mut self) -> LogicNode {
        let mut left = self.parse_and_expr();
        loop {
            self.skip_ws();
            if self.peek() == Some(b'|') {
                self.advance();
                let right = self.parse_and_expr();
                left = LogicNode::Or(Box::new(left), Box::new(right));
            } else {
                break;
            }
        }
        left
    }

    fn parse_and_expr(&mut self) -> LogicNode {
        let mut left = self.parse_unary();
        loop {
            self.skip_ws();
            if self.peek() == Some(b'&') {
                self.advance();
                let right = self.parse_unary();
                left = LogicNode::And(Box::new(left), Box::new(right));
            } else {
                break;
            }
        }
        left
    }

    /// Parse an atom optionally followed by a count modifier (>X[,Y], <X[,Y], =X[,Y]).
    fn parse_unary(&mut self) -> LogicNode {
        let node = self.parse_atom();
        self.skip_ws();
        match self.peek() {
            Some(b'>') => {
                self.advance();
                let n = self.parse_u32();
                let min_diff = self.parse_comma_number();
                LogicNode::Count(Box::new(node), CountOp::Gt(n, min_diff))
            }
            Some(b'<') => {
                self.advance();
                let n = self.parse_u32();
                let min_diff = self.parse_comma_number();
                LogicNode::Count(Box::new(node), CountOp::Lt(n, min_diff))
            }
            Some(b'=') => {
                self.advance();
                let n = self.parse_u32();
                let min_diff = self.parse_comma_number();
                LogicNode::Count(Box::new(node), CountOp::Eq(n, min_diff))
            }
            _ => node,
        }
    }

    fn parse_atom(&mut self) -> LogicNode {
        self.skip_ws();
        if self.peek() == Some(b'(') {
            self.advance();
            let node = self.parse_expr();
            self.skip_ws();
            if self.peek() == Some(b')') {
                self.advance();
            }
            return node;
        }
        let idx = (self.parse_u32() as usize).min(self.max_subsigs.saturating_sub(1));
        LogicNode::Leaf(idx)
    }

    /// Parse optional `,Y` diversity part of count modifier (e.g. `>5,2`).
    /// Returns the Y value, or 0 if absent.
    fn parse_comma_number(&mut self) -> u32 {
        self.skip_ws();
        if self.peek() == Some(b',') {
            self.advance();
            self.parse_u32()
        } else {
            0
        }
    }
}

fn parse_hex_string(hex: &str) -> Option<Vec<u8>> {
    let clean: String = hex.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if clean.len() % 2 != 0 || clean.is_empty() {
        return None;
    }
    hex::decode(&clean).ok()
}

fn parse_wildcard_hex(hex: &str) -> Option<(Vec<u8>, Vec<bool>)> {
    let cleaned: String = hex
        .chars()
        .filter(|c| c.is_ascii_hexdigit() || *c == '?')
        .collect();
    if cleaned.len() % 2 != 0 || cleaned.is_empty() {
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
