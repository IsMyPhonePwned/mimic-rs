//! Minimal YARA-like rule parser and matcher for the browser (WASM).
//! Supports a subset: rule name, strings ($id = "ascii" or $id = { hex }), condition "any of them".

#[derive(Debug, Clone)]
pub struct YaraLiteRule {
    pub name: String,
    pub patterns: Vec<Vec<u8>>,
}

/// Parse YARA-like source into rules. Supports:
///   rule RuleName { strings: $a = "literal" $b = { 48 45 4c 4c 4f } condition: any of them }
/// Multiple rules allowed. Returns error message or list of rules.
pub fn parse_yara_lite(source: &str) -> Result<Vec<YaraLiteRule>, String> {
    let mut rules = Vec::new();
    let mut rest = source.trim();

    while let Some(after_rule) = rest.strip_prefix("rule ") {
        let (name, after_open) = match after_rule.find(" {") {
            Some(i) => {
                let name = after_rule[..i].trim().to_string();
                if name.is_empty() {
                    return Err("empty rule name".into());
                }
                // Include the opening '{' so find_balanced_brace can match braces
                let after_open = after_rule[i + 1..].trim_start();
                (name, after_open)
            }
            None => return Err("expected '{' after rule name".into()),
        };

        let (body, after) = match find_balanced_brace(after_open) {
            Some((b, a)) => (b, a),
            None => return Err("unmatched braces in rule".into()),
        };

        let patterns = parse_rule_body(&body)?;
        if patterns.is_empty() {
            return Err(format!("rule '{}' has no strings", name));
        }
        rules.push(YaraLiteRule { name, patterns });
        rest = after.trim();
    }

    if rules.is_empty() && !source.trim().is_empty() {
        return Err("no valid rule found (expected 'rule Name { ... }')".into());
    }
    Ok(rules)
}

fn find_balanced_brace(s: &str) -> Option<(&str, &str)> {
    let bytes = s.as_bytes();
    if bytes.is_empty() || bytes[0] != b'{' {
        return None;
    }
    let mut depth: i32 = 1;
    let mut i = 1;
    while i < bytes.len() {
        match bytes[i] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    let inner = std::str::from_utf8(&bytes[1..i]).ok()?.trim();
                    let rest = std::str::from_utf8(&bytes[i + 1..]).ok()?.trim();
                    return Some((inner, rest));
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

fn parse_rule_body(body: &str) -> Result<Vec<Vec<u8>>, String> {
    let mut patterns = Vec::new();
    let lower = body.to_lowercase();
    let strings_start = lower.find("strings:").ok_or("missing 'strings:' section")?;
    let cond_start = lower.find("condition:").ok_or("missing 'condition:' section")?;
    let strings_section = body[strings_start + 8..cond_start].trim();
    let condition = body[cond_start + 10..].trim();

    if !condition.contains("any of them")
        && !condition.contains("all of them")
        && !condition.contains("1 of them")
    {
        return Err("only 'any of them' / 'all of them' / '1 of them' conditions are supported".into());
    }

    let mut s = strings_section;
    while let Some(dollar) = s.find('$') {
        s = s[dollar + 1..].trim_start();
        let id_end = s
            .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .unwrap_or(s.len());
        let _id = s[..id_end].trim();
        s = s[id_end..].trim_start();
        if let Some(eq) = s.find('=') {
            s = s[eq + 1..].trim_start();
            if s.starts_with('"') {
                let end = s[1..].find('"').ok_or("unterminated string literal")?;
                let lit = s[1..1 + end].replace("\\\"", "\"").replace("\\\\", "\\");
                patterns.push(lit.into_bytes());
                s = s[1 + end + 1..].trim_start();
            } else if s.starts_with('{') {
                let end = s[1..].find('}').ok_or("unterminated hex block")?;
                let hex_str = s[1..1 + end].replace(|c: char| c.is_whitespace(), "");
                let bytes = hex::decode(hex_str.as_bytes()).map_err(|_| "invalid hex in {} block")?;
                patterns.push(bytes);
                s = s[1 + end + 1..].trim_start();
            } else {
                return Err("expected \" or { after =".into());
            }
        }
    }

    Ok(patterns)
}

/// Run compiled rules on data. Returns list of (rule_name, namespace) for matching rules.
pub fn scan_yara_lite(rules: &[YaraLiteRule], data: &[u8]) -> Vec<(String, String)> {
    let mut matches = Vec::new();
    for rule in rules {
        let any_match = rule.patterns.iter().any(|pat| {
            if pat.is_empty() {
                return false;
            }
            data.windows(pat.len()).any(|w| w == pat.as_slice())
        });
        if any_match {
            matches.push((rule.name.clone(), "default".to_string()));
        }
    }
    matches
}
