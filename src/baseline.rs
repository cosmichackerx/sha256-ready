//! Baseline file: accept the findings that exist today and fail only on new ones.
//!
//! An entry is (rule, file, normalized snippet) plus a count, so a *new* copy of an accepted line still fails
//! and line-number shifts do not invalidate the baseline.

use crate::scan::{Finding, ScanStats};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct Entry {
    pub rule: String,
    pub file: String,
    pub snippet: String,
    pub count: usize,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Baseline {
    pub version: u32,
    pub tool: String,
    pub entries: Vec<Entry>,
}

pub fn normalize(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn key(rule: &str, file: &str, snippet: &str) -> (String, String, String) {
    (rule.to_string(), file.to_string(), normalize(snippet))
}

pub fn from_findings(findings: &[Finding]) -> Baseline {
    let mut counts: BTreeMap<(String, String, String), usize> = BTreeMap::new();
    for f in findings {
        *counts.entry(key(f.rule, &f.file, &f.snippet)).or_default() += 1;
    }
    Baseline {
        version: 1,
        tool: "sha256-ready".into(),
        entries: counts.into_iter().map(|((rule, file, snippet), count)| Entry { rule, file, snippet, count }).collect(),
    }
}

pub fn write(path: &Path, findings: &[Finding]) -> Result<usize, String> {
    let b = from_findings(findings);
    let json = serde_json::to_string_pretty(&b).map_err(|e| e.to_string())?;
    fs::write(path, format!("{json}\n")).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    Ok(b.entries.iter().map(|e| e.count).sum())
}

pub fn load(path: &Path) -> Result<Baseline, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("cannot read baseline {}: {e}", path.display()))?;
    let b: Baseline = serde_json::from_str(&text).map_err(|e| format!("invalid baseline {}: {e}", path.display()))?;
    if b.version != 1 {
        return Err(format!("unsupported baseline version {} in {}", b.version, path.display()));
    }
    Ok(b)
}

/// Remove findings accepted by the baseline. Returns (remaining findings, number of stale baseline entries).
pub fn apply(b: &Baseline, findings: Vec<Finding>, stats: &mut ScanStats) -> (Vec<Finding>, usize) {
    let mut budget: BTreeMap<(String, String, String), usize> = BTreeMap::new();
    for e in &b.entries {
        *budget.entry(key(&e.rule, &e.file, &e.snippet)).or_default() += e.count;
    }
    let mut kept = Vec::new();
    for f in findings {
        let k = key(f.rule, &f.file, &f.snippet);
        match budget.get_mut(&k) {
            Some(n) if *n > 0 => {
                *n -= 1;
                stats.baselined += 1;
            }
            _ => kept.push(f),
        }
    }
    let stale = budget.values().filter(|&&n| n > 0).count();
    (kept, stale)
}
