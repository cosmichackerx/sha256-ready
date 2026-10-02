use crate::rules::{rule, Severity, RULES};
use crate::scan::{Finding, ScanStats};
use serde_json::{json, Value};

pub fn counts(f: &[Finding]) -> (usize, usize, usize) {
    let c = |s: Severity| f.iter().filter(|x| x.severity == s).count();
    (c(Severity::Error), c(Severity::Warning), c(Severity::Info))
}

fn summary(f: &[Finding], st: &ScanStats) -> String {
    let (e, w, i) = counts(f);
    if f.is_empty() {
        return format!("No SHA-1 (40 character) assumptions found in {} file(s).", st.files_scanned);
    }
    format!("{} finding(s): {e} error, {w} warning, {i} info in {} file(s) scanned.", f.len(), st.files_scanned)
}

pub fn text(f: &[Finding], st: &ScanStats) -> String {
    let mut out = String::new();
    let mut last = "";
    for x in f {
        if x.file != last {
            if !last.is_empty() {
                out.push('\n');
            }
            out.push_str(&format!("{}\n", x.file));
            last = &x.file;
        }
        out.push_str(&format!("  {:>5}:{:<3} {:<7} {:<18} {}\n", x.line, x.column, x.severity.as_str(), x.rule, x.message));
        out.push_str(&format!("             {}\n", x.snippet));
    }
    if !f.is_empty() {
        out.push('\n');
    }
    out.push_str(&summary(f, st));
    out.push('\n');
    if st.suppressed > 0 {
        out.push_str(&format!("{} finding(s) suppressed by `sha256-ready: ignore` comments.\n", st.suppressed));
    }
    if st.baselined > 0 {
        out.push_str(&format!("{} finding(s) accepted by the baseline file.\n", st.baselined));
    }
    if st.unchanged_filtered > 0 {
        out.push_str(&format!("{} finding(s) on lines not changed since the --changed-since ref were hidden.\n", st.unchanged_filtered));
    }
    if !f.is_empty() {
        out.push_str("Run `sha256-ready rules --explain <rule>` for the reason and the fix.\n");
    }
    out
}

pub fn markdown(f: &[Finding], st: &ScanStats) -> String {
    let mut out = String::from("### sha256-ready\n\n");
    out.push_str(&format!("**{}**\n\n", summary(f, st)));
    if !f.is_empty() {
        out.push_str("| Severity | Rule | Location | Detail |\n|---|---|---|---|\n");
        for x in f {
            let snip = x.snippet.replace('|', "\\|").replace('`', "'");
            out.push_str(&format!("| {} | `{}` | `{}:{}` | {} — `{}` |\n", x.severity.as_str(), x.rule, x.file, x.line, x.message, snip));
        }
    }
    out
}

fn gh_escape(s: &str, prop: bool) -> String {
    let mut r = s.replace('%', "%25").replace('\r', "%0D").replace('\n', "%0A");
    if prop {
        r = r.replace(':', "%3A").replace(',', "%2C");
    }
    r
}

/// GitHub Actions workflow commands.
pub fn github(f: &[Finding]) -> String {
    f.iter()
        .map(|x| {
            let level = match x.severity {
                Severity::Error => "error",
                Severity::Warning => "warning",
                Severity::Info => "notice",
            };
            format!(
                "::{level} file={},line={},col={},title={}::{}",
                gh_escape(&x.file, true),
                x.line,
                x.column,
                gh_escape(x.rule, true),
                gh_escape(&format!("{} (fix: {})", x.message, rule(x.rule).fix), false)
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn json(f: &[Finding], st: &ScanStats) -> String {
    let (e, w, i) = counts(f);
    serde_json::to_string_pretty(&json!({
        "schema": 1,
        "tool": "sha256-ready",
        "version": env!("CARGO_PKG_VERSION"),
        "summary": { "error": e, "warning": w, "info": i, "files_scanned": st.files_scanned, "suppressed": st.suppressed, "baselined": st.baselined, "hidden_unchanged": st.unchanged_filtered },
        "findings": f,
    }))
    .unwrap()
}

fn sarif_level(s: Severity) -> &'static str {
    match s {
        Severity::Error => "error",
        Severity::Warning => "warning",
        Severity::Info => "note",
    }
}

/// SARIF 2.1.0 for GitHub code scanning.
pub fn sarif(f: &[Finding]) -> String {
    let rules: Vec<Value> = RULES
        .iter()
        .map(|r| {
            json!({
                "id": r.id,
                "name": r.id,
                "shortDescription": { "text": r.title },
                "fullDescription": { "text": r.why },
                "help": { "text": format!("{}\n\nFix: {}", r.why, r.fix) },
                "helpUri": "https://github.com/cosmichackerx/sha256-ready#rules",
                "defaultConfiguration": { "level": sarif_level(r.severity) },
                "properties": { "tags": ["git", "sha256", "compatibility"] }
            })
        })
        .collect();
    let results: Vec<Value> = f
        .iter()
        .map(|x| {
            let idx = RULES.iter().position(|r| r.id == x.rule).unwrap_or(0);
            json!({
                "ruleId": x.rule,
                "ruleIndex": idx,
                "level": sarif_level(x.severity),
                "message": { "text": format!("{} Fix: {}", x.message, rule(x.rule).fix) },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": x.file, "uriBaseId": "%SRCROOT%" },
                        "region": { "startLine": x.line, "startColumn": x.column, "snippet": { "text": x.snippet } }
                    }
                }]
            })
        })
        .collect();
    serde_json::to_string_pretty(&json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": "sha256-ready",
                "version": env!("CARGO_PKG_VERSION"),
                "informationUri": "https://github.com/cosmichackerx/sha256-ready",
                "rules": rules
            }},
            "originalUriBaseIds": { "%SRCROOT%": { "description": { "text": "Scan root" } } },
            "results": results
        }]
    }))
    .unwrap()
}
