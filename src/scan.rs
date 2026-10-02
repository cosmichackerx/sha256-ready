use crate::rules::{check_line, FileContext, Severity};
use ignore::overrides::OverrideBuilder;
use ignore::WalkBuilder;
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize)]
pub struct Finding {
    pub rule: &'static str,
    pub severity: Severity,
    /// Path relative to the scan root, with forward slashes.
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub message: String,
    /// The offending line, trimmed and shortened.
    pub snippet: String,
    /// Path as found on disk (not serialized); used for --changed-since filtering.
    #[serde(skip)]
    pub abs: PathBuf,
}

pub struct Options {
    pub roots: Vec<PathBuf>,
    pub exclude: Vec<String>,
    pub use_gitignore: bool,
    pub max_filesize: u64,
    /// Report findings in test/fixture files one level lower (error -> warning -> info).
    pub demote_tests: bool,
    /// Files that must never be scanned (for example the baseline file itself).
    pub skip_files: Vec<PathBuf>,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            roots: vec![PathBuf::from(".")],
            exclude: vec![],
            use_gitignore: true,
            max_filesize: 1_000_000,
            demote_tests: true,
            skip_files: vec![],
        }
    }
}

#[derive(Default, Debug, Serialize)]
pub struct ScanStats {
    pub files_scanned: usize,
    pub files_skipped_binary: usize,
    pub files_skipped_large: usize,
    pub suppressed: usize,
    /// Findings dropped because they are not on lines changed since `--changed-since`.
    pub unchanged_filtered: usize,
    /// Findings accepted by a baseline file.
    pub baselined: usize,
}

const SKIP_NAMES: &[&str] = &[
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "Cargo.lock",
    "go.sum",
    "poetry.lock",
    "Gemfile.lock",
    "composer.lock",
    "Pipfile.lock",
    "uv.lock",
];
const SKIP_SUFFIXES: &[&str] = &[".min.js", ".min.css", ".map", ".svg", ".lock", ".snap"];

fn snippet(line: &str) -> String {
    let t = line.trim();
    if t.chars().count() > 160 {
        let cut: String = t.chars().take(159).collect();
        format!("{cut}…")
    } else {
        t.to_string()
    }
}

fn is_suppressed(lines: &[&str], idx: usize) -> bool {
    let marker = "sha256-ready: ignore";
    lines[idx].contains(marker) || (idx > 0 && lines[idx - 1].contains(marker) && !lines[idx - 1].contains("ignore-file"))
}

/// Heuristic: does this path look like a test, spec or fixture file?
pub fn is_test_path(path: &str) -> bool {
    let p = path.replace('\\', "/").to_lowercase();
    let in_dir = p.split('/').rev().skip(1).any(|seg| {
        matches!(
            seg,
            "test"
                | "tests"
                | "spec"
                | "specs"
                | "__tests__"
                | "fixtures"
                | "fixture"
                | "testdata"
                | "testing"
                | "e2e"
                | "__mocks__"
                | "mocks"
        )
    });
    let file = p.rsplit('/').next().unwrap_or("");
    in_dir
        || file.starts_with("test_")
        || file.contains("_test.")
        || file.contains(".test.")
        || file.contains(".spec.")
        || file.ends_with("_spec.rb")
        || file.ends_with("test.java")
        || file.ends_with("tests.java")
}

fn demote(s: Severity) -> Severity {
    match s {
        Severity::Error => Severity::Warning,
        _ => Severity::Info,
    }
}

/// Scan the text of one file. `name` is only used for the findings.
pub fn scan_text(name: &str, text: &str, stats: &mut ScanStats) -> Vec<Finding> {
    scan_text_with(name, text, stats, false)
}

pub fn scan_text_with(name: &str, text: &str, stats: &mut ScanStats, demote_tests: bool) -> Vec<Finding> {
    let demote_here = demote_tests && is_test_path(name);
    let lines: Vec<&str> = text.lines().collect();
    if lines.iter().take(20).any(|l| l.contains("sha256-ready: ignore-file")) {
        return vec![];
    }
    let ctx = FileContext::new(text);
    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if line.len() > 2000 {
            continue; // minified / generated line
        }
        let hits = check_line(line, &ctx);
        if hits.is_empty() {
            continue;
        }
        if is_suppressed(&lines, i) {
            stats.suppressed += hits.len();
            continue;
        }
        for h in hits {
            out.push(Finding {
                rule: h.rule,
                severity: if demote_here { demote(h.severity) } else { h.severity },
                file: name.to_string(),
                line: i + 1,
                column: h.column,
                message: h.message,
                snippet: snippet(line),
                abs: PathBuf::new(),
            });
        }
    }
    out
}

fn rel(root: &Path, p: &Path) -> String {
    let r = p.strip_prefix(root).unwrap_or(p);
    let s = r.to_string_lossy().replace('\\', "/");
    s.trim_start_matches("./").to_string()
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

pub fn scan(opts: &Options) -> Result<(Vec<Finding>, ScanStats), String> {
    let mut findings = Vec::new();
    let mut stats = ScanStats::default();
    for root in &opts.roots {
        if !root.exists() {
            return Err(format!("path does not exist: {}", root.display()));
        }
        let base = if root.is_file() { root.parent().unwrap_or(Path::new(".")).to_path_buf() } else { root.clone() };
        let mut wb = WalkBuilder::new(root);
        wb.hidden(false).git_ignore(opts.use_gitignore).git_global(false).git_exclude(opts.use_gitignore).require_git(false);
        wb.filter_entry(|e| {
            let n = e.file_name().to_string_lossy();
            !(n == ".git" || n == "node_modules" && e.file_type().is_some_and(|t| t.is_dir()))
        });
        if !opts.exclude.is_empty() {
            let mut ob = OverrideBuilder::new(&base);
            for g in &opts.exclude {
                ob.add(&format!("!{g}")).map_err(|e| format!("bad --exclude glob '{g}': {e}"))?;
            }
            wb.overrides(ob.build().map_err(|e| e.to_string())?);
        }
        for entry in wb.build() {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            if !entry.file_type().is_some_and(|t| t.is_file()) {
                continue;
            }
            let path = entry.path();
            if opts.skip_files.iter().any(|s| same_file(s, path)) {
                continue;
            }
            let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
            if SKIP_NAMES.contains(&name.as_str()) || SKIP_SUFFIXES.iter().any(|s| name.ends_with(s)) {
                continue;
            }
            let meta = match fs::metadata(path) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if meta.len() > opts.max_filesize {
                stats.files_skipped_large += 1;
                continue;
            }
            let bytes = match fs::read(path) {
                Ok(b) => b,
                Err(_) => continue,
            };
            if bytes.iter().take(8192).any(|&b| b == 0) {
                stats.files_skipped_binary += 1;
                continue;
            }
            let text = String::from_utf8_lossy(&bytes);
            stats.files_scanned += 1;
            let display = if root.is_file() { rel(Path::new(""), root) } else { rel(&base, path) };
            let mut found = scan_text_with(&display, &text, &mut stats, opts.demote_tests);
            for f in &mut found {
                f.abs = path.to_path_buf();
            }
            findings.extend(found);
        }
    }
    findings.sort_by(|a, b| a.file.cmp(&b.file).then(a.line.cmp(&b.line)).then(a.rule.cmp(b.rule)));
    Ok((findings, stats))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_detection() {
        for p in [
            "tests/a.go",
            "src/foo_test.go",
            "lib/x.spec.ts",
            "a/b/__tests__/c.js",
            "test_util.py",
            "spec/models/a_spec.rb",
            "x/testdata/y.txt",
            "src/FooTest.java",
        ] {
            assert!(is_test_path(p), "{p}");
        }
        for p in ["src/main.rs", "contest/winner.py", "latest/a.go", "src/attestation.ts", "src/resources/a.json"] {
            assert!(!is_test_path(p), "{p}");
        }
    }

    #[test]
    fn scan_text_collects_line_numbers_and_respects_ignores() {
        let mut st = ScanStats::default();
        let f = scan_text("a.sh", "ok\necho $x | cut -c1-40 # commit\n# sha256-ready: ignore\necho $y | cut -c1-40 # commit\n", &mut st);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].line, 2);
        assert_eq!(st.suppressed, 1);
    }

    #[test]
    fn demotion_lowers_one_level() {
        let mut st = ScanStats::default();
        let f = scan_text_with("tests/a.sh", "grep -E '^[0-9a-f]{40}$'\n", &mut st, true);
        assert_eq!(f[0].severity, Severity::Warning);
        let f = scan_text_with("src/a.sh", "grep -E '^[0-9a-f]{40}$'\n", &mut st, true);
        assert_eq!(f[0].severity, Severity::Error);
    }
}
