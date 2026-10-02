//! `--changed-since <ref>`: keep only findings on lines that differ from a base ref.

use crate::scan::{Finding, ScanStats};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

/// `None` means "every line of the file" (untracked or whole-file mode).
pub type LineRanges = Option<Vec<(usize, usize)>>;

pub struct Changed {
    files: HashMap<PathBuf, LineRanges>,
}

fn git(dir: &Path, args: &[&str]) -> Result<String, String> {
    let out = Command::new("git")
        .arg("-c")
        .arg("core.quotepath=false")
        .args(args)
        .current_dir(dir)
        .output()
        .map_err(|e| format!("cannot run git: {e}"))?;
    if !out.status.success() {
        return Err(format!("git {} failed: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Parse `git diff -U0` output into new-side line ranges per file (paths relative to the repo root).
pub fn parse_diff(diff: &str) -> HashMap<String, Vec<(usize, usize)>> {
    let mut out: HashMap<String, Vec<(usize, usize)>> = HashMap::new();
    let mut current: Option<String> = None;
    for line in diff.lines() {
        if let Some(rest) = line.strip_prefix("+++ ") {
            current = if rest == "/dev/null" {
                None
            } else {
                let p = rest.trim_matches('"');
                Some(p.strip_prefix("b/").unwrap_or(p).to_string())
            };
        } else if line.starts_with("@@") {
            let Some(file) = &current else { continue };
            // @@ -a,b +c,d @@
            let plus = line.split_whitespace().find(|t| t.starts_with('+')).unwrap_or("+0");
            let spec = plus.trim_start_matches('+');
            let (start, count) = match spec.split_once(',') {
                Some((a, b)) => (a.parse::<usize>().unwrap_or(0), b.parse::<usize>().unwrap_or(1)),
                None => (spec.parse::<usize>().unwrap_or(0), 1),
            };
            let ranges = out.entry(file.clone()).or_default();
            if count > 0 {
                ranges.push((start, start + count - 1));
            }
        }
    }
    out
}

impl Changed {
    /// Compare the working tree against the merge base of `since` and HEAD. Untracked files count as fully changed.
    pub fn load(dir: &Path, since: &str, whole_files: bool) -> Result<Changed, String> {
        let top = git(dir, &["rev-parse", "--show-toplevel"]).map_err(|_| "--changed-since needs a git repository".to_string())?;
        let top = PathBuf::from(top.trim());
        let base = git(dir, &["merge-base", since, "HEAD"])
            .map(|s| s.trim().to_string())
            .or_else(|_| git(dir, &["rev-parse", "--verify", &format!("{since}^{{commit}}")]).map(|s| s.trim().to_string()))
            .map_err(|_| format!("cannot resolve '{since}' (in a CI checkout use fetch-depth: 0, or fetch the base branch first)"))?;
        let diff = git(&top, &["diff", "-U0", "--no-color", "--no-ext-diff", "--src-prefix=a/", "--dst-prefix=b/", &base])?;
        let mut files: HashMap<PathBuf, LineRanges> = HashMap::new();
        for (name, ranges) in parse_diff(&diff) {
            files.insert(canon(&top.join(name)), if whole_files { None } else { Some(ranges) });
        }
        if whole_files {
            // pure renames / mode changes have no hunks; list names too
            for name in git(&top, &["diff", "--name-only", "--diff-filter=ACMR", &base])?.lines() {
                files.entry(canon(&top.join(name))).or_insert(None);
            }
        }
        for name in git(&top, &["ls-files", "--others", "--exclude-standard"])?.lines() {
            files.insert(canon(&top.join(name)), None);
        }
        Ok(Changed { files })
    }

    pub fn keeps(&self, f: &Finding) -> bool {
        match self.files.get(&canon(&f.abs)) {
            None => false,
            Some(None) => true,
            Some(Some(ranges)) => ranges.iter().any(|&(a, b)| f.line >= a && f.line <= b),
        }
    }

    pub fn filter(&self, findings: Vec<Finding>, stats: &mut ScanStats) -> Vec<Finding> {
        let before = findings.len();
        let kept: Vec<Finding> = findings.into_iter().filter(|f| self.keeps(f)).collect();
        stats.unchanged_filtered += before - kept.len();
        kept
    }
}

fn canon(p: &Path) -> PathBuf {
    p.canonicalize().unwrap_or_else(|_| p.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hunks() {
        let d = "diff --git a/x.sh b/x.sh\n--- a/x.sh\n+++ b/x.sh\n@@ -3,0 +4,2 @@ foo\n+a\n+b\n@@ -10 +12 @@\n+c\n@@ -20,2 +0,0 @@\n-x\n-y\ndiff --git a/gone b/gone\n--- a/gone\n+++ /dev/null\n@@ -1 +0,0 @@\n-z\n";
        let m = parse_diff(d);
        assert_eq!(m["x.sh"], vec![(4, 5), (12, 12)]);
        assert!(!m.contains_key("gone"));
    }
}
