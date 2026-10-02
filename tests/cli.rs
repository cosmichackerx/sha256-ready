use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sha256-ready"))
}

fn write(dir: &Path, rel: &str, body: &str) {
    let p = dir.join(rel);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, body).unwrap();
}

fn scan(dir: &Path, args: &[&str]) -> Output {
    bin().arg("scan").arg(dir).args(args).output().unwrap()
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn git_available() -> bool {
    Command::new("git").arg("--version").output().map(|o| o.status.success()).unwrap_or(false)
}

const BAD_SH: &str =
    "#!/bin/sh\nrev=$(git rev-parse HEAD)\nshort=$(echo \"$rev\" | cut -c1-40)\necho \"$rev\" | grep -E '^[0-9a-f]{40}$'\n";

#[test]
fn clean_tree_exits_zero() {
    let d = tempfile::tempdir().unwrap();
    write(d.path(), "ok.sh", "#!/bin/sh\ngit rev-parse HEAD\n");
    let o = scan(d.path(), &[]);
    assert_eq!(o.status.code(), Some(0));
    assert!(stdout(&o).contains("No SHA-1"));
}

#[test]
fn findings_fail_by_default_and_fail_on_never_passes() {
    let d = tempfile::tempdir().unwrap();
    write(d.path(), "bad.sh", BAD_SH);
    let o = scan(d.path(), &[]);
    assert_eq!(o.status.code(), Some(1));
    let t = stdout(&o);
    assert!(t.contains("hex40-pattern") && t.contains("truncate-40"), "{t}");
    assert_eq!(scan(d.path(), &["--fail-on", "never"]).status.code(), Some(0));
}

#[test]
fn bad_fail_on_is_usage_error() {
    let d = tempfile::tempdir().unwrap();
    assert_eq!(scan(d.path(), &["--fail-on", "bogus"]).status.code(), Some(2));
}

#[test]
fn exclude_and_suppression_comments_work() {
    let d = tempfile::tempdir().unwrap();
    write(d.path(), "vendor/bad.sh", BAD_SH);
    assert_eq!(scan(d.path(), &["--exclude", "vendor/**"]).status.code(), Some(0));

    let d = tempfile::tempdir().unwrap();
    write(
        d.path(),
        "a.sh",
        "# sha256-ready: ignore\necho \"$x\" | grep -E '^[0-9a-f]{40}$'\necho \"$x\" | cut -c1-40 # sha256-ready: ignore\n",
    );
    assert_eq!(scan(d.path(), &[]).status.code(), Some(0));

    let d = tempfile::tempdir().unwrap();
    write(d.path(), "b.sh", &format!("# sha256-ready: ignore-file\n{BAD_SH}"));
    assert_eq!(scan(d.path(), &[]).status.code(), Some(0));
}

#[test]
fn test_files_are_demoted_unless_strict() {
    let d = tempfile::tempdir().unwrap();
    write(d.path(), "tests/null_test.go", "const z = \"0000000000000000000000000000000000000000\"\n");
    assert_eq!(scan(d.path(), &[]).status.code(), Some(0));
    assert_eq!(scan(d.path(), &["--strict-tests"]).status.code(), Some(1));
}

#[test]
fn gitignored_files_are_skipped_unless_asked() {
    if !git_available() {
        return;
    }
    let d = tempfile::tempdir().unwrap();
    assert!(Command::new("git").args(["init", "-q"]).current_dir(d.path()).status().unwrap().success());
    write(d.path(), ".gitignore", "generated/\n");
    write(d.path(), "generated/bad.sh", BAD_SH);
    assert_eq!(scan(d.path(), &[]).status.code(), Some(0));
    assert_eq!(scan(d.path(), &["--no-gitignore"]).status.code(), Some(1));
}

#[test]
fn json_output_is_valid_and_complete() {
    let d = tempfile::tempdir().unwrap();
    write(d.path(), "bad.sh", BAD_SH);
    let o = scan(d.path(), &["--format", "json", "--fail-on", "never"]);
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).expect("valid json");
    let f = v["findings"].as_array().unwrap();
    assert!(f.iter().any(|x| x["rule"] == "hex40-pattern" && x["line"] == 4 && x["file"] == "bad.sh"));
    assert!(v["summary"]["files_scanned"].as_u64().unwrap() >= 1);
}

#[test]
fn sarif_output_has_rules_and_results() {
    let d = tempfile::tempdir().unwrap();
    write(d.path(), "bad.sh", BAD_SH);
    let o = scan(d.path(), &["--format", "sarif", "--fail-on", "never"]);
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).expect("valid sarif json");
    assert_eq!(v["version"], "2.1.0");
    let run = &v["runs"][0];
    assert_eq!(run["tool"]["driver"]["name"], "sha256-ready");
    assert!(run["tool"]["driver"]["rules"].as_array().unwrap().len() >= 10);
    let r = &run["results"][0];
    assert!(r["ruleId"].is_string());
    assert!(r["locations"][0]["physicalLocation"]["region"]["startLine"].as_u64().unwrap() >= 1);
}

#[test]
fn github_format_emits_workflow_commands() {
    let d = tempfile::tempdir().unwrap();
    write(d.path(), "bad.sh", BAD_SH);
    let o = scan(d.path(), &["--format", "github", "--fail-on", "never"]);
    let t = stdout(&o);
    assert!(t.lines().any(|l| l.starts_with("::error file=") && l.contains("hex40-pattern")), "{t}");
}

#[test]
fn markdown_and_output_file() {
    let d = tempfile::tempdir().unwrap();
    write(d.path(), "bad.sh", BAD_SH);
    let out = d.path().join("report.md");
    let o = scan(d.path(), &["--format", "markdown", "--fail-on", "never", "-o", out.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(0));
    let md = fs::read_to_string(out).unwrap();
    assert!(md.contains("hex40-pattern") && md.contains("bad.sh"));
}

#[test]
fn rules_lists_and_explains() {
    let o = bin().arg("rules").output().unwrap();
    let t = stdout(&o);
    for id in ["hex40-pattern", "length-40", "null-oid", "column-40"] {
        assert!(t.contains(id), "{id} missing");
    }
    let o = bin().args(["rules", "--explain", "null-oid"]).output().unwrap();
    assert!(stdout(&o).contains("Fix:"));
    assert_eq!(bin().args(["rules", "--explain", "nope"]).output().unwrap().status.code(), Some(2));
}

#[test]
fn sandbox_runs_command_in_a_sha256_repository() {
    if !git_available() {
        return;
    }
    let probe = tempfile::tempdir().unwrap();
    let ok = Command::new("git")
        .args(["init", "-q", "--object-format=sha256"])
        .current_dir(probe.path())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        eprintln!("git without --object-format=sha256 support, skipping");
        return;
    }
    let o = bin().args(["sandbox", "--", "git", "rev-parse", "HEAD"]).output().unwrap();
    assert_eq!(o.status.code(), Some(0), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(stdout(&o).trim().len(), 64, "HEAD should be 64 hex chars: {}", stdout(&o));
}

#[test]
fn sandbox_exports_environment_and_propagates_failure() {
    if !git_available() {
        return;
    }
    let probe = tempfile::tempdir().unwrap();
    if !Command::new("git")
        .args(["init", "-q", "--object-format=sha256"])
        .current_dir(probe.path())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
    {
        return;
    }
    // a SHA-1 style lookup fails inside the sandbox and its exit code is propagated
    let o = bin()
        .args(["sandbox", "--", "git", "rev-parse", "--verify", "0000000000000000000000000000000000000000^{commit}"])
        .output()
        .unwrap();
    assert_ne!(o.status.code(), Some(0), "the command's failure is propagated");
    let o = bin().args(["sandbox", "--object-format", "sha1", "--", "git", "rev-parse", "HEAD"]).output().unwrap();
    assert_eq!(stdout(&o).trim().len(), 40);
}

fn git_in(dir: &Path, args: &[&str]) {
    let st = Command::new("git")
        .args(["-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"])
        .args(args)
        .current_dir(dir)
        .status()
        .unwrap();
    assert!(st.success(), "git {args:?} failed");
}

#[test]
fn changed_since_reports_only_changed_lines_and_untracked_files() {
    if !git_available() {
        return;
    }
    let d = tempfile::tempdir().unwrap();
    git_in(d.path(), &["init", "-q", "-b", "main"]);
    write(d.path(), "old.sh", "echo $a | cut -c1-40 # commit\n");
    git_in(d.path(), &["add", "-A"]);
    git_in(d.path(), &["commit", "-q", "-m", "base"]);
    git_in(d.path(), &["checkout", "-q", "-b", "feature"]);
    // one new bad line appended to an old file with an existing bad line, plus a brand new committed file
    write(d.path(), "old.sh", "echo $a | cut -c1-40 # commit\necho $b | grep -E '^[0-9a-f]{40}$'\n");
    write(d.path(), "new.sh", "[ \"${#rev}\" -eq 40 ]\n");
    git_in(d.path(), &["add", "-A"]);
    git_in(d.path(), &["commit", "-q", "-m", "feature"]);
    // and an untracked file
    write(d.path(), "untracked.sh", "x=$(git rev-parse HEAD | cut -c1-40)\n");

    let all = stdout(&scan(d.path(), &["--format", "json", "--fail-on", "never"]));
    let all: serde_json::Value = serde_json::from_str(&all).unwrap();
    assert_eq!(all["findings"].as_array().unwrap().len(), 4);

    let o = scan(d.path(), &["--changed-since", "main", "--format", "json", "--fail-on", "never"]);
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap_or_else(|_| panic!("{}", String::from_utf8_lossy(&o.stderr)));
    let mut got: Vec<(String, u64)> =
        v["findings"].as_array().unwrap().iter().map(|f| (f["file"].as_str().unwrap().to_string(), f["line"].as_u64().unwrap())).collect();
    got.sort();
    assert_eq!(got, vec![("new.sh".to_string(), 1), ("old.sh".to_string(), 2), ("untracked.sh".to_string(), 1)]);
    assert_eq!(v["summary"]["hidden_unchanged"], 1);

    let o = scan(d.path(), &["--changed-since", "main", "--whole-files", "--format", "json", "--fail-on", "never"]);
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["findings"].as_array().unwrap().len(), 4);
}

#[test]
fn changed_since_unknown_ref_is_usage_error() {
    if !git_available() {
        return;
    }
    let d = tempfile::tempdir().unwrap();
    git_in(d.path(), &["init", "-q", "-b", "main"]);
    write(d.path(), "a.sh", "echo hi\n");
    git_in(d.path(), &["add", "-A"]);
    git_in(d.path(), &["commit", "-q", "-m", "x"]);
    let o = scan(d.path(), &["--changed-since", "no-such-ref"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&o.stderr).contains("cannot resolve"));
}

#[test]
fn baseline_accepts_existing_findings_and_fails_on_new_ones() {
    let d = tempfile::tempdir().unwrap();
    write(d.path(), "a.sh", BAD_SH);
    let bl = d.path().join("sha256-ready.baseline.json");
    let o = scan(d.path(), &["--write-baseline", bl.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(0));
    assert!(bl.exists());
    // the baseline file contains the offending snippets but is never scanned itself
    assert_eq!(scan(d.path(), &["--baseline", bl.to_str().unwrap()]).status.code(), Some(0));
    // moving the lines does not matter
    write(d.path(), "a.sh", &format!("# a new comment line\n\n{BAD_SH}"));
    assert_eq!(scan(d.path(), &["--baseline", bl.to_str().unwrap()]).status.code(), Some(0));
    // a new copy of an accepted line, or a new kind of finding, fails
    write(d.path(), "a.sh", &format!("{BAD_SH}echo \"$rev\" | grep -E '^[0-9a-f]{{40}}$'\n"));
    assert_eq!(scan(d.path(), &["--baseline", bl.to_str().unwrap()]).status.code(), Some(1));
    write(d.path(), "b.sh", "[ \"${#sha}\" -eq 40 ]\n");
    write(d.path(), "a.sh", BAD_SH);
    let o = scan(d.path(), &["--baseline", bl.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(1));
    assert!(stdout(&o).contains("b.sh") && !stdout(&o).contains("a.sh"), "{}", stdout(&o));
}

#[test]
fn stale_baseline_entries_are_reported_and_bad_baseline_is_usage_error() {
    let d = tempfile::tempdir().unwrap();
    write(d.path(), "a.sh", BAD_SH);
    let bl = d.path().join("bl.json");
    scan(d.path(), &["--write-baseline", bl.to_str().unwrap()]);
    write(d.path(), "a.sh", "echo clean\n");
    let o = scan(d.path(), &["--baseline", bl.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&o.stderr).contains("no longer match"));
    fs::write(&bl, "not json").unwrap();
    assert_eq!(scan(d.path(), &["--baseline", bl.to_str().unwrap()]).status.code(), Some(2));
}

#[test]
fn file_arguments_keep_their_directory_in_findings() {
    let d = tempfile::tempdir().unwrap();
    write(d.path(), "sub/dir/a.sh", BAD_SH);
    let f = d.path().join("sub/dir/a.sh");
    let o = bin().arg("scan").arg(&f).args(["--format", "json", "--fail-on", "never"]).output().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    let file = v["findings"][0]["file"].as_str().unwrap().to_string();
    assert!(file.ends_with("sub/dir/a.sh"), "{file}");
}
