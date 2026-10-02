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
