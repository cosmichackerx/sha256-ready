//! `sha256-ready sandbox -- <command>`: run a command inside a throw-away repository that uses the SHA-256
//! object format, so release scripts, hooks and CI helpers can be tried against 64 character object names.

use std::path::Path;
use std::process::{Command, Stdio};

fn git(dir: &Path, args: &[&str]) -> Result<String, String> {
    let out = Command::new("git")
        .current_dir(dir)
        .args([
            "-c",
            "user.name=sandbox",
            "-c",
            "user.email=sandbox@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "tag.gpgsign=false",
            "-c",
            "init.defaultBranch=main",
            "-c",
            "core.autocrlf=false",
        ])
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("could not run git: {e}"))?;
    if !out.status.success() {
        return Err(format!("git {} failed: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

pub struct Sandbox {
    pub dir: std::path::PathBuf,
    pub head: String,
    pub previous: String,
    pub tag: String,
}

/// Create the repository in `dir` (which must exist and be empty).
pub fn create(dir: &Path, format: &str, commits: usize) -> Result<Sandbox, String> {
    git(dir, &["init", "-q", "--object-format", format])?;
    let fmt = git(dir, &["rev-parse", "--show-object-format"])?;
    if fmt != format {
        return Err(format!("expected object format {format}, repository reports {fmt}"));
    }
    let mut previous = String::new();
    for n in 1..=commits.max(1) {
        std::fs::write(dir.join("README.md"), format!("# sandbox\n\ncommit {n}\n")).map_err(|e| e.to_string())?;
        git(dir, &["add", "-A"])?;
        previous = git(dir, &["rev-parse", "--verify", "-q", "HEAD"]).unwrap_or_default();
        git(dir, &["commit", "-q", "-m", &format!("sandbox commit {n}")])?;
        if n == 1 {
            git(dir, &["tag", "v0.0.1"])?;
        }
    }
    let head = git(dir, &["rev-parse", "HEAD"])?;
    let expected = if format == "sha256" { 64 } else { 40 };
    if head.len() != expected {
        return Err(format!("HEAD has {} characters, expected {expected}", head.len()));
    }
    Ok(Sandbox { dir: dir.to_path_buf(), head, previous, tag: "v0.0.1".into() })
}

pub fn run(format: &str, commits: usize, keep: bool, cmd: &[String]) -> Result<i32, String> {
    if cmd.is_empty() {
        return Err("no command given; usage: sha256-ready sandbox -- <command> [args...]".into());
    }
    let tmp = tempfile::Builder::new().prefix("sha256-ready-").tempdir().map_err(|e| e.to_string())?;
    let sb = create(tmp.path(), format, commits)?;
    eprintln!("sha256-ready: sandbox repository ({format}) at {}", sb.dir.display());
    eprintln!("sha256-ready: HEAD = {} ({} characters)", sb.head, sb.head.len());
    let status = Command::new(&cmd[0])
        .args(&cmd[1..])
        .current_dir(&sb.dir)
        .env("SHA256_READY_SANDBOX", "1")
        .env("SANDBOX_OBJECT_FORMAT", format)
        .env("SANDBOX_HEAD", &sb.head)
        .env("SANDBOX_PREVIOUS", &sb.previous)
        .env("SANDBOX_TAG", &sb.tag)
        .status()
        .map_err(|e| format!("could not run '{}': {e}", cmd[0]))?;
    let code = status.code().unwrap_or(1);
    if keep {
        let kept = tmp.keep();
        eprintln!("sha256-ready: kept sandbox at {}", kept.display());
    }
    if code == 0 {
        eprintln!("sha256-ready: command succeeded against a {format} repository");
    } else {
        eprintln!("sha256-ready: command exited with status {code} against a {format} repository");
    }
    Ok(code)
}
