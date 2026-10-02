use clap::{Parser, Subcommand, ValueEnum};
use sha256_ready::rules::{rule, Severity, RULES};
use sha256_ready::{report, sandbox, scan};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "sha256-ready",
    version,
    about = "Find code that assumes Git object names are 40 characters (SHA-1), before SHA-256 repositories reach your pipeline",
    long_about = "Scans a source tree for regexes, length checks, truncations, database columns and null-id comparisons that only work for 40 character SHA-1 object names, and can run any command inside a throw-away SHA-256 repository (`sandbox`).\n\nExit codes: 0 ok, 1 findings at or above --fail-on, 2 usage error. `sandbox` returns the exit code of the command it ran."
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Text,
    Json,
    Markdown,
    Github,
    Sarif,
}

#[derive(Subcommand)]
enum Cmd {
    /// Scan files for SHA-1 (40 character) assumptions
    Scan {
        /// Files or directories to scan
        #[arg(default_value = ".")]
        paths: Vec<PathBuf>,
        #[arg(short, long, value_enum, default_value = "text")]
        format: Format,
        /// Lowest severity that makes the exit code 1: error, warning, info or never
        #[arg(long, default_value = "error")]
        fail_on: String,
        /// Glob to exclude (repeatable), e.g. --exclude 'vendor/**'
        #[arg(short = 'x', long)]
        exclude: Vec<String>,
        /// Do not honour .gitignore files
        #[arg(long)]
        no_gitignore: bool,
        /// Report test/fixture findings at full severity (default: one level lower)
        #[arg(long)]
        strict_tests: bool,
        /// Write the report to a file instead of stdout
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// List the rules, or explain one
    Rules {
        /// Rule id to explain
        #[arg(long)]
        explain: Option<String>,
    },
    /// Run a command inside a throw-away repository that uses the SHA-256 object format
    Sandbox {
        /// Object format of the throw-away repository
        #[arg(long, default_value = "sha256")]
        object_format: String,
        /// Number of commits to create (HEAD and SANDBOX_PREVIOUS are exported)
        #[arg(long, default_value_t = 2)]
        commits: usize,
        /// Keep the directory afterwards
        #[arg(long)]
        keep: bool,
        /// Command to run, after `--`
        #[arg(last = true)]
        command: Vec<String>,
    },
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(msg) => {
            eprintln!("sha256-ready: {msg}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<u8, String> {
    let cli = Cli::parse();
    match cli.command {
        Cmd::Rules { explain } => {
            match explain {
                Some(id) => {
                    let r = RULES.iter().find(|r| r.id == id).ok_or_else(|| format!("unknown rule '{id}' (see `sha256-ready rules`)"))?;
                    println!("{}  [{}]\n{}\n\nWhy: {}\nFix: {}", r.id, r.severity.as_str(), r.title, r.why, r.fix);
                }
                None => {
                    for r in RULES {
                        println!("{:<18} {:<8} {}", r.id, r.severity.as_str(), r.title);
                    }
                    println!("\nSuppress a line with a `sha256-ready: ignore` comment on it or on the line above; skip a file with `sha256-ready: ignore-file` in its first 20 lines.");
                }
            }
            Ok(0)
        }
        Cmd::Sandbox { object_format, commits, keep, command } => {
            if !matches!(object_format.as_str(), "sha1" | "sha256") {
                return Err("--object-format must be sha1 or sha256".into());
            }
            let code = sandbox::run(&object_format, commits, keep, &command)?;
            Ok(u8::try_from(code).unwrap_or(1))
        }
        Cmd::Scan { paths, format, fail_on, exclude, no_gitignore, strict_tests, output } => {
            let threshold = if fail_on == "never" {
                None
            } else {
                Some(Severity::parse(&fail_on).ok_or_else(|| format!("unknown --fail-on '{fail_on}' (error, warning, info, never)"))?)
            };
            let opts =
                scan::Options { roots: paths, exclude, use_gitignore: !no_gitignore, demote_tests: !strict_tests, ..Default::default() };
            let (findings, stats) = scan::scan(&opts)?;
            let body = match format {
                Format::Text => report::text(&findings, &stats),
                Format::Json => report::json(&findings, &stats),
                Format::Markdown => report::markdown(&findings, &stats),
                Format::Github => report::github(&findings),
                Format::Sarif => report::sarif(&findings),
            };
            match output {
                Some(p) => {
                    std::fs::write(&p, format!("{}\n", body.trim_end())).map_err(|e| format!("cannot write {}: {e}", p.display()))?
                }
                None if !body.is_empty() => println!("{}", body.trim_end()),
                None => {}
            }
            let failed = threshold.is_some_and(|t| findings.iter().any(|f| f.severity >= t));
            let _ = rule; // keep the import used in all cfgs
            Ok(u8::from(failed))
        }
    }
}
