# sha256-ready

**Find code that assumes a Git commit hash is 40 characters, before Git 3.0 makes SHA-256 repositories the default.**

[![CI](https://github.com/cosmichackerx/sha256-ready/actions/workflows/ci.yml/badge.svg)](https://github.com/cosmichackerx/sha256-ready/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

`sha256-ready` is a single-binary CLI (Rust) and GitHub Action that audits a source tree for the code that
breaks when Git object names change from 40 hex characters (SHA-1) to 64 (SHA-256): the `^[0-9a-f]{40}$`
regular expressions, `len(sha) == 40` checks, `cut -c1-40` and `[:40]` truncations, `VARCHAR(40)` and
`char(40)` columns, `0000000000000000000000000000000000000000` null-object-id comparisons in hooks and CI
scripts, hard-coded empty-tree ids and `GIT_OID_HEXSZ`-style constants. It also has a **sandbox** that runs any command in a
throw-away `git init --object-format=sha256` repository, so you can see whether your hook, release script
or test suite survives a SHA-256 repo.

## Why now

The Git project plans to switch the default object format of new repositories from SHA-1 to SHA-256 in Git 3.0
(see [`Documentation/BreakingChanges`](https://git-scm.com/docs/BreakingChanges)). Hosting platforms, tools and
libraries have supported SHA-256 repositories to very different degrees, and most application code and CI
glue was written when "a commit hash is 40 hex characters" was always true. Nothing flags those assumptions
until the first SHA-256 repository reaches the pipeline, and then they fail silently (a truncated hash that no
longer resolves, a regex that never matches, a column that rejects the insert).

## Install

```bash
# from source (Rust 1.85+)
cargo install --git https://github.com/cosmichackerx/sha256-ready

# or download a binary + checksum from the latest release
# https://github.com/cosmichackerx/sha256-ready/releases
```

Release binaries: Linux (x86_64, aarch64), macOS (arm64, x86_64), Windows (x86_64).

## Use

```bash
sha256-ready scan                       # scan the current directory (honours .gitignore)
sha256-ready scan src ci --fail-on warning
sha256-ready scan . --format sarif -o sha256-ready.sarif   # GitHub code scanning
sha256-ready scan . --format github     # ::error file=... annotations in Actions logs
sha256-ready rules --explain null-oid   # why it matters and how to fix it
sha256-ready sandbox -- ./scripts/release.sh
```

Exit codes: `0` nothing at or above `--fail-on` (default `error`), `1` findings, `2` usage error. `sandbox` returns the
exit code of the command it ran.

### Example output

Real output from a scan of [GitPython](https://github.com/gitpython-developers/GitPython) at commit `6306c5c`
(shallow clone, excerpt). These are places where it still assumes 40:

```text
git/objects/commit.py
    592:20  error   length-40          length compared with 40; SHA-256 names have 64 characters
             assert len(hexsha) == 40, "Invalid line: %s" % hexsha
git/refs/log.py
     44:37  error   hex40-pattern      pattern matches exactly 40 hex characters; SHA-256 names have 64
             _re_hexsha_only = re.compile(r"^[0-9A-Fa-f]{40}$")
    131:25  error   truncate-40        value cut at 40 characters; a SHA-256 name would be truncated silently
             oldhexsha = info[:40]
git/repo/fun.py
    178:34  error   hex-range-max-40   hex range ends at 40; SHA-256 names have 64 characters
             match = re.match(r"^.+-\d+-g([0-9A-Fa-f]{4,40})(?:-dirty)?$", name)
git/diff.py
     86:17  warning empty-tree-sha1    SHA-1 id of the empty tree/blob hard-coded; it differs in SHA-256 repositories
             NULL_TREE_SHA = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
    265:22  warning abbrev-40          --abbrev=40 asks for the full SHA-1 length only; use --no-abbrev
             args.append("--abbrev=40")  # We need full shas.

66 finding(s): 10 error, 48 warning, 8 info in 303 file(s) scanned.
```

Sandbox, on a machine whose default is still SHA-1:

```text
$ sha256-ready sandbox -- sh -c 'echo "HEAD=$(git rev-parse HEAD)"'
sha256-ready: sandbox repository (sha256) at /tmp/sha256-ready-XDDhNF
sha256-ready: HEAD = ab6635bf3d5e682e13223e86372588863935f6d503f7394a2cead083af2d34f5 (64 characters)
HEAD=ab6635bf3d5e682e13223e86372588863935f6d503f7394a2cead083af2d34f5
sha256-ready: command succeeded against a sha256 repository
```

The command runs with the sandbox repository as its working directory and these variables set:
`SHA256_READY_SANDBOX`, `SANDBOX_OBJECT_FORMAT`, `SANDBOX_HEAD`, `SANDBOX_PREVIOUS` (the commit before HEAD) and
`SANDBOX_TAG` (`v0.0.1`). Add `--keep` to keep the directory, `--commits N` for more history, and
`--object-format sha1` to compare.

## Rules

| Rule | Severity | Finds |
| --- | --- | --- |
| `hex40-pattern` | error | `[0-9a-f]{40}`, `[[:xdigit:]]{40}` and friends |
| `hex-range-max-40` | error | `[0-9a-f]{7,40}` (abbreviation patterns capped at 40) |
| `length-40` | error/warning | `len(sha) == 40`, `${#rev} -eq 40`, `hash.length !== 40`, `.len() == 40` |
| `truncate-40` | error | `cut -c1-40`, `[:40]`, `substring(0, 40)`, `%.40s`, `${sha:0:40}` |
| `column-40` | error | `VARCHAR(40)`, `char(40)`, `BINARY(20)`, `maxLength: 40` next to commit/hash/oid names |
| `bytes-20` | warning | `unsigned char id[20]`, `[u8; 20]`, `new byte[20]` object-id buffers |
| `null-oid` | error | 40 zeros (hook `old`/`new` revision checks, "branch deleted" markers) |
| `empty-tree-sha1` | warning | `4b825dc6…` (empty tree) and `e69de29b…` (empty blob) |
| `abbrev-40` | warning | `--abbrev=40`, `core.abbrev = 40` used to get "the full hash" |
| `api-constant` | warning | `GIT_OID_HEXSZ`, `GIT_OID_RAWSZ`, `GIT_SHA1_HEXSZ`, … |
| `sha1-object-hash` | warning | hand-rolled `sha1("blob <size>\0" + data)` |

`sha256-ready rules --explain <id>` prints the reason and the suggested fix for each rule.

### What it deliberately does *not* flag

- A literal 40-hex hash (`uses: actions/checkout@<sha>`, lockfile entries, test vectors): that is data, not an assumption.
- Lines that already mention 64 (`{64}|{40}`, `in (40, 64)`): they support both on purpose.
- Length/truncation checks on lines that have nothing to do with hashes (`len(title) == 40`).
- Literals labelled SHA-1 on the same line (`NULL_SHA1`, `GIT_OID_SHA1_HEXZERO`) are reported as `info`, not errors.
- Findings in tests, specs and fixtures are reported **one level lower**; use `--strict-tests` to keep full severity.

Silence a line with `# sha256-ready: ignore` (same or previous line, any comment style), or a file with
`sha256-ready: ignore-file` in its first 20 lines. Use `--exclude 'vendor/**'` for paths.

## GitHub Action

```yaml
name: sha256-ready
on: [pull_request]
permissions:
  contents: read
  security-events: write   # only for the SARIF upload
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: cosmichackerx/sha256-ready@v0.1.0
        with:
          fail-on: error            # error | warning | info | never
          format: github            # annotations on the PR diff
          exclude: |
            vendor/**
          sarif-file: sha256-ready.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: sha256-ready.sarif
```

The action downloads the release binary for the runner and verifies its SHA-256 checksum before running it.
`version: source` builds from the action checkout instead (this is what the repository's own CI uses).

## Measured on real repositories

Shallow clones (depth 1) of public projects on 2026-10-02, default settings. "Errors" were all reviewed by hand;
every one is a real 40-character assumption (some are intentional for a SHA-1-only protocol, e.g. Azure DevOps'
all-zero "delete branch" id, so treat them as review items rather than bugs).

| Repository | Commit | Errors | Warnings | Info |
| --- | --- | ---: | ---: | ---: |
| gitpython-developers/GitPython | `6306c5c` | 10 | 48 | 8 |
| dependabot/dependabot-core | `2cf1d5e` | 27 | 20 | 0 |
| go-gitea/gitea | `bea6fca` | 15 | 39 | 2 |
| renovatebot/renovate | `ae4be16` | 8 | 7 | 8 |
| jenkinsci/git-plugin | `5c3ffb2` | 3 | 8 | 1 |
| orhun/git-cliff | `60e0be9` | 2 | 0 | 2 |
| gitoxide (GitoxideLabs) | `8f1280f` | 4 | 93 | 195 |
| go-git/go-git | `fedc50f` | 1 | 66 | 35 |
| commitizen-tools/commitizen | `642b8be` | 1 | 0 | 0 |
| libgit2/libgit2 | `0551dfd` | 0 | 234 | 114 |
| libgit2/pygit2 | `13849c7` | 0 | 29 | 4 |
| pre-commit, semantic-release, release-it, husky, lefthook, gitlint | various | 0 | 0 | 0 |

Libraries that already abstract the object format (libgit2, gitoxide, go-git) produce mostly warnings and info
on SHA-1 constants and test data. Application code that merely *consumes* hashes (dependabot-core, gitea, renovate)
has the real errors. These numbers say nothing about the quality of those projects: the scan is a heuristic and the
list above is a snapshot, not an issue report. No issues or pull requests were opened against them.

## Limits

- It is a line-based heuristic, not a parser: it cannot see a 40 that arrives through a constant defined elsewhere,
  or a hash length computed at run time. Treat a clean scan as "no obvious assumptions", not as proof.
- `sandbox` needs `git` 2.29 or newer on `PATH`.
- Built-in rules only (no custom rule files yet, see the roadmap issues).

## Development

```bash
cargo test
cargo clippy --all-targets -- -D warnings
```

See [CONTRIBUTING.md](CONTRIBUTING.md). MIT licensed, no telemetry, no network access.

<sub>Keywords: Git 3.0, SHA-256, sha256 object format, SHA-1 to SHA-256 migration, 40 hex characters, commit hash length, `object-format`, `[0-9a-f]{40}`, varchar(40), null oid, pre-receive hook, CI audit, code scanning, SARIF.</sub>
