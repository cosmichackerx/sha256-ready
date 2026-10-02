# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-10-02

### Added
- `sha256-ready scan`: 11 rules that find code assuming 40-character (SHA-1) Git object names:
  `hex40-pattern`, `hex-range-max-40`, `length-40`, `truncate-40`, `column-40`, `bytes-20`, `null-oid`,
  `empty-tree-sha1`, `abbrev-40`, `api-constant`, `sha1-object-hash`.
- Output formats: text, JSON, Markdown, GitHub annotations and SARIF 2.1.0.
- `sha256-ready sandbox -- <command>`: run any command in a throw-away repository created with
  `--object-format sha256` (exports `SANDBOX_HEAD`, `SANDBOX_PREVIOUS`, `SANDBOX_TAG`, `SANDBOX_OBJECT_FORMAT`).
- `sha256-ready rules [--explain ID]`.
- Suppressions: `sha256-ready: ignore` (same or previous line) and `sha256-ready: ignore-file` (first 20 lines).
- Findings in test/spec/fixture files are reported one severity level lower (`--strict-tests` disables this).
- Honours `.gitignore`; skips lockfiles, binaries and files over 1 MB.
- Composite GitHub Action (`action.yml`) that downloads a checksum-verified release binary.
- Release binaries for Linux (x86_64, aarch64), macOS (arm64, x86_64) and Windows (x86_64).
