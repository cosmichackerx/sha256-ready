# Contributing

```bash
cargo test            # unit + integration tests (the sandbox tests need git >= 2.29)
cargo fmt --all
cargo clippy --all-targets -- -D warnings
```

Adding a rule: add a `RuleInfo` (id, severity, title, why, fix) and a pattern in `src/rules.rs`,
then add **positive and negative** unit tests. A new rule must not fire on literal 40-hex hashes
(pinned action SHAs, lock files) or on lines that already handle 64 characters.
False-positive reports with a minimal line of code are very welcome.
* Releasing: bump the version and the README pins in a PR, merge when green, then run **Actions > Release gate** with the new tag (for example `v1.2.3`) *before* you create the tag. The same check runs again on the tag, and a weekly job (`claims-latest.yml`) fails when the README pins an older release than the newest tag.
