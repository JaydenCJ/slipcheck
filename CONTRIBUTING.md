# Contributing to slipcheck

Thanks for your interest in improving slipcheck. Issues, discussions and pull requests are all welcome.

## Getting started

Prerequisites: Rust 1.75 or newer (stable toolchain).

```bash
git clone https://github.com/JaydenCJ/slipcheck.git
cd slipcheck
cargo build
cargo test
bash scripts/smoke.sh
```

`scripts/smoke.sh` exercises the compiled binary end to end against the committed hostile fixtures (traversal tar, symlink-escape tar, setuid tar, name-smuggling zip) plus a tarball created by the system `tar`, and asserts on findings and exit codes. It finishes in well under a minute and must print `SMOKE OK`.

## Before you open a pull request

1. `cargo fmt` — formatting is enforced.
2. `cargo clippy --all-targets -- -D warnings` — clippy must be clean.
3. `cargo test` — unit tests and the CLI integration tests must pass.
4. `bash scripts/smoke.sh` — the smoke test must print `SMOKE OK`.
5. Add tests for behavior changes. Detection logic lives in pure modules (`paths`, `audit`, `tar`, `zip`, `gzip`, `inflate`, `format`) that never touch the filesystem; please keep it that way. New hostile-archive shapes belong in `src/testkit.rs` builders or as tiny committed fixtures under `examples/fixtures/`.

## Ground rules

- Keep dependencies minimal. slipcheck currently has **zero** runtime dependencies — including its own DEFLATE decompressor — and an archive auditor must not carry its own supply chain; adding a dependency needs a very strong justification in the PR description.
- slipcheck only ever reads. No network calls, no telemetry, and never a write, chmod or extraction of the scanned archive.
- Fail closed: when metadata cannot be decoded (encrypted symlink target, oversized link, corrupt local header), the answer is a finding, never a silent pass — and malformed input must produce a typed error, never a panic.
- Determinism first: tests build archive bytes from the wire format up, use temp dirs, and may not depend on wall-clock time, locale or the host filesystem's case sensitivity.
- Code comments and doc comments are written in English.
- Compatibility first: parse what real tools emit (GNU/PAX tar quirks, ZIP64, DOS-made zip entries) rather than only the tidy spec subset.

## Reporting bugs

Please include your `slipcheck --version` output, the `slipcheck scan --json` record for the archive, and — if at all possible — the smallest archive that reproduces the problem (or the `python3`/`tar` commands to rebuild it). False negatives are treated as security bugs; see below.

## Security

If you find an archive that slipcheck wrongly reports as clean (a false negative), please do not open a public issue. Use GitHub's private vulnerability reporting on this repository instead.
