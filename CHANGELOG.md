# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-07-13

### Added

- Path audit: absolute names (leading separator, Windows drive letters, UNC), `..` traversal with full component-walk normalization (catches `a/../../b` round-trips that counting checks miss), and backslash-as-separator handling so Windows-only escapes are flagged everywhere.
- Symlink engine: targets resolved relative to the link's own directory, chains followed through every earlier in-archive link (with a loop guard), and later entries that write *through* a planted symlink flagged as `link-indirection` — the two-step zip-slip variant that pure name checks miss.
- Hard-link audit with archive-root-relative target semantics, plus setuid/setgid/world-writable mode bits, device nodes, fifos, duplicate paths and case-insensitive collisions.
- tar reader: v7, ustar (prefix field), GNU long names/links and base-256 sizes, PAX `path`/`linkpath`/`size` records (hostile PAX overrides are audited, not trusted), header checksum verification in both unsigned and signed conventions.
- zip reader: central-directory driven with ZIP64 support, unix mode extraction from external attributes, symlink target decoding (stored and deflate, capped at 4 KiB), and local-header cross-checking — a name smuggled into the local header is both reported (`name-mismatch`) and audited itself.
- In-tree DEFLATE decompressor (stored, fixed and dynamic Huffman) and gzip container reader with CRC-32/ISIZE verification and multi-member support, keeping the crate std-only.
- Bomb guard: every decompression is capped by `--max-unpacked` (default 1 GiB); exceeding it is a critical `unpack-limit` finding, not a crash.
- CLI: `scan` (files or stdin via `-`, multiple archives, `--json`, `--quiet`, `--fail-on critical|warning|never`, repeatable `--allow`, `--format`, `--max-unpacked`) and `checks` (the reference table of all twelve checks); exit codes 0/1/2 as the CI contract.
- Format detection by magic bytes only — gzip and zip signatures, ustar magic, and first-header checksum validation for pre-POSIX tars.
- Test suite: 96 unit tests, 21 CLI integration tests against the compiled binary (driven by the committed hostile fixtures in `examples/fixtures/`), and `scripts/smoke.sh`.

[0.1.0]: https://github.com/JaydenCJ/slipcheck/releases/tag/v0.1.0
