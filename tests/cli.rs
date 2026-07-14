//! End-to-end tests against the compiled `slipcheck` binary, driven by
//! the committed fixture archives in `examples/fixtures/` (which this
//! suite therefore also validates). Everything is offline and
//! deterministic: fixtures are bytes in the repo, temp files are cleaned
//! up, exit codes are the contract under test.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_slipcheck")
}

fn fixture(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("examples/fixtures")
        .join(name);
    assert!(path.exists(), "missing fixture {name}");
    path.to_string_lossy().into_owned()
}

fn run(args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .output()
        .expect("failed to run slipcheck")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn version_matches_the_manifest() {
    let out = run(&["--version"]);
    assert!(out.status.success());
    assert_eq!(
        stdout(&out).trim(),
        format!("slipcheck {}", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn help_lists_commands_and_exit_codes() {
    let out = run(&["help"]);
    assert!(out.status.success());
    let text = stdout(&out);
    for needle in ["scan", "checks", "--fail-on", "--allow", "EXIT CODES"] {
        assert!(text.contains(needle), "help must mention '{needle}'");
    }
}

#[test]
fn no_arguments_is_a_usage_error() {
    let out = run(&[]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn unknown_command_is_a_usage_error() {
    let out = run(&["frobnicate"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("unknown command"));
}

#[test]
fn checks_command_lists_every_check_id() {
    let out = run(&["checks"]);
    assert!(out.status.success());
    let text = stdout(&out);
    for id in [
        "absolute-path",
        "traversal",
        "link-escape",
        "link-indirection",
        "setuid",
        "setgid",
        "world-writable",
        "special-file",
        "duplicate-path",
        "case-collision",
        "name-mismatch",
        "unpack-limit",
    ] {
        assert!(text.contains(id), "checks table must list '{id}'");
    }
}

#[test]
fn clean_archive_exits_zero() {
    let out = run(&["scan", &fixture("clean.tar.gz")]);
    assert_eq!(out.status.code(), Some(0));
    let text = stdout(&out);
    assert!(text.contains("tar.gz"));
    assert!(text.contains("clean"));
}

#[test]
fn traversal_fixture_fails_with_the_hostile_path_named() {
    let out = run(&["scan", &fixture("traversal.tar")]);
    assert_eq!(out.status.code(), Some(1));
    let text = stdout(&out);
    assert!(text.contains("CRITICAL"));
    assert!(text.contains("traversal"));
    assert!(text.contains("../../etc/cron.d/backdoor"));
}

#[test]
fn absolute_path_fixture_fails() {
    let out = run(&["scan", &fixture("absolute.tar")]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stdout(&out).contains("absolute-path"));
}

#[test]
fn symlink_escape_fixture_reports_link_and_write_through() {
    let out = run(&["scan", &fixture("symlink-escape.tar")]);
    assert_eq!(out.status.code(), Some(1));
    let text = stdout(&out);
    assert!(text.contains("link-escape"));
    assert!(text.contains("link-indirection"));
}

#[test]
fn sneaky_zip_reports_mismatch_smuggled_name_and_symlink() {
    let out = run(&["scan", &fixture("sneaky.zip")]);
    assert_eq!(out.status.code(), Some(1));
    let text = stdout(&out);
    assert!(text.contains("name-mismatch"));
    assert!(
        text.contains("../../evil.sh"),
        "the smuggled local name must be audited"
    );
    assert!(text.contains("link-escape"));
    assert!(text.contains("case-collision"));
}

#[test]
fn setuid_fixture_fails_and_allow_suppresses_it() {
    let out = run(&["scan", &fixture("setuid.tar")]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stdout(&out).contains("setuid"));

    let out = run(&["scan", &fixture("setuid.tar"), "--allow", "setuid"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(stdout(&out).contains("clean"));
}

#[test]
fn fail_on_warning_promotes_warnings_to_failures() {
    // clean.tar.gz has no warnings either, so build the contrast with
    // sneaky.zip: allow every critical check, leaving only warnings.
    let out = run(&[
        "scan",
        &fixture("sneaky.zip"),
        "--allow",
        "traversal",
        "--allow",
        "link-escape",
    ]);
    // Only warnings remain -> default threshold (critical) passes.
    assert_eq!(out.status.code(), Some(0));

    let out = run(&[
        "scan",
        &fixture("sneaky.zip"),
        "--allow",
        "traversal",
        "--allow",
        "link-escape",
        "--fail-on",
        "warning",
    ]);
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn fail_on_never_always_exits_zero_but_still_reports() {
    let out = run(&["scan", &fixture("traversal.tar"), "--fail-on", "never"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(stdout(&out).contains("CRITICAL"));
}

#[test]
fn json_output_is_structured_and_lists_findings() {
    let out = run(&["scan", &fixture("traversal.tar"), "--json"]);
    assert_eq!(out.status.code(), Some(1));
    let text = stdout(&out);
    assert!(text.contains("\"slipcheck\": \"0.1.0\""));
    assert!(text.contains("\"format\": \"tar\""));
    assert!(text.contains("\"check\": \"traversal\""));
    assert!(text.contains("\"critical\": 1"));
    // The hostile path contains no quotes here, but the document must
    // stay balanced regardless.
    assert_eq!(text.matches('{').count(), text.matches('}').count());
}

#[test]
fn quiet_mode_prints_nothing_but_keeps_the_exit_code() {
    let out = run(&["scan", &fixture("traversal.tar"), "--quiet"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stdout(&out).is_empty());
}

#[test]
fn stdin_scanning_with_dash() {
    let data = std::fs::read(fixture("clean.tar.gz")).unwrap();
    let mut child = Command::new(bin())
        .args(["scan", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(&data).unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(stdout(&out).contains("(stdin)"));
}

#[test]
fn multiple_archives_aggregate_and_any_failure_wins() {
    let out = run(&["scan", &fixture("clean.tar.gz"), &fixture("setuid.tar")]);
    assert_eq!(out.status.code(), Some(1));
    let text = stdout(&out);
    assert!(text.contains("2 archives scanned"));
}

#[test]
fn missing_file_is_exit_two_with_stderr() {
    let out = run(&["scan", "/nonexistent/archive.tar"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("/nonexistent/archive.tar"));
}

#[test]
fn garbage_input_is_exit_two_not_a_panic() {
    let dir = std::env::temp_dir().join(format!("slipcheck-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("garbage.bin");
    std::fs::write(&path, b"not an archive at all, just prose").unwrap();
    let out = run(&["scan", path.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("unrecognized format"));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn forced_format_flag_reaches_the_reader() {
    // Forcing zip on a tar file must fail cleanly with exit 2.
    let out = run(&["scan", &fixture("traversal.tar"), "--format", "zip"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("malformed archive"));
}

#[test]
fn max_unpacked_cap_turns_big_streams_into_unpack_limit() {
    let out = run(&["scan", &fixture("clean.tar.gz"), "--max-unpacked", "1K"]);
    // The clean fixture inflates past 1 KiB (tar blocks are 512 bytes
    // each), so the bomb guard trips: exit 1, unpack-limit finding.
    assert_eq!(out.status.code(), Some(1));
    assert!(stdout(&out).contains("unpack-limit"));
}
