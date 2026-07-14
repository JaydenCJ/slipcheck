//! Hand-rolled CLI: `scan`, `checks`, `help`, `version`. No parser
//! dependency; exit codes are the contract (0 = pass, 1 = findings at or
//! above `--fail-on`, 2 = usage or read/parse error).

use std::io::Read;

use crate::findings::{Check, Severity};
use crate::format::Format;
use crate::report::{self, ScanFailure};
use crate::scan::{self, ScanOptions};
use crate::VERSION;

const USAGE: &str = "\
slipcheck — audit archives for extraction hazards before extracting

USAGE:
    slipcheck <COMMAND> [OPTIONS]

COMMANDS:
    scan <ARCHIVE>...   Audit tar / tar.gz / zip archives ('-' reads stdin)
    checks              List every check with its id, severity and meaning
    help                Show this help
    version             Show version

SCAN OPTIONS:
    --json                Machine-readable report on stdout
    --quiet               No output; the exit code is the answer
    --fail-on <LEVEL>     Exit 1 threshold: critical (default), warning, never
    --allow <CHECK>       Suppress a check by id (repeatable)
    --format <FMT>        Force format: tar, tar.gz, zip (default: detect)
    --max-unpacked <N>    Decompression cap, e.g. 512M, 2G (default: 1G)

EXIT CODES:
    0   no findings at or above the --fail-on level
    1   findings at or above the --fail-on level
    2   usage error, unreadable file, or malformed archive
";

/// What `--fail-on` accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FailOn {
    Critical,
    Warning,
    Never,
}

#[derive(Debug)]
struct ScanArgs {
    paths: Vec<String>,
    json: bool,
    quiet: bool,
    fail_on: FailOn,
    opts: ScanOptions,
}

fn usage_error(message: &str) -> i32 {
    eprintln!("slipcheck: {message}");
    eprintln!("Run 'slipcheck help' for usage.");
    2
}

/// Parse sizes like `4096`, `64K`, `512M`, `2G` (binary units).
fn parse_size(text: &str) -> Option<usize> {
    if text.is_empty() {
        return None;
    }
    let (digits, factor) = match text.as_bytes()[text.len() - 1] {
        b'K' | b'k' => (&text[..text.len() - 1], 1usize << 10),
        b'M' | b'm' => (&text[..text.len() - 1], 1 << 20),
        b'G' | b'g' => (&text[..text.len() - 1], 1 << 30),
        _ => (text, 1),
    };
    let value: usize = digits.parse().ok()?;
    value.checked_mul(factor)
}

fn parse_scan_args(args: &[String]) -> Result<ScanArgs, String> {
    let mut parsed = ScanArgs {
        paths: Vec::new(),
        json: false,
        quiet: false,
        fail_on: FailOn::Critical,
        opts: ScanOptions::default(),
    };
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--json" => parsed.json = true,
            "--quiet" => parsed.quiet = true,
            "--fail-on" => {
                let value = iter.next().ok_or("--fail-on needs a value")?;
                parsed.fail_on = match value.as_str() {
                    "critical" => FailOn::Critical,
                    "warning" => FailOn::Warning,
                    "never" => FailOn::Never,
                    other => return Err(format!("unknown --fail-on level '{other}'")),
                };
            }
            "--allow" => {
                let value = iter.next().ok_or("--allow needs a check id")?;
                let check = Check::from_id(value)
                    .ok_or_else(|| format!("unknown check '{value}' (see 'slipcheck checks')"))?;
                parsed.opts.allow.push(check);
            }
            "--format" => {
                let value = iter.next().ok_or("--format needs a value")?;
                parsed.opts.format = Some(
                    Format::from_flag(value)
                        .ok_or_else(|| format!("unknown format '{value}' (tar, tar.gz, zip)"))?,
                );
            }
            "--max-unpacked" => {
                let value = iter.next().ok_or("--max-unpacked needs a size")?;
                parsed.opts.max_unpacked = parse_size(value)
                    .ok_or_else(|| format!("invalid size '{value}' (try 512M or 2G)"))?;
            }
            other if other.starts_with("--") => {
                return Err(format!("unknown option '{other}'"));
            }
            path => parsed.paths.push(path.to_string()),
        }
    }
    if parsed.paths.is_empty() {
        return Err("scan needs at least one archive path (or '-')".to_string());
    }
    Ok(parsed)
}

fn read_input(path: &str) -> Result<Vec<u8>, String> {
    if path == "-" {
        let mut data = Vec::new();
        std::io::stdin()
            .read_to_end(&mut data)
            .map_err(|e| format!("stdin: {e}"))?;
        return Ok(data);
    }
    std::fs::read(path).map_err(|e| format!("{path}: {e}"))
}

fn run_scan(args: &[String]) -> i32 {
    let parsed = match parse_scan_args(args) {
        Ok(parsed) => parsed,
        Err(message) => return usage_error(&message),
    };
    let mut reports = Vec::new();
    let mut failures: Vec<ScanFailure> = Vec::new();
    for path in &parsed.paths {
        let data = match read_input(path) {
            Ok(data) => data,
            Err(error) => {
                failures.push(ScanFailure {
                    path: path.clone(),
                    error,
                });
                continue;
            }
        };
        let display = if path == "-" {
            "(stdin)"
        } else {
            path.as_str()
        };
        match scan::scan_bytes(display, &data, &parsed.opts) {
            Ok(report) => reports.push(report),
            Err(error) => failures.push(ScanFailure {
                path: display.to_string(),
                error: error.to_string(),
            }),
        }
    }

    if parsed.json {
        if !parsed.quiet {
            emit(&format!("{}\n", report::json(&reports, &failures)));
        }
    } else if !parsed.quiet {
        let mut text = String::new();
        for archive in &reports {
            text.push_str(&report::human(archive));
        }
        text.push_str(&report::summary(&reports, &failures));
        text.push('\n');
        emit(&text);
    }
    if !parsed.json {
        // Errors always reach stderr, even under --quiet; in JSON mode
        // they are embedded in the document instead.
        for failure in &failures {
            eprintln!("slipcheck: {}: {}", failure.path, failure.error);
        }
    }

    if !failures.is_empty() {
        return 2;
    }
    let threshold = match parsed.fail_on {
        FailOn::Never => return 0,
        FailOn::Critical => Severity::Critical,
        FailOn::Warning => Severity::Warning,
    };
    let triggered = reports
        .iter()
        .any(|r| r.findings.iter().any(|f| f.severity >= threshold));
    if triggered {
        1
    } else {
        0
    }
}

fn run_checks() -> i32 {
    let mut table = format!("{:<18} {:<9} DESCRIPTION\n", "ID", "SEVERITY");
    for check in Check::ALL {
        table.push_str(&format!(
            "{:<18} {:<9} {}\n",
            check.id(),
            check.default_severity().label(),
            check.describe()
        ));
    }
    emit(&table);
    0
}

/// Write to stdout, ignoring broken pipes: `slipcheck ... | head` must
/// never turn into a crash — the exit code still reflects the scan.
fn emit(text: &str) {
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(text.as_bytes());
    let _ = out.flush();
}

/// Entry point: returns the process exit code.
pub fn run(args: &[String]) -> i32 {
    match args.first().map(String::as_str) {
        None | Some("help") | Some("--help") | Some("-h") => {
            emit(USAGE);
            if args.is_empty() {
                2
            } else {
                0
            }
        }
        Some("version") | Some("--version") | Some("-V") => {
            emit(&format!("slipcheck {VERSION}\n"));
            0
        }
        Some("scan") => run_scan(&args[1..]),
        Some("checks") => run_checks(),
        Some(other) => usage_error(&format!("unknown command '{other}'")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_size_accepts_binary_suffixes() {
        assert_eq!(parse_size("4096"), Some(4096));
        assert_eq!(parse_size("64K"), Some(64 << 10));
        assert_eq!(parse_size("512M"), Some(512 << 20));
        assert_eq!(parse_size("2g"), Some(2 << 30));
        assert_eq!(parse_size(""), None);
        assert_eq!(parse_size("12X"), None);
        assert_eq!(parse_size("M"), None);
    }

    #[test]
    fn scan_args_defaults_and_flags() {
        let args: Vec<String> = [
            "a.tar",
            "--json",
            "--fail-on",
            "warning",
            "--allow",
            "setuid",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let parsed = parse_scan_args(&args).unwrap();
        assert_eq!(parsed.paths, vec!["a.tar"]);
        assert!(parsed.json);
        assert_eq!(parsed.fail_on, FailOn::Warning);
        assert_eq!(parsed.opts.allow, vec![Check::Setuid]);
        assert_eq!(parsed.opts.max_unpacked, scan::DEFAULT_MAX_UNPACKED);
    }

    #[test]
    fn scan_args_reject_unknown_values() {
        let bad = |args: &[&str]| {
            let owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();
            parse_scan_args(&owned).unwrap_err()
        };
        assert!(bad(&["a.tar", "--fail-on", "sometimes"]).contains("--fail-on"));
        assert!(bad(&["a.tar", "--allow", "nope"]).contains("unknown check"));
        assert!(bad(&["a.tar", "--format", "rar"]).contains("unknown format"));
        assert!(bad(&["a.tar", "--frobnicate"]).contains("unknown option"));
        assert!(bad(&[]).contains("at least one archive"));
    }
}
