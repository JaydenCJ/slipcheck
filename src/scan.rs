//! Orchestration: bytes in, audited report out. Detects the format,
//! decodes entries with the right reader and hands everything to the
//! auditor. One archive = one [`ArchiveReport`].

use std::fmt;

use crate::audit::Auditor;
use crate::findings::{Check, Finding, Severity};
use crate::format::{self, Format};
use crate::gzip::{self, GzipError};
use crate::inflate::InflateError;
use crate::{tar, zip};

/// Default cap on decompressed bytes: 1 GiB.
pub const DEFAULT_MAX_UNPACKED: usize = 1 << 30;

#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Force a format instead of magic-byte detection.
    pub format: Option<Format>,
    /// Checks suppressed via `--allow`.
    pub allow: Vec<Check>,
    /// Cap on total decompressed bytes (bomb guard).
    pub max_unpacked: usize,
}

impl Default for ScanOptions {
    fn default() -> ScanOptions {
        ScanOptions {
            format: None,
            allow: Vec::new(),
            max_unpacked: DEFAULT_MAX_UNPACKED,
        }
    }
}

/// The audited result for one archive.
#[derive(Debug)]
pub struct ArchiveReport {
    pub path: String,
    pub format: Format,
    pub entries: usize,
    pub findings: Vec<Finding>,
}

impl ArchiveReport {
    pub fn count(&self, severity: Severity) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == severity)
            .count()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanError {
    /// The bytes match no supported format.
    UnknownFormat,
    /// The archive is structurally broken; the string names how.
    Malformed(String),
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanError::UnknownFormat => {
                write!(f, "unrecognized format (tar, tar.gz and zip are supported)")
            }
            ScanError::Malformed(detail) => write!(f, "malformed archive: {detail}"),
        }
    }
}

/// Scan one archive held in memory.
pub fn scan_bytes(name: &str, data: &[u8], opts: &ScanOptions) -> Result<ArchiveReport, ScanError> {
    let detected = match opts.format {
        Some(forced) => forced,
        None => format::detect(data).ok_or(ScanError::UnknownFormat)?,
    };
    let (entries, pre_findings) = match detected {
        Format::Tar => {
            let entries =
                tar::read_entries(data).map_err(|e| ScanError::Malformed(e.to_string()))?;
            (entries, Vec::new())
        }
        Format::TarGz => match gzip::decompress(data, opts.max_unpacked) {
            Ok(inner) => {
                // A .gz of something that is not a tarball must not pass
                // as a "clean tar.gz with zero entries".
                let all_zero = inner.iter().all(|&b| b == 0);
                if !all_zero && format::detect(&inner) != Some(Format::Tar) {
                    return Err(ScanError::Malformed(
                        "gzip payload is not a tar archive".to_string(),
                    ));
                }
                let entries = tar::read_entries(&inner)
                    .map_err(|e| ScanError::Malformed(format!("inner tar: {e}")))?;
                (entries, Vec::new())
            }
            Err(GzipError::Inflate(InflateError::OutputLimit)) => {
                // Not an error: this is exactly what the bomb guard is
                // for, and it must fail the scan, not crash it.
                let finding = Finding::critical(
                    Check::UnpackLimit,
                    name,
                    format!(
                        "stream inflates past the {} byte cap; possible decompression bomb (raise with --max-unpacked to scan anyway)",
                        opts.max_unpacked
                    ),
                );
                let (findings, _) = Auditor::run(&[], vec![finding], &opts.allow);
                return Ok(ArchiveReport {
                    path: name.to_string(),
                    format: detected,
                    entries: 0,
                    findings,
                });
            }
            Err(other) => return Err(ScanError::Malformed(other.to_string())),
        },
        Format::Zip => zip::read_entries(data).map_err(|e| ScanError::Malformed(e.to_string()))?,
    };
    let (findings, entry_count) = Auditor::run(&entries, pre_findings, &opts.allow);
    Ok(ArchiveReport {
        path: name.to_string(),
        format: detected,
        entries: entry_count,
        findings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{gzip_wrap, TarBuilder, ZipBuilder};

    #[test]
    fn tar_gz_is_unwrapped_and_audited() {
        let tar = TarBuilder::new()
            .file("ok.txt", b"fine")
            .symlink("escape", "../outside")
            .finish();
        let report = scan_bytes("pkg.tgz", &gzip_wrap(&tar), &ScanOptions::default()).unwrap();
        assert_eq!(report.format, Format::TarGz);
        assert_eq!(report.entries, 2);
        assert_eq!(report.count(Severity::Critical), 1);
        assert_eq!(report.findings[0].check, Check::LinkEscape);
    }

    #[test]
    fn forced_format_overrides_detection() {
        let tar = TarBuilder::new().file("a.txt", b"x").finish();
        let opts = ScanOptions {
            format: Some(Format::Tar),
            ..ScanOptions::default()
        };
        assert!(scan_bytes("a.tar", &tar, &opts).is_ok());
        // Forcing zip on tar bytes must fail loudly, not misparse.
        let opts = ScanOptions {
            format: Some(Format::Zip),
            ..ScanOptions::default()
        };
        assert!(matches!(
            scan_bytes("a.tar", &tar, &opts),
            Err(ScanError::Malformed(_))
        ));
    }

    #[test]
    fn unknown_format_is_a_typed_error() {
        assert_eq!(
            scan_bytes("x", b"neither tar nor zip", &ScanOptions::default()).unwrap_err(),
            ScanError::UnknownFormat
        );
    }

    #[test]
    fn unpack_limit_becomes_a_critical_finding_not_a_crash() {
        let tar = TarBuilder::new().file("big.bin", &[0u8; 100_000]).finish();
        let opts = ScanOptions {
            max_unpacked: 1024,
            ..ScanOptions::default()
        };
        let report = scan_bytes("bomb.tgz", &gzip_wrap(&tar), &opts).unwrap();
        assert_eq!(report.count(Severity::Critical), 1);
        assert_eq!(report.findings[0].check, Check::UnpackLimit);
    }

    #[test]
    fn allow_list_reaches_the_auditor() {
        let zip = ZipBuilder::new()
            .file_mode("bin/tool", 0o4755, b"x")
            .finish();
        let opts = ScanOptions {
            allow: vec![Check::Setuid],
            ..ScanOptions::default()
        };
        let report = scan_bytes("pkg.zip", &zip, &opts).unwrap();
        assert!(report.findings.is_empty());
    }

    #[test]
    fn gzip_of_non_tar_bytes_is_malformed() {
        // A .gz of plain text must not pass as "clean tar.gz, 0 entries".
        let gz = gzip_wrap(b"a plain text file, not a tarball");
        let err = scan_bytes("x.gz", &gz, &ScanOptions::default()).unwrap_err();
        assert!(matches!(err, ScanError::Malformed(_)));
        // But a genuinely empty tarball (all-NUL end markers) is fine.
        let empty = gzip_wrap(&[0u8; 1024]);
        let report = scan_bytes("empty.tgz", &empty, &ScanOptions::default()).unwrap();
        assert_eq!(report.entries, 0);
        assert!(report.findings.is_empty());
    }
}
