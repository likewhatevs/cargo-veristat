use anyhow::{Context, Result};
use std::io::Write;
use std::process::Command;

use crate::cli::GfmMode;
use crate::veristat::{RunResult, VerifierLog};

const TRUNCATION_THRESHOLD: usize = 40;
const TRUNCATION_CONTEXT: usize = 20;

pub(crate) struct SystemInfo {
    pub kernel: Option<String>,
    pub package_commits: Vec<(String, String)>, // (package_name, short_hash)
}

impl SystemInfo {
    pub(crate) fn detect(packages: &[String]) -> Self {
        let kernel = Command::new("uname")
            .arg("-a")
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());

        let mut package_commits = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for pkg in packages {
            if !seen.insert(pkg.clone()) {
                continue;
            }
            if let Some(hash) = git_short_head() {
                package_commits.push((pkg.clone(), hash));
            }
        }

        SystemInfo {
            kernel,
            package_commits,
        }
    }

    #[cfg(test)]
    fn new(kernel: Option<&str>, commits: &[(&str, &str)]) -> Self {
        SystemInfo {
            kernel: kernel.map(|s| s.to_string()),
            package_commits: commits
                .iter()
                .map(|(p, h)| (p.to_string(), h.to_string()))
                .collect(),
        }
    }
}

fn git_short_head() -> Option<String> {
    Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
}

fn escape_pipe(s: &str) -> String {
    s.replace('|', "\\|")
}

/// Truncate a verifier log: top N + "... (M lines omitted) ..." + bottom N.
fn truncate_log(log: &str) -> String {
    let lines: Vec<&str> = log.lines().collect();
    if lines.len() <= TRUNCATION_THRESHOLD {
        return log.to_string();
    }

    let omitted = lines.len() - 2 * TRUNCATION_CONTEXT;
    let mut out = String::new();
    for line in &lines[..TRUNCATION_CONTEXT] {
        out.push_str(line);
        out.push('\n');
    }
    out.push_str(&format!("... ({} lines omitted) ...\n", omitted));
    for (i, line) in lines[lines.len() - TRUNCATION_CONTEXT..].iter().enumerate() {
        out.push_str(line);
        if i < TRUNCATION_CONTEXT - 1 {
            out.push('\n');
        }
    }
    out
}

/// Write the GFM summary table.
fn write_summary_table(w: &mut impl Write, results: &[RunResult]) -> std::io::Result<()> {
    writeln!(w, "### Summary\n")?;
    writeln!(
        w,
        "| Package | Config | File | Program | Verdict | Total Insns |"
    )?;
    writeln!(
        w,
        "|---------|--------|------|---------|---------|-------------|"
    )?;

    for result in results {
        let pkg = &result.key.package;
        let config = result.key.config.as_deref().unwrap_or("\u{2014}"); // em-dash

        let file_name_idx = result.headers.iter().position(|h| h == "file_name");
        let prog_name_idx = result.headers.iter().position(|h| h == "prog_name");
        let verdict_idx = result.headers.iter().position(|h| h == "verdict");
        let total_insns_idx = result.headers.iter().position(|h| h == "total_insns");

        for record in &result.verdict.records {
            let file = file_name_idx.and_then(|i| record.get(i)).unwrap_or("?");
            // Strip path prefix to show just the filename
            let file = std::path::Path::new(file)
                .file_name()
                .and_then(|f| f.to_str())
                .unwrap_or(file);
            let prog = prog_name_idx.and_then(|i| record.get(i)).unwrap_or("?");
            let verdict_str = verdict_idx.and_then(|i| record.get(i)).unwrap_or("?");
            let total_insns = total_insns_idx.and_then(|i| record.get(i)).unwrap_or("?");

            let verdict_display = if verdict_str.to_lowercase() == "success" {
                ":white_check_mark: success".to_string()
            } else {
                ":boom: **failure**".to_string()
            };

            writeln!(
                w,
                "| {} | {} | {} | {} | {} | {} |",
                escape_pipe(pkg),
                escape_pipe(config),
                escape_pipe(file),
                escape_pipe(prog),
                verdict_display,
                escape_pipe(total_insns),
            )?;
        }
    }

    Ok(())
}

/// Write system info bullets.
fn write_system_info(w: &mut impl Write, info: &SystemInfo) -> std::io::Result<()> {
    if info.kernel.is_none() && info.package_commits.is_empty() {
        return Ok(());
    }
    writeln!(w)?;
    if let Some(ref kernel) = info.kernel {
        writeln!(w, "- **Kernel**: {}", kernel)?;
    }
    for (pkg, hash) in &info.package_commits {
        writeln!(w, "- **{} Commit**: {}", pkg, hash)?;
    }
    Ok(())
}

/// Write Verifier Errors section (truncated logs, <details open>).
fn write_verifier_errors(w: &mut impl Write, logs: &[VerifierLog]) -> std::io::Result<()> {
    if logs.is_empty() {
        return Ok(());
    }

    writeln!(w, "\n### Verifier Errors\n")?;

    for log in logs {
        let line_count = log.log_body.lines().count();
        let config_display = log.key.config.as_deref().unwrap_or("\u{2014}");
        let label = format!("{} / {}", log.key.package, config_display);

        let truncated = truncate_log(&log.log_body);
        let is_truncated = line_count > TRUNCATION_THRESHOLD;

        let escaped_label = escape_html(&label);
        let summary = if is_truncated {
            format!(
                "<code>{}</code> \u{2014} {} (truncated, {} lines)",
                escape_html(&log.header),
                escaped_label,
                line_count
            )
        } else {
            format!(
                "<code>{}</code> \u{2014} {} ({} lines)",
                escape_html(&log.header),
                escaped_label,
                line_count
            )
        };

        writeln!(w, "<details open>")?;
        writeln!(w, "<summary>{}</summary>\n", summary)?;
        writeln!(w, "```")?;
        writeln!(w, "{}", truncated.trim_end())?;
        writeln!(w, "```\n")?;
        writeln!(w, "</details>\n")?;
    }

    Ok(())
}

/// Write Full Verifier Logs section (collapsed, only when any log > threshold).
fn write_full_logs(w: &mut impl Write, logs: &[VerifierLog]) -> std::io::Result<()> {
    let needs_full = logs
        .iter()
        .any(|l| l.log_body.lines().count() > TRUNCATION_THRESHOLD);
    if !needs_full {
        return Ok(());
    }

    writeln!(w, "\n### Full Verifier Logs\n")?;

    for log in logs {
        if log.log_body.lines().count() <= TRUNCATION_THRESHOLD {
            continue;
        }

        let line_count = log.log_body.lines().count();
        let config_display = log.key.config.as_deref().unwrap_or("\u{2014}");
        let label = format!("{} / {}", log.key.package, config_display);
        let summary = format!(
            "<code>{}</code> \u{2014} {} ({} lines)",
            escape_html(&log.header),
            escape_html(&label),
            line_count
        );

        writeln!(w, "<details>")?;
        writeln!(w, "<summary>{}</summary>\n", summary)?;
        writeln!(w, "```")?;
        writeln!(w, "{}", log.log_body.trim_end())?;
        writeln!(w, "```\n")?;
        writeln!(w, "</details>\n")?;
    }

    Ok(())
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Write the complete GFM report.
pub(crate) fn write_gfm_report(
    w: &mut impl Write,
    info: &SystemInfo,
    results: &[RunResult],
    logs: &[VerifierLog],
) -> std::io::Result<()> {
    writeln!(w, "## Verification Report\n")?;
    write_summary_table(w, results)?;
    write_system_info(w, info)?;
    write_verifier_errors(w, logs)?;
    write_full_logs(w, logs)?;
    Ok(())
}

/// Emit GitHub Actions workflow commands to stdout.
pub(crate) fn emit_workflow_commands(
    w: &mut impl Write,
    mode: GfmMode,
    results: &[RunResult],
) -> std::io::Result<()> {
    for result in results {
        let label = result.key.to_string();
        let prog_count = result.verdict.records.len();

        let total_insns_idx = result.headers.iter().position(|h| h == "total_insns");
        let total_insns: u64 = total_insns_idx
            .map(|idx| {
                result
                    .verdict
                    .records
                    .iter()
                    .filter_map(|r| r.get(idx).and_then(|v| v.parse::<u64>().ok()))
                    .sum()
            })
            .unwrap_or(0);

        if result.verdict.failed {
            // Collect failing program names
            let verdict_idx = result.headers.iter().position(|h| h == "verdict");
            let prog_name_idx = result.headers.iter().position(|h| h == "prog_name");
            let failed_progs: Vec<&str> = result
                .verdict
                .records
                .iter()
                .filter(|r| {
                    verdict_idx
                        .and_then(|i| r.get(i))
                        .is_some_and(|v| v.to_lowercase() != "success")
                })
                .filter_map(|r| prog_name_idx.and_then(|i| r.get(i)))
                .collect();

            let msg = if failed_progs.len() == 1 {
                format!("FAIL \u{2014} {} failed verification", failed_progs[0])
            } else {
                format!(
                    "FAIL \u{2014} {} programs failed verification",
                    failed_progs.len()
                )
            };
            writeln!(w, "::error title={}::{}", label, msg)?;
        } else {
            let msg = format!(
                "PASS \u{2014} {} programs, {} total insns",
                prog_count, total_insns
            );
            match mode {
                GfmMode::Full => {
                    writeln!(w, "::notice title={}::{}", label, msg)?;
                }
                GfmMode::ErrOnly => {
                    writeln!(w, "::debug::{}: {}", label, msg)?;
                }
                GfmMode::Off => {}
            }
        }
    }
    Ok(())
}

/// Write GFM report to stderr and workflow commands to stdout.
pub(crate) fn report_gfm(mode: GfmMode, results: &[RunResult], logs: &[VerifierLog]) -> Result<()> {
    let mut seen = std::collections::HashSet::new();
    let packages: Vec<String> = results
        .iter()
        .filter_map(|r| {
            if seen.insert(r.key.package.clone()) {
                Some(r.key.package.clone())
            } else {
                None
            }
        })
        .collect();
    let info = SystemInfo::detect(&packages);

    let mut stderr = std::io::stderr().lock();
    write_gfm_report(&mut stderr, &info, results, logs)
        .context("Failed to write GFM report to stderr")?;

    let mut stdout = std::io::stdout().lock();
    emit_workflow_commands(&mut stdout, mode, results)
        .context("Failed to write workflow commands")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::veristat::{PackageVerdict, RunKey};

    fn make_headers(cols: &[&str]) -> csv::StringRecord {
        let mut rec = csv::StringRecord::new();
        for col in cols {
            rec.push_field(col);
        }
        rec
    }

    fn make_record(fields: &[&str]) -> csv::StringRecord {
        let mut rec = csv::StringRecord::new();
        for f in fields {
            rec.push_field(f);
        }
        rec
    }

    fn make_result(
        pkg: &str,
        config: Option<&str>,
        records: Vec<(&str, &str, &str, &str)>, // (file, prog, verdict, total_insns)
    ) -> RunResult {
        let mut failed = false;
        let csv_records: Vec<csv::StringRecord> = records
            .iter()
            .map(|(file, prog, verdict, insns)| {
                if verdict.to_lowercase() != "success" {
                    failed = true;
                }
                make_record(&[file, prog, verdict, insns])
            })
            .collect();

        RunResult {
            key: RunKey {
                package: pkg.to_string(),
                config: config.map(|s| s.to_string()),
            },
            headers: make_headers(&["file_name", "prog_name", "verdict", "total_insns"]),
            verdict: PackageVerdict {
                records: csv_records,
                failed,
            },
            objects: Vec::new(),
            globals_path: None,
        }
    }

    fn make_log(pkg: &str, config: Option<&str>, header: &str, body: &str) -> VerifierLog {
        VerifierLog {
            key: RunKey {
                package: pkg.to_string(),
                config: config.map(|s| s.to_string()),
            },
            header: header.to_string(),
            log_body: body.to_string(),
        }
    }

    fn output_string(f: impl FnOnce(&mut Vec<u8>) -> std::io::Result<()>) -> String {
        let mut buf = Vec::new();
        f(&mut buf).unwrap();
        String::from_utf8(buf).unwrap()
    }

    // --- Summary table tests ---

    #[test]
    fn gfm_summary_table_columns() {
        let results = vec![make_result(
            "scx_layered",
            Some("(baseline)"),
            vec![("bpf.bpf.o", "main_prog", "success", "1234")],
        )];
        let out = output_string(|w| write_summary_table(w, &results));

        assert!(out.contains("| Package | Config | File | Program | Verdict | Total Insns |"));
        assert!(out.contains("| scx_layered | (baseline) | bpf.bpf.o | main_prog | :white_check_mark: success | 1234 |"));
    }

    #[test]
    fn gfm_summary_config_none_shows_dash() {
        let results = vec![make_result(
            "scx_rusty",
            None,
            vec![("bpf.bpf.o", "prog", "success", "100")],
        )];
        let out = output_string(|w| write_summary_table(w, &results));

        // em-dash
        assert!(out.contains("| scx_rusty | \u{2014} |"));
    }

    #[test]
    fn gfm_summary_failure_display() {
        let results = vec![make_result(
            "scx_layered",
            Some("8_layers"),
            vec![("bpf.bpf.o", "bad_prog", "failure", "5678")],
        )];
        let out = output_string(|w| write_summary_table(w, &results));

        assert!(out.contains(":boom: **failure**"));
    }

    // --- System info tests ---

    #[test]
    fn gfm_system_info_bullets() {
        let info = SystemInfo::new(
            Some("Linux ripper 6.12.0-gabc1234 #1 SMP"),
            &[("scx_layered", "def5678")],
        );
        let out = output_string(|w| write_system_info(w, &info));

        assert!(out.contains("- **Kernel**: Linux ripper 6.12.0-gabc1234 #1 SMP"));
        assert!(out.contains("- **scx_layered Commit**: def5678"));
    }

    #[test]
    fn gfm_system_info_package_name_in_commit_label() {
        let info = SystemInfo::new(None, &[("scx_bpfland", "abc1234")]);
        let out = output_string(|w| write_system_info(w, &info));

        assert!(out.contains("**scx_bpfland Commit**"));
    }

    #[test]
    fn gfm_system_info_omits_missing() {
        let info = SystemInfo::new(None, &[]);
        let out = output_string(|w| write_system_info(w, &info));

        assert!(out.is_empty());
    }

    // --- Report tests ---

    #[test]
    fn gfm_report_all_passing() {
        let results = vec![make_result(
            "scx_layered",
            Some("(baseline)"),
            vec![
                ("bpf.bpf.o", "prog1", "success", "100"),
                ("bpf.bpf.o", "prog2", "success", "200"),
            ],
        )];
        let info = SystemInfo::new(Some("Linux test"), &[]);
        let out = output_string(|w| write_gfm_report(w, &info, &results, &[]));

        assert!(out.contains("## Verification Report"));
        assert!(out.contains("### Summary"));
        assert!(!out.contains("### Verifier Errors"));
        assert!(!out.contains("### Full Verifier Logs"));
    }

    #[test]
    fn gfm_report_with_failures() {
        let results = vec![make_result(
            "scx_layered",
            Some("8_layers"),
            vec![("bpf.bpf.o", "bad_prog", "failure", "5678")],
        )];
        let logs = vec![make_log(
            "scx_layered",
            Some("8_layers"),
            "bad_prog",
            "0: R1=ctx() R10=fp0\nR0 invalid mem access\nverification time 42 usec",
        )];
        let info = SystemInfo::new(None, &[]);
        let out = output_string(|w| write_gfm_report(w, &info, &results, &logs));

        assert!(out.contains("### Verifier Errors"));
        assert!(out.contains("<details open>"));
        assert!(out.contains("bad_prog"));
        assert!(out.contains("R0 invalid mem access"));
    }

    #[test]
    fn gfm_report_full_logs_when_long() {
        let long_body: String = (0..50).map(|i| format!("line {}\n", i)).collect();
        let logs = vec![make_log(
            "scx_layered",
            Some("8_layers"),
            "bad_prog",
            &long_body,
        )];
        let results = vec![make_result(
            "scx_layered",
            Some("8_layers"),
            vec![("bpf.bpf.o", "bad_prog", "failure", "5678")],
        )];
        let info = SystemInfo::new(None, &[]);
        let out = output_string(|w| write_gfm_report(w, &info, &results, &logs));

        assert!(out.contains("### Full Verifier Logs"));
        assert!(out.contains("<details>\n<summary>"));
    }

    #[test]
    fn gfm_report_no_full_logs_when_short() {
        let short_body: String = (0..30).map(|i| format!("line {}\n", i)).collect();
        let logs = vec![make_log(
            "scx_layered",
            Some("8_layers"),
            "bad_prog",
            &short_body,
        )];
        let results = vec![make_result(
            "scx_layered",
            Some("8_layers"),
            vec![("bpf.bpf.o", "bad_prog", "failure", "5678")],
        )];
        let info = SystemInfo::new(None, &[]);
        let out = output_string(|w| write_gfm_report(w, &info, &results, &logs));

        assert!(out.contains("### Verifier Errors"));
        assert!(!out.contains("### Full Verifier Logs"));
    }

    // --- Verifier log truncation tests ---

    #[test]
    fn verifier_log_truncation() {
        let lines: String = (0..100).map(|i| format!("line {}\n", i)).collect();
        let truncated = truncate_log(&lines);

        // Should have top 20 lines
        assert!(truncated.contains("line 0"));
        assert!(truncated.contains("line 19"));
        // Should have omission marker
        assert!(truncated.contains("... (60 lines omitted) ..."));
        // Should have bottom 20 lines
        assert!(truncated.contains("line 80"));
        assert!(truncated.contains("line 99"));
        // Should NOT have middle lines
        assert!(!truncated.contains("line 20\n"));
        assert!(!truncated.contains("line 79\n"));
    }

    #[test]
    fn verifier_log_short_shows_all() {
        let lines: String = (0..30).map(|i| format!("line {}\n", i)).collect();
        let result = truncate_log(&lines);

        assert_eq!(result, lines);
        assert!(!result.contains("omitted"));
    }

    #[test]
    fn verifier_log_exactly_threshold() {
        let lines: String = (0..40).map(|i| format!("line {}\n", i)).collect();
        let result = truncate_log(&lines);

        assert_eq!(result, lines);
        assert!(!result.contains("omitted"));
    }

    // --- Workflow command tests ---

    #[test]
    fn workflow_commands_full_passing() {
        let results = vec![make_result(
            "scx_layered",
            Some("(baseline)"),
            vec![
                ("bpf.bpf.o", "prog1", "success", "100"),
                ("bpf.bpf.o", "prog2", "success", "200"),
            ],
        )];
        let out = output_string(|w| emit_workflow_commands(w, GfmMode::Full, &results));

        assert!(out.contains("::notice title=scx_layered / (baseline)::PASS"));
        assert!(out.contains("2 programs"));
        assert!(out.contains("300 total insns"));
    }

    #[test]
    fn workflow_commands_erronly_passing() {
        let results = vec![make_result(
            "scx_layered",
            Some("(baseline)"),
            vec![("bpf.bpf.o", "prog1", "success", "100")],
        )];
        let out = output_string(|w| emit_workflow_commands(w, GfmMode::ErrOnly, &results));

        assert!(out.contains("::debug::scx_layered / (baseline): PASS"));
        assert!(!out.contains("::notice"));
    }

    #[test]
    fn workflow_commands_failure() {
        let results = vec![make_result(
            "scx_layered",
            Some("8_layers"),
            vec![("bpf.bpf.o", "bad_prog", "failure", "5678")],
        )];
        let out = output_string(|w| emit_workflow_commands(w, GfmMode::Full, &results));

        assert!(out.contains("::error title=scx_layered / 8_layers::FAIL"));
        assert!(out.contains("bad_prog failed verification"));
    }

    #[test]
    fn workflow_commands_failure_multiple_progs() {
        let results = vec![make_result(
            "scx_layered",
            Some("8_layers"),
            vec![
                ("bpf.bpf.o", "bad1", "failure", "100"),
                ("bpf.bpf.o", "bad2", "failure", "200"),
            ],
        )];
        let out = output_string(|w| emit_workflow_commands(w, GfmMode::Full, &results));

        assert!(out.contains("::error title=scx_layered / 8_layers::FAIL"));
        assert!(out.contains("2 programs failed verification"));
    }

    // --- Escape tests ---

    #[test]
    fn escape_pipe_in_table_cells() {
        assert_eq!(escape_pipe("foo|bar"), "foo\\|bar");
        assert_eq!(escape_pipe("no pipes"), "no pipes");
    }

    #[test]
    fn escape_pipe_in_summary_table() {
        let results = vec![make_result(
            "pkg|name",
            None,
            vec![("file|name.bpf.o", "prog|name", "success", "100")],
        )];
        let out = output_string(|w| write_summary_table(w, &results));

        assert!(out.contains("pkg\\|name"));
        assert!(out.contains("prog\\|name"));
    }
}
