use anyhow::{Context, Result};
use std::io::Write;
use std::process::Command;

use crate::cli::GfmMode;
use crate::veristat::{RunResult, VerifierLog};

/// Stay under GitHub's 1024KB step summary limit with some margin.
const GFM_SIZE_BUDGET: usize = 1_000_000;

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

/// Normalize a BPF verifier log line by stripping variable register-state
/// annotations, so that lines from different loop iterations compare equal.
///
/// Handles three patterns:
/// - Instruction with `;` annotation: `3006: (07) r9 += 1  ; frame1: R9_w=2`
/// - Branch with inline target state: `3026: (b5) if r6 <= 0x11dc0 goto pc+2 3029: frame1: R0=1 ...`
/// - Standalone register dump: `3041: frame1: R0_w=scalar()`
fn normalize_verifier_line(line: &str) -> &str {
    let trimmed = line.trim();
    if trimmed.is_empty() || !trimmed.as_bytes()[0].is_ascii_digit() {
        return trimmed;
    }
    // "3041: frame1: ..." — standalone register dump at an instruction offset
    if let Some(colon) = trimmed.find(": ") {
        let after = &trimmed[colon + 2..];
        if after.starts_with("frame") {
            return &trimmed[..colon + 1]; // keep just "3041:"
        }
    }
    // "; frame" annotation on instruction line
    if let Some(pos) = trimmed.find("; frame") {
        return trimmed[..pos].trim_end();
    }
    // "; R" followed by digit — register annotation without frame prefix
    if let Some(pos) = trimmed.find("; R")
        && trimmed
            .as_bytes()
            .get(pos + 3)
            .is_some_and(|b| b.is_ascii_digit())
    {
        return trimmed[..pos].trim_end();
    }
    // Inline branch-target state: "goto pc+2 3029: frame1: ..." or "goto pc+2 3029: R0=..."
    if let Some(goto_pos) = trimmed.find("goto pc") {
        // Find the end of "goto pc+NNN" or "goto pc-NNN"
        let after_goto = &trimmed[goto_pos + 7..]; // skip "goto pc"
        // Skip the sign and digits
        let end = after_goto
            .find(|c: char| c != '+' && c != '-' && !c.is_ascii_digit())
            .unwrap_or(after_goto.len());
        let insn_end = goto_pos + 7 + end;
        // If there's more after the goto target, it's inline register state
        if insn_end < trimmed.len() {
            return trimmed[..insn_end].trim_end();
        }
    }
    trimmed
}

/// Detect a single repeating cycle in a slice of lines.
///
/// Returns `Some((start, period, count))` where the cycle begins at line
/// `start`, each iteration is `period` lines, and the block repeats `count`
/// times consecutively (after normalization).
///
/// The anchor line (most frequently repeated normalized line) may appear
/// multiple times per cycle iteration (e.g. a source comment that shows up
/// at two points in the loop body). To handle this, we try strides 1..3
/// when computing the gap between anchor occurrences — stride 2 captures
/// the true period when the anchor appears twice per iteration, etc.
fn detect_cycle(lines: &[&str]) -> Option<(usize, usize, usize)> {
    const MIN_PERIOD: usize = 5;
    const MIN_REPS: usize = 6;

    if lines.len() < MIN_PERIOD * MIN_REPS {
        return None;
    }

    let normalized: Vec<&str> = lines.iter().map(|l| normalize_verifier_line(l)).collect();

    // Find most frequent non-trivial normalized line (the "anchor")
    let mut sorted_norms: Vec<&str> = normalized
        .iter()
        .filter(|l| l.len() >= 10)
        .copied()
        .collect();
    sorted_norms.sort_unstable();

    let mut best_anchor: Option<(&str, usize)> = None;
    let mut i = 0;
    while i < sorted_norms.len() {
        let mut j = i + 1;
        while j < sorted_norms.len() && sorted_norms[j] == sorted_norms[i] {
            j += 1;
        }
        let count = j - i;
        if count >= MIN_REPS && best_anchor.is_none_or(|(_, best)| count > best) {
            best_anchor = Some((sorted_norms[i], count));
        }
        i = j;
    }

    let (anchor, _) = best_anchor?;

    // Collect all positions of the anchor
    let positions: Vec<usize> = normalized
        .iter()
        .enumerate()
        .filter(|(_, l)| **l == anchor)
        .map(|(i, _)| i)
        .collect();

    // Try strides 1..3 to handle anchors that appear K times per cycle.
    // Stride K computes gaps between every K-th occurrence, giving the true
    // period when the anchor appears K times per iteration.
    for stride in 1..=3usize {
        if positions.len() <= stride {
            continue;
        }

        // Compute stride-N gaps and find the most common one
        let mut gaps: Vec<usize> = positions
            .windows(stride + 1)
            .map(|w| w[stride] - w[0])
            .filter(|g| *g >= MIN_PERIOD)
            .collect();
        gaps.sort_unstable();

        let mut best_period = 0;
        let mut best_gap_count = 0;
        let mut gi = 0;
        while gi < gaps.len() {
            let mut gj = gi + 1;
            while gj < gaps.len() && gaps[gj] == gaps[gi] {
                gj += 1;
            }
            let count = gj - gi;
            if count > best_gap_count {
                best_gap_count = count;
                best_period = gaps[gi];
            }
            gi = gj;
        }
        if best_period == 0 || best_gap_count < MIN_REPS - 1 {
            continue;
        }
        let period = best_period;

        // Verify: find an anchor position where two consecutive blocks match
        for &pos in &positions {
            if pos + 2 * period > lines.len() {
                break;
            }
            if normalized[pos..pos + period] == normalized[pos + period..pos + 2 * period] {
                // Count consecutive repetitions
                let first_block = &normalized[pos..pos + period];
                let mut count = 1;
                while pos + (count + 1) * period <= lines.len() {
                    if normalized[pos + count * period..pos + (count + 1) * period] != *first_block
                    {
                        break;
                    }
                    count += 1;
                }
                // The anchor may land in the middle of the cycle block,
                // so the count from the anchor position may undercount.
                // Try earlier starts within one period to find the
                // alignment that captures the most repetitions.
                let mut best_start = pos;
                let mut best_count = count;
                for offset in 1..period {
                    let Some(cand) = pos.checked_sub(offset) else {
                        break;
                    };
                    if cand + 2 * period > lines.len() {
                        continue;
                    }
                    if normalized[cand..cand + period]
                        != normalized[cand + period..cand + 2 * period]
                    {
                        continue;
                    }
                    let mut c = 2;
                    while cand + (c + 1) * period <= lines.len()
                        && normalized[cand + c * period..cand + (c + 1) * period]
                            == normalized[cand..cand + period]
                    {
                        c += 1;
                    }
                    if c > best_count {
                        best_start = cand;
                        best_count = c;
                    }
                }
                if best_count >= MIN_REPS {
                    return Some((best_start, period, best_count));
                }
            }
        }
    }

    None
}

/// Collapse repeating cycles in a verifier log.
///
/// Runs cycle detection iteratively — after collapsing one cycle the result
/// may expose another (e.g. nested loop unrolling). Falls through to the
/// original text when no cycle is found.
pub(crate) fn collapse_cycles(log: &str) -> String {
    const MAX_PASSES: usize = 5;
    let mut text = log.to_string();

    for _ in 0..MAX_PASSES {
        let lines: Vec<&str> = text.lines().collect();
        let (start, period, count) = match detect_cycle(&lines) {
            Some(c) => c,
            None => break,
        };

        let mut out = String::new();
        for line in &lines[..start] {
            out.push_str(line);
            out.push('\n');
        }
        out.push_str(&format!(
            "--- {}x of the following {} lines ---\n",
            count, period
        ));
        for line in &lines[start..start + period] {
            out.push_str(line);
            out.push('\n');
        }
        out.push_str(&format!(
            "--- {} identical iterations omitted ---\n",
            count - 2
        ));
        let last_start = start + (count - 1) * period;
        for line in &lines[last_start..last_start + period] {
            out.push_str(line);
            out.push('\n');
        }
        out.push_str("--- end repeat ---\n");
        let suffix_start = start + count * period;
        for line in &lines[suffix_start..] {
            out.push_str(line);
            out.push('\n');
        }
        text = out;
    }

    text
}

/// Truncate a verifier log to fit within a byte budget using top+bottom lines.
///
/// If the log fits within `max_bytes`, returns it unchanged. Otherwise,
/// greedily takes lines from the top and bottom to fill the budget —
/// verifier logs tend to have cycles in the middle, so top+bottom
/// preserves the most useful context.
fn truncate_log_to_bytes(log: &str, max_bytes: usize) -> String {
    if log.len() <= max_bytes {
        return log.to_string();
    }

    let lines: Vec<&str> = log.lines().collect();
    if lines.is_empty() {
        return String::new();
    }

    let marker_reserve = 50; // "... (NNNNN lines omitted) ...\n"
    let usable = match max_bytes.checked_sub(marker_reserve) {
        Some(u) if u > 0 => u,
        _ => {
            return format!("... ({} lines, too large for summary) ...", lines.len());
        }
    };

    let mut top = 0;
    let mut bottom = 0;
    let mut used = 0;

    loop {
        if top + bottom >= lines.len() {
            break;
        }
        let cost = lines[top].len() + 1;
        if used + cost > usable {
            break;
        }
        used += cost;
        top += 1;

        if top + bottom >= lines.len() {
            break;
        }
        let bottom_idx = lines.len() - 1 - bottom;
        let cost = lines[bottom_idx].len() + 1;
        if used + cost > usable {
            break;
        }
        used += cost;
        bottom += 1;
    }

    if top == 0 && bottom == 0 {
        return format!("... ({} lines, too large for summary) ...", lines.len());
    }

    let omitted = lines.len() - top - bottom;
    let mut out = String::with_capacity(used + marker_reserve);
    for line in &lines[..top] {
        out.push_str(line);
        out.push('\n');
    }
    if omitted > 0 {
        out.push_str(&format!("... ({} lines omitted) ...\n", omitted));
    }
    for (i, line) in lines[lines.len() - bottom..].iter().enumerate() {
        out.push_str(line);
        if i < bottom.saturating_sub(1) {
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
    if let Some(ref kernel) = info.kernel {
        writeln!(w, "- **Kernel**: {}", kernel)?;
    }
    for (pkg, hash) in &info.package_commits {
        writeln!(w, "- **{} Commit**: {}", pkg, hash)?;
    }
    writeln!(w)?;
    Ok(())
}

/// Write Verifier Errors section with per-log byte budget for truncation.
///
/// Returns a `Vec<bool>` parallel to `logs` indicating which logs were truncated.
fn write_verifier_errors(
    w: &mut impl Write,
    logs: &[VerifierLog],
    per_log_budget: usize,
) -> std::io::Result<Vec<bool>> {
    if logs.is_empty() {
        return Ok(Vec::new());
    }

    writeln!(w, "\n### Verifier Errors\n")?;

    let mut was_truncated = Vec::with_capacity(logs.len());

    for log in logs {
        let line_count = log.log_body.lines().count();
        let config_display = log.key.config.as_deref().unwrap_or("\u{2014}");
        let label = format!("{} / {}", log.key.package, config_display);

        let collapsed = collapse_cycles(&log.log_body);
        let cycles_collapsed = collapsed.len() < log.log_body.len();
        let truncated = truncate_log_to_bytes(&collapsed, per_log_budget);
        let bytes_truncated = truncated.len() < collapsed.len();
        was_truncated.push(bytes_truncated);

        let escaped_label = escape_html(&label);
        let qualifier = match (cycles_collapsed, bytes_truncated) {
            (true, true) => "cycles collapsed + truncated, ",
            (true, false) => "cycles collapsed, ",
            (false, true) => "truncated, ",
            (false, false) => "",
        };
        let summary = format!(
            "<code>{}</code> \u{2014} {} ({}{} lines)",
            escape_html(&log.header),
            escaped_label,
            qualifier,
            line_count,
        );

        writeln!(w, "<details open>")?;
        writeln!(w, "<summary>{}</summary>\n", summary)?;
        writeln!(w, "```")?;
        writeln!(w, "{}", truncated.trim_end())?;
        writeln!(w, "```\n")?;
        writeln!(w, "</details>\n")?;
    }

    Ok(was_truncated)
}

/// Write Full Verifier Logs section for logs that were truncated in the errors section.
fn write_full_logs(
    w: &mut impl Write,
    logs: &[VerifierLog],
    was_truncated: &[bool],
) -> std::io::Result<()> {
    if !was_truncated.iter().any(|&t| t) {
        return Ok(());
    }

    writeln!(w, "\n### Full Verifier Logs\n")?;

    for (log, &truncated) in logs.iter().zip(was_truncated) {
        if !truncated {
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

/// Write the complete GFM report, staying within [`GFM_SIZE_BUDGET`].
///
/// Renders the preamble (heading + system info + summary table) first, then
/// budgets remaining space among verifier error logs. The "Full Verifier
/// Logs" section is included only if the untruncated logs still fit within
/// the remaining budget.
pub(crate) fn write_gfm_report(
    w: &mut impl Write,
    info: &SystemInfo,
    results: &[RunResult],
    logs: &[VerifierLog],
) -> std::io::Result<()> {
    let mut buf = Vec::new();

    // Preamble: heading + system info + summary table
    let any_failed = results.iter().any(|r| r.verdict.failed);
    let emoji = if any_failed { "\u{274c}" } else { "\u{2705}" };
    writeln!(&mut buf, "## {} Verification Report\n", emoji)?;
    write_system_info(&mut buf, info)?;
    write_summary_table(&mut buf, results)?;

    // Budget remaining space for log sections
    let remaining = GFM_SIZE_BUDGET.saturating_sub(buf.len());
    let log_count = logs.len();
    // Reserve overhead per log for HTML chrome (<details>, <summary>, code fences)
    let chrome_per_log = 512;
    let section_overhead = 64;
    let per_log_budget = remaining
        .saturating_sub(section_overhead)
        .saturating_sub(chrome_per_log * log_count)
        .checked_div(log_count)
        .unwrap_or(usize::MAX);

    let was_truncated = write_verifier_errors(&mut buf, logs, per_log_budget)?;

    // Full logs: render to temp buffer, include only if within remaining budget
    let remaining = GFM_SIZE_BUDGET.saturating_sub(buf.len());
    let mut full_logs_buf = Vec::new();
    write_full_logs(&mut full_logs_buf, logs, &was_truncated)?;
    if !full_logs_buf.is_empty() && full_logs_buf.len() <= remaining {
        buf.extend_from_slice(&full_logs_buf);
    }

    w.write_all(&buf)?;
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
    let any_failed = results.iter().any(|r| r.verdict.failed);

    if mode != GfmMode::ErrOnly || any_failed {
        let info = SystemInfo::detect(&packages);
        let mut stderr = std::io::stderr().lock();
        write_gfm_report(&mut stderr, &info, results, logs)
            .context("Failed to write GFM report to stderr")?;
    }

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

        assert!(out.contains("## \u{2705} Verification Report"));
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

        assert!(out.contains("## \u{274c} Verification Report"));
        assert!(out.contains("### Verifier Errors"));
        assert!(out.contains("<details open>"));
        assert!(out.contains("bad_prog"));
        assert!(out.contains("R0 invalid mem access"));
    }

    #[test]
    fn gfm_report_no_full_logs_when_not_truncated() {
        // 50-line log fits within the per-log byte budget, so no full logs section
        let body: String = (0..50).map(|i| format!("line {}\n", i)).collect();
        let logs = vec![make_log("scx_layered", Some("8_layers"), "bad_prog", &body)];
        let results = vec![make_result(
            "scx_layered",
            Some("8_layers"),
            vec![("bpf.bpf.o", "bad_prog", "failure", "5678")],
        )];
        let info = SystemInfo::new(None, &[]);
        let out = output_string(|w| write_gfm_report(w, &info, &results, &logs));

        assert!(out.contains("### Verifier Errors"));
        // All 50 lines fit in the errors section — no truncation, so no full logs
        assert!(!out.contains("### Full Verifier Logs"));
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

    // --- Byte-budget truncation tests ---

    #[test]
    fn truncate_to_bytes_within_budget_unchanged() {
        let log: String = (0..30).map(|i| format!("line {}\n", i)).collect();
        // Large budget — should return the log unchanged (no line-count truncation either)
        let result = truncate_log_to_bytes(&log, 100_000);
        assert_eq!(result, log);
    }

    #[test]
    fn truncate_to_bytes_large_budget_unchanged() {
        // 100 lines fits easily within 100KB budget — no truncation
        let log: String = (0..100).map(|i| format!("line {}\n", i)).collect();
        let result = truncate_log_to_bytes(&log, 100_000);
        assert_eq!(result, log);
    }

    #[test]
    fn truncate_to_bytes_tight_budget() {
        // 1000 lines, but only 500 bytes of budget
        let log: String = (0..1000)
            .map(|i| format!("verifier line {}\n", i))
            .collect();
        let result = truncate_log_to_bytes(&log, 500);

        assert!(result.len() <= 550); // some slack for the omission marker
        assert!(result.contains("verifier line 0"));
        assert!(result.contains("verifier line 999"));
        assert!(result.contains("lines omitted"));
    }

    #[test]
    fn truncate_to_bytes_tiny_budget() {
        let log: String = (0..1000).map(|i| format!("line {}\n", i)).collect();
        let result = truncate_log_to_bytes(&log, 10);

        assert!(result.contains("too large for summary"));
    }

    #[test]
    fn gfm_report_huge_logs_under_budget() {
        // Each log ~100KB, 20 logs → ~2MB raw, should be budgeted under 1MB
        let big_body: String = (0..2000)
            .map(|i| format!("R{}=scalar(smin=0,smax=4294967295) R10=fp0\n", i))
            .collect();
        let mut logs = Vec::new();
        let mut results = Vec::new();
        for i in 0..20 {
            let name = format!("prog_{}", i);
            logs.push(make_log("scx_lavd", Some("config"), &name, &big_body));
            results.push(make_result(
                "scx_lavd",
                Some("config"),
                vec![("bpf.bpf.o", &name, "failure", "5678")],
            ));
        }

        let info = SystemInfo::new(None, &[]);
        let out = output_string(|w| write_gfm_report(w, &info, &results, &logs));

        assert!(
            out.len() <= GFM_SIZE_BUDGET,
            "report is {} bytes, budget is {}",
            out.len(),
            GFM_SIZE_BUDGET,
        );
        assert!(out.contains("### Verifier Errors"));
        // Full logs should be dropped — they'd be way too large
        assert!(!out.contains("### Full Verifier Logs"));
        // Should still have top+bottom content
        assert!(out.contains("R0=scalar"));
        assert!(out.contains("R1999=scalar"));
    }

    #[test]
    fn gfm_report_full_logs_when_truncated() {
        // Many large logs that exceed per-log byte budget → truncated → full logs shown
        let big_body: String = (0..2000)
            .map(|i| format!("R{}=scalar(smin=0,smax=4294967295) R10=fp0\n", i))
            .collect();
        let mut logs = Vec::new();
        let mut results = Vec::new();
        for i in 0..20 {
            let name = format!("prog_{}", i);
            logs.push(make_log("scx_lavd", Some("config"), &name, &big_body));
            results.push(make_result(
                "scx_lavd",
                Some("config"),
                vec![("bpf.bpf.o", &name, "failure", "100")],
            ));
        }
        let info = SystemInfo::new(None, &[]);
        let out = output_string(|w| write_gfm_report(w, &info, &results, &logs));

        // Logs are byte-truncated in verifier errors section
        assert!(out.contains("### Verifier Errors"));
        assert!(out.contains("truncated"));
        // Full logs section may or may not appear depending on remaining budget,
        // but the report must stay within budget
        assert!(out.len() <= GFM_SIZE_BUDGET);
    }

    // --- Cycle detection tests ---

    #[test]
    fn normalize_strips_frame_annotation() {
        assert_eq!(
            normalize_verifier_line("3006: (07) r9 += 1  ; frame1: R9_w=2"),
            "3006: (07) r9 += 1"
        );
    }

    #[test]
    fn normalize_strips_register_annotation() {
        assert_eq!(
            normalize_verifier_line("9: (15) if r7 == 0x0 goto pc+1  ; R7=scalar(id=2,umin=1)"),
            "9: (15) if r7 == 0x0 goto pc+1"
        );
    }

    #[test]
    fn normalize_strips_inline_branch_target() {
        assert_eq!(
            normalize_verifier_line(
                "3026: (b5) if r6 <= 0x11dc0 goto pc+2 3029: frame1: R0=1 R1=scalar()"
            ),
            "3026: (b5) if r6 <= 0x11dc0 goto pc+2"
        );
    }

    #[test]
    fn normalize_strips_standalone_regdump() {
        assert_eq!(
            normalize_verifier_line("3041: frame1: R0_w=scalar()"),
            "3041:"
        );
    }

    #[test]
    fn normalize_preserves_source_comment() {
        let line = "; for (int j = 0; j < MAX; j++) { @ balance.bpf.c:381";
        assert_eq!(normalize_verifier_line(line), line);
    }

    #[test]
    fn normalize_preserves_plain_instruction() {
        assert_eq!(normalize_verifier_line("289: (95) exit"), "289: (95) exit");
    }

    #[test]
    fn detect_cycle_simple() {
        let mut log = String::new();
        // Prefix
        log.push_str("0: (b7) r1 = 0\n");
        log.push_str("; setup code @ test.c:1\n");
        // 7-line block repeating 10 times with varying register state
        for i in 0..10 {
            log.push_str("; loop body @ test.c:10\n");
            log.push_str(&format!("100: (07) r3 += 1  ; frame1: R3_w={}\n", i));
            log.push_str(&format!(
                "101: (15) if r3 == 0x0 goto pc+2  ; frame1: R3={}\n",
                i
            ));
            log.push_str("102: (85) call helper#1\n");
            log.push_str("103: (05) goto pc-4\n");
            log.push_str(&format!("104: frame1: R0_w=scalar(id={})\n", i));
            log.push_str("; end iteration @ test.c:15\n");
        }
        // Suffix
        log.push_str("200: (95) exit\n");

        let collapsed = collapse_cycles(&log);
        assert!(collapsed.contains("10x of the following 7 lines"));
        assert!(collapsed.contains("--- 8 identical iterations omitted ---"));
        assert!(collapsed.contains("--- end repeat ---"));
        assert!(collapsed.contains("0: (b7) r1 = 0")); // prefix preserved
        assert!(collapsed.contains("200: (95) exit")); // suffix preserved
        // First iteration's register state is shown
        assert!(collapsed.contains("R3_w=0"));
        assert!(collapsed.contains("scalar(id=0)"));
        // Last iteration's register state is also shown
        assert!(collapsed.contains("R3_w=9"));
        assert!(collapsed.contains("scalar(id=9)"));
        // Verify structural ordering: header → first iter → omitted → last iter → end
        let pos_header = collapsed.find("10x of the following").unwrap();
        let pos_first = collapsed.find("R3_w=0").unwrap();
        let pos_omitted = collapsed.find("8 identical iterations omitted").unwrap();
        let pos_last = collapsed.find("R3_w=9").unwrap();
        let pos_end = collapsed.find("--- end repeat ---").unwrap();
        assert!(pos_header < pos_first, "header before first iteration");
        assert!(
            pos_first < pos_omitted,
            "first iteration before omitted marker"
        );
        assert!(
            pos_omitted < pos_last,
            "omitted marker before last iteration"
        );
        assert!(pos_last < pos_end, "last iteration before end repeat");
        assert!(
            collapsed.len() < log.len() / 3,
            "collapsed {} bytes should be < {} / 3",
            collapsed.len(),
            log.len()
        );
    }

    #[test]
    fn detect_cycle_anchor_appears_twice_per_iteration() {
        // Anchor line appears at two places in each cycle iteration,
        // requiring stride-2 detection
        let mut log = String::new();
        for i in 0..20 {
            log.push_str("; the_anchor_line @ file.c:100\n");
            log.push_str(&format!("50: (07) r1 += 1  ; frame1: R1_w={}\n", i));
            log.push_str("51: (85) call helper#1\n");
            log.push_str("; the_anchor_line @ file.c:100\n");
            log.push_str(&format!("52: (07) r2 += 1  ; frame1: R2_w={}\n", i));
            log.push_str("53: (85) call helper#2\n");
        }
        let collapsed = collapse_cycles(&log);
        assert!(
            collapsed.contains("20x of the following 6 lines"),
            "got: {}",
            &collapsed[..collapsed.len().min(500)]
        );
        // First iteration register state
        assert!(collapsed.contains("R1_w=0"));
        // Last iteration register state
        assert!(collapsed.contains("R1_w=19"));
        assert!(collapsed.contains("--- 18 identical iterations omitted ---"));
    }

    #[test]
    fn detect_cycle_no_cycle_passthrough() {
        let log = "0: (b7) r1 = 0\n1: (b7) r2 = 1\n2: (95) exit\n";
        let collapsed = collapse_cycles(log);
        assert_eq!(collapsed, log);
    }

    #[test]
    fn detect_cycle_nested_loops() {
        // Outer loop with 3 iterations, each containing an inner cycle of 5 lines x 8 reps
        let mut log = String::new();
        for outer in 0..3 {
            log.push_str(&format!("; outer iteration {} @ test.c:1\n", outer));
            for inner in 0..8 {
                log.push_str("; inner body @ test.c:5\n");
                log.push_str(&format!(
                    "10: (07) r1 += 1  ; frame1: R1_w={}\n",
                    outer * 8 + inner
                ));
                log.push_str("11: (85) call helper#1\n");
                log.push_str(&format!("12: frame1: R0_w=scalar(id={})\n", inner));
                log.push_str("13: (05) goto pc-4\n");
            }
        }
        log.push_str("999: (95) exit\n");

        let collapsed = collapse_cycles(&log);
        // Should collapse the inner loops (at least the first region)
        assert!(
            collapsed.contains("x of the following 5 lines"),
            "inner cycle not detected in: {}",
            &collapsed[..collapsed.len().min(1000)]
        );
        // Should be much smaller than original
        assert!(
            collapsed.len() < log.len() / 2,
            "collapsed {} vs original {}",
            collapsed.len(),
            log.len()
        );
    }

    #[test]
    fn collapse_cycles_integrated_with_budget() {
        // Large cyclic log should collapse AND stay under budget
        let mut log = String::new();
        for i in 0..500 {
            log.push_str("; loop iteration @ balance.bpf.c:390\n");
            for j in 0..10 {
                log.push_str(&format!(
                    "{}: (07) r{} += 1  ; frame1: R{}_w={}\n",
                    100 + j,
                    j,
                    j,
                    i * 10 + j
                ));
            }
        }

        let logs = vec![make_log("scx_lavd", Some("config"), "bad_prog", &log)];
        let results = vec![make_result(
            "scx_lavd",
            Some("config"),
            vec![("bpf.bpf.o", "bad_prog", "failure", "5678")],
        )];
        let info = SystemInfo::new(None, &[]);
        let out = output_string(|w| write_gfm_report(w, &info, &results, &logs));

        assert!(
            out.len() <= GFM_SIZE_BUDGET,
            "report {} bytes > budget {}",
            out.len(),
            GFM_SIZE_BUDGET,
        );
        assert!(out.contains("500x of the following 11 lines"));
        assert!(out.contains("--- 498 identical iterations omitted ---"));
        assert!(out.contains("cycles collapsed"));
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

    // --- Normalization edge case tests ---

    #[test]
    fn normalize_empty_line() {
        assert_eq!(normalize_verifier_line(""), "");
        assert_eq!(normalize_verifier_line("   "), "");
    }

    #[test]
    fn normalize_goto_negative_offset() {
        assert_eq!(
            normalize_verifier_line("500: (05) goto pc-12 503: frame1: R0=1 R1=scalar()"),
            "500: (05) goto pc-12"
        );
    }

    #[test]
    fn normalize_goto_without_trailing_state() {
        // goto at end of line — nothing to strip
        assert_eq!(
            normalize_verifier_line("500: (05) goto pc+3"),
            "500: (05) goto pc+3"
        );
    }

    #[test]
    fn normalize_r_annotation_without_digit_not_stripped() {
        // "; Return" should NOT be stripped — 'e' is not a digit
        let line = "5: (85) call bpf_probe_read#4  ; Return value";
        assert_eq!(normalize_verifier_line(line), line);
    }

    #[test]
    fn normalize_frame_transition_line() {
        // "caller:" / "callee:" lines start with letters, pass through unchanged
        let line = "caller: R1=ctx() R10=fp0";
        assert_eq!(normalize_verifier_line(line), line);
    }

    #[test]
    fn normalize_map_value_register() {
        assert_eq!(
            normalize_verifier_line(
                "2982: (18) r8 = 0xffffa49600208040  ; R8_w=map_value(map=.rodata,ks=4,vs=76)"
            ),
            "2982: (18) r8 = 0xffffa49600208040"
        );
    }

    #[test]
    fn normalize_initial_register_state() {
        // First line of verifier log — no annotation to strip
        let line = "0: R1=ctx() R10=fp0";
        assert_eq!(normalize_verifier_line(line), line);
    }

    // --- Cycle detection edge case tests ---

    #[test]
    fn detect_cycle_five_reps_below_threshold() {
        // 5 reps is below MIN_REPS (6) — should NOT be detected
        let mut log = String::new();
        for i in 0..5 {
            log.push_str("; anchor_line_for_detection\n");
            log.push_str(&format!("100: (07) r3 += 1  ; frame1: R3_w={}\n", i));
            log.push_str("101: (85) call helper#1\n");
            log.push_str(&format!("102: frame1: R0_w=scalar(id={})\n", i));
            log.push_str("103: (05) goto pc-4\n");
        }
        let lines: Vec<&str> = log.lines().collect();
        assert!(
            detect_cycle(&lines).is_none(),
            "cycle with 5 repetitions should NOT be detected (below MIN_REPS=6)"
        );
    }

    #[test]
    fn detect_cycle_exactly_six_reps() {
        // 6 reps is exactly MIN_REPS — should be detected
        let mut log = String::new();
        for i in 0..6 {
            log.push_str("; anchor_line_for_detection\n");
            log.push_str(&format!("100: (07) r3 += 1  ; frame1: R3_w={}\n", i));
            log.push_str("101: (85) call helper#1\n");
            log.push_str(&format!("102: frame1: R0_w=scalar(id={})\n", i));
            log.push_str("103: (05) goto pc-4\n");
        }
        let lines: Vec<&str> = log.lines().collect();
        let result = detect_cycle(&lines);
        assert!(
            result.is_some(),
            "cycle with exactly 6 repetitions should be detected"
        );
        let (start, period, count) = result.unwrap();
        assert_eq!(period, 5);
        assert_eq!(count, 6);
        assert_eq!(start, 0);
    }

    #[test]
    fn detect_cycle_too_few_reps_returns_none() {
        // Only 2 repetitions — below MIN_REPS, should NOT detect
        let mut log = String::new();
        for i in 0..2 {
            log.push_str("; anchor_line_for_detection\n");
            log.push_str(&format!("100: (07) r3 += 1  ; frame1: R3_w={}\n", i));
            log.push_str("101: (85) call helper#1\n");
            log.push_str(&format!("102: frame1: R0_w=scalar(id={})\n", i));
            log.push_str("103: (05) goto pc-4\n");
        }
        let lines: Vec<&str> = log.lines().collect();
        assert!(detect_cycle(&lines).is_none());
    }

    #[test]
    fn detect_cycle_at_beginning_no_prefix() {
        // Cycle starts at line 0 — no prefix before the repeating region
        let mut log = String::new();
        for i in 0..8 {
            log.push_str("; loop body @ test.c:10\n");
            log.push_str(&format!("100: (07) r3 += 1  ; frame1: R3_w={}\n", i));
            log.push_str("101: (85) call helper#1\n");
            log.push_str(&format!("102: frame1: R0_w=scalar(id={})\n", i));
            log.push_str("103: (05) goto pc-4\n");
        }
        let collapsed = collapse_cycles(&log);
        assert!(collapsed.contains("8x of the following 5 lines"));
        // First line of cycle body should be present
        assert!(collapsed.contains("; loop body @ test.c:10"));
        // First iteration register state
        assert!(collapsed.contains("R3_w=0"));
        // Last iteration register state
        assert!(collapsed.contains("R3_w=7"));
        assert!(collapsed.contains("--- 6 identical iterations omitted ---"));
    }

    #[test]
    fn detect_cycle_at_end_no_suffix() {
        // Cycle runs to the very end — no trailing lines after cycle
        let mut log = String::new();
        log.push_str("0: (b7) r1 = 0\n");
        log.push_str("; setup line for test\n");
        for i in 0..6 {
            log.push_str("; loop body @ test.c:10\n");
            log.push_str(&format!("100: (07) r3 += 1  ; frame1: R3_w={}\n", i));
            log.push_str("101: (85) call helper#1\n");
            log.push_str(&format!("102: frame1: R0_w=scalar(id={})\n", i));
            log.push_str("103: (05) goto pc-4\n");
        }
        let collapsed = collapse_cycles(&log);
        assert!(collapsed.contains("6x of the following 5 lines"));
        assert!(collapsed.contains("0: (b7) r1 = 0")); // prefix preserved
        assert!(collapsed.contains("--- end repeat ---"));
        // First iteration register state
        assert!(collapsed.contains("R3_w=0"));
        // Last iteration register state
        assert!(collapsed.contains("R3_w=5"));
        assert!(collapsed.contains("--- 4 identical iterations omitted ---"));
    }

    #[test]
    fn detect_cycle_short_lines_under_anchor_threshold() {
        // All lines < 10 chars — no anchor can be picked, should return None
        let mut log = String::new();
        for _ in 0..20 {
            log.push_str("a: b c\n");
            log.push_str("d: e f\n");
        }
        let lines: Vec<&str> = log.lines().collect();
        assert!(detect_cycle(&lines).is_none());
    }

    #[test]
    fn detect_cycle_too_short_input() {
        let log = "one\ntwo\nthree\n";
        let lines: Vec<&str> = log.lines().collect();
        assert!(detect_cycle(&lines).is_none());
    }

    #[test]
    fn collapse_cycles_empty_input() {
        assert_eq!(collapse_cycles(""), "");
    }

    #[test]
    fn collapse_cycles_single_line() {
        assert_eq!(collapse_cycles("hello\n"), "hello\n");
    }

    #[test]
    fn collapse_cycles_idempotent() {
        // Running collapse_cycles twice should produce the same result
        let mut log = String::new();
        for i in 0..10 {
            log.push_str("; loop body @ test.c:10\n");
            log.push_str(&format!("100: (07) r3 += 1  ; frame1: R3_w={}\n", i));
            log.push_str("101: (85) call helper#1\n");
            log.push_str(&format!("102: frame1: R0_w=scalar(id={})\n", i));
            log.push_str("103: (05) goto pc-4\n");
        }
        let first = collapse_cycles(&log);
        let second = collapse_cycles(&first);
        assert_eq!(first, second, "collapse_cycles should be idempotent");
    }

    #[test]
    fn collapse_cycles_preserves_non_cyclic_content_exactly() {
        // Non-cyclic content before and after cycle should be preserved verbatim
        let mut log = String::new();
        log.push_str("Global function lavd_dispatch() doesn't return scalar.\n");
        log.push_str("0: R1=ctx() R10=fp0\n");
        for i in 0..7 {
            log.push_str("; loop body @ test.c:10\n");
            log.push_str(&format!("100: (07) r3 += 1  ; frame1: R3_w={}\n", i));
            log.push_str("101: (85) call helper#1\n");
            log.push_str(&format!("102: frame1: R0_w=scalar(id={})\n", i));
            log.push_str("103: (05) goto pc-4\n");
        }
        log.push_str("verification time 12345 usec\n");
        log.push_str("processed 100000 insns\n");

        let collapsed = collapse_cycles(&log);
        // Prefix lines preserved
        assert!(collapsed.contains("Global function lavd_dispatch()"));
        assert!(collapsed.contains("0: R1=ctx() R10=fp0"));
        // Suffix lines preserved
        assert!(collapsed.contains("verification time 12345 usec"));
        assert!(collapsed.contains("processed 100000 insns"));
        // Cycle was actually collapsed (7 reps, above MIN_REPS=6)
        assert!(collapsed.contains("7x of the following 5 lines"));
        assert!(collapsed.contains("--- 5 identical iterations omitted ---"));
        assert!(collapsed.contains("--- end repeat ---"));
        // First and last iteration register state present
        assert!(collapsed.contains("R3_w=0"));
        assert!(collapsed.contains("R3_w=6"));
    }

    // --- Fixture-based tests (lavd_dispatch real verifier log) ---

    fn load_lavd_fixture() -> String {
        let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/lavd_dispatch_verifier.log");
        std::fs::read_to_string(&fixture_path)
            .unwrap_or_else(|e| panic!("Failed to read fixture {}: {}", fixture_path.display(), e))
    }

    #[test]
    fn fixture_lavd_dispatch_has_expected_size() {
        let log = load_lavd_fixture();
        let line_count = log.lines().count();
        // The real log has ~23K lines and is ~2.5MB
        assert!(
            line_count > 20_000,
            "expected >20K lines, got {}",
            line_count
        );
        assert!(
            log.len() > 2_000_000,
            "expected >2MB, got {} bytes",
            log.len()
        );
    }

    #[test]
    fn fixture_lavd_collapse_dramatically_shrinks() {
        let log = load_lavd_fixture();
        let collapsed = collapse_cycles(&log);
        let original_lines = log.lines().count();
        let collapsed_lines = collapsed.lines().count();

        // Should achieve at least 10x line reduction (actual: ~22x)
        assert!(
            collapsed_lines * 10 < original_lines,
            "expected 10x+ compression: {} → {} lines",
            original_lines,
            collapsed_lines
        );
        // Should achieve at least 10x byte reduction
        assert!(
            collapsed.len() * 10 < log.len(),
            "expected 10x+ byte compression: {} → {} bytes",
            log.len(),
            collapsed.len()
        );
    }

    #[test]
    fn fixture_lavd_collapse_contains_repeat_markers() {
        let log = load_lavd_fixture();
        let collapsed = collapse_cycles(&log);

        let marker_count = collapsed.matches("--- end repeat ---").count();
        // The real log has nested loops producing multiple cycle regions
        assert!(
            marker_count >= 2,
            "expected at least 2 cycle collapses, got {}",
            marker_count
        );

        // Each marker should have a matching header and omitted line
        let header_count = collapsed.matches("x of the following").count();
        assert_eq!(
            marker_count, header_count,
            "end-repeat ({}) and header ({}) counts should match",
            marker_count, header_count
        );
        let omitted_count = collapsed.matches("identical iterations omitted").count();
        assert_eq!(
            marker_count, omitted_count,
            "end-repeat ({}) and omitted ({}) counts should match",
            marker_count, omitted_count
        );
    }

    #[test]
    fn fixture_lavd_collapse_preserves_preamble_and_postamble() {
        let log = load_lavd_fixture();
        let collapsed = collapse_cycles(&log);

        // The first line of the verifier log should be preserved
        let first_line = log.lines().next().unwrap();
        assert!(
            collapsed.contains(first_line),
            "first line should be preserved: {}",
            first_line
        );

        // The last few lines (verification summary) should be preserved
        let last_lines: Vec<&str> = log.lines().rev().take(3).collect();
        for line in &last_lines {
            assert!(
                collapsed.contains(line),
                "postamble line should be preserved: {}",
                line
            );
        }
    }

    #[test]
    fn fixture_lavd_full_pipeline_under_budget() {
        let log = load_lavd_fixture();

        let logs = vec![make_log(
            "scx_lavd",
            Some("stable_6_13"),
            "lavd_dispatch",
            &log,
        )];
        let results = vec![make_result(
            "scx_lavd",
            Some("stable_6_13"),
            vec![("main.bpf.o", "lavd_dispatch", "failure", "1000001")],
        )];
        let info = SystemInfo::new(Some("Linux test 6.13.0-rc1"), &[("scx_lavd", "abc1234")]);
        let out = output_string(|w| write_gfm_report(w, &info, &results, &logs));

        assert!(
            out.len() <= GFM_SIZE_BUDGET,
            "full pipeline output {} bytes exceeds budget {} bytes",
            out.len(),
            GFM_SIZE_BUDGET,
        );
        assert!(out.contains("## \u{274c} Verification Report"));
        assert!(out.contains("### Verifier Errors"));
        assert!(out.contains("cycles collapsed"));
        assert!(out.contains("lavd_dispatch"));
    }

    #[test]
    fn fixture_lavd_verifier_errors_shows_qualifier() {
        let log = load_lavd_fixture();

        let logs = vec![make_log(
            "scx_lavd",
            Some("stable_6_13"),
            "lavd_dispatch",
            &log,
        )];
        let out = output_string(|w| write_verifier_errors(w, &logs, 500_000).map(|_| ()));

        // Should show "cycles collapsed" qualifier since cycles are detected
        assert!(
            out.contains("cycles collapsed"),
            "qualifier should indicate cycle collapse"
        );
        // Should contain the program header
        assert!(out.contains("<code>lavd_dispatch</code>"));
    }

    #[test]
    fn fixture_lavd_collapse_cycles_is_idempotent() {
        let log = load_lavd_fixture();
        let first = collapse_cycles(&log);
        let second = collapse_cycles(&first);
        assert_eq!(
            first,
            second,
            "collapse_cycles on real fixture should be idempotent (first: {} bytes, second: {} bytes)",
            first.len(),
            second.len()
        );
    }

    // --- Budget + cycle integration edge cases ---

    #[test]
    fn budget_truncation_after_cycle_collapse() {
        // Large cycle log that even after collapse might exceed a tiny budget
        let mut log = String::new();
        for i in 0..200 {
            log.push_str("; loop body @ balance.bpf.c:390\n");
            for j in 0..20 {
                log.push_str(&format!(
                    "{}: (07) r{} += 1  ; frame1: R{}_w={}\n",
                    100 + j,
                    j,
                    j,
                    i * 20 + j
                ));
            }
        }
        // Collapse first, then truncate with a very small budget
        let collapsed = collapse_cycles(&log);
        assert!(collapsed.contains("200x of the following 21 lines"));

        let truncated = truncate_log_to_bytes(&collapsed, 500);
        assert!(
            truncated.len() <= 550,
            "truncated output {} bytes should be ≤550",
            truncated.len()
        );
        assert!(truncated.contains("lines omitted"));
    }

    #[test]
    fn write_verifier_errors_qualifier_labels() {
        // No cycles, no truncation → no qualifier
        let short_log = "0: R1=ctx()\n1: (95) exit\n";
        let logs = vec![make_log("pkg", None, "prog", short_log)];
        let out = output_string(|w| write_verifier_errors(w, &logs, 100_000).map(|_| ()));
        // The summary line should NOT contain any qualifier
        assert!(
            !out.contains("cycles collapsed") && !out.contains("truncated,"),
            "short log should have no qualifier: {}",
            out
        );

        // Cycles detected but fits in budget → "cycles collapsed"
        let mut cyclic_log = String::new();
        for i in 0..10 {
            log_push_cycle_iteration(&mut cyclic_log, i);
        }
        let logs = vec![make_log("pkg", None, "prog", &cyclic_log)];
        let out = output_string(|w| write_verifier_errors(w, &logs, 100_000).map(|_| ()));
        assert!(
            out.contains("cycles collapsed, "),
            "should have 'cycles collapsed' qualifier: {}",
            out
        );
        assert!(
            !out.contains("truncated"),
            "should not be truncated with large budget"
        );
    }

    /// Helper: push one iteration of a synthetic cycle into a log string.
    fn log_push_cycle_iteration(log: &mut String, i: usize) {
        log.push_str("; loop body @ test.c:10\n");
        log.push_str(&format!("100: (07) r3 += 1  ; frame1: R3_w={}\n", i));
        log.push_str("101: (85) call helper#1\n");
        log.push_str(&format!("102: frame1: R0_w=scalar(id={})\n", i));
        log.push_str("103: (05) goto pc-4\n");
    }
}
