use anyhow::{Context, Result};
#[cfg(test)]
use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct RunKey {
    pub package: String,
    pub config: Option<String>, // None = no-config run, Some = named config
}

impl fmt::Display for RunKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.config {
            Some(config) => write!(f, "{} / {}", self.package, config),
            None => write!(f, "{}", self.package),
        }
    }
}

pub(crate) struct VeristatRun {
    pub key: RunKey,
    pub objects: Vec<PathBuf>,
    pub globals: Vec<String>, // empty = no globals
}

pub(crate) struct PackageVerdict {
    pub records: Vec<csv::StringRecord>,
    pub failed: bool,
}

pub(crate) struct RunResult {
    pub key: RunKey,
    pub headers: csv::StringRecord,
    pub verdict: PackageVerdict,
    pub objects: Vec<PathBuf>,
    pub globals_path: Option<PathBuf>,
}

pub(crate) struct VerifierLog {
    pub key: RunKey,
    pub header: String,
    pub log_body: String,
}

/// Build a mapping from object filename -> package name.
#[cfg(test)]
pub(crate) fn build_object_map(
    objects_by_package: &HashMap<String, Vec<PathBuf>>,
) -> HashMap<String, String> {
    let mut object_map = HashMap::new();
    for (pkg, objects) in objects_by_package {
        for obj in objects {
            let filename = obj.file_name().unwrap().to_str().unwrap().to_string();
            object_map.insert(filename, pkg.clone());
        }
    }
    object_map
}

/// Parse veristat CSV output and group results by package.
///
/// Returns the CSV headers and a map of package name -> verdict.
#[cfg(test)]
pub(crate) fn parse_and_group(
    csv_text: &str,
    object_map: &HashMap<String, String>,
) -> Result<(csv::StringRecord, HashMap<String, PackageVerdict>)> {
    let mut reader = csv::ReaderBuilder::new()
        .trim(csv::Trim::All)
        .flexible(true)
        .from_reader(csv_text.as_bytes());

    let headers = reader.headers()?.clone();

    let file_name_idx = headers
        .iter()
        .position(|h| h == "file_name")
        .context("veristat CSV missing 'file_name' column")?;
    let verdict_idx = headers
        .iter()
        .position(|h| h == "verdict")
        .context("veristat CSV missing 'verdict' column")?;

    let mut packages: HashMap<String, PackageVerdict> = HashMap::new();

    for result in reader.records() {
        let record = result?;
        let file_name = record.get(file_name_idx).unwrap_or("").to_string();
        let verdict = record.get(verdict_idx).unwrap_or("").to_lowercase();

        let basename = Path::new(&file_name)
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or(&file_name);
        let package = object_map
            .get(basename)
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());

        let entry = packages.entry(package).or_insert_with(|| PackageVerdict {
            records: Vec::new(),
            failed: false,
        });

        if verdict != "success" {
            entry.failed = true;
        }
        entry.records.push(record);
    }

    Ok((headers, packages))
}

/// Check that veristat is available on $PATH.
pub fn check_veristat() -> Result<()> {
    match Command::new("veristat").arg("--help").output() {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            anyhow::bail!(
                "veristat not found on $PATH.\n\
                 Install it via:\n  \
                 dnf install veristat\n  \
                 apt install veristat\n  \
                 or build from https://github.com/libbpf/veristat"
            );
        }
        Err(e) => Err(e).context("Failed to run veristat"),
    }
}

/// Write global variable presets to a file for veristat `-G @file`.
///
/// Each line is `var = value`, matching veristat's expected format.
/// `name` is used to make the filename unique across multiple runs.
/// Returns the path to the written file.
fn write_globals_file(temp_dir: &Path, global_vars: &[String], name: &str) -> Result<PathBuf> {
    let path = temp_dir.join(format!("globals_{}.txt", name));
    let contents = global_vars.join("\n") + "\n";
    std::fs::write(&path, contents).context("Failed to write globals file")?;
    Ok(path)
}

/// Run veristat -o csv on objects with an optional globals file.
fn run_veristat_csv(objects: &[PathBuf], globals_path: Option<&Path>) -> Result<String> {
    let mut cmd = Command::new("veristat");
    cmd.arg("-o").arg("csv");
    if let Some(path) = globals_path {
        cmd.arg("-G").arg(format!("@{}", path.display()));
    }
    cmd.args(objects);

    let output = cmd.output().context("Failed to run veristat")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut msg = format!("veristat exited with status {}", output.status);
        if !stderr.is_empty() {
            msg.push_str(&format!("\nstderr: {}", stderr.trim()));
        }
        if !stdout.is_empty() {
            msg.push_str(&format!("\nstdout: {}", stdout.trim()));
        }
        anyhow::bail!("{}", msg);
    }

    String::from_utf8(output.stdout).context("veristat output is not valid UTF-8")
}

/// Parse veristat CSV output into a verdict (headers + records + pass/fail).
///
/// Unlike `parse_and_group`, this doesn't group by package — all records
/// belong to a single run.
fn parse_run_csv(csv_text: &str) -> Result<(csv::StringRecord, PackageVerdict)> {
    let mut reader = csv::ReaderBuilder::new()
        .trim(csv::Trim::All)
        .flexible(true)
        .from_reader(csv_text.as_bytes());

    let headers = reader.headers()?.clone();

    // Validate required columns upfront so callers can safely unwrap
    if !headers.iter().any(|h| h == "file_name") {
        anyhow::bail!("veristat CSV missing 'file_name' column");
    }
    let verdict_idx = headers
        .iter()
        .position(|h| h == "verdict")
        .context("veristat CSV missing 'verdict' column")?;

    let mut records = Vec::new();
    let mut failed = false;

    for result in reader.records() {
        let record = result?;
        let verdict = record.get(verdict_idx).unwrap_or("").to_lowercase();
        if verdict != "success" {
            failed = true;
        }
        records.push(record);
    }

    Ok((headers, PackageVerdict { records, failed }))
}

/// Execute veristat runs and collect structured results.
///
/// Each `VeristatRun` specifies a set of BPF objects and optional globals.
pub(crate) fn execute_runs(runs: &[VeristatRun], temp_dir: &Path) -> Result<Vec<RunResult>> {
    let total_objects: usize = runs.iter().map(|r| r.objects.len()).sum();

    if total_objects == 0 {
        return Ok(Vec::new());
    }

    println!(
        "Running veristat on {} BPF object(s) across {} run(s)...",
        total_objects,
        runs.len()
    );

    let mut results: Vec<RunResult> = Vec::new();

    for run in runs {
        let mut sorted_objects = run.objects.clone();
        sorted_objects.sort();

        let (csv_output, globals_path) = if !run.globals.is_empty() {
            let globals_name = match &run.key.config {
                Some(config) => format!("{}_{}", run.key.package, config),
                None => run.key.package.clone(),
            };
            let globals_path = write_globals_file(temp_dir, &run.globals, &globals_name)?;
            println!(
                "Using {} global variable(s) for {}",
                run.globals.len(),
                run.key
            );

            // Veristat requires ALL globals to match variables in EACH object.
            // When a package has multiple BPF objects (e.g. main scheduler +
            // kfuncs test), globals from one object's rodata won't exist in
            // the other. Run per-object: try with globals, fall back without.
            let mut csv_parts: Vec<String> = Vec::new();
            let mut headers: Option<String> = None;

            for obj in &sorted_objects {
                let csv = match run_veristat_csv(std::slice::from_ref(obj), Some(&globals_path)) {
                    Ok(csv) => csv,
                    Err(_) => {
                        let name = obj.file_name().unwrap().to_string_lossy();
                        eprintln!(
                            "note: rodata globals not applicable to {}, running without",
                            name
                        );
                        run_veristat_csv(std::slice::from_ref(obj), None)?
                    }
                };

                let mut lines = csv.lines();
                if let Some(header) = lines.next() {
                    if headers.is_none() {
                        headers = Some(header.to_string());
                    }
                    csv_parts.extend(lines.map(|l| l.to_string()));
                }
            }

            let combined = match headers {
                Some(h) => {
                    let mut combined = h;
                    for part in &csv_parts {
                        combined.push('\n');
                        combined.push_str(part);
                    }
                    combined.push('\n');
                    combined
                }
                None => String::new(),
            };
            (combined, Some(globals_path))
        } else {
            (run_veristat_csv(&sorted_objects, None)?, None)
        };

        let (headers, verdict) = parse_run_csv(&csv_output)?;
        results.push(RunResult {
            key: run.key.clone(),
            headers,
            verdict,
            objects: sorted_objects,
            globals_path,
        });
    }

    Ok(results)
}

/// Re-run veristat with `-v` on failing programs and return structured logs.
pub(crate) fn collect_verifier_logs(results: &[RunResult]) -> Vec<VerifierLog> {
    let mut logs = Vec::new();

    for result in results {
        if !result.verdict.failed {
            continue;
        }

        let file_name_idx = result.headers.iter().position(|h| h == "file_name");
        let verdict_idx = result.headers.iter().position(|h| h == "verdict");
        let prog_name_idx = result.headers.iter().position(|h| h == "prog_name");

        let (file_name_idx, verdict_idx) = match (file_name_idx, verdict_idx) {
            (Some(f), Some(v)) => (f, v),
            _ => continue,
        };

        let mut failed_by_object: std::collections::BTreeMap<String, Vec<String>> =
            std::collections::BTreeMap::new();
        for record in &result.verdict.records {
            let verdict = record.get(verdict_idx).unwrap_or("").to_lowercase();
            if verdict == "success" {
                continue;
            }
            let file_name = record.get(file_name_idx).unwrap_or("").to_string();
            let prog_name = prog_name_idx
                .and_then(|i| record.get(i))
                .unwrap_or("")
                .to_string();
            if !prog_name.is_empty() {
                failed_by_object
                    .entry(file_name)
                    .or_default()
                    .push(prog_name);
            }
        }

        for (file_name, progs) in &failed_by_object {
            let csv_basename = Path::new(file_name)
                .file_name()
                .and_then(|f| f.to_str())
                .unwrap_or(file_name);
            let obj_path = result.objects.iter().find(|p| {
                p.file_name()
                    .and_then(|f| f.to_str())
                    .is_some_and(|f| f == csv_basename)
            });
            if let Some(obj_path) = obj_path {
                for (header, log_body) in
                    run_verbose_veristat(obj_path, progs, result.globals_path.as_deref())
                {
                    logs.push(VerifierLog {
                        key: result.key.clone(),
                        header,
                        log_body,
                    });
                }
            }
        }
    }

    logs
}

/// Print human-readable report to stdout.
///
/// Returns true if all runs passed, false if any failed.
pub(crate) fn print_report(
    results: &[RunResult],
    logs: &[VerifierLog],
    temp_dir: &Path,
    raw: bool,
) -> Result<bool> {
    let mut all_passed = true;

    for result in results {
        let status = if result.verdict.failed {
            "FAILED"
        } else {
            "PASSED"
        };

        println!("\n=== {} [{}] ===", result.key, status);

        if result.verdict.failed {
            all_passed = false;
        }

        let file_name_idx = result
            .headers
            .iter()
            .position(|h| h == "file_name")
            .unwrap();
        let verdict_idx = result.headers.iter().position(|h| h == "verdict").unwrap();

        // Write per-run CSV and run veristat -R for readable output
        let csv_filename = match &result.key.config {
            Some(config) => format!("{}_{}.csv", result.key.package, config),
            None => format!("{}.csv", result.key.package),
        };
        let csv_path = temp_dir.join(&csv_filename);
        write_package_csv(&csv_path, &result.headers, &result.verdict.records)?;

        let prog_name_idx = result.headers.iter().position(|h| h == "prog_name");

        match replay_csv(&csv_path) {
            Ok(output) => print!("{}", output),
            Err(_) => {
                // Fallback: print records manually
                for record in &result.verdict.records {
                    let fname = record.get(file_name_idx).unwrap_or("?");
                    let prog = prog_name_idx.and_then(|i| record.get(i)).unwrap_or("?");
                    let verdict_str = record.get(verdict_idx).unwrap_or("?");
                    println!("  {} / {} : {}", fname, prog, verdict_str);
                }
            }
        }
    }

    // Print verifier error logs
    if !logs.is_empty() {
        println!("\n=== Verifier Logs ===");
        for log in logs {
            println!("\nPROCESSING {}", log.header);
            let body = if raw {
                log.log_body.clone()
            } else {
                crate::gfm::collapse_cycles(&log.log_body)
            };
            println!("{}", body);
        }
    }

    // Print summary
    println!("\n=== Summary ===");
    let max_label_len = results
        .iter()
        .map(|r| r.key.to_string().len() + 1) // +1 for colon
        .max()
        .unwrap_or(0);
    for result in results {
        let label = format!("{}:", result.key);
        let status = if result.verdict.failed {
            "\x1b[1;5;31mFAIL \u{1F4A5}\x1b[0m"
        } else {
            "\x1b[32mPASS \u{2705}\x1b[0m"
        };
        println!("  {:<width$}  {}", label, status, width = max_label_len);
    }

    let total = results.len();
    let fail_count = results.iter().filter(|r| r.verdict.failed).count();
    let pass_count = total - fail_count;
    println!(
        "\n{} passed, {} failed, {} total",
        pass_count, fail_count, total
    );

    if !all_passed {
        print_rainbow_banner();
    }

    Ok(all_passed)
}

/// Run veristat on a list of runs and report results.
///
/// Each `VeristatRun` specifies a set of BPF objects and optional globals.
/// Returns true if all runs passed, false if any failed.
pub fn run_and_report(runs: &[VeristatRun], temp_dir: &Path, raw: bool) -> Result<bool> {
    let results = execute_runs(runs, temp_dir)?;
    if results.is_empty() {
        println!("No BPF objects to verify.");
        return Ok(true);
    }
    let logs = collect_verifier_logs(&results);
    print_report(&results, &logs, temp_dir, raw)
}

/// Write a per-package CSV file from grouped records.
fn write_package_csv(
    path: &Path,
    headers: &csv::StringRecord,
    records: &[csv::StringRecord],
) -> Result<()> {
    let mut writer = csv::Writer::from_path(path)
        .with_context(|| format!("Failed to create CSV file: {}", path.display()))?;
    writer.write_record(headers)?;
    for record in records {
        writer.write_record(record)?;
    }
    writer.flush()?;
    Ok(())
}

/// Collect failing program names grouped by object file name.
///
/// Scans package verdicts for non-success records and returns a map of
/// `object_file_name -> [prog_name, ...]` for programs that need verifier logs.
#[cfg(test)]
fn collect_failed_programs(
    headers: &csv::StringRecord,
    package_verdicts: &HashMap<String, PackageVerdict>,
) -> HashMap<String, Vec<String>> {
    let file_name_idx = headers.iter().position(|h| h == "file_name");
    let verdict_idx = headers.iter().position(|h| h == "verdict");
    let prog_name_idx = headers.iter().position(|h| h == "prog_name");

    let mut failed_by_object: HashMap<String, Vec<String>> = HashMap::new();

    let (file_name_idx, verdict_idx) = match (file_name_idx, verdict_idx) {
        (Some(f), Some(v)) => (f, v),
        _ => return failed_by_object,
    };

    for pv in package_verdicts.values() {
        if !pv.failed {
            continue;
        }
        for record in &pv.records {
            let verdict = record.get(verdict_idx).unwrap_or("").to_lowercase();
            if verdict == "success" {
                continue;
            }
            let file_name = record.get(file_name_idx).unwrap_or("").to_string();
            let prog_name = prog_name_idx
                .and_then(|i| record.get(i))
                .unwrap_or("")
                .to_string();
            if !prog_name.is_empty() {
                failed_by_object
                    .entry(file_name)
                    .or_default()
                    .push(prog_name);
            }
        }
    }

    failed_by_object
}

/// Extract verifier failure logs from `veristat -v` output.
///
/// Returns `(header_line, log_body)` pairs for each failing program.
fn extract_failure_logs(veristat_output: &str) -> Vec<(String, String)> {
    let mut results = Vec::new();

    for chunk in veristat_output.split("PROCESSING ") {
        if chunk.is_empty() || !chunk.contains("VERDICT: failure") {
            continue;
        }
        let header = chunk.lines().next().unwrap_or("").to_string();
        let mut log_lines = Vec::new();
        for line in chunk.lines().skip(1) {
            // Stop at the results table (header is "File ... Program ... Verdict")
            if (line.starts_with("File") && line.contains("Verdict")) || line.starts_with("---") {
                break;
            }
            log_lines.push(line);
        }
        results.push((header, log_lines.join("\n")));
    }

    results
}

/// Re-run veristat with `-v` on specific failing programs and return structured logs.
///
/// Returns `(header_line, log_body)` pairs for each failing program.
/// When `globals_path` is provided, tries running with globals first. If that
/// fails (globals not applicable to this object), falls back to running without.
fn run_verbose_veristat(
    obj_path: &Path,
    prog_names: &[String],
    globals_path: Option<&Path>,
) -> Vec<(String, String)> {
    let run_verbose = |globals: Option<&Path>| -> std::io::Result<std::process::Output> {
        let mut cmd = Command::new("veristat");
        cmd.arg("-v");
        if let Some(path) = globals {
            cmd.arg("-G").arg(format!("@{}", path.display()));
        }
        for prog in prog_names {
            cmd.arg("-f").arg(prog);
        }
        cmd.arg(obj_path);
        cmd.output()
    };

    // Try with globals first; fall back to without if they don't apply
    let output = match run_verbose(globals_path) {
        Ok(o) if o.status.success() || globals_path.is_none() => o,
        Ok(_) => match run_verbose(None) {
            Ok(o) => o,
            Err(e) => {
                eprintln!("warning: failed to retrieve verifier logs: {}", e);
                return Vec::new();
            }
        },
        Err(e) => {
            eprintln!("warning: failed to retrieve verifier logs: {}", e);
            return Vec::new();
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    extract_failure_logs(&stdout)
}

/// Print a failure banner that's hard to miss.
fn print_rainbow_banner() {
    let text = "!!!!!!!!!!VERIFICATION FAILED!!!!!!!!!!";
    let colors = [
        "\x1b[1;4;5;31m",
        "\x1b[1;4;5;33m",
        "\x1b[1;4;5;32m",
        "\x1b[1;4;5;36m",
        "\x1b[1;4;5;35m",
        "\x1b[1;4;5;91m",
        "\x1b[1;4;5;93m",
        "\x1b[1;4;5;95m",
    ];
    let offset = std::time::UNIX_EPOCH
        .elapsed()
        .unwrap_or_default()
        .subsec_nanos() as usize;
    let rainbow: String = text
        .chars()
        .enumerate()
        .map(|(i, c)| format!("{}{}", colors[(i / 5 + offset) % colors.len()], c))
        .collect();
    println!(
        "\n\u{1F62D}\u{1F625} {}\x1b[0m \u{1F625}\u{1F62D}\x07\n",
        rainbow
    );
}

/// Replay a CSV file through `veristat -R` for human-readable output.
fn replay_csv(csv_path: &Path) -> Result<String> {
    let output = Command::new("veristat")
        .arg("-R")
        .arg(csv_path)
        .output()
        .context("Failed to run veristat -R")?;

    if !output.status.success() {
        anyhow::bail!("veristat -R failed");
    }

    String::from_utf8(output.stdout).context("veristat -R output is not valid UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_object_map_single_package() {
        let mut objects = HashMap::new();
        objects.insert(
            "pkg_foo".to_string(),
            vec![PathBuf::from("/tmp/pkg_foo_bpf.bpf.o")],
        );
        let map = build_object_map(&objects);
        assert_eq!(map.get("pkg_foo_bpf.bpf.o").unwrap(), "pkg_foo");
    }

    #[test]
    fn build_object_map_multiple_packages() {
        let mut objects = HashMap::new();
        objects.insert(
            "pkg_foo".to_string(),
            vec![PathBuf::from("/tmp/pkg_foo_a.bpf.o")],
        );
        objects.insert(
            "pkg_bar".to_string(),
            vec![
                PathBuf::from("/tmp/pkg_bar_x.bpf.o"),
                PathBuf::from("/tmp/pkg_bar_y.bpf.o"),
            ],
        );
        let map = build_object_map(&objects);
        assert_eq!(map.len(), 3);
        assert_eq!(map.get("pkg_foo_a.bpf.o").unwrap(), "pkg_foo");
        assert_eq!(map.get("pkg_bar_x.bpf.o").unwrap(), "pkg_bar");
        assert_eq!(map.get("pkg_bar_y.bpf.o").unwrap(), "pkg_bar");
    }

    #[test]
    fn parse_and_group_all_success() {
        let csv = "file_name,prog_name,verdict,duration_us\n\
                   pkg_foo_bpf.bpf.o,main_prog,success,123\n\
                   pkg_foo_bpf.bpf.o,helper,success,45\n";
        let mut object_map = HashMap::new();
        object_map.insert("pkg_foo_bpf.bpf.o".to_string(), "pkg_foo".to_string());

        let (headers, packages) = parse_and_group(csv, &object_map).unwrap();
        assert!(headers.iter().any(|h| h == "file_name"));
        assert_eq!(packages.len(), 1);
        let pv = packages.get("pkg_foo").unwrap();
        assert!(!pv.failed);
        assert_eq!(pv.records.len(), 2);
    }

    #[test]
    fn parse_and_group_mixed_verdicts() {
        let csv = "file_name,prog_name,verdict,duration_us\n\
                   pkg_foo_bpf.bpf.o,main_prog,success,123\n\
                   pkg_bar_bpf.bpf.o,prog,failure,99\n";
        let mut object_map = HashMap::new();
        object_map.insert("pkg_foo_bpf.bpf.o".to_string(), "pkg_foo".to_string());
        object_map.insert("pkg_bar_bpf.bpf.o".to_string(), "pkg_bar".to_string());

        let (_, packages) = parse_and_group(csv, &object_map).unwrap();
        assert!(!packages.get("pkg_foo").unwrap().failed);
        assert!(packages.get("pkg_bar").unwrap().failed);
    }

    #[test]
    fn parse_and_group_case_insensitive_verdict() {
        let csv = "file_name,prog_name,verdict\n\
                   a.bpf.o,prog,Success\n";
        let mut object_map = HashMap::new();
        object_map.insert("a.bpf.o".to_string(), "pkg".to_string());

        let (_, packages) = parse_and_group(csv, &object_map).unwrap();
        assert!(!packages.get("pkg").unwrap().failed);
    }

    #[test]
    fn parse_and_group_multiple_packages_grouped() {
        let csv = "file_name,prog_name,verdict\n\
                   a.bpf.o,p1,success\n\
                   b.bpf.o,p2,success\n\
                   a.bpf.o,p3,success\n";
        let mut object_map = HashMap::new();
        object_map.insert("a.bpf.o".to_string(), "pkg_a".to_string());
        object_map.insert("b.bpf.o".to_string(), "pkg_b".to_string());

        let (_, packages) = parse_and_group(csv, &object_map).unwrap();
        assert_eq!(packages.len(), 2);
        assert_eq!(packages.get("pkg_a").unwrap().records.len(), 2);
        assert_eq!(packages.get("pkg_b").unwrap().records.len(), 1);
    }

    #[test]
    fn parse_and_group_unknown_filename() {
        let csv = "file_name,prog_name,verdict\n\
                   unknown.bpf.o,prog,success\n";
        let object_map = HashMap::new();

        let (_, packages) = parse_and_group(csv, &object_map).unwrap();
        assert!(packages.contains_key("unknown"));
    }

    #[test]
    fn parse_and_group_empty_csv() {
        let csv = "file_name,prog_name,verdict\n";
        let object_map = HashMap::new();

        let (headers, packages) = parse_and_group(csv, &object_map).unwrap();
        assert!(headers.iter().any(|h| h == "file_name"));
        assert!(packages.is_empty());
    }

    #[test]
    fn write_globals_file_format() {
        let dir = tempfile::tempdir().unwrap();
        let vars = vec![
            "nr_layers = 4".to_string(),
            "smt_enabled = 1".to_string(),
            "order[0] = 10".to_string(),
        ];
        let path = write_globals_file(dir.path(), &vars, "test_pkg").unwrap();

        assert_eq!(path, dir.path().join("globals_test_pkg.txt"));
        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents, "nr_layers = 4\nsmt_enabled = 1\norder[0] = 10\n");
    }

    #[test]
    fn write_globals_file_single_var() {
        let dir = tempfile::tempdir().unwrap();
        let vars = vec!["x = 42".to_string()];
        let path = write_globals_file(dir.path(), &vars, "single").unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents, "x = 42\n");
    }

    // --- RunKey tests ---

    #[test]
    fn run_key_display_without_config() {
        let key = RunKey {
            package: "scx_rusty".to_string(),
            config: None,
        };
        assert_eq!(key.to_string(), "scx_rusty");
    }

    #[test]
    fn run_key_display_with_config() {
        let key = RunKey {
            package: "scx_layered".to_string(),
            config: Some("4_layers".to_string()),
        };
        assert_eq!(key.to_string(), "scx_layered / 4_layers");
    }

    #[test]
    fn run_key_display_baseline() {
        let key = RunKey {
            package: "scx_layered".to_string(),
            config: Some("(baseline)".to_string()),
        };
        assert_eq!(key.to_string(), "scx_layered / (baseline)");
    }

    #[test]
    fn run_key_ordering() {
        let mut keys = vec![
            RunKey {
                package: "scx_layered".to_string(),
                config: Some("8_layers".to_string()),
            },
            RunKey {
                package: "scx_rusty".to_string(),
                config: None,
            },
            RunKey {
                package: "scx_layered".to_string(),
                config: Some("(baseline)".to_string()),
            },
            RunKey {
                package: "scx_layered".to_string(),
                config: Some("4_layers".to_string()),
            },
        ];
        keys.sort();

        assert_eq!(keys[0].to_string(), "scx_layered / (baseline)");
        assert_eq!(keys[1].to_string(), "scx_layered / 4_layers");
        assert_eq!(keys[2].to_string(), "scx_layered / 8_layers");
        assert_eq!(keys[3].to_string(), "scx_rusty");
    }

    #[test]
    fn run_key_none_before_some() {
        let none_key = RunKey {
            package: "pkg".to_string(),
            config: None,
        };
        let some_key = RunKey {
            package: "pkg".to_string(),
            config: Some("config".to_string()),
        };
        assert!(none_key < some_key);
    }

    // --- parse_run_csv tests ---

    #[test]
    fn parse_run_csv_all_success() {
        let csv = "file_name,prog_name,verdict,duration_us\n\
                   a.bpf.o,prog1,success,100\n\
                   a.bpf.o,prog2,success,200\n";
        let (headers, pv) = parse_run_csv(csv).unwrap();
        assert!(!pv.failed);
        assert_eq!(pv.records.len(), 2);
        assert!(headers.iter().any(|h| h == "file_name"));
    }

    #[test]
    fn parse_run_csv_mixed_verdicts() {
        let csv = "file_name,prog_name,verdict\n\
                   a.bpf.o,good,success\n\
                   a.bpf.o,bad,failure\n";
        let (_, pv) = parse_run_csv(csv).unwrap();
        assert!(pv.failed);
        assert_eq!(pv.records.len(), 2);
    }

    #[test]
    fn parse_run_csv_empty() {
        let csv = "file_name,prog_name,verdict\n";
        let (_, pv) = parse_run_csv(csv).unwrap();
        assert!(!pv.failed);
        assert!(pv.records.is_empty());
    }

    #[test]
    fn parse_run_csv_case_insensitive_verdict() {
        let csv = "file_name,prog_name,verdict\n\
                   a.bpf.o,prog,Success\n";
        let (_, pv) = parse_run_csv(csv).unwrap();
        assert!(!pv.failed);
    }

    #[test]
    fn parse_run_csv_missing_file_name_column() {
        let csv = "prog_name,verdict\n\
                   prog,success\n";
        assert!(parse_run_csv(csv).is_err());
    }

    #[test]
    fn parse_run_csv_missing_verdict_column() {
        let csv = "file_name,prog_name\n\
                   a.bpf.o,prog\n";
        assert!(parse_run_csv(csv).is_err());
    }

    // --- collect_failed_programs tests ---

    fn make_verdicts(
        csv: &str,
        object_map: &HashMap<String, String>,
    ) -> (csv::StringRecord, HashMap<String, PackageVerdict>) {
        parse_and_group(csv, object_map).unwrap()
    }

    #[test]
    fn collect_failed_programs_finds_failures() {
        let csv = "file_name,prog_name,verdict\n\
                   a.bpf.o,good_prog,success\n\
                   a.bpf.o,bad_prog,failure\n\
                   a.bpf.o,also_bad,failure\n";
        let mut object_map = HashMap::new();
        object_map.insert("a.bpf.o".to_string(), "pkg".to_string());

        let (headers, verdicts) = make_verdicts(csv, &object_map);
        let failed = collect_failed_programs(&headers, &verdicts);

        assert_eq!(failed.len(), 1);
        let progs = failed.get("a.bpf.o").unwrap();
        assert_eq!(progs.len(), 2);
        assert!(progs.contains(&"bad_prog".to_string()));
        assert!(progs.contains(&"also_bad".to_string()));
    }

    #[test]
    fn collect_failed_programs_empty_when_all_pass() {
        let csv = "file_name,prog_name,verdict\n\
                   a.bpf.o,prog1,success\n\
                   a.bpf.o,prog2,success\n";
        let mut object_map = HashMap::new();
        object_map.insert("a.bpf.o".to_string(), "pkg".to_string());

        let (headers, verdicts) = make_verdicts(csv, &object_map);
        let failed = collect_failed_programs(&headers, &verdicts);

        assert!(failed.is_empty());
    }

    #[test]
    fn collect_failed_programs_multiple_objects() {
        let csv = "file_name,prog_name,verdict\n\
                   a.bpf.o,prog1,failure\n\
                   b.bpf.o,prog2,success\n\
                   b.bpf.o,prog3,failure\n";
        let mut object_map = HashMap::new();
        object_map.insert("a.bpf.o".to_string(), "pkg_a".to_string());
        object_map.insert("b.bpf.o".to_string(), "pkg_b".to_string());

        let (headers, verdicts) = make_verdicts(csv, &object_map);
        let failed = collect_failed_programs(&headers, &verdicts);

        assert_eq!(failed.len(), 2);
        assert_eq!(failed["a.bpf.o"], vec!["prog1"]);
        assert_eq!(failed["b.bpf.o"], vec!["prog3"]);
    }

    // --- extract_failure_logs tests ---

    #[test]
    fn extract_failure_logs_parses_single_failure() {
        let output = "\
Processing 'test.bpf.o'...\n\
PROCESSING /tmp/test.bpf.o/bad_prog, DURATION US: 42, VERDICT: failure, VERIFIER LOG:\n\
0: R1=ctx() R10=fp0\n\
1: (79) r0 = *(u64 *)(r1 +0)\n\
R0 invalid mem access 'map_value_or_null'\n\
verification time 42 usec\n\
File         Program   Verdict\n\
-----------  --------  -------\n\
test.bpf.o   bad_prog  failure\n";

        let logs = extract_failure_logs(output);
        assert_eq!(logs.len(), 1);
        assert!(logs[0].0.contains("bad_prog"));
        assert!(logs[0].0.contains("VERDICT: failure"));
        assert!(logs[0].1.contains("R0 invalid mem access"));
        assert!(logs[0].1.contains("verification time 42 usec"));
        // Should NOT contain the table
        assert!(!logs[0].1.contains("File"));
    }

    #[test]
    fn extract_failure_logs_skips_success() {
        let output = "\
PROCESSING /tmp/test.bpf.o/good_prog, DURATION US: 10, VERDICT: success, VERIFIER LOG:\n\
verification time 10 usec\n\
PROCESSING /tmp/test.bpf.o/bad_prog, DURATION US: 42, VERDICT: failure, VERIFIER LOG:\n\
R0 invalid mem access\n\
File         Program   Verdict\n\
-----------  --------  -------\n";

        let logs = extract_failure_logs(output);
        assert_eq!(logs.len(), 1);
        assert!(logs[0].0.contains("bad_prog"));
    }

    #[test]
    fn extract_failure_logs_multiple_failures() {
        let output = "\
PROCESSING obj/prog_a, DURATION US: 10, VERDICT: failure, VERIFIER LOG:\n\
error A\n\
File  Prog  Verdict\n\
---   ---   ---\n\
PROCESSING obj/prog_b, DURATION US: 20, VERDICT: failure, VERIFIER LOG:\n\
error B\n\
File  Prog  Verdict\n\
---   ---   ---\n";

        let logs = extract_failure_logs(output);
        assert_eq!(logs.len(), 2);
        assert!(logs[0].1.contains("error A"));
        assert!(logs[1].1.contains("error B"));
    }

    #[test]
    fn extract_failure_logs_empty_output() {
        let logs = extract_failure_logs("");
        assert!(logs.is_empty());
    }

    #[test]
    fn extract_failure_logs_no_failures() {
        let output = "\
PROCESSING obj/prog, DURATION US: 10, VERDICT: success, VERIFIER LOG:\n\
all good\n\
File  Prog  Verdict\n";

        let logs = extract_failure_logs(output);
        assert!(logs.is_empty());
    }

    #[test]
    fn extract_failure_logs_preserves_file_in_log() {
        // A verifier log line starting with "File" but not containing "Verdict"
        // should NOT be treated as the results table header.
        let output = "\
PROCESSING obj/prog, DURATION US: 10, VERDICT: failure, VERIFIER LOG:\n\
0: R1=ctx()\n\
File offset 0x1234 references something\n\
R0 invalid mem access\n\
File         Program   Verdict\n\
-----------  --------  -------\n";

        let logs = extract_failure_logs(output);
        assert_eq!(logs.len(), 1);
        assert!(
            logs[0].1.contains("File offset 0x1234"),
            "log line starting with 'File' should be preserved: {}",
            logs[0].1
        );
        assert!(logs[0].1.contains("R0 invalid mem access"));
        // Table header should NOT be in the log
        assert!(!logs[0].1.contains("Verdict"));
    }

    // --- Integration tests (require clang + veristat + CAP_BPF) ---

    #[cfg(feature = "integration")]
    fn bpf_src(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("bpf")
            .join(name)
    }

    #[cfg(feature = "integration")]
    fn compile_bpf(src: &Path, out: &Path) {
        let status = Command::new("clang")
            .args(["-target", "bpf", "-O2", "-g", "-c"])
            .arg(src)
            .arg("-o")
            .arg(out)
            .status()
            .expect("clang not found — install clang to run integration tests");
        assert!(
            status.success(),
            "clang failed to compile {}",
            src.display()
        );
    }

    #[cfg(feature = "integration")]
    fn get_total_insns(csv_text: &str) -> u64 {
        let mut reader = csv::ReaderBuilder::new()
            .trim(csv::Trim::All)
            .from_reader(csv_text.as_bytes());
        let headers = reader.headers().unwrap().clone();
        let idx = headers
            .iter()
            .position(|h| h == "total_insns")
            .expect("CSV missing total_insns column");
        let record = reader.records().next().expect("no CSV records").unwrap();
        record
            .get(idx)
            .unwrap()
            .parse::<u64>()
            .expect("total_insns not a number")
    }

    #[test]
    #[cfg(feature = "integration")]
    fn integration_pass_program_verifies() {
        let tmp = tempfile::tempdir().unwrap();
        let obj = tmp.path().join("pass.bpf.o");
        compile_bpf(&bpf_src("pass.bpf.c"), &obj);

        let csv_output =
            run_veristat_csv(&[obj.clone()], None).expect("veristat failed on pass.bpf.o");

        let mut object_map = HashMap::new();
        object_map.insert("pass.bpf.o".to_string(), "test_pass".to_string());

        let (_, packages) = parse_and_group(&csv_output, &object_map).unwrap();
        let pv = packages.get("test_pass").expect("package not found");
        assert!(!pv.failed, "pass.bpf.o should verify successfully");
        assert!(!pv.records.is_empty(), "should have at least one record");
    }

    #[test]
    #[cfg(feature = "integration")]
    fn integration_fail_program_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let obj = tmp.path().join("fail.bpf.o");
        compile_bpf(&bpf_src("fail.bpf.c"), &obj);

        let csv_output =
            run_veristat_csv(&[obj.clone()], None).expect("veristat failed to run on fail.bpf.o");

        let mut object_map = HashMap::new();
        object_map.insert("fail.bpf.o".to_string(), "test_fail".to_string());

        let (headers, packages) = parse_and_group(&csv_output, &object_map).unwrap();
        let pv = packages.get("test_fail").expect("package not found");
        assert!(pv.failed, "fail.bpf.o should fail verification");

        let failed = collect_failed_programs(&headers, &packages);
        assert!(
            !failed.is_empty(),
            "collect_failed_programs should find failing programs"
        );
    }

    #[test]
    #[cfg(feature = "integration")]
    fn integration_rodata_changes_output() {
        let tmp = tempfile::tempdir().unwrap();
        let obj = tmp.path().join("pass.bpf.o");
        compile_bpf(&bpf_src("pass.bpf.c"), &obj);

        // Run without rodata overrides (defaults: mode=0, threshold=0)
        let csv_default =
            run_veristat_csv(&[obj.clone()], None).expect("veristat failed without globals");
        let insns_default = get_total_insns(&csv_default);

        // Write rodata overrides: mode=1 enables all branches, threshold=500
        let global_vars = vec!["mode = 1".to_string(), "threshold = 500".to_string()];
        let globals_path = write_globals_file(tmp.path(), &global_vars, "test").unwrap();

        let csv_rodata =
            run_veristat_csv(&[obj], Some(&globals_path)).expect("veristat failed with globals");
        let insns_rodata = get_total_insns(&csv_rodata);

        assert!(
            insns_rodata > insns_default,
            "rodata overrides should increase instruction count: \
             default={}, with rodata={}",
            insns_default,
            insns_rodata
        );
    }

    #[test]
    #[cfg(feature = "integration")]
    fn integration_verifier_logs_contain_error() {
        let tmp = tempfile::tempdir().unwrap();
        let obj = tmp.path().join("fail.bpf.o");
        compile_bpf(&bpf_src("fail.bpf.c"), &obj);

        let output = Command::new("veristat")
            .arg("-v")
            .arg(&obj)
            .output()
            .expect("veristat -v failed to run");
        let stdout = String::from_utf8_lossy(&output.stdout);

        let logs = extract_failure_logs(&stdout);
        assert!(!logs.is_empty(), "should extract failure logs");

        let all_logs: String = logs.iter().map(|(_, body)| body.as_str()).collect();
        assert!(
            all_logs.contains("map_value_or_null"),
            "verifier log should mention map_value_or_null, got: {}",
            all_logs
        );
    }

    // --- Round-trip rodata test helpers ---

    /// RAII guard that unpins a BPF program on drop (even on panic).
    #[cfg(feature = "integration")]
    struct BpfPin {
        path: String,
    }

    #[cfg(feature = "integration")]
    impl Drop for BpfPin {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    /// Parse bpftool JSON, handling both single-object and array-of-one formats.
    #[cfg(feature = "integration")]
    fn parse_bpftool_obj(output: &[u8]) -> serde_json::Value {
        let json: serde_json::Value =
            serde_json::from_slice(output).expect("failed to parse bpftool JSON");
        if let Some(arr) = json.as_array() {
            arr.first().cloned().expect("empty bpftool JSON array")
        } else {
            json
        }
    }

    /// Load a BPF program via bpftool and pin it. Returns a guard that unpins on drop.
    #[cfg(feature = "integration")]
    fn bpftool_load(obj: &Path, pin_path: &str) -> BpfPin {
        let status = Command::new("bpftool")
            .args(["prog", "load"])
            .arg(obj)
            .arg(pin_path)
            .status()
            .expect("bpftool not found — install bpftool to run integration tests");
        assert!(status.success(), "bpftool prog load failed");
        BpfPin {
            path: pin_path.to_string(),
        }
    }

    /// Get all map IDs for a pinned BPF program.
    #[cfg(feature = "integration")]
    fn bpftool_get_map_ids(pin_path: &str) -> Vec<u32> {
        let output = Command::new("bpftool")
            .args(["prog", "show", "pinned", pin_path, "-j"])
            .output()
            .expect("bpftool prog show failed");
        assert!(
            output.status.success(),
            "bpftool prog show failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let prog = parse_bpftool_obj(&output.stdout);
        prog["map_ids"]
            .as_array()
            .expect("no map_ids in bpftool prog show output")
            .iter()
            .map(|v| v.as_u64().unwrap() as u32)
            .collect()
    }

    /// Dump a BPF map to a JSON file via bpftool.
    #[cfg(feature = "integration")]
    fn bpftool_dump_map(map_id: u32, out_path: &Path) {
        bpftool_dump_map_flags(map_id, out_path, &["-j"]);
    }

    /// Dump a BPF map to a JSON file via bpftool (plain BTF format, no `-j`).
    ///
    /// Without `-j`, bpftool outputs decoded BTF directly under `value`
    /// (no `formatted` wrapper, no hex arrays). This is Format 2.
    #[cfg(feature = "integration")]
    fn bpftool_dump_map_plain(map_id: u32, out_path: &Path) {
        bpftool_dump_map_flags(map_id, out_path, &[]);
    }

    #[cfg(feature = "integration")]
    fn bpftool_dump_map_flags(map_id: u32, out_path: &Path, flags: &[&str]) {
        let output = Command::new("bpftool")
            .args(["map", "dump", "id", &map_id.to_string()])
            .args(flags)
            .output()
            .expect("bpftool map dump failed");
        assert!(
            output.status.success(),
            "bpftool map dump failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        std::fs::write(out_path, &output.stdout).expect("failed to write rodata dump");
    }

    #[test]
    #[cfg(feature = "integration")]
    fn integration_roundtrip_rodata() {
        let tmp = tempfile::tempdir().unwrap();
        let obj = tmp.path().join("roundtrip.bpf.o");
        compile_bpf(&bpf_src("roundtrip.bpf.c"), &obj);

        // Load the program via bpftool so we can dump its datasec maps
        let pin_path = format!("/sys/fs/bpf/cargo_veristat_test_{}", std::process::id());
        let _guard = bpftool_load(&obj, &pin_path);

        // Dump ALL maps, parse each as a datasec, collect globals
        let map_ids = bpftool_get_map_ids(&pin_path);
        let mut globals = Vec::new();
        let mut datasecs_found = 0;

        for (i, &id) in map_ids.iter().enumerate() {
            let dump_path = tmp.path().join(format!("map_{}.json", i));
            bpftool_dump_map(id, &dump_path);
            match crate::rodata::parse_rodata(&dump_path) {
                Ok(parsed) if !parsed.is_empty() => {
                    globals.extend(parsed);
                    datasecs_found += 1;
                }
                _ => {} // not a datasec map or empty
            }
        }

        assert!(
            datasecs_found >= 3,
            "expected .rodata, .data, and .bss maps, found {} datasecs",
            datasecs_found
        );

        // --- Type coverage: verify all expected types survived the round-trip ---

        // .rodata: int scalar
        assert!(
            globals.iter().any(|g| g.starts_with("mode = ")),
            "missing .rodata int scalar 'mode': {:?}",
            globals
        );
        // .rodata: unsigned long long (u64 > 2^32, not a boundary value)
        assert!(
            globals.iter().any(|g| g == "big_val = 5000000001"),
            "missing .rodata u64 'big_val': {:?}",
            globals
        );
        // .rodata: _Bool
        assert!(
            globals.iter().any(|g| g.starts_with("flag = ")),
            "missing .rodata _Bool 'flag': {:?}",
            globals
        );
        // .rodata: int array (arbitrary non-zero values)
        let arr_expected = [17, 42, 99, 253];
        for (i, &val) in arr_expected.iter().enumerate() {
            let expected = format!("arr[{}] = {}", i, val);
            assert!(
                globals.iter().any(|g| g == &expected),
                "missing or wrong .rodata 'arr[{}]', expected '{}': {:?}",
                i,
                expected,
                globals
            );
        }
        // .rodata: char array (string expanded to bytes)
        assert!(
            globals.iter().any(|g| g.starts_with("name[0] = ")),
            "missing .rodata char array 'name': {:?}",
            globals
        );
        // .data: arbitrary non-zero initializers
        assert!(
            globals.iter().any(|g| g == "data_counter = 137"),
            "missing .data 'data_counter': {:?}",
            globals
        );
        assert!(
            globals.iter().any(|g| g == "data_limit = 8642"),
            "missing .data 'data_limit': {:?}",
            globals
        );
        // .bss: zero-initialized
        assert!(
            globals.iter().any(|g| g == "bss_state = 0"),
            "missing .bss 'bss_state': {:?}",
            globals
        );
        assert!(
            globals.iter().any(|g| g == "bss_counter = 0"),
            "missing .bss 'bss_counter': {:?}",
            globals
        );

        // --- Lossless round-trip: all globals via -G should equal no -G ---

        let csv_baseline =
            run_veristat_csv(&[obj.clone()], None).expect("veristat failed without globals");
        let insns_baseline = get_total_insns(&csv_baseline);

        let globals_path = write_globals_file(tmp.path(), &globals, "roundtrip").unwrap();
        let csv_roundtrip = run_veristat_csv(&[obj.clone()], Some(&globals_path))
            .expect("veristat failed with round-trip globals");
        let insns_roundtrip = get_total_insns(&csv_roundtrip);

        assert_eq!(
            insns_baseline, insns_roundtrip,
            "round-trip globals should produce identical verification: \
             baseline={}, roundtrip={}",
            insns_baseline, insns_roundtrip
        );

        // --- Delta: modified .rodata globals change verification output ---

        let modified: Vec<String> = globals
            .iter()
            .map(|g| {
                if g.starts_with("mode = ") {
                    "mode = 1".to_string()
                } else {
                    g.clone()
                }
            })
            .collect();

        let modified_dir = tmp.path().join("modified");
        std::fs::create_dir(&modified_dir).unwrap();
        let modified_path = write_globals_file(&modified_dir, &modified, "modified").unwrap();

        let csv_modified = run_veristat_csv(&[obj], Some(&modified_path))
            .expect("veristat failed with modified globals");
        let insns_modified = get_total_insns(&csv_modified);

        assert!(
            insns_modified > insns_baseline,
            "modified globals (mode=1) should increase instruction count: \
             baseline={}, modified={}",
            insns_baseline,
            insns_modified
        );
    }

    /// Same as `integration_roundtrip_rodata` but uses `bpftool map dump` without
    /// `-j` (Format 2: decoded values directly under `value`, no `formatted` wrapper).
    #[test]
    #[cfg(feature = "integration")]
    fn integration_roundtrip_rodata_direct_value() {
        let tmp = tempfile::tempdir().unwrap();
        let obj = tmp.path().join("roundtrip.bpf.o");
        compile_bpf(&bpf_src("roundtrip.bpf.c"), &obj);

        let pin_path = format!("/sys/fs/bpf/cargo_veristat_test_dv_{}", std::process::id());
        let _guard = bpftool_load(&obj, &pin_path);

        let map_ids = bpftool_get_map_ids(&pin_path);
        let mut globals = Vec::new();
        let mut datasecs_found = 0;

        for (i, &id) in map_ids.iter().enumerate() {
            let dump_path = tmp.path().join(format!("map_dv_{}.json", i));
            bpftool_dump_map_plain(id, &dump_path);
            match crate::rodata::parse_rodata(&dump_path) {
                Ok(parsed) if !parsed.is_empty() => {
                    globals.extend(parsed);
                    datasecs_found += 1;
                }
                _ => {}
            }
        }

        assert!(
            datasecs_found >= 3,
            "expected .rodata, .data, and .bss maps from plain format, found {} datasecs",
            datasecs_found
        );

        // Spot-check key values survived the round-trip with Format 2
        assert!(
            globals.iter().any(|g| g == "big_val = 5000000001"),
            "missing .rodata u64 'big_val' in plain format: {:?}",
            globals
        );
        assert!(
            globals.iter().any(|g| g == "data_counter = 137"),
            "missing .data 'data_counter' in plain format: {:?}",
            globals
        );
        assert!(
            globals.iter().any(|g| g == "bss_state = 0"),
            "missing .bss 'bss_state' in plain format: {:?}",
            globals
        );

        // Lossless round-trip: globals from plain format feed back to veristat identically
        let csv_baseline =
            run_veristat_csv(&[obj.clone()], None).expect("veristat failed without globals");
        let insns_baseline = get_total_insns(&csv_baseline);

        let globals_path = write_globals_file(tmp.path(), &globals, "roundtrip_dv").unwrap();
        let csv_roundtrip = run_veristat_csv(&[obj], Some(&globals_path))
            .expect("veristat failed with plain-format round-trip globals");
        let insns_roundtrip = get_total_insns(&csv_roundtrip);

        assert_eq!(
            insns_baseline, insns_roundtrip,
            "plain-format round-trip globals should produce identical verification: \
             baseline={}, roundtrip={}",
            insns_baseline, insns_roundtrip
        );
    }
}
