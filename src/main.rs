#![deny(dead_code)]

mod cli;
mod discovery;
mod extract;
mod gfm;
mod rodata;
mod veristat;

use anyhow::{Context, Result};
use clap::Parser;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process;
use std::time::SystemTime;

fn main() {
    let cli::Cargo::Veristat(args) = cli::Cargo::parse();

    if let Err(e) = run(args) {
        eprintln!("error: {:#}", e);
        process::exit(1);
    }
}

fn run(args: cli::Args) -> Result<()> {
    // --rodata applies to a single scheduler, so require exactly one target
    if args.rodata.is_some() && args.targets.len() != 1 {
        anyhow::bail!(
            "--rodata requires exactly one target package (e.g. `cargo veristat --rodata dump.json scx_layered`)"
        );
    }

    // Check veristat is available early
    veristat::check_veristat()?;

    // Load workspace metadata once
    let metadata = discovery::load_metadata(args.manifest_path.as_ref())?;

    // Discover packages
    let packages = discovery::discover(&metadata, &args.targets, args.manifest_path.as_ref())?;

    if packages.is_empty() {
        eprintln!("No packages found.");
        return Ok(());
    }

    println!(
        "Found {} package(s): {}",
        packages.len(),
        packages
            .iter()
            .map(|p| p.name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );

    // Get workspace target directory
    let target_dir = discovery::target_dir(&metadata);
    let profile_dir = profile_target_dir(args.profile.as_deref());

    // Build stale/missing packages and extract BPF objects
    let temp_dir = tempfile::tempdir().context("Failed to create temp directory")?;
    let mut objects_by_package: HashMap<String, Vec<PathBuf>> = HashMap::new();
    let mut build_errors: Vec<String> = Vec::new();

    for pkg in &packages {
        let binary_name = discovery::binary_name(&metadata, &pkg.name);
        let binary_path = target_dir.join(&profile_dir).join(&binary_name);

        // Build if stale or missing
        if is_stale(&binary_path, &pkg.manifest_dir) {
            println!("Building {}...", pkg.name);
            let mut cmd = process::Command::new("cargo");
            cmd.arg("build").arg("-p").arg(&pkg.name);
            if let Some(ref profile) = args.profile {
                cmd.arg("--profile").arg(profile);
            }
            if let Some(ref manifest) = args.manifest_path {
                cmd.arg("--manifest-path").arg(manifest);
            }
            let status = cmd
                .status()
                .with_context(|| format!("Failed to run cargo build for {}", pkg.name))?;
            if !status.success() {
                eprintln!("error: cargo build failed for {}", pkg.name);
                build_errors.push(pkg.name.clone());
                continue;
            }
        } else {
            println!("{} is up to date, skipping build.", pkg.name);
        }

        // Extract BPF objects — try .bpf.objs section first, then skeleton fallback
        let bpf_objects = match extract::extract_bpf_objects(&binary_path) {
            Ok(objs) => objs,
            Err(e) => {
                eprintln!(
                    "error: failed to extract BPF objects from {}: {:#}",
                    pkg.name, e
                );
                build_errors.push(pkg.name.clone());
                continue;
            }
        };

        let bpf_objects = if bpf_objects.is_empty() {
            match extract::find_skeleton_objects(&target_dir, &profile_dir, &pkg.name) {
                Ok(objs) => objs,
                Err(e) => {
                    eprintln!(
                        "error: failed to extract skeleton objects for {}: {:#}",
                        pkg.name, e
                    );
                    build_errors.push(pkg.name.clone());
                    continue;
                }
            }
        } else {
            bpf_objects
        };

        if bpf_objects.is_empty() {
            continue;
        }

        let mut paths = Vec::new();
        for obj in &bpf_objects {
            let filename = format!("{}_{}.bpf.o", pkg.name, obj.name);
            let obj_path = temp_dir.path().join(&filename);
            std::fs::write(&obj_path, &obj.data).with_context(|| {
                format!("Failed to write BPF object: {}", obj_path.display())
            })?;
            paths.push(obj_path);
        }

        println!(
            "  Extracted {} BPF object(s) from {}",
            paths.len(),
            pkg.name
        );
        objects_by_package.insert(pkg.name.clone(), paths);
    }

    if objects_by_package.is_empty() {
        eprintln!("No BPF objects extracted from any package.");
        process::exit(1);
    }

    // Build the list of veristat runs
    let mut runs: Vec<veristat::VeristatRun> = Vec::new();

    if let Some(rodata_path) = &args.rodata {
        // --rodata: single target, single run with those globals
        let pkg_name = &args.targets[0];
        if let Some(objects) = objects_by_package.get(pkg_name) {
            let vars = rodata::parse_rodata(rodata_path)?;
            let exclude = rodata::find_resizable_map_vars(objects);
            let (vars, removed) = rodata::filter_globals(vars, &exclude);
            if !removed.is_empty() {
                println!(
                    "Excluded {} resizable-map sizing variable(s): {}",
                    removed.len(),
                    removed.join(", ")
                );
            }

            runs.push(veristat::VeristatRun {
                key: veristat::RunKey {
                    package: pkg_name.clone(),
                    config: None,
                },
                objects: objects.clone(),
                globals: vars,
            });
        }
    } else {
        // Auto-discovery: for each package, check for veristat/ directory
        for (pkg_name, objects) in &objects_by_package {
            let pkg = packages.iter().find(|p| &p.name == pkg_name);
            let manifest_dir = pkg.map(|p| p.manifest_dir.as_path());

            let exclude = rodata::find_resizable_map_vars(objects);
            let configs = match manifest_dir {
                Some(dir) => rodata::discover_configs(dir, "veristat", &exclude)?,
                None => Vec::new(),
            };

            if configs.is_empty() {
                // No veristat/ dir: single baseline run (current behavior)
                runs.push(veristat::VeristatRun {
                    key: veristat::RunKey {
                        package: pkg_name.clone(),
                        config: None,
                    },
                    objects: objects.clone(),
                    globals: Vec::new(),
                });
            } else {
                // Baseline run first
                runs.push(veristat::VeristatRun {
                    key: veristat::RunKey {
                        package: pkg_name.clone(),
                        config: Some("(baseline)".into()),
                    },
                    objects: objects.clone(),
                    globals: Vec::new(),
                });
                // Then one run per config
                for config in configs {
                    runs.push(veristat::VeristatRun {
                        key: veristat::RunKey {
                            package: pkg_name.clone(),
                            config: Some(config.name),
                        },
                        objects: objects.clone(),
                        globals: config.globals,
                    });
                }
            }
        }
    }

    // Sort runs for deterministic ordering
    runs.sort_by(|a, b| a.key.cmp(&b.key));

    // Run veristat
    let gfm_mode = args.gfm_mode();

    let all_passed = if gfm_mode == cli::GfmMode::Off {
        veristat::run_and_report(&runs, temp_dir.path(), args.raw)?
    } else {
        let results = veristat::execute_runs(&runs, temp_dir.path())?;
        if results.is_empty() {
            println!("No BPF objects to verify.");
            true
        } else {
            let logs = veristat::collect_verifier_logs(&results);
            let all_passed = veristat::print_report(&results, &logs, temp_dir.path(), args.raw)?;
            gfm::report_gfm(gfm_mode, &results, &logs).context("Failed to write GFM report")?;
            all_passed
        }
    };

    // Report build errors
    if !build_errors.is_empty() {
        eprintln!("\nBuild/extract errors for: {}", build_errors.join(", "));
    }

    if !all_passed || !build_errors.is_empty() {
        process::exit(1);
    }

    Ok(())
}

/// Map a cargo `--profile` name to its target subdirectory.
///
/// Cargo uses `debug` for dev/test and `release` for release/bench.
/// Custom profiles use their name directly.
pub(crate) fn profile_target_dir(profile: Option<&str>) -> String {
    match profile {
        None | Some("dev") => "debug".into(),
        Some("test") => "debug".into(),
        Some("release") => "release".into(),
        Some("bench") => "release".into(),
        Some(custom) => custom.into(),
    }
}

/// Check if the binary is stale (missing or older than source files).
pub(crate) fn is_stale(binary: &Path, source_dir: &Path) -> bool {
    let binary_mtime = match std::fs::metadata(binary) {
        Ok(m) => match m.modified() {
            Ok(t) => t,
            Err(_) => return true,
        },
        Err(_) => return true, // binary doesn't exist
    };

    match newest_mtime(source_dir) {
        Ok(source_mtime) => source_mtime > binary_mtime,
        Err(_) => true, // can't read source dir, rebuild to be safe
    }
}

/// Recursively find the newest modification time in a directory.
pub(crate) fn newest_mtime(dir: &Path) -> Result<SystemTime> {
    let mut newest = SystemTime::UNIX_EPOCH;

    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Skip hidden dirs, target dir, and common non-source dirs
        if name_str.starts_with('.') || name_str == "target" {
            continue;
        }

        let ft = entry.file_type()?;
        if ft.is_dir() {
            if let Ok(t) = newest_mtime(&entry.path())
                && t > newest
            {
                newest = t;
            }
        } else if ft.is_file()
            && let Ok(modified) = entry.metadata()?.modified()
            && modified > newest
        {
            newest = modified;
        }
    }

    Ok(newest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn is_stale_returns_true_when_binary_missing() {
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("nonexistent");
        let source = dir.path();
        assert!(is_stale(&binary, source));
    }

    #[test]
    fn is_stale_returns_true_when_source_newer() {
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("bin");
        fs::write(&binary, b"old").unwrap();

        // Small sleep so mtime differs
        thread::sleep(Duration::from_millis(50));

        let src_dir = dir.path().join("src");
        fs::create_dir(&src_dir).unwrap();
        fs::write(src_dir.join("main.rs"), b"new").unwrap();

        assert!(is_stale(&binary, &src_dir));
    }

    #[test]
    fn is_stale_returns_false_when_binary_newer() {
        let dir = tempfile::tempdir().unwrap();
        let src_dir = dir.path().join("src");
        fs::create_dir(&src_dir).unwrap();
        fs::write(src_dir.join("main.rs"), b"source").unwrap();

        thread::sleep(Duration::from_millis(50));

        let binary = dir.path().join("bin");
        fs::write(&binary, b"binary").unwrap();

        assert!(!is_stale(&binary, &src_dir));
    }

    #[test]
    fn newest_mtime_skips_hidden_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let hidden = dir.path().join(".hidden");
        fs::create_dir(&hidden).unwrap();
        fs::write(hidden.join("file.txt"), b"hidden").unwrap();

        // The visible file is older but should be the only one found
        let visible = dir.path().join("visible.txt");
        fs::write(&visible, b"visible").unwrap();

        let mtime = newest_mtime(dir.path()).unwrap();
        let visible_mtime = fs::metadata(&visible).unwrap().modified().unwrap();
        assert_eq!(mtime, visible_mtime);
    }

    #[test]
    fn newest_mtime_skips_target_dir() {
        let dir = tempfile::tempdir().unwrap();

        let visible = dir.path().join("visible.txt");
        fs::write(&visible, b"visible").unwrap();

        thread::sleep(Duration::from_millis(50));

        let target = dir.path().join("target");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("newer.txt"), b"newer").unwrap();

        let mtime = newest_mtime(dir.path()).unwrap();
        let visible_mtime = fs::metadata(&visible).unwrap().modified().unwrap();
        assert_eq!(mtime, visible_mtime);
    }

    #[test]
    fn newest_mtime_finds_nested_file() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a").join("b");
        fs::create_dir_all(&nested).unwrap();

        fs::write(dir.path().join("top.txt"), b"top").unwrap();

        thread::sleep(Duration::from_millis(50));

        let deep = nested.join("deep.txt");
        fs::write(&deep, b"deep").unwrap();

        let mtime = newest_mtime(dir.path()).unwrap();
        let deep_mtime = fs::metadata(&deep).unwrap().modified().unwrap();
        assert_eq!(mtime, deep_mtime);
    }

    #[test]
    fn profile_target_dir_defaults_to_debug() {
        assert_eq!(profile_target_dir(None), "debug");
    }

    #[test]
    fn profile_target_dir_dev_maps_to_debug() {
        assert_eq!(profile_target_dir(Some("dev")), "debug");
    }

    #[test]
    fn profile_target_dir_test_maps_to_debug() {
        assert_eq!(profile_target_dir(Some("test")), "debug");
    }

    #[test]
    fn profile_target_dir_release() {
        assert_eq!(profile_target_dir(Some("release")), "release");
    }

    #[test]
    fn profile_target_dir_bench_maps_to_release() {
        assert_eq!(profile_target_dir(Some("bench")), "release");
    }

    #[test]
    fn profile_target_dir_custom() {
        assert_eq!(profile_target_dir(Some("ci")), "ci");
    }
}
