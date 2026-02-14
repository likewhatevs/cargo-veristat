use anyhow::{Context, Result};
use cargo_metadata::{Metadata, MetadataCommand};
use std::path::PathBuf;

pub struct BpfPackage {
    pub name: String,
    pub manifest_dir: PathBuf,
    pub disable_veristat: bool,
}

/// Discover packages in the workspace that may contain BPF objects.
///
/// Returns all workspace packages that have a binary target. Packages with
/// `[package.metadata.veristat] disable = true` are skipped unless explicitly
/// named in `targets`.
///
/// When `manifest_path` points to a specific package (not the workspace root)
/// and no explicit targets are given, discovery is scoped to just that package.
pub fn discover(
    metadata: &Metadata,
    targets: &[String],
    manifest_path: Option<&PathBuf>,
) -> Result<Vec<BpfPackage>> {
    let packages: Vec<BpfPackage> = metadata
        .packages
        .iter()
        .filter(|p| metadata.workspace_members.contains(&p.id))
        .filter(|p| p.targets.iter().any(|t| t.is_bin()))
        .map(|p| {
            let disable = p
                .metadata
                .get("veristat")
                .and_then(|v| v.get("disable"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            BpfPackage {
                name: p.name.clone(),
                manifest_dir: p.manifest_path.parent().unwrap().into(),
                disable_veristat: disable,
            }
        })
        .collect();

    if targets.is_empty() {
        // If --manifest-path points to a specific package, scope to it
        if let Some(scope) = manifest_scope(metadata, manifest_path) {
            return Ok(packages.into_iter().filter(|p| p.name == scope).collect());
        }
        // Return all non-disabled packages
        Ok(packages
            .into_iter()
            .filter(|p| !p.disable_veristat)
            .collect())
    } else {
        // Return only named targets (even if disabled)
        let result: Vec<BpfPackage> = packages
            .into_iter()
            .filter(|p| targets.contains(&p.name))
            .collect();

        // Warn about unknown targets
        for target in targets {
            if !result.iter().any(|p| p.name == *target) {
                eprintln!("warning: no package named '{}'", target);
            }
        }

        Ok(result)
    }
}

/// Find the binary name for a package from cached metadata.
pub fn binary_name(metadata: &Metadata, package_name: &str) -> String {
    metadata
        .packages
        .iter()
        .find(|p| p.name == package_name)
        .and_then(|pkg| {
            pkg.targets
                .iter()
                .find(|t| t.is_bin())
                .map(|t| t.name.clone())
        })
        .unwrap_or_else(|| package_name.to_string())
}

/// Get the workspace target directory from cached metadata.
pub fn target_dir(metadata: &Metadata) -> PathBuf {
    metadata.target_directory.clone().into()
}

/// If `manifest_path` points to a specific package's Cargo.toml (not the
/// workspace root), return that package's name so discovery can be scoped.
fn manifest_scope(metadata: &Metadata, manifest_path: Option<&PathBuf>) -> Option<String> {
    let manifest_path = manifest_path?;
    let manifest_path = std::fs::canonicalize(manifest_path).ok()?;

    let workspace_manifest: PathBuf =
        PathBuf::from(metadata.workspace_root.as_str()).join("Cargo.toml");
    let workspace_manifest = std::fs::canonicalize(&workspace_manifest).ok()?;

    if manifest_path == workspace_manifest {
        return None;
    }

    metadata
        .packages
        .iter()
        .find(|p| {
            std::fs::canonicalize(p.manifest_path.as_std_path())
                .ok()
                .as_deref()
                == Some(manifest_path.as_path())
        })
        .map(|p| p.name.clone())
}

/// Load workspace metadata.
pub fn load_metadata(manifest_path: Option<&PathBuf>) -> Result<Metadata> {
    let mut cmd = MetadataCommand::new();
    if let Some(path) = manifest_path {
        cmd.manifest_path(path);
    }
    cmd.exec().context("Failed to run cargo metadata")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_package(name: &str, metadata: serde_json::Value, has_bin: bool) -> serde_json::Value {
        let mut targets = vec![];
        if has_bin {
            targets.push(serde_json::json!({
                "name": name,
                "src_path": format!("/{}/src/main.rs", name),
                "kind": ["bin"],
                "crate_types": ["bin"],
                "required_features": [],
                "edition": "2021",
                "doctest": false,
                "test": true,
                "doc": true
            }));
        } else {
            targets.push(serde_json::json!({
                "name": name,
                "src_path": format!("/{}/src/lib.rs", name),
                "kind": ["lib"],
                "crate_types": ["lib"],
                "required_features": [],
                "edition": "2021",
                "doctest": true,
                "test": true,
                "doc": true
            }));
        }

        serde_json::json!({
            "name": name,
            "version": "0.1.0",
            "id": format!("{} 0.1.0 (path+file:///{})", name, name),
            "manifest_path": format!("/{}/Cargo.toml", name),
            "dependencies": [],
            "targets": targets,
            "features": {},
            "metadata": metadata,
            "authors": [],
            "categories": [],
            "keywords": [],
            "source": null,
            "description": null,
            "license": null,
            "license_file": null,
            "readme": null,
            "repository": null,
            "homepage": null,
            "documentation": null,
            "links": null,
            "publish": null,
            "default_run": null,
            "rust_version": null,
            "edition": "2021"
        })
    }

    fn mock_metadata() -> Metadata {
        let bin_foo = make_package("bin_foo", serde_json::Value::Null, true);
        let bin_bar = make_package(
            "bin_bar",
            serde_json::json!({"veristat": {"disable": true}}),
            true,
        );
        let some_lib = make_package("some_lib", serde_json::Value::Null, false);
        // A bin package that is NOT a workspace member (e.g. an external dep)
        let external_bin = make_package("external_bin", serde_json::Value::Null, true);

        let json = serde_json::json!({
            "packages": [bin_foo, bin_bar, some_lib, external_bin],
            "workspace_members": [
                "bin_foo 0.1.0 (path+file:///bin_foo)",
                "bin_bar 0.1.0 (path+file:///bin_bar)",
                "some_lib 0.1.0 (path+file:///some_lib)"
            ],
            "workspace_root": "/workspace",
            "target_directory": "/workspace/target",
            "version": 1,
            "resolve": null,
            "metadata": null
        });

        serde_json::from_value(json).expect("failed to parse mock metadata")
    }

    #[test]
    fn discover_no_targets_excludes_disabled_and_libs() {
        let meta = mock_metadata();
        let result = discover(&meta, &[], None).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "bin_foo");
    }

    #[test]
    fn discover_explicit_disabled_target_included() {
        let meta = mock_metadata();
        let targets = vec!["bin_bar".to_string()];
        let result = discover(&meta, &targets, None).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "bin_bar");
    }

    #[test]
    fn discover_unknown_target_returns_empty() {
        let meta = mock_metadata();
        let targets = vec!["nonexistent".to_string()];
        let result = discover(&meta, &targets, None).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn discover_lib_only_package_excluded() {
        let meta = mock_metadata();
        let result = discover(&meta, &[], None).unwrap();
        assert!(!result.iter().any(|p| p.name == "some_lib"));
    }

    #[test]
    fn discover_excludes_non_workspace_packages() {
        let meta = mock_metadata();
        let result = discover(&meta, &[], None).unwrap();
        assert!(!result.iter().any(|p| p.name == "external_bin"));
    }

    #[test]
    fn binary_name_known_package() {
        let meta = mock_metadata();
        assert_eq!(binary_name(&meta, "bin_foo"), "bin_foo");
    }

    #[test]
    fn binary_name_unknown_package_returns_name() {
        let meta = mock_metadata();
        assert_eq!(binary_name(&meta, "nonexistent"), "nonexistent");
    }

    /// Build mock metadata backed by real files on disk so canonicalize works.
    fn mock_metadata_on_disk(root: &std::path::Path) -> Metadata {
        // Create workspace root Cargo.toml
        std::fs::write(root.join("Cargo.toml"), b"[workspace]").unwrap();

        // Create package dirs with Cargo.toml
        for name in &["pkg_a", "pkg_b"] {
            let dir = root.join(name);
            std::fs::create_dir_all(dir.join("src")).unwrap();
            std::fs::write(dir.join("Cargo.toml"), b"[package]").unwrap();
            std::fs::write(dir.join("src/main.rs"), b"fn main(){}").unwrap();
        }

        let pkg = |name: &str| -> serde_json::Value {
            let dir = root.join(name);
            serde_json::json!({
                "name": name,
                "version": "0.1.0",
                "id": format!("{} 0.1.0 (path+file://{})", name, dir.display()),
                "manifest_path": dir.join("Cargo.toml").to_string_lossy(),
                "dependencies": [],
                "targets": [{
                    "name": name,
                    "src_path": dir.join("src/main.rs").to_string_lossy(),
                    "kind": ["bin"],
                    "crate_types": ["bin"],
                    "required_features": [],
                    "edition": "2021",
                    "doctest": false,
                    "test": true,
                    "doc": true
                }],
                "features": {},
                "metadata": null,
                "authors": [],
                "categories": [],
                "keywords": [],
                "source": null,
                "description": null,
                "license": null,
                "license_file": null,
                "readme": null,
                "repository": null,
                "homepage": null,
                "documentation": null,
                "links": null,
                "publish": null,
                "default_run": null,
                "rust_version": null,
                "edition": "2021"
            })
        };

        let json = serde_json::json!({
            "packages": [pkg("pkg_a"), pkg("pkg_b")],
            "workspace_members": [
                format!("pkg_a 0.1.0 (path+file://{})", root.join("pkg_a").display()),
                format!("pkg_b 0.1.0 (path+file://{})", root.join("pkg_b").display()),
            ],
            "workspace_root": root.to_string_lossy(),
            "target_directory": root.join("target").to_string_lossy(),
            "version": 1,
            "resolve": null,
            "metadata": null
        });

        serde_json::from_value(json).expect("failed to parse mock metadata")
    }

    #[test]
    fn discover_manifest_path_scopes_to_package() {
        let dir = tempfile::tempdir().unwrap();
        let meta = mock_metadata_on_disk(dir.path());
        let manifest = dir.path().join("pkg_a/Cargo.toml");
        let result = discover(&meta, &[], Some(&manifest)).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "pkg_a");
    }

    #[test]
    fn discover_workspace_manifest_returns_all() {
        let dir = tempfile::tempdir().unwrap();
        let meta = mock_metadata_on_disk(dir.path());
        let manifest = dir.path().join("Cargo.toml");
        let result = discover(&meta, &[], Some(&manifest)).unwrap();
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn discover_explicit_targets_ignore_manifest_scope() {
        let dir = tempfile::tempdir().unwrap();
        let meta = mock_metadata_on_disk(dir.path());
        let manifest = dir.path().join("pkg_a/Cargo.toml");
        let targets = vec!["pkg_b".to_string()];
        let result = discover(&meta, &targets, Some(&manifest)).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "pkg_b");
    }
}
