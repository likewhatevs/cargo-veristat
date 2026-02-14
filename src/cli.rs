use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "cargo", bin_name = "cargo")]
pub enum Cargo {
    /// Run veristat verification on workspace packages
    Veristat(Args),
}

#[derive(Parser)]
pub struct Args {
    /// Specific packages to verify (default: all binary packages in workspace)
    pub targets: Vec<String>,

    /// Path to Cargo.toml
    #[arg(long)]
    pub manifest_path: Option<PathBuf>,

    /// Path to bpftool rodata JSON dump (from `bpftool map dump name <map>.rodata`)
    #[arg(long)]
    pub rodata: Option<PathBuf>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Args {
        let Cargo::Veristat(args) = Cargo::try_parse_from(args).unwrap();
        args
    }

    #[test]
    fn parse_no_targets() {
        let args = parse(&["cargo", "veristat"]);
        assert!(args.targets.is_empty());
        assert!(args.manifest_path.is_none());
    }

    #[test]
    fn parse_multiple_targets() {
        let args = parse(&["cargo", "veristat", "pkg_foo", "pkg_bar"]);
        assert_eq!(args.targets, vec!["pkg_foo", "pkg_bar"]);
    }

    #[test]
    fn parse_with_manifest_path() {
        let args = parse(&["cargo", "veristat", "--manifest-path", "/some/Cargo.toml"]);
        assert!(args.targets.is_empty());
        assert_eq!(
            args.manifest_path.unwrap(),
            PathBuf::from("/some/Cargo.toml")
        );
    }

    #[test]
    fn parse_targets_and_manifest_path() {
        let args = parse(&[
            "cargo",
            "veristat",
            "--manifest-path",
            "/some/Cargo.toml",
            "pkg_foo",
        ]);
        assert_eq!(args.targets, vec!["pkg_foo"]);
        assert_eq!(
            args.manifest_path.unwrap(),
            PathBuf::from("/some/Cargo.toml")
        );
    }

    #[test]
    fn parse_with_rodata() {
        let args = parse(&["cargo", "veristat", "--rodata", "/tmp/rodata.json"]);
        assert_eq!(args.rodata.unwrap(), PathBuf::from("/tmp/rodata.json"));
    }

    #[test]
    fn parse_rodata_with_targets() {
        let args = parse(&[
            "cargo",
            "veristat",
            "--rodata",
            "/tmp/rodata.json",
            "--manifest-path",
            "/some/Cargo.toml",
            "pkg_foo",
        ]);
        assert_eq!(args.rodata.unwrap(), PathBuf::from("/tmp/rodata.json"));
        assert_eq!(
            args.manifest_path.unwrap(),
            PathBuf::from("/some/Cargo.toml")
        );
        assert_eq!(args.targets, vec!["pkg_foo"]);
    }

    #[test]
    fn parse_no_rodata_is_none() {
        let args = parse(&["cargo", "veristat"]);
        assert!(args.rodata.is_none());
    }
}
