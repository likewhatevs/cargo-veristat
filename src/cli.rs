use clap::Parser;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GfmMode {
    Off,
    Full,
    ErrOnly,
}

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

    /// Build profile to use (e.g. release, ci). Defaults to dev.
    #[arg(long)]
    pub profile: Option<String>,

    /// Emit GFM markdown to stderr for $GITHUB_STEP_SUMMARY.
    #[arg(long)]
    pub stderr_gfm: bool,

    /// Like --stderr-gfm but uses ::debug:: for passing runs (hidden by default).
    #[arg(long, conflicts_with = "stderr_gfm")]
    pub stderr_gfm_erronly: bool,
}

impl Args {
    pub(crate) fn gfm_mode(&self) -> GfmMode {
        if self.stderr_gfm {
            GfmMode::Full
        } else if self.stderr_gfm_erronly {
            GfmMode::ErrOnly
        } else {
            GfmMode::Off
        }
    }
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

    #[test]
    fn parse_with_profile() {
        let args = parse(&["cargo", "veristat", "--profile", "release"]);
        assert_eq!(args.profile.unwrap(), "release");
    }

    #[test]
    fn parse_custom_profile() {
        let args = parse(&["cargo", "veristat", "--profile", "ci", "pkg_foo"]);
        assert_eq!(args.profile.unwrap(), "ci");
        assert_eq!(args.targets, vec!["pkg_foo"]);
    }

    #[test]
    fn parse_no_profile_is_none() {
        let args = parse(&["cargo", "veristat"]);
        assert!(args.profile.is_none());
    }

    #[test]
    fn parse_stderr_gfm() {
        let args = parse(&["cargo", "veristat", "--stderr-gfm"]);
        assert!(args.stderr_gfm);
        assert!(!args.stderr_gfm_erronly);
    }

    #[test]
    fn parse_stderr_gfm_erronly() {
        let args = parse(&["cargo", "veristat", "--stderr-gfm-erronly"]);
        assert!(!args.stderr_gfm);
        assert!(args.stderr_gfm_erronly);
    }

    #[test]
    fn parse_stderr_gfm_conflict() {
        let result =
            Cargo::try_parse_from(["cargo", "veristat", "--stderr-gfm", "--stderr-gfm-erronly"]);
        assert!(result.is_err());
    }

    #[test]
    fn gfm_mode_off_by_default() {
        let args = parse(&["cargo", "veristat"]);
        assert_eq!(args.gfm_mode(), GfmMode::Off);
    }

    #[test]
    fn gfm_mode_full() {
        let args = parse(&["cargo", "veristat", "--stderr-gfm"]);
        assert_eq!(args.gfm_mode(), GfmMode::Full);
    }

    #[test]
    fn gfm_mode_erronly() {
        let args = parse(&["cargo", "veristat", "--stderr-gfm-erronly"]);
        assert_eq!(args.gfm_mode(), GfmMode::ErrOnly);
    }
}
