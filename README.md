# cargo-veristat

[![CI](https://github.com/likewhatevs/cargo-veristat/actions/workflows/ci.yml/badge.svg)](https://github.com/likewhatevs/cargo-veristat/actions/workflows/ci.yml)
[![codecov](https://codecov.io/github/likewhatevs/cargo-veristat/graph/badge.svg)](https://codecov.io/github/likewhatevs/cargo-veristat)

A Cargo subcommand that runs [veristat](https://github.com/libbpf/veristat) verification on BPF programs embedded in Rust binaries. It automates the build-extract-verify pipeline for workspaces like [sched_ext](https://github.com/sched-ext/scx).

In addition to that, it supports playing rodata dumps through the verifier in the format bpftool map dump outputs. In other words, pair this with vng (i.e. iterate kernel versions) and rodata dumps (1 for each variation of your input rodata/variables) and the command `cargo veristat` will let you know if you are happy or sad.

## Prerequisites

- **veristat** on `$PATH` (`dnf install veristat` / `apt install veristat` / build from source)
- **CAP_BPF** — veristat needs BPF privileges, so run with `sudo`
- **clang** — required by build systems that compile BPF C code (e.g. `libbpf-cargo`)

## Install

```sh
cargo install --path .
```

## Usage

```sh
# Verify all binary packages in a workspace
sudo cargo veristat

# Verify specific packages
sudo cargo veristat scx_layered scx_rusty

# Verify packages in another workspace
sudo cargo veristat --manifest-path /path/to/Cargo.toml scx_layered

# Build with a specific profile
sudo cargo veristat --profile release scx_layered
```

For each package, `cargo veristat` will:

1. Build the package (if stale or missing)
2. Extract BPF `.o` objects from the binary's `.bpf.objs` ELF section
3. Run `veristat` on each object and report pass/fail per program
4. Re-run `veristat -v` on failing programs to show verifier error logs

## Rodata configurations

BPF programs often use `.rodata` globals (e.g. `nr_layers`, `smt_enabled`) that change which code paths the verifier explores. `cargo veristat` supports testing multiple rodata configurations to catch verification failures that only occur with specific settings.

### Auto-discovery

Place [bpftool](https://github.com/libbpf/bpftool) JSON dumps in a `veristat/` directory at the package root:

```
scheds/rust/scx_layered/
    Cargo.toml
    src/
    veristat/
        4_layers.json
        8_layers.json
        smt_disabled.json
```

Each `*.json` file is a bpftool map dump (the format produced by `bpftool map dump`). The filename stem becomes the configuration name. When a `veristat/` directory is present, `cargo veristat` runs N+1 verifications:

1. A **baseline** run with no globals
2. One run per JSON file, applying those globals via `veristat -G`

```
=== scx_layered / (baseline) [PASSED] ===
<veristat table>

=== scx_layered / 4_layers [PASSED] ===
<veristat table>

=== scx_layered / 8_layers [FAILED] ===
<veristat table>

=== Summary ===
  scx_layered / (baseline):  PASS
  scx_layered / 4_layers:    PASS
  scx_layered / 8_layers:    FAIL
```

Packages without a `veristat/` directory get a single run with no globals (the default behavior).

#### Creating a config file

Dump the rodata map from a running BPF program:

```sh
# Find the map ID
sudo bpftool map show | grep rodata

# Dump it
sudo bpftool map dump id <MAP_ID> -j > my_config.json
```

Edit the values in the JSON to represent the configuration you want to test, then drop the file into `veristat/`.

### Manual override (`--rodata`)

For one-off testing, pass a rodata dump directly. This requires exactly one target and bypasses auto-discovery:

```sh
sudo cargo veristat --rodata dump.json scx_layered
```

## Resizable map filtering

BPF's `RESIZABLE_ARRAY` macro creates `.data.X` / `.bss.X` sections with a 1-byte placeholder. The corresponding `X_len` variable in `.rodata` tells userspace how large the map is, but veristat can't resize maps — so setting `X_len` to a large value while the map stays at 1 byte causes false verification failures.

`cargo veristat` automatically detects these sections in the ELF objects and excludes the corresponding `_len` variables from globals. This applies to both auto-discovered configs and `--rodata`.

## GitHub Actions integration

`--stderr-gfm` and `--stderr-gfm-erronly` emit a GFM markdown report to stderr (suitable for `$GITHUB_STEP_SUMMARY`) and GitHub Actions workflow commands to stdout.

```sh
# Full mode: ::notice for passing runs, ::error for failures
sudo cargo veristat --stderr-gfm --profile ci scx_layered 2>> "$GITHUB_STEP_SUMMARY"

# Error-only mode: ::debug for passing runs (hidden by default), ::error for failures
sudo cargo veristat --stderr-gfm-erronly --profile ci scx_layered 2>> "$GITHUB_STEP_SUMMARY"
```

The GFM report includes:

1. A summary table with per-program pass/fail and instruction counts
2. System info (kernel version, git commit)
3. Truncated verifier error logs for failing programs (expanded by default)
4. Full verifier logs in collapsed sections (when logs exceed 40 lines)

The two flags are mutually exclusive. Normal stdout output (human-readable tables, verifier logs) is produced regardless.

## Disabling veristat for a package

Add to the package's `Cargo.toml`:

```toml
[package.metadata.veristat]
disable = true
```

Disabled packages are skipped during workspace-wide runs but can still be verified by naming them explicitly:

```sh
sudo cargo veristat disabled_package
```

