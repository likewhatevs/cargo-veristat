# cargo-veristat

[![CI](https://github.com/likewhatevs/cargo-veristat/actions/workflows/ci.yml/badge.svg)](https://github.com/likewhatevs/cargo-veristat/actions/workflows/ci.yml)
[![codecov](https://codecov.io/github/likewhatevs/cargo-veristat/graph/badge.svg)](https://codecov.io/github/likewhatevs/cargo-veristat)

A Cargo subcommand that runs [veristat](https://github.com/libbpf/veristat) verification on BPF programs embedded in Rust binaries. It automates the build-extract-verify pipeline for workspaces like [sched_ext](https://github.com/sched-ext/scx).

In addition to that, it supports playing rodata dumps through the verifier in the format bpftool map dump outputs. In other words, pair this with vng (i.e. iterate kernel versions) and rodata dumps (1 for each variation of your input rodata/variables) and the command `cargo veristat` will let you know if you are happy or sad.

## Prerequisites

- **veristat** on `$PATH` (`dnf install veristat` / `apt install veristat` / build from source)
- **CAP_BPF + CAP_PERFMON** — veristat needs BPF privileges, so run with `sudo` (or `setcap cap_bpf,cap_perfmon+ep $(which veristat)`)
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

Verifier logs have repeating cycles collapsed by default for readability. Use `--raw` to disable cycle collapse and see the full unprocessed verifier output.

## Cycle collapse

BPF verifier logs for loop-heavy programs can be enormous — the verifier unrolls loops and prints every iteration, producing thousands of nearly-identical lines that differ only in register state annotations. `cargo veristat` detects these repeating blocks and collapses them, keeping the first and last iteration so you can see the entry state and final state while skipping the repetitive middle.

The detection works by normalizing lines (stripping variable register annotations like `; R3_w=42`), finding the most frequently repeated line as an anchor, then computing the cycle period and count via stride-based gap analysis. Nested loops are handled by running up to 5 collapse passes. A cycle must repeat at least 6 times to be collapsed.

For example, a log like:

```
0: (b7) r1 = 0
; loop body @ balance.bpf.c:390
100: (07) r3 += 1  ; frame1: R3_w=0
101: (85) call helper#1
102: (05) goto pc-4
; loop body @ balance.bpf.c:390
100: (07) r3 += 1  ; frame1: R3_w=1
101: (85) call helper#1
102: (05) goto pc-4
  ... (200 more identical iterations) ...
; loop body @ balance.bpf.c:390
100: (07) r3 += 1  ; frame1: R3_w=202
101: (85) call helper#1
102: (05) goto pc-4
200: (95) exit
```

becomes:

```
0: (b7) r1 = 0
--- 203x of the following 4 lines ---
; loop body @ balance.bpf.c:390
100: (07) r3 += 1  ; frame1: R3_w=0
101: (85) call helper#1
102: (05) goto pc-4
--- 201 identical iterations omitted ---
; loop body @ balance.bpf.c:390
100: (07) r3 += 1  ; frame1: R3_w=202
101: (85) call helper#1
102: (05) goto pc-4
--- end repeat ---
200: (95) exit
```

If cycle collapse alone doesn't shrink a log enough for the GFM size budget, a top+bottom byte-budget truncation is applied — the beginning and end of the log are kept (where the most useful context typically lives) and the middle is cut with a `lines omitted` marker.

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
3. Verifier error logs for failing programs (cycle-collapsed and truncated to fit a 1MB size budget, expanded by default)
4. Full untruncated verifier logs in collapsed sections (included when they fit within the remaining budget)

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

