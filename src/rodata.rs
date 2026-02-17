use anyhow::{Context, Result};
use object::{Object, ObjectSection};
use serde_json::Value;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// A rodata configuration discovered from a `veristat/` directory.
pub struct RodataConfig {
    /// Filename stem, e.g. "4_layers"
    pub name: String,
    /// Parsed and filtered `var = value` lines
    pub globals: Vec<String>,
}

/// Parse a bpftool rodata JSON dump and return veristat `-G` lines.
///
/// Supports two bpftool output formats:
///
/// **Format 1** (`bpftool map dump -j`): decoded values under `formatted.value`:
/// ```json
/// [{"key": [...], "value": [...], "formatted": {"value": {".rodata": [...]}}}]
/// ```
///
/// **Format 2** (`bpftool map dump` without `-j`): decoded values directly under `value`:
/// ```json
/// [{"value": {".rodata": [...]}}]
/// ```
///
/// Returns lines like `var = 42`, `arr[0] = 1`, etc.
pub fn parse_rodata(path: &Path) -> Result<Vec<String>> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read rodata file: {}", path.display()))?;
    parse_rodata_json(&contents)
}

/// Find rodata variable names that control resizable BPF map sizes.
///
/// BPF's `RESIZABLE_ARRAY` macro creates `.data.X` (or `.bss.X`) sections
/// with a 1-byte placeholder. The corresponding `X_len` variable in
/// `.rodata` tells the runtime code how large the map actually is. Userspace
/// calls `set_value_size()` to resize the map before loading, but veristat
/// can't do this — so setting `X_len` to a large value while the map stays
/// at 1 byte causes false verification failures.
///
/// This function inspects BPF ELF objects to find such sections and returns
/// the set of `X_len` variable names that should be excluded from globals.
pub fn find_resizable_map_vars(bpf_objects: &[PathBuf]) -> HashSet<String> {
    let mut exclude = HashSet::new();

    for obj_path in bpf_objects {
        let data = match std::fs::read(obj_path) {
            Ok(d) => d,
            Err(_) => continue,
        };
        let elf = match object::File::parse(&*data) {
            Ok(f) => f,
            Err(_) => continue,
        };

        for section in elf.sections() {
            let name = match section.name() {
                Ok(n) => n,
                Err(_) => continue,
            };

            // Look for .data.X or .bss.X sections with size <= 1
            // (RESIZABLE_ARRAY placeholder)
            let map_name = if let Some(suffix) = name.strip_prefix(".data.") {
                suffix
            } else if let Some(suffix) = name.strip_prefix(".bss.") {
                suffix
            } else {
                continue;
            };

            if section.size() <= 1 && !map_name.is_empty() {
                exclude.insert(format!("{}_len", map_name));
            }
        }
    }

    exclude
}

/// Filter global variable lines, removing any whose base name is in `exclude`.
///
/// Each line has the form `var = value` or `var[i] = value`. The base name
/// is the part before any `[` or ` = `. Returns the filtered lines and the
/// set of base names that were actually removed.
pub fn filter_globals(
    globals: Vec<String>,
    exclude: &HashSet<String>,
) -> (Vec<String>, Vec<String>) {
    if exclude.is_empty() {
        return (globals, Vec::new());
    }

    let mut removed = HashSet::new();
    let filtered = globals
        .into_iter()
        .filter(|line| {
            let base = global_var_base_name(line);
            if exclude.contains(base) {
                removed.insert(base.to_string());
                false
            } else {
                true
            }
        })
        .collect();

    let mut removed: Vec<String> = removed.into_iter().collect();
    removed.sort();
    (filtered, removed)
}

/// Discover rodata configurations from JSON files in a directory.
///
/// Scans `{manifest_dir}/{dir_name}/` for `*.json` files, parses each with
/// `parse_rodata()`, filters with `filter_globals()`, and returns configs
/// sorted by name. Returns an empty Vec if the directory doesn't exist.
/// Fails loudly if a JSON file exists but can't be parsed.
pub fn discover_configs(
    manifest_dir: &Path,
    dir_name: &str,
    exclude_vars: &HashSet<String>,
) -> Result<Vec<RodataConfig>> {
    let dir = manifest_dir.join(dir_name);
    if !dir.is_dir() {
        return Ok(Vec::new());
    }

    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .with_context(|| format!("Failed to read directory: {}", dir.display()))?
        .collect::<std::io::Result<Vec<_>>>()
        .with_context(|| format!("Failed to read directory entries: {}", dir.display()))?;

    entries.sort_by_key(|e| e.file_name());

    let mut configs = Vec::new();
    for entry in entries {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }

        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();

        if name.is_empty() {
            continue;
        }

        let globals = parse_rodata(&path)
            .with_context(|| format!("Failed to parse config: {}", path.display()))?;
        let (globals, removed) = filter_globals(globals, exclude_vars);
        if !removed.is_empty() {
            eprintln!(
                "note: excluded {} resizable-map variable(s) from {}: {}",
                removed.len(),
                path.display(),
                removed.join(", ")
            );
        }

        if globals.is_empty() {
            eprintln!(
                "note: all variables in {} were excluded, skipping",
                path.display()
            );
            continue;
        }

        configs.push(RodataConfig { name, globals });
    }

    Ok(configs)
}

/// Extract the base variable name from a globals line.
///
/// `"foo = 42"` → `"foo"`, `"arr[0] = 1"` → `"arr"`, `"m[0][1] = 3"` → `"m"`
fn global_var_base_name(line: &str) -> &str {
    let before_eq = line.split(" = ").next().unwrap_or("");
    before_eq.split('[').next().unwrap_or("")
}

/// Extract variable entries from any BTF datasec in bpftool JSON.
///
/// Tries `formatted.value.<section>` first (Format 1, `-j` flag), then
/// falls back to `value.<section>` as an object (Format 2, no `-j`).
/// If `value` is an array (raw hex bytes), `as_object()` returns `None`
/// and the fallback is correctly skipped.
fn extract_datasec_entries(root: &Value) -> Option<Vec<&Value>> {
    let first = root.as_array()?.first()?;

    let sections = first
        .get("formatted")
        .and_then(|f| f.get("value"))
        .and_then(|v| v.as_object())
        .or_else(|| first.get("value").and_then(|v| v.as_object()));

    let sections = sections?;

    let mut entries = Vec::new();
    for section in sections.values() {
        if let Some(arr) = section.as_array() {
            entries.extend(arr.iter());
        }
    }

    Some(entries)
}

fn parse_rodata_json(json: &str) -> Result<Vec<String>> {
    let root: Value = serde_json::from_str(json).context("Failed to parse globals JSON")?;

    let entries = extract_datasec_entries(&root)
        .context("Unexpected bpftool JSON structure: expected [{\"formatted\": {\"value\": {\"<section>\": [...]}}}] or [{\"value\": {\"<section>\": [...]}}]")?;

    let mut lines = Vec::new();

    for entry in entries {
        if let Some(obj) = entry.as_object() {
            for (key, value) in obj {
                // Skip variables with dots in their name (e.g. BPF format strings
                // like `func.____fmt`). Veristat's -G parser interprets dots as
                // struct field access, so these can't be set and would cause
                // "preset not applied" errors.
                if key.contains('.') {
                    continue;
                }

                emit_value(&mut lines, key, value);
            }
        }
    }

    Ok(lines)
}

fn emit_value(lines: &mut Vec<String>, prefix: &str, value: &Value) {
    match value {
        Value::Number(n) => {
            lines.push(format!("{} = {}", prefix, n));
        }
        Value::Bool(b) => {
            lines.push(format!("{} = {}", prefix, if *b { 1 } else { 0 }));
        }
        Value::String(s) => {
            // Expand string as byte array including NUL terminator
            for (i, byte) in s.bytes().enumerate() {
                lines.push(format!("{}[{}] = {}", prefix, i, byte));
            }
            // NUL terminator
            lines.push(format!("{}[{}] = 0", prefix, s.len()));
        }
        Value::Array(arr) => {
            for (i, elem) in arr.iter().enumerate() {
                let indexed = format!("{}[{}]", prefix, i);
                emit_value(lines, &indexed, elem);
            }
        }
        other => {
            eprintln!(
                "warning: skipping unsupported rodata value for '{}': {}",
                prefix, other
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(json: &str) -> Vec<String> {
        parse_rodata_json(json).unwrap()
    }

    fn rodata_json(entries: &str) -> String {
        format!(r#"[{{"formatted": {{"value": {{".rodata": [{entries}]}}}}}}]"#)
    }

    fn datasec_json(section: &str, entries: &str) -> String {
        format!(r#"[{{"formatted": {{"value": {{"{section}": [{entries}]}}}}}}]"#)
    }

    #[test]
    fn data_section_parsed() {
        let json = datasec_json(".data", r#"{"counter": 42}"#);
        assert_eq!(parse(&json), vec!["counter = 42"]);
    }

    #[test]
    fn bss_section_parsed() {
        let json = datasec_json(".bss", r#"{"zeroed": 0}, {"flag": false}"#);
        assert_eq!(parse(&json), vec!["zeroed = 0", "flag = 0"]);
    }

    #[test]
    fn custom_datasec_parsed() {
        let json = datasec_json(".data.my_section", r#"{"x": 99}"#);
        assert_eq!(parse(&json), vec!["x = 99"]);
    }

    #[test]
    fn scalar_integer() {
        let json = rodata_json(r#"{"nr_layers": 4}"#);
        assert_eq!(parse(&json), vec!["nr_layers = 4"]);
    }

    #[test]
    fn boolean_true() {
        let json = rodata_json(r#"{"smt_enabled": true}"#);
        assert_eq!(parse(&json), vec!["smt_enabled = 1"]);
    }

    #[test]
    fn boolean_false() {
        let json = rodata_json(r#"{"smt_enabled": false}"#);
        assert_eq!(parse(&json), vec!["smt_enabled = 0"]);
    }

    #[test]
    fn array_of_ints() {
        let json = rodata_json(r#"{"order": [10, 20, 30]}"#);
        assert_eq!(
            parse(&json),
            vec!["order[0] = 10", "order[1] = 20", "order[2] = 30"]
        );
    }

    #[test]
    fn array_of_bools() {
        let json = rodata_json(r#"{"flags": [true, false, true]}"#);
        assert_eq!(
            parse(&json),
            vec!["flags[0] = 1", "flags[1] = 0", "flags[2] = 1"]
        );
    }

    #[test]
    fn string_expanded_as_bytes() {
        // Non-dotted string variable names get byte-expanded
        let json = rodata_json(r#"{"hi_fb_thread_name": "AB"}"#);
        assert_eq!(
            parse(&json),
            vec![
                "hi_fb_thread_name[0] = 65",
                "hi_fb_thread_name[1] = 66",
                "hi_fb_thread_name[2] = 0",
            ]
        );
    }

    #[test]
    fn nested_array() {
        let json = rodata_json(r#"{"matrix": [[1, 2], [3, 4]]}"#);
        assert_eq!(
            parse(&json),
            vec![
                "matrix[0][0] = 1",
                "matrix[0][1] = 2",
                "matrix[1][0] = 3",
                "matrix[1][1] = 4",
            ]
        );
    }

    #[test]
    fn multiple_entries() {
        let json = rodata_json(r#"{"a": 1}, {"b": true}, {"c": [5]}"#);
        assert_eq!(parse(&json), vec!["a = 1", "b = 1", "c[0] = 5"]);
    }

    #[test]
    fn empty_rodata() {
        let json = rodata_json("");
        assert_eq!(parse(&json), Vec::<String>::new());
    }

    #[test]
    fn null_value_skipped() {
        let json = rodata_json(r#"{"x": null}"#);
        assert_eq!(parse(&json), Vec::<String>::new());
    }

    #[test]
    fn object_value_skipped() {
        let json = rodata_json(r#"{"x": {"nested": 1}}"#);
        assert_eq!(parse(&json), Vec::<String>::new());
    }

    #[test]
    fn mixed_types() {
        let json = rodata_json(
            r#"{"nr_layers": 4}, {"smt_enabled": true}, {"order": [0, 1]}, {"name": "A"}, {"bad": null}"#,
        );
        assert_eq!(
            parse(&json),
            vec![
                "nr_layers = 4",
                "smt_enabled = 1",
                "order[0] = 0",
                "order[1] = 1",
                "name[0] = 65",
                "name[1] = 0",
            ]
        );
    }

    #[test]
    fn parse_rodata_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rodata.json");
        std::fs::write(
            &path,
            r#"[{"formatted": {"value": {".rodata": [{"nr_layers": 4}]}}}]"#,
        )
        .unwrap();
        let result = parse_rodata(&path).unwrap();
        assert_eq!(result, vec!["nr_layers = 4"]);
    }

    #[test]
    fn dotted_names_skipped() {
        // BPF format strings have dotted names like `func.____fmt`.
        // Veristat -G interprets dots as struct field access, so these
        // can't be set and must be skipped.
        let json = rodata_json(
            r#"{"nr_layers": 4}, {"match_layer.____fmt": "MATCH %s"}, {"smt_enabled": true}"#,
        );
        assert_eq!(parse(&json), vec!["nr_layers = 4", "smt_enabled = 1"]);
    }

    #[test]
    fn real_bpftool_structure() {
        // Real bpftool output has key, value (raw hex), and formatted
        let json = r#"[{
            "key": ["0x00","0x00","0x00","0x00"],
            "value": ["0x04","0x00"],
            "formatted": {
                "value": {
                    ".rodata": [
                        {"nr_layers": 4},
                        {"smt_enabled": true}
                    ]
                }
            }
        }]"#;
        assert_eq!(parse(json), vec!["nr_layers = 4", "smt_enabled = 1"]);
    }

    #[test]
    fn large_u64() {
        // Real rodata contains u64::MAX (e.g. __SCX_SLICE_INF = 18446744073709551615).
        // Verify serde_json preserves full precision and doesn't downcast to f64.
        let json = rodata_json(r#"{"__SCX_SLICE_INF": 18446744073709551615}"#);
        assert_eq!(parse(&json), vec!["__SCX_SLICE_INF = 18446744073709551615"]);
    }

    #[test]
    fn large_u64_above_i64_max() {
        // Values > i64::MAX but < u64::MAX (e.g. __SCX_DSQ_FLAG_BUILTIN = 2^63)
        let json = rodata_json(r#"{"flag": 9223372036854775808}"#);
        assert_eq!(parse(&json), vec!["flag = 9223372036854775808"]);
    }

    #[test]
    fn negative_integer() {
        // __sibling_cpu array contains -1 for CPUs without SMT siblings
        let json = rodata_json(r#"{"sibling": [-1, 0, -1, 1]}"#);
        assert_eq!(
            parse(&json),
            vec![
                "sibling[0] = -1",
                "sibling[1] = 0",
                "sibling[2] = -1",
                "sibling[3] = 1",
            ]
        );
    }

    #[test]
    fn empty_string() {
        // Empty string should emit only the NUL terminator
        let json = rodata_json(r#"{"name": ""}"#);
        assert_eq!(parse(&json), vec!["name[0] = 0"]);
    }

    #[test]
    fn empty_array() {
        // Empty array produces no output lines
        let json = rodata_json(r#"{"arr": []}"#);
        assert_eq!(parse(&json), Vec::<String>::new());
    }

    #[test]
    fn parse_rodata_empty_outer_array() {
        let result = parse_rodata_json("[]");
        assert!(result.is_err());
    }

    #[test]
    fn parse_rodata_file_not_found() {
        let result = parse_rodata(Path::new("/nonexistent/rodata.json"));
        assert!(result.is_err());
    }

    #[test]
    fn parse_rodata_invalid_json() {
        let result = parse_rodata_json("not json");
        assert!(result.is_err());
    }

    #[test]
    fn parse_rodata_wrong_structure() {
        let result = parse_rodata_json(r#"{"wrong": "structure"}"#);
        assert!(result.is_err());
    }

    /// Create a minimal ELF file with the given section names and sizes.
    fn create_test_elf(sections: &[(&str, usize)]) -> Vec<u8> {
        use object::write::Object as WriteObject;
        use object::{Architecture, BinaryFormat, Endianness};

        let mut obj = WriteObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);

        for (name, size) in sections {
            let section_id = obj.add_section(
                Vec::new(),
                name.as_bytes().to_vec(),
                object::SectionKind::Data,
            );
            obj.section_mut(section_id).set_data(vec![0u8; *size], 1);
        }

        obj.write().unwrap()
    }

    #[test]
    fn resizable_map_detects_small_data_section() {
        let elf = create_test_elf(&[(".data.uei_dump", 1)]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.bpf.o");
        std::fs::write(&path, &elf).unwrap();

        let result = find_resizable_map_vars(&[path]);
        assert!(result.contains("uei_dump_len"));
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn resizable_map_skips_normal_data_section() {
        // .data.cpumask with size 8 is NOT a resizable array
        let elf = create_test_elf(&[(".data.cpumask", 8)]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.bpf.o");
        std::fs::write(&path, &elf).unwrap();

        let result = find_resizable_map_vars(&[path]);
        assert!(result.is_empty());
    }

    #[test]
    fn resizable_map_detects_bss_section() {
        let elf = create_test_elf(&[(".bss.dump_buf", 1)]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.bpf.o");
        std::fs::write(&path, &elf).unwrap();

        let result = find_resizable_map_vars(&[path]);
        assert!(result.contains("dump_buf_len"));
    }

    #[test]
    fn resizable_map_detects_zero_size_section() {
        let elf = create_test_elf(&[(".data.buf", 0)]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.bpf.o");
        std::fs::write(&path, &elf).unwrap();

        let result = find_resizable_map_vars(&[path]);
        assert!(result.contains("buf_len"));
    }

    #[test]
    fn resizable_map_ignores_plain_data_section() {
        // Plain .data (no suffix) should not generate any exclusions
        let elf = create_test_elf(&[(".data", 1)]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.bpf.o");
        std::fs::write(&path, &elf).unwrap();

        let result = find_resizable_map_vars(&[path]);
        assert!(result.is_empty());
    }

    #[test]
    fn resizable_map_multiple_objects() {
        let dir = tempfile::tempdir().unwrap();

        let elf1 = create_test_elf(&[(".data.uei_dump", 1), (".data.cpumask", 8)]);
        let path1 = dir.path().join("a.bpf.o");
        std::fs::write(&path1, &elf1).unwrap();

        let elf2 = create_test_elf(&[(".bss.other_buf", 0)]);
        let path2 = dir.path().join("b.bpf.o");
        std::fs::write(&path2, &elf2).unwrap();

        let result = find_resizable_map_vars(&[path1, path2]);
        assert_eq!(result.len(), 2);
        assert!(result.contains("uei_dump_len"));
        assert!(result.contains("other_buf_len"));
    }

    #[test]
    fn resizable_map_empty_objects() {
        let result = find_resizable_map_vars(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn resizable_map_nonexistent_file() {
        let result = find_resizable_map_vars(&[PathBuf::from("/nonexistent/test.bpf.o")]);
        assert!(result.is_empty());
    }

    #[test]
    fn resizable_map_skips_bss_with_large_size() {
        // .bss.X with size > 1 is NOT a resizable array
        let elf = create_test_elf(&[(".bss.large_buf", 64)]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.bpf.o");
        std::fs::write(&path, &elf).unwrap();

        let result = find_resizable_map_vars(&[path]);
        assert!(result.is_empty());
    }

    #[test]
    fn resizable_map_ignores_rodata_sections() {
        // .rodata.X sections are const data, not resizable maps
        let elf = create_test_elf(&[(".rodata.config", 1)]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.bpf.o");
        std::fs::write(&path, &elf).unwrap();

        let result = find_resizable_map_vars(&[path]);
        assert!(result.is_empty());
    }

    #[test]
    fn resizable_map_size_boundary_two_bytes() {
        // .data.X with size 2 is NOT a resizable array placeholder
        let elf = create_test_elf(&[(".data.small", 2)]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.bpf.o");
        std::fs::write(&path, &elf).unwrap();

        let result = find_resizable_map_vars(&[path]);
        assert!(result.is_empty());
    }

    #[test]
    fn resizable_map_invalid_file_skipped() {
        // Non-ELF file should be silently skipped, not panic
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("garbage.bpf.o");
        std::fs::write(&path, b"this is not an ELF file").unwrap();

        let result = find_resizable_map_vars(&[path]);
        assert!(result.is_empty());
    }

    // --- filter_globals tests ---

    #[test]
    fn global_var_base_name_scalar() {
        assert_eq!(global_var_base_name("nr_layers = 4"), "nr_layers");
    }

    #[test]
    fn global_var_base_name_array() {
        assert_eq!(global_var_base_name("order[0] = 10"), "order");
    }

    #[test]
    fn global_var_base_name_nested_array() {
        assert_eq!(global_var_base_name("matrix[0][1] = 3"), "matrix");
    }

    #[test]
    fn filter_globals_removes_matching_scalar() {
        let globals = vec![
            "nr_layers = 4".to_string(),
            "uei_dump_len = 32768".to_string(),
            "smt_enabled = 1".to_string(),
        ];
        let exclude: HashSet<String> = ["uei_dump_len".to_string()].into();

        let (filtered, removed) = filter_globals(globals, &exclude);
        assert_eq!(filtered, vec!["nr_layers = 4", "smt_enabled = 1"]);
        assert_eq!(removed, vec!["uei_dump_len"]);
    }

    #[test]
    fn filter_globals_removes_matching_array_by_base_name() {
        // If a _len var were hypothetically an array, all elements
        // should be removed based on the base name.
        let globals = vec![
            "nr_layers = 4".to_string(),
            "buf_len[0] = 1".to_string(),
            "buf_len[1] = 2".to_string(),
            "smt_enabled = 1".to_string(),
        ];
        let exclude: HashSet<String> = ["buf_len".to_string()].into();

        let (filtered, removed) = filter_globals(globals, &exclude);
        assert_eq!(filtered, vec!["nr_layers = 4", "smt_enabled = 1"]);
        assert_eq!(removed, vec!["buf_len"]);
    }

    #[test]
    fn filter_globals_empty_exclude_is_noop() {
        let globals = vec!["x = 1".to_string(), "y = 2".to_string()];
        let exclude = HashSet::new();

        let (filtered, removed) = filter_globals(globals, &exclude);
        assert_eq!(filtered, vec!["x = 1", "y = 2"]);
        assert!(removed.is_empty());
    }

    #[test]
    fn filter_globals_no_matches() {
        let globals = vec!["nr_layers = 4".to_string()];
        let exclude: HashSet<String> = ["nonexistent_len".to_string()].into();

        let (filtered, removed) = filter_globals(globals, &exclude);
        assert_eq!(filtered, vec!["nr_layers = 4"]);
        assert!(removed.is_empty());
    }

    #[test]
    fn filter_globals_does_not_partial_match() {
        // "uei_dump_len_extra" should NOT be removed by exclude "uei_dump_len"
        let globals = vec![
            "uei_dump_len_extra = 99".to_string(),
            "uei_dump_len = 32768".to_string(),
        ];
        let exclude: HashSet<String> = ["uei_dump_len".to_string()].into();

        let (filtered, removed) = filter_globals(globals, &exclude);
        assert_eq!(filtered, vec!["uei_dump_len_extra = 99"]);
        assert_eq!(removed, vec!["uei_dump_len"]);
    }

    // --- discover_configs tests ---

    fn write_rodata_json(dir: &Path, filename: &str, entries: &str) {
        let json = format!(r#"[{{"formatted": {{"value": {{".rodata": [{entries}]}}}}}}]"#);
        std::fs::write(dir.join(filename), json).unwrap();
    }

    #[test]
    fn discover_configs_finds_json_files() {
        let dir = tempfile::tempdir().unwrap();
        let veristat_dir = dir.path().join("veristat");
        std::fs::create_dir(&veristat_dir).unwrap();
        write_rodata_json(&veristat_dir, "4_layers.json", r#"{"nr_layers": 4}"#);
        write_rodata_json(&veristat_dir, "8_layers.json", r#"{"nr_layers": 8}"#);

        let configs = discover_configs(dir.path(), "veristat", &HashSet::new()).unwrap();
        assert_eq!(configs.len(), 2);
        assert_eq!(configs[0].name, "4_layers");
        assert_eq!(configs[0].globals, vec!["nr_layers = 4"]);
        assert_eq!(configs[1].name, "8_layers");
        assert_eq!(configs[1].globals, vec!["nr_layers = 8"]);
    }

    #[test]
    fn discover_configs_no_dir() {
        let dir = tempfile::tempdir().unwrap();
        let configs = discover_configs(dir.path(), "veristat", &HashSet::new()).unwrap();
        assert!(configs.is_empty());
    }

    #[test]
    fn discover_configs_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("veristat")).unwrap();
        let configs = discover_configs(dir.path(), "veristat", &HashSet::new()).unwrap();
        assert!(configs.is_empty());
    }

    #[test]
    fn discover_configs_ignores_non_json() {
        let dir = tempfile::tempdir().unwrap();
        let veristat_dir = dir.path().join("veristat");
        std::fs::create_dir(&veristat_dir).unwrap();
        write_rodata_json(&veristat_dir, "good.json", r#"{"x": 1}"#);
        std::fs::write(veristat_dir.join("readme.txt"), "not json").unwrap();
        std::fs::write(veristat_dir.join("notes.md"), "# notes").unwrap();

        let configs = discover_configs(dir.path(), "veristat", &HashSet::new()).unwrap();
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].name, "good");
    }

    #[test]
    fn discover_configs_sorted_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let veristat_dir = dir.path().join("veristat");
        std::fs::create_dir(&veristat_dir).unwrap();
        write_rodata_json(&veristat_dir, "zebra.json", r#"{"z": 1}"#);
        write_rodata_json(&veristat_dir, "alpha.json", r#"{"a": 1}"#);
        write_rodata_json(&veristat_dir, "middle.json", r#"{"m": 1}"#);

        let configs = discover_configs(dir.path(), "veristat", &HashSet::new()).unwrap();
        let names: Vec<&str> = configs.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, vec!["alpha", "middle", "zebra"]);
    }

    #[test]
    fn discover_configs_filters_resizable_vars() {
        let dir = tempfile::tempdir().unwrap();
        let veristat_dir = dir.path().join("veristat");
        std::fs::create_dir(&veristat_dir).unwrap();
        write_rodata_json(
            &veristat_dir,
            "config.json",
            r#"{"nr_layers": 4}, {"uei_dump_len": 32768}, {"smt_enabled": true}"#,
        );

        let exclude: HashSet<String> = ["uei_dump_len".to_string()].into();
        let configs = discover_configs(dir.path(), "veristat", &exclude).unwrap();
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].globals, vec!["nr_layers = 4", "smt_enabled = 1"]);
    }

    #[test]
    fn discover_configs_skips_all_filtered() {
        let dir = tempfile::tempdir().unwrap();
        let veristat_dir = dir.path().join("veristat");
        std::fs::create_dir(&veristat_dir).unwrap();
        // Config where every variable is in the exclude set
        write_rodata_json(
            &veristat_dir,
            "only_resizable.json",
            r#"{"uei_dump_len": 32768}"#,
        );
        // Config with a mix — one survives filtering
        write_rodata_json(
            &veristat_dir,
            "mixed.json",
            r#"{"nr_layers": 4}, {"uei_dump_len": 32768}"#,
        );

        let exclude: HashSet<String> = ["uei_dump_len".to_string()].into();
        let configs = discover_configs(dir.path(), "veristat", &exclude).unwrap();
        // only_resizable.json should be skipped (all vars filtered)
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].name, "mixed");
        assert_eq!(configs[0].globals, vec!["nr_layers = 4"]);
    }

    #[test]
    fn discover_configs_ignores_subdirectories() {
        let dir = tempfile::tempdir().unwrap();
        let veristat_dir = dir.path().join("veristat");
        std::fs::create_dir(&veristat_dir).unwrap();
        write_rodata_json(&veristat_dir, "good.json", r#"{"x": 1}"#);

        // Create a subdirectory — should be ignored
        let subdir = veristat_dir.join("subdir");
        std::fs::create_dir(&subdir).unwrap();
        write_rodata_json(&subdir, "nested.json", r#"{"y": 2}"#);

        let configs = discover_configs(dir.path(), "veristat", &HashSet::new()).unwrap();
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].name, "good");
    }

    #[test]
    fn discover_configs_invalid_json_fails() {
        let dir = tempfile::tempdir().unwrap();
        let veristat_dir = dir.path().join("veristat");
        std::fs::create_dir(&veristat_dir).unwrap();
        std::fs::write(veristat_dir.join("bad.json"), "not valid json").unwrap();

        let result = discover_configs(dir.path(), "veristat", &HashSet::new());
        assert!(result.is_err());
    }

    /// Build Format 2 JSON: `value` is an object with decoded sections (no `formatted` wrapper).
    fn direct_value_json(section: &str, entries: &str) -> String {
        format!(r#"[{{"value": {{"{section}": [{entries}]}}}}]"#)
    }

    #[test]
    fn direct_value_rodata_parsed() {
        let json = direct_value_json(".rodata", r#"{"nr_layers": 137}"#);
        assert_eq!(parse(&json), vec!["nr_layers = 137"]);
    }

    #[test]
    fn direct_value_multiple_sections() {
        let json = r#"[{"value": {
            ".rodata": [{"nr_layers": 137}],
            ".data": [{"counter": 8642}]
        }}]"#;
        let result = parse(json);
        assert!(result.contains(&"nr_layers = 137".to_string()));
        assert!(result.contains(&"counter = 8642".to_string()));
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn direct_value_real_rsched_dump() {
        // Subset of a real rsched bpftool map dump (Format 2)
        let json = r#"[{"value": {
            ".rodata": [
                {"nr_layers": 6},
                {"smt_enabled": true},
                {"__sibling_cpu": [-1, 0, -1, 2]},
                {"slice_ns": 5000000001}
            ]
        }}]"#;
        assert_eq!(
            parse(json),
            vec![
                "nr_layers = 6",
                "smt_enabled = 1",
                "__sibling_cpu[0] = -1",
                "__sibling_cpu[1] = 0",
                "__sibling_cpu[2] = -1",
                "__sibling_cpu[3] = 2",
                "slice_ns = 5000000001",
            ]
        );
    }

    #[test]
    fn raw_hex_value_without_formatted_errors() {
        // Format 1 with raw hex `value` array but NO `formatted` key → error
        let json = r#"[{"key": ["0x00"], "value": ["0x04","0x00"]}]"#;
        let result = parse_rodata_json(json);
        assert!(result.is_err());
    }

    #[test]
    fn formatted_preferred_over_direct_value() {
        // When both `formatted.value` and `value` (object) exist, prefer `formatted`
        let json = r#"[{
            "value": {".rodata": [{"wrong": 999}]},
            "formatted": {"value": {".rodata": [{"right": 137}]}}
        }]"#;
        assert_eq!(parse(json), vec!["right = 137"]);
    }

    #[test]
    fn direct_value_bss_section() {
        let json = direct_value_json(".bss", r#"{"zeroed": 0}, {"flag": false}"#);
        assert_eq!(parse(&json), vec!["zeroed = 0", "flag = 0"]);
    }

    #[test]
    fn direct_value_dotted_names_skipped() {
        let json = direct_value_json(
            ".rodata",
            r#"{"nr_layers": 137}, {"match_layer.____fmt": "MATCH %s"}, {"smt_enabled": true}"#,
        );
        assert_eq!(parse(&json), vec!["nr_layers = 137", "smt_enabled = 1"]);
    }

    #[test]
    fn integration_rodata_plus_elf_filtering() {
        // End-to-end: parse rodata JSON, detect resizable maps from ELF,
        // filter globals, verify correct result.
        let json =
            rodata_json(r#"{"nr_layers": 4}, {"uei_dump_len": 32768}, {"smt_enabled": true}"#);
        let globals = parse_rodata_json(&json).unwrap();
        assert_eq!(globals.len(), 3);

        // Create ELF with .data.uei_dump (size 1) → resizable
        let elf = create_test_elf(&[(".data.uei_dump", 1), (".data.cpumask", 8)]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.bpf.o");
        std::fs::write(&path, &elf).unwrap();

        let exclude = find_resizable_map_vars(&[path]);
        assert_eq!(exclude.len(), 1);
        assert!(exclude.contains("uei_dump_len"));

        let (filtered, removed) = filter_globals(globals, &exclude);
        assert_eq!(filtered, vec!["nr_layers = 4", "smt_enabled = 1"]);
        assert_eq!(removed, vec!["uei_dump_len"]);
    }
}
