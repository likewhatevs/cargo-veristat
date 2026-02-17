use anyhow::{Context, Result};
use object::{Object, ObjectSection, ObjectSymbol};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub struct BpfObject {
    pub name: String,
    pub data: Vec<u8>,
}

const ELF_MAGIC: &[u8] = b"\x7fELF";

/// Demangle a Rust symbol name and return the last path component.
pub(crate) fn friendly_name(raw: &str) -> String {
    let demangled = rustc_demangle::demangle(raw).to_string();
    if demangled.contains("::") {
        demangled
            .rsplit("::")
            .next()
            .unwrap_or(&demangled)
            .to_string()
    } else {
        demangled
    }
}

/// Extract BPF objects from a binary's `.bpf.objs` ELF section.
///
/// First tries symbol-based extraction (works with unstripped binaries).
/// Falls back to scanning for ELF magic bytes when symbols are stripped.
pub fn extract_bpf_objects(binary_path: &Path) -> Result<Vec<BpfObject>> {
    let binary_data = std::fs::read(binary_path)
        .with_context(|| format!("Failed to read binary: {}", binary_path.display()))?;

    let elf = object::File::parse(&*binary_data)
        .with_context(|| format!("Failed to parse ELF: {}", binary_path.display()))?;

    let bpf_section = match elf.section_by_name(".bpf.objs") {
        Some(s) => s,
        None => return Ok(vec![]),
    };

    let section_data = bpf_section
        .data()
        .context("Failed to read .bpf.objs section data")?;

    let objects = extract_via_symbols(
        &elf,
        bpf_section.address(),
        bpf_section.index(),
        section_data,
    );

    if !objects.is_empty() {
        return Ok(objects);
    }

    // Symbols stripped — scan for ELF magic bytes
    Ok(extract_via_magic(section_data))
}

/// Extract BPF objects using symbol table entries (unstripped binaries).
fn extract_via_symbols(
    elf: &object::File,
    section_addr: u64,
    section_idx: object::SectionIndex,
    section_data: &[u8],
) -> Vec<BpfObject> {
    let mut objects = Vec::new();

    for symbol in elf.symbols() {
        if symbol.section_index() != Some(section_idx) {
            continue;
        }

        let raw_name = match symbol.name() {
            Ok(n) if !n.is_empty() => n,
            _ => continue,
        };

        let size = symbol.size() as usize;
        if size == 0 {
            continue;
        }

        let Some(offset) = symbol.address().checked_sub(section_addr) else {
            continue;
        };
        let offset = offset as usize;
        if offset + size > section_data.len() {
            eprintln!(
                "warning: symbol '{}' extends beyond section data (offset={}, size={}, section_len={}), skipping",
                raw_name,
                offset,
                size,
                section_data.len()
            );
            continue;
        }

        let data = section_data[offset..offset + size].to_vec();

        objects.push(BpfObject {
            name: friendly_name(raw_name),
            data,
        });
    }

    objects
}

/// Compute the size of an ELF file from its header.
///
/// Returns the end of the section header table, which is the file size
/// for well-formed ELF relocatable objects (BPF .o files).
fn elf_file_size(data: &[u8]) -> Option<usize> {
    if data.len() < 6 || &data[0..4] != ELF_MAGIC {
        return None;
    }
    let class = data[4];
    let le = data[5] == 1;

    match class {
        2 if data.len() >= 64 => {
            // ELF64: e_shoff at 40, e_shentsize at 58, e_shnum at 60
            let e_shoff = if le {
                u64::from_le_bytes(data[40..48].try_into().ok()?)
            } else {
                u64::from_be_bytes(data[40..48].try_into().ok()?)
            };
            let e_shentsize = if le {
                u16::from_le_bytes(data[58..60].try_into().ok()?)
            } else {
                u16::from_be_bytes(data[58..60].try_into().ok()?)
            };
            let e_shnum = if le {
                u16::from_le_bytes(data[60..62].try_into().ok()?)
            } else {
                u16::from_be_bytes(data[60..62].try_into().ok()?)
            };
            let size = e_shoff + (e_shnum as u64) * (e_shentsize as u64);
            if size >= 64 {
                Some(size as usize)
            } else {
                None
            }
        }
        1 if data.len() >= 52 => {
            // ELF32: e_shoff at 32, e_shentsize at 46, e_shnum at 48
            let e_shoff = if le {
                u32::from_le_bytes(data[32..36].try_into().ok()?) as u64
            } else {
                u32::from_be_bytes(data[32..36].try_into().ok()?) as u64
            };
            let e_shentsize = if le {
                u16::from_le_bytes(data[46..48].try_into().ok()?)
            } else {
                u16::from_be_bytes(data[46..48].try_into().ok()?)
            };
            let e_shnum = if le {
                u16::from_le_bytes(data[48..50].try_into().ok()?)
            } else {
                u16::from_be_bytes(data[48..50].try_into().ok()?)
            };
            let size = e_shoff + (e_shnum as u64) * (e_shentsize as u64);
            if size >= 52 {
                Some(size as usize)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Extract BPF objects by scanning for ELF magic bytes (stripped binaries).
///
/// Parses the ELF header at each candidate offset to compute the real object
/// size, avoiding false splits from `\x7fELF` bytes inside object data.
fn extract_via_magic(section_data: &[u8]) -> Vec<BpfObject> {
    let mut objects = Vec::new();
    let mut pos = 0;

    while pos + ELF_MAGIC.len() <= section_data.len() {
        if &section_data[pos..pos + ELF_MAGIC.len()] != ELF_MAGIC {
            pos += 1;
            continue;
        }

        let remaining = &section_data[pos..];
        if let Some(size) = elf_file_size(remaining)
            && size <= remaining.len()
        {
            objects.push(BpfObject {
                name: format!("bpf_{}", objects.len()),
                data: remaining[..size].to_vec(),
            });
            pos += size;
            continue;
        }

        // Can't determine size — skip past this magic and keep scanning
        pos += ELF_MAGIC.len();
    }

    objects
}

const SKEL_DATA_PREFIX: &str = "const DATA: &[u8] = &[";

/// Extract a BPF object from a `*.skel.rs` skeleton file.
///
/// libbpf-cargo (<= 0.25) embeds BPF object bytes as
/// `const DATA: &[u8] = &[127, 69, 76, 70, ...];` in generated skeleton files.
/// This function parses that byte array back into raw BPF object data.
/// Newer libbpf-cargo uses `include_bytes!` with a `.bpf.objs` link section,
/// which is handled by [`extract_bpf_objects`] instead.
pub fn extract_from_skeleton(skel_path: &Path) -> Result<Option<BpfObject>> {
    let content = std::fs::read_to_string(skel_path)
        .with_context(|| format!("Failed to read skeleton: {}", skel_path.display()))?;

    let Some(start) = content.find(SKEL_DATA_PREFIX) else {
        return Ok(None);
    };
    let rest = &content[start + SKEL_DATA_PREFIX.len()..];

    // Single-pass parse: consume digits/commas/whitespace, stop at ']'.
    // Anything else means this isn't a byte-array literal we understand.
    let mut data = Vec::new();
    let mut acc: Option<u32> = None;
    let mut found_close = false;

    for ch in rest.chars() {
        match ch {
            ']' => {
                if let Some(v) = acc {
                    anyhow::ensure!(v <= 255, "Value {} exceeds u8 in {}", v, skel_path.display());
                    data.push(v as u8);
                }
                found_close = true;
                break;
            }
            ',' => {
                if let Some(v) = acc {
                    anyhow::ensure!(v <= 255, "Value {} exceeds u8 in {}", v, skel_path.display());
                    data.push(v as u8);
                    acc = None;
                }
            }
            '0'..='9' => {
                let digit = (ch as u32) - b'0' as u32;
                acc = Some(acc.unwrap_or(0) * 10 + digit);
            }
            c if c.is_ascii_whitespace() => {}
            _ => anyhow::bail!(
                "Unexpected character '{}' in DATA array in {}",
                ch,
                skel_path.display()
            ),
        }
    }

    anyhow::ensure!(
        found_close,
        "Unclosed DATA array in {}",
        skel_path.display()
    );

    let stem = skel_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown");
    let name = stem.strip_suffix(".skel").unwrap_or(stem).to_string();

    Ok(Some(BpfObject { name, data }))
}

/// Find skeleton files in the cargo build directory and extract BPF objects.
///
/// Scans `{target_dir}/{profile_dir}/build/{pkg_name}-*/out/*.skel.rs`.
/// When multiple build dirs contain the same skeleton name, the newest by
/// mtime wins (handles stale build directories).
pub fn find_skeleton_objects(
    target_dir: &Path,
    profile_dir: &str,
    pkg_name: &str,
) -> Result<Vec<BpfObject>> {
    let build_dir = target_dir.join(profile_dir).join("build");
    let prefix = format!("{}-", pkg_name);

    let entries = match std::fs::read_dir(&build_dir) {
        Ok(e) => e,
        Err(_) => return Ok(vec![]),
    };

    // Collect candidate skeleton files grouped by stem, keeping newest mtime
    let mut best: HashMap<String, PathBuf> = HashMap::new();

    for entry in entries.filter_map(|e| e.ok()) {
        let dir_name = entry.file_name();
        let dir_name = dir_name.to_string_lossy();
        if !dir_name.starts_with(&prefix) {
            continue;
        }

        let out_dir = entry.path().join("out");
        let out_entries = match std::fs::read_dir(&out_dir) {
            Ok(e) => e,
            Err(_) => continue,
        };

        for file in out_entries.filter_map(|e| e.ok()) {
            let fname = file.file_name();
            let fname = fname.to_string_lossy();
            if !fname.ends_with(".skel.rs") {
                continue;
            }

            let stem = fname.strip_suffix(".skel.rs").unwrap().to_string();
            let path = file.path();

            let dominated = best.get(&stem).is_some_and(|existing| {
                let existing_mtime = std::fs::metadata(existing)
                    .and_then(|m| m.modified())
                    .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
                let new_mtime = std::fs::metadata(&path)
                    .and_then(|m| m.modified())
                    .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
                new_mtime <= existing_mtime
            });

            if !dominated {
                best.insert(stem, path);
            }
        }
    }

    let mut objects = Vec::new();
    let mut paths: Vec<_> = best.into_values().collect();
    paths.sort();

    for path in paths {
        match extract_from_skeleton(&path) {
            Ok(Some(obj)) => objects.push(obj),
            Ok(None) => {}
            Err(e) => {
                eprintln!(
                    "warning: failed to extract from skeleton {}: {:#}",
                    path.display(),
                    e
                );
            }
        }
    }

    Ok(objects)
}

#[cfg(test)]
mod tests {
    use super::*;
    use object::write::{Object as WriteObject, Symbol, SymbolSection};
    use object::{Architecture, BinaryFormat, Endianness, SymbolFlags, SymbolKind, SymbolScope};

    /// Build a synthetic ELF with a `.bpf.objs` section containing the given symbols.
    /// Each entry is (symbol_name, data). Returns the raw ELF bytes.
    fn build_elf_with_bpf_objs(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut obj = WriteObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
        let section_id = obj.add_section(vec![], b".bpf.objs".to_vec(), object::SectionKind::Data);

        for &(name, data) in entries {
            let offset = obj.append_section_data(section_id, data, 1);
            obj.add_symbol(Symbol {
                name: name.as_bytes().to_vec(),
                value: offset,
                size: data.len() as u64,
                kind: SymbolKind::Data,
                scope: SymbolScope::Compilation,
                weak: false,
                section: SymbolSection::Section(section_id),
                flags: SymbolFlags::None,
            });
        }

        obj.write().unwrap()
    }

    fn write_elf(data: &[u8]) -> tempfile::NamedTempFile {
        let f = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(f.path(), data).unwrap();
        f
    }

    #[test]
    fn extract_returns_empty_for_non_bpf_elf() {
        let binary = std::env::current_exe().unwrap();
        let result = extract_bpf_objects(&binary).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn extract_single_object() {
        let payload = b"\x7fELF_fake_bpf_object";
        let elf = build_elf_with_bpf_objs(&[("my_prog", payload)]);
        let f = write_elf(&elf);

        let result = extract_bpf_objects(f.path()).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "my_prog");
        assert_eq!(result[0].data, payload);
    }

    #[test]
    fn extract_multiple_objects() {
        let a = b"aaaa_data";
        let b_data = b"bbbb_data_longer";
        let elf = build_elf_with_bpf_objs(&[("alpha", a), ("beta", b_data)]);
        let f = write_elf(&elf);

        let result = extract_bpf_objects(f.path()).unwrap();
        assert_eq!(result.len(), 2);
        let names: Vec<&str> = result.iter().map(|o| o.name.as_str()).collect();
        assert!(names.contains(&"alpha"));
        assert!(names.contains(&"beta"));

        let alpha = result.iter().find(|o| o.name == "alpha").unwrap();
        assert_eq!(alpha.data, a);
        let beta = result.iter().find(|o| o.name == "beta").unwrap();
        assert_eq!(beta.data, b_data);
    }

    #[test]
    fn extract_skips_zero_size_symbol() {
        let mut obj = WriteObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
        let section_id = obj.add_section(vec![], b".bpf.objs".to_vec(), object::SectionKind::Data);
        let payload = b"real_data";
        let offset = obj.append_section_data(section_id, payload, 1);
        // Real symbol
        obj.add_symbol(Symbol {
            name: b"real".to_vec(),
            value: offset,
            size: payload.len() as u64,
            kind: SymbolKind::Data,
            scope: SymbolScope::Compilation,
            weak: false,
            section: SymbolSection::Section(section_id),
            flags: SymbolFlags::None,
        });
        // Zero-size symbol (should be skipped)
        obj.add_symbol(Symbol {
            name: b"empty".to_vec(),
            value: offset,
            size: 0,
            kind: SymbolKind::Data,
            scope: SymbolScope::Compilation,
            weak: false,
            section: SymbolSection::Section(section_id),
            flags: SymbolFlags::None,
        });
        let elf = obj.write().unwrap();
        let f = write_elf(&elf);

        let result = extract_bpf_objects(f.path()).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "real");
    }

    #[test]
    fn extract_skips_empty_name_symbol() {
        let mut obj = WriteObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
        let section_id = obj.add_section(vec![], b".bpf.objs".to_vec(), object::SectionKind::Data);
        let payload = b"some_data";
        let offset = obj.append_section_data(section_id, payload, 1);
        // Named symbol
        obj.add_symbol(Symbol {
            name: b"named".to_vec(),
            value: offset,
            size: payload.len() as u64,
            kind: SymbolKind::Data,
            scope: SymbolScope::Compilation,
            weak: false,
            section: SymbolSection::Section(section_id),
            flags: SymbolFlags::None,
        });
        // Empty-name symbol
        obj.add_symbol(Symbol {
            name: vec![],
            value: offset,
            size: payload.len() as u64,
            kind: SymbolKind::Data,
            scope: SymbolScope::Compilation,
            weak: false,
            section: SymbolSection::Section(section_id),
            flags: SymbolFlags::None,
        });
        let elf = obj.write().unwrap();
        let f = write_elf(&elf);

        let result = extract_bpf_objects(f.path()).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "named");
    }

    #[test]
    fn extract_demangled_names() {
        let payload = b"bpf_obj_bytes";
        let mangled = "_RNvCskl2ZOjHICPH_7scx_foo3bpf";
        let elf = build_elf_with_bpf_objs(&[(mangled, payload)]);
        let f = write_elf(&elf);

        let result = extract_bpf_objects(f.path()).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "bpf");
        assert_eq!(result[0].data, payload);
    }

    #[test]
    fn extract_errors_on_missing_file() {
        let result = extract_bpf_objects(Path::new("/nonexistent/binary"));
        assert!(result.is_err());
    }

    #[test]
    fn extract_errors_on_invalid_elf() {
        let f = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(f.path(), b"this is not an ELF file").unwrap();
        let result = extract_bpf_objects(f.path());
        assert!(result.is_err());
    }

    /// Build a minimal valid BPF ELF (ELF64 little-endian relocatable).
    fn build_mini_bpf_elf() -> Vec<u8> {
        let mut obj = WriteObject::new(BinaryFormat::Elf, Architecture::Sbf, Endianness::Little);
        let section_id = obj.add_section(vec![], b".text".to_vec(), object::SectionKind::Text);
        obj.append_section_data(
            section_id,
            &[0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            1,
        ); // BPF_EXIT
        obj.write().unwrap()
    }

    /// Build a synthetic ELF with a `.bpf.objs` section but NO symbols (simulates stripped binary).
    fn build_stripped_elf_with_bpf_objs(blobs: &[&[u8]]) -> Vec<u8> {
        let mut obj = WriteObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
        let section_id = obj.add_section(vec![], b".bpf.objs".to_vec(), object::SectionKind::Data);

        for blob in blobs {
            obj.append_section_data(section_id, blob, 1);
        }

        obj.write().unwrap()
    }

    #[test]
    fn extract_stripped_single_object() {
        let bpf_elf = build_mini_bpf_elf();
        let elf = build_stripped_elf_with_bpf_objs(&[&bpf_elf]);
        let f = write_elf(&elf);

        let result = extract_bpf_objects(f.path()).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "bpf_0");
        assert_eq!(result[0].data, bpf_elf);
    }

    #[test]
    fn extract_stripped_multiple_objects() {
        let bpf_a = build_mini_bpf_elf();
        let bpf_b = build_mini_bpf_elf();
        let mut combined = Vec::new();
        combined.extend_from_slice(&bpf_a);
        combined.extend_from_slice(&bpf_b);

        let elf = build_stripped_elf_with_bpf_objs(&[&combined]);
        let f = write_elf(&elf);

        let result = extract_bpf_objects(f.path()).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].name, "bpf_0");
        assert_eq!(result[0].data, bpf_a);
        assert_eq!(result[1].name, "bpf_1");
        assert_eq!(result[1].data, bpf_b);
    }

    #[test]
    fn extract_stripped_prefers_symbols_when_available() {
        let bpf_elf = build_mini_bpf_elf();
        let elf = build_elf_with_bpf_objs(&[("my_named_prog", &bpf_elf)]);
        let f = write_elf(&elf);

        let result = extract_bpf_objects(f.path()).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "my_named_prog");
    }

    #[test]
    fn extract_magic_with_real_elfs() {
        let bpf_a = build_mini_bpf_elf();
        let bpf_b = build_mini_bpf_elf();
        let mut data = Vec::new();
        data.extend_from_slice(&bpf_a);
        data.extend_from_slice(&bpf_b);

        let result = extract_via_magic(&data);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].data, bpf_a);
        assert_eq!(result[1].data, bpf_b);
    }

    #[test]
    fn extract_magic_ignores_internal_elf_bytes() {
        // A BPF ELF that happens to contain \x7fELF in its data section
        let mut obj = WriteObject::new(BinaryFormat::Elf, Architecture::Sbf, Endianness::Little);
        let section_id = obj.add_section(
            vec![],
            b".rodata".to_vec(),
            object::SectionKind::ReadOnlyData,
        );
        // Embed \x7fELF inside rodata — should NOT cause a false split
        obj.append_section_data(section_id, b"\x7fELF_not_a_real_elf", 1);
        let text_id = obj.add_section(vec![], b".text".to_vec(), object::SectionKind::Text);
        obj.append_section_data(
            text_id,
            &[0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            1,
        );
        let bpf_elf = obj.write().unwrap();

        let result = extract_via_magic(&bpf_elf);
        // Should find exactly 1 object — the internal \x7fELF should not split it
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].data, bpf_elf);
    }

    #[test]
    fn extract_magic_empty_section() {
        let result = extract_via_magic(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn extract_magic_no_elf_headers() {
        let result = extract_via_magic(b"not an elf at all");
        assert!(result.is_empty());
    }

    #[test]
    fn elf_file_size_valid_elf64() {
        let bpf_elf = build_mini_bpf_elf();
        let size = elf_file_size(&bpf_elf).unwrap();
        assert_eq!(size, bpf_elf.len());
    }

    #[test]
    fn elf_file_size_too_short() {
        assert!(elf_file_size(b"\x7fELF").is_none());
        assert!(elf_file_size(b"").is_none());
    }

    #[test]
    fn elf_file_size_bad_magic() {
        let mut data = [0u8; 64];
        data[0..4].copy_from_slice(b"NOTF");
        assert!(elf_file_size(&data).is_none());
    }

    #[test]
    fn extract_via_symbols_skips_underflow_address() {
        // Build an ELF with a symbol in .bpf.objs, then call extract_via_symbols
        // with a section_addr higher than the symbol address to trigger checked_sub
        let payload = b"some_bpf_data";
        let elf_bytes = build_elf_with_bpf_objs(&[("test_sym", payload)]);
        let elf = object::File::parse(&*elf_bytes).unwrap();

        let bpf_section = elf.section_by_name(".bpf.objs").unwrap();
        let section_data = bpf_section.data().unwrap();
        let section_idx = bpf_section.index();

        // Pass a bogus section_addr much higher than any symbol address
        let result = extract_via_symbols(&elf, u64::MAX, section_idx, section_data);
        assert!(
            result.is_empty(),
            "should skip symbols with address < section_addr"
        );
    }

    #[test]
    fn friendly_name_plain() {
        assert_eq!(friendly_name("bpf"), "bpf");
    }

    #[test]
    fn friendly_name_demangled_rust_symbol() {
        let mangled = "_RNvCskl2ZOjHICPH_7scx_foo3bpf";
        let result = friendly_name(mangled);
        assert_eq!(result, "bpf");
    }

    #[test]
    fn friendly_name_with_colons_takes_last_segment() {
        assert_eq!(friendly_name("foo::bar::baz"), "baz");
    }

    #[test]
    fn friendly_name_hash_suffix_unchanged() {
        let name = "h5208f5a69f77cebb";
        assert_eq!(friendly_name(name), name);
    }

    // -- skeleton extraction tests --

    fn write_skel(dir: &Path, name: &str, content: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn extract_from_skeleton_valid() {
        let dir = tempfile::tempdir().unwrap();
        // ELF magic: 127=0x7f, 69='E', 76='L', 70='F'
        let content = "const DATA: &[u8] = &[127, 69, 76, 70, 1, 2, 3];";
        let path = write_skel(dir.path(), "prog.skel.rs", content);

        let obj = extract_from_skeleton(&path).unwrap().unwrap();
        assert_eq!(obj.data, vec![127, 69, 76, 70, 1, 2, 3]);
        assert_eq!(obj.name, "prog");
    }

    #[test]
    fn extract_from_skeleton_no_data() {
        let dir = tempfile::tempdir().unwrap();
        let content = "pub struct ProgSkel { /* no DATA const */ }";
        let path = write_skel(dir.path(), "empty.skel.rs", content);

        assert!(extract_from_skeleton(&path).unwrap().is_none());
    }

    #[test]
    fn extract_from_skeleton_overflow_value_errors() {
        let dir = tempfile::tempdir().unwrap();
        let content = "const DATA: &[u8] = &[256];";
        let path = write_skel(dir.path(), "bad.skel.rs", content);

        assert!(extract_from_skeleton(&path).is_err());
    }

    #[test]
    fn extract_from_skeleton_unexpected_char_errors() {
        let dir = tempfile::tempdir().unwrap();
        let content = "const DATA: &[u8] = &[127, 0x45];";
        let path = write_skel(dir.path(), "hex.skel.rs", content);

        assert!(extract_from_skeleton(&path).is_err());
    }

    #[test]
    fn extract_from_skeleton_unclosed_errors() {
        let dir = tempfile::tempdir().unwrap();
        let content = "const DATA: &[u8] = &[127, 69";
        let path = write_skel(dir.path(), "open.skel.rs", content);

        assert!(extract_from_skeleton(&path).is_err());
    }

    #[test]
    fn extract_from_skeleton_name_from_filename() {
        let dir = tempfile::tempdir().unwrap();
        let content = "const DATA: &[u8] = &[42];";
        let path = write_skel(dir.path(), "foo.skel.rs", content);

        let obj = extract_from_skeleton(&path).unwrap().unwrap();
        assert_eq!(obj.name, "foo");
    }

    #[test]
    fn find_skeleton_objects_picks_newest() {
        let dir = tempfile::tempdir().unwrap();
        let build = dir.path().join("debug").join("build");

        // Older build dir
        let old_out = build.join("mypkg-aaa111").join("out");
        std::fs::create_dir_all(&old_out).unwrap();
        write_skel(&old_out, "sched.skel.rs", "const DATA: &[u8] = &[10];");

        // Small sleep so mtime differs
        std::thread::sleep(std::time::Duration::from_millis(50));

        // Newer build dir
        let new_out = build.join("mypkg-bbb222").join("out");
        std::fs::create_dir_all(&new_out).unwrap();
        write_skel(&new_out, "sched.skel.rs", "const DATA: &[u8] = &[20];");

        let objects = find_skeleton_objects(dir.path(), "debug", "mypkg").unwrap();
        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0].name, "sched");
        assert_eq!(objects[0].data, vec![20]);
    }

    #[test]
    fn find_skeleton_objects_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let objects = find_skeleton_objects(dir.path(), "debug", "nonexistent").unwrap();
        assert!(objects.is_empty());
    }
}
