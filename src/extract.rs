use anyhow::{Context, Result};
use object::{Object, ObjectSection, ObjectSymbol};
use std::path::Path;

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

    let objects = extract_via_symbols(&elf, bpf_section.address(), bpf_section.index(), section_data);

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
        let mut obj =
            WriteObject::new(BinaryFormat::Elf, Architecture::Sbf, Endianness::Little);
        let section_id =
            obj.add_section(vec![], b".text".to_vec(), object::SectionKind::Text);
        obj.append_section_data(section_id, &[0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], 1); // BPF_EXIT
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
        let mut obj =
            WriteObject::new(BinaryFormat::Elf, Architecture::Sbf, Endianness::Little);
        let section_id =
            obj.add_section(vec![], b".rodata".to_vec(), object::SectionKind::ReadOnlyData);
        // Embed \x7fELF inside rodata — should NOT cause a false split
        obj.append_section_data(section_id, b"\x7fELF_not_a_real_elf", 1);
        let text_id =
            obj.add_section(vec![], b".text".to_vec(), object::SectionKind::Text);
        obj.append_section_data(text_id, &[0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], 1);
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
        assert!(result.is_empty(), "should skip symbols with address < section_addr");
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
}
