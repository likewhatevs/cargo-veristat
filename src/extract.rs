use anyhow::{Context, Result};
use object::{Object, ObjectSection, ObjectSymbol};
use std::path::Path;

pub struct BpfObject {
    pub name: String,
    pub data: Vec<u8>,
}

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
/// Parses the ELF binary natively using the `object` crate, finds symbols
/// in the `.bpf.objs` section, and returns their data with demangled names.
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
    let section_addr = bpf_section.address();
    let section_idx = bpf_section.index();

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

        let offset = (symbol.address() - section_addr) as usize;
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
