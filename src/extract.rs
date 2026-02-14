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
                raw_name, offset, size, section_data.len()
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

    #[test]
    fn extract_returns_empty_for_non_bpf_elf() {
        // The test binary itself is a valid ELF without a .bpf.objs section.
        let binary = std::env::current_exe().unwrap();
        let result = extract_bpf_objects(&binary).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn friendly_name_plain() {
        assert_eq!(friendly_name("bpf"), "bpf");
    }

    #[test]
    fn friendly_name_demangled_rust_symbol() {
        // A real Rust mangled symbol that demangles to "scx_foo::bpf".
        // We take the last path component: "bpf".
        let mangled = "_RNvCskl2ZOjHICPH_7scx_foo3bpf";
        let result = friendly_name(mangled);
        assert_eq!(result, "bpf");
    }

    #[test]
    fn friendly_name_with_colons_takes_last_segment() {
        // If demangle produces a path with ::, we take the last component.
        assert_eq!(friendly_name("foo::bar::baz"), "baz");
    }

    #[test]
    fn friendly_name_hash_suffix_unchanged() {
        // A hash suffix like h5208f5a69f77cebb is not a mangled symbol
        let name = "h5208f5a69f77cebb";
        assert_eq!(friendly_name(name), name);
    }
}
