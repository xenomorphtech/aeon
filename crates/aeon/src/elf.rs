use std::collections::HashMap;

use object::SectionFlags;

const R_AARCH64_ABS64: u32 = 257;
const R_AARCH64_GLOB_DAT: u32 = 1025;
const R_AARCH64_JUMP_SLOT: u32 = 1026;
const R_AARCH64_RELATIVE: u32 = 1027;

#[derive(Debug, Clone)]
pub struct FunctionInfo {
    pub addr: u64,
    pub size: u64,
    pub name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Segment {
    pub file_offset: u64,
    pub vaddr: u64,
    pub file_size: u64,
    pub mem_size: u64,
}

#[derive(Debug, Clone)]
pub struct SectionInfo {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub is_alloc: bool,
    pub is_writable: bool,
    pub is_executable: bool,
}

#[derive(Debug, Clone)]
pub struct LoadedBinary {
    pub data: Vec<u8>,
    pub text_section_file_offset: u64,
    pub text_section_addr: u64,
    pub text_section_size: u64,
    pub functions: Vec<FunctionInfo>,
    pub segments: Vec<Segment>,
    pub sections: Vec<SectionInfo>,
}

impl LoadedBinary {
    /// Get raw bytes for a function within .text
    pub fn function_bytes(&self, func: &FunctionInfo) -> Option<&[u8]> {
        let offset_in_text = func.addr.checked_sub(self.text_section_addr)?;
        let file_offset = self.text_section_file_offset + offset_in_text;
        let end = file_offset + func.size;
        if end <= self.data.len() as u64 {
            Some(&self.data[file_offset as usize..end as usize])
        } else {
            None
        }
    }

    /// Find the function containing a given address (binary search, O(log n))
    pub fn function_containing(&self, addr: u64) -> Option<&FunctionInfo> {
        let idx = self.functions.partition_point(|f| f.addr <= addr);
        if idx == 0 {
            return None;
        }
        let func = &self.functions[idx - 1];
        if addr < func.addr + func.size {
            Some(func)
        } else {
            None
        }
    }

    /// Resolve a virtual address to a file offset using LOAD segments
    pub fn vaddr_to_file_offset(&self, vaddr: u64) -> Option<usize> {
        for seg in &self.segments {
            if vaddr >= seg.vaddr && vaddr < seg.vaddr + seg.file_size {
                let offset = seg.file_offset + (vaddr - seg.vaddr);
                if (offset as usize) < self.data.len() {
                    return Some(offset as usize);
                }
            }
        }
        None
    }

    /// Check whether a virtual address falls within any mapped LOAD segment.
    pub fn contains_vaddr(&self, vaddr: u64) -> bool {
        self.segments
            .iter()
            .any(|seg| vaddr >= seg.vaddr && vaddr < seg.vaddr + seg.mem_size)
    }

    /// Find the section containing a virtual address.
    pub fn section_containing(&self, vaddr: u64) -> Option<&SectionInfo> {
        self.sections
            .iter()
            .find(|section| vaddr >= section.address && vaddr < section.address + section.size)
    }

    /// Read raw bytes at a virtual address, up to `len` bytes
    pub fn read_vaddr(&self, vaddr: u64, len: usize) -> Option<&[u8]> {
        let off = self.vaddr_to_file_offset(vaddr)?;
        let end = (off + len).min(self.data.len());
        Some(&self.data[off..end])
    }

    /// Read a null-terminated string at a virtual address
    pub fn read_string(&self, vaddr: u64, max_len: usize) -> Option<String> {
        let off = self.vaddr_to_file_offset(vaddr)?;
        let end = (off + max_len).min(self.data.len());
        let slice = &self.data[off..end];
        let nul = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
        String::from_utf8(slice[..nul].to_vec()).ok()
    }

    /// Get raw bytes for the entire .text section
    pub fn text_bytes(&self) -> &[u8] {
        let start = self.text_section_file_offset as usize;
        let end = start + self.text_section_size as usize;
        &self.data[start..end.min(self.data.len())]
    }
}

pub fn load_elf(path: &str) -> Result<LoadedBinary, Box<dyn std::error::Error>> {
    use object::read::elf::{ElfFile64, FileHeader, ProgramHeader};
    use object::{Object, ObjectSection, ObjectSymbol, SymbolKind};

    let mut data = std::fs::read(path)?;

    // Parse LOAD segments for vaddr resolution
    let segments = {
        let elf = ElfFile64::<object::LittleEndian>::parse(&data[..])?;
        let endian = elf.endian();
        elf.elf_header()
            .program_headers(endian, &*data)?
            .iter()
            .filter(|ph| ph.p_type(endian) == object::elf::PT_LOAD)
            .map(|ph| Segment {
                file_offset: ph.p_offset(endian).into(),
                vaddr: ph.p_vaddr(endian).into(),
                file_size: ph.p_filesz(endian).into(),
                mem_size: ph.p_memsz(endian).into(),
            })
            .collect::<Vec<_>>()
    };

    let (text_file_offset, text_addr, text_size, mut functions, mut sections) = {
        let obj = object::File::parse(&data[..])?;

        // .text section
        let text = obj
            .section_by_name(".text")
            .ok_or("no .text section found")?;
        let (text_file_offset, _) = text.file_range().ok_or("no file range for .text")?;
        let text_addr = text.address();
        let text_size = text.size();

        // Parse .eh_frame for function boundaries
        let mut functions = Vec::new();
        if let Some(eh_frame_section) = obj.section_by_name(".eh_frame") {
            if let Ok(eh_frame_data) = eh_frame_section.data() {
                let eh_frame_addr = eh_frame_section.address();
                functions = parse_eh_frame(eh_frame_data, eh_frame_addr, text_addr);
            }
        }

        let mut sections = obj
            .sections()
            .filter_map(|section| {
                let name = section.name().ok()?.to_string();
                let (file_offset, file_size) = section.file_range().unwrap_or((0, 0));
                let flags = match section.flags() {
                    SectionFlags::Elf { sh_flags } => sh_flags,
                    _ => 0,
                };

                Some(SectionInfo {
                    name,
                    address: section.address(),
                    size: section.size(),
                    file_offset,
                    file_size,
                    is_alloc: flags & object::elf::SHF_ALLOC as u64 != 0,
                    is_writable: flags & object::elf::SHF_WRITE as u64 != 0,
                    is_executable: flags & object::elf::SHF_EXECINSTR as u64 != 0,
                })
            })
            .collect::<Vec<_>>();
        sections.sort_by_key(|section| section.address);

        // Map symbol names from .dynsym
        let mut sym_map: HashMap<u64, String> = HashMap::new();
        for sym in obj.dynamic_symbols() {
            if sym.kind() == SymbolKind::Text && sym.size() > 0 {
                if let Ok(name) = sym.name() {
                    sym_map.insert(sym.address(), name.to_string());
                }
            }
        }
        for func in &mut functions {
            if let Some(name) = sym_map.get(&func.addr) {
                func.name = Some(name.clone());
            }
        }

        (text_file_offset, text_addr, text_size, functions, sections)
    };

    apply_relocations(&mut data, &segments, path)?;

    functions.sort_by_key(|f| f.addr);
    sections.sort_by_key(|section| section.address);

    Ok(LoadedBinary {
        data,
        text_section_file_offset: text_file_offset,
        text_section_addr: text_addr,
        text_section_size: text_size,
        functions,
        segments,
        sections,
    })
}

fn apply_relocations(
    data: &mut [u8],
    segments: &[Segment],
    _path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use object::{Object, ObjectSection, RelocationTarget};

    let obj = object::File::parse(&data[..])?;
    let dynamic_symbol_values = build_dynamic_symbol_values(&obj)?;
    let mut relocations_to_apply = Vec::new();

    // Android shared objects often store .rela.dyn in packed APS2 form.
    if let Some(section) = obj.section_by_name(".rela.dyn") {
        let bytes = section.data()?;
        if bytes.starts_with(b"APS2") {
            relocations_to_apply.extend(parse_android_rela_aps2(bytes)?);
        }
    }

    if let Some(relocations) = obj.dynamic_relocations() {
        for (offset, relocation) in relocations {
            let object::RelocationFlags::Elf { r_type } = relocation.flags() else {
                continue;
            };
            let addend = relocation.addend();
            let sym = match relocation.target() {
                RelocationTarget::Symbol(index) => index.0 as u32,
                _ => 0,
            };
            let reloc = PackedRela {
                offset,
                sym,
                typ: r_type,
                addend,
            };
            relocations_to_apply.push(reloc);
        }
    }

    drop(obj);

    for reloc in relocations_to_apply {
        apply_relocation_record(data, segments, &dynamic_symbol_values, reloc)?;
    }

    Ok(())
}

fn build_dynamic_symbol_values<'data, T>(
    obj: &T,
) -> Result<Vec<Option<u64>>, Box<dyn std::error::Error>>
where
    T: object::Object<'data>,
{
    use object::{ObjectSymbol, ObjectSymbolTable};

    let Some(symbols) = obj.dynamic_symbol_table() else {
        return Ok(Vec::new());
    };

    let mut values = vec![None; symbols.symbols().count() + 1];
    for symbol in symbols.symbols() {
        let index = symbol.index().0;
        if index >= values.len() {
            values.resize(index + 1, None);
        }
        if symbol.is_definition() {
            values[index] = Some(symbol.address());
        }
    }
    Ok(values)
}

#[derive(Debug, Clone, Copy)]
struct PackedRela {
    offset: u64,
    sym: u32,
    typ: u32,
    addend: i64,
}

fn parse_android_rela_aps2(data: &[u8]) -> Result<Vec<PackedRela>, Box<dyn std::error::Error>> {
    if data.len() < 4 || &data[..4] != b"APS2" {
        return Err("invalid Android packed relocation header".into());
    }

    const RELOCATION_GROUPED_BY_INFO_FLAG: u64 = 1;
    const RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG: u64 = 1 << 1;
    const RELOCATION_GROUPED_BY_ADDEND_FLAG: u64 = 1 << 2;
    const RELOCATION_GROUP_HAS_ADDEND_FLAG: u64 = 1 << 3;

    let mut reader = Leb128Reader::new(&data[4..]);
    let relocation_count = reader.read_sleb128()? as usize;
    let initial_offset = reader.read_sleb128()?;
    let mut reloc_offset = initial_offset;
    let mut reloc_addend = 0i64;
    let mut relocs = Vec::with_capacity(relocation_count);

    while relocs.len() < relocation_count {
        let group_size = reader.read_sleb128()? as usize;
        let group_flags = reader.read_sleb128()? as u64;

        let mut group_offset_delta = 0i64;
        if group_flags & RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG != 0 {
            group_offset_delta = reader.read_sleb128()?;
        }

        let mut group_info = 0u64;
        if group_flags & RELOCATION_GROUPED_BY_INFO_FLAG != 0 {
            group_info = reader.read_sleb128()? as u64;
        }

        if group_flags & RELOCATION_GROUP_HAS_ADDEND_FLAG != 0
            && group_flags & RELOCATION_GROUPED_BY_ADDEND_FLAG != 0
        {
            reloc_addend += reader.read_sleb128()?;
        }

        for _ in 0..group_size {
            if group_flags & RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG != 0 {
                reloc_offset += group_offset_delta;
            } else {
                reloc_offset += reader.read_sleb128()?;
            }

            let info = if group_flags & RELOCATION_GROUPED_BY_INFO_FLAG != 0 {
                group_info
            } else {
                reader.read_sleb128()? as u64
            };

            if group_flags & RELOCATION_GROUP_HAS_ADDEND_FLAG != 0 {
                if group_flags & RELOCATION_GROUPED_BY_ADDEND_FLAG == 0 {
                    reloc_addend += reader.read_sleb128()?;
                }
            } else {
                reloc_addend = 0;
            }

            relocs.push(PackedRela {
                offset: reloc_offset as u64,
                sym: (info >> 32) as u32,
                typ: info as u32,
                addend: reloc_addend,
            });
        }
    }

    Ok(relocs)
}

fn apply_relocation_record(
    data: &mut [u8],
    segments: &[Segment],
    dynamic_symbol_values: &[Option<u64>],
    reloc: PackedRela,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(file_offset) = vaddr_to_file_offset(segments, data.len(), reloc.offset) else {
        return Ok(());
    };
    if file_offset + 8 > data.len() {
        return Ok(());
    }

    let value = match reloc.typ {
        R_AARCH64_RELATIVE => reloc.addend as u64,
        R_AARCH64_ABS64 | R_AARCH64_GLOB_DAT | R_AARCH64_JUMP_SLOT => {
            let Some(Some(symbol_addr)) = dynamic_symbol_values.get(reloc.sym as usize).copied()
            else {
                return Ok(());
            };
            symbol_addr.wrapping_add_signed(reloc.addend)
        }
        _ => return Ok(()),
    };

    data[file_offset..file_offset + 8].copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn vaddr_to_file_offset(segments: &[Segment], data_len: usize, vaddr: u64) -> Option<usize> {
    for seg in segments {
        if vaddr >= seg.vaddr && vaddr < seg.vaddr + seg.file_size {
            let offset = seg.file_offset + (vaddr - seg.vaddr);
            if (offset as usize) < data_len {
                return Some(offset as usize);
            }
        }
    }
    None
}

struct Leb128Reader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Leb128Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    fn read_sleb128(&mut self) -> Result<i64, Box<dyn std::error::Error>> {
        let mut result = 0i64;
        let mut shift = 0u32;
        let mut byte;

        loop {
            byte = *self
                .data
                .get(self.offset)
                .ok_or("unexpected end of packed relocation stream")?;
            self.offset += 1;
            result |= i64::from(byte & 0x7f) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                break;
            }
            if shift >= 64 {
                return Err("packed relocation sleb128 too large".into());
            }
        }

        if shift < 64 && byte & 0x40 != 0 {
            result |= (!0i64) << shift;
        }

        Ok(result)
    }
}

fn parse_eh_frame(data: &[u8], section_addr: u64, text_addr: u64) -> Vec<FunctionInfo> {
    use gimli::{BaseAddresses, CieOrFde, EhFrame, LittleEndian, UnwindSection};

    let eh_frame = EhFrame::new(data, LittleEndian);
    let bases = BaseAddresses::default()
        .set_eh_frame(section_addr)
        .set_text(text_addr);

    let mut functions = Vec::new();
    let mut entries = eh_frame.entries(&bases);

    while let Ok(Some(entry)) = entries.next() {
        if let CieOrFde::Fde(partial) = entry {
            if let Ok(fde) = partial.parse(|_, _, offset| eh_frame.cie_from_offset(&bases, offset))
            {
                let addr = fde.initial_address();
                let size = fde.len() as u64;
                if size > 0 {
                    functions.push(FunctionInfo {
                        addr,
                        size,
                        name: None,
                    });
                }
            }
        }
    }

    functions
}

#[cfg(test)]
mod tests {
    use super::{
        apply_relocation_record, parse_android_rela_aps2, PackedRela, Segment, R_AARCH64_ABS64,
        R_AARCH64_RELATIVE,
    };

    fn encode_sleb128(mut value: i64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (value & 0x7f) as u8;
            let sign_bit_set = byte & 0x40 != 0;
            value >>= 7;
            let done = (value == 0 && !sign_bit_set) || (value == -1 && sign_bit_set);
            out.push(if done { byte } else { byte | 0x80 });
            if done {
                break;
            }
        }
        out
    }

    #[test]
    fn parses_android_aps2_relocations() {
        let mut bytes = b"APS2".to_vec();
        // relocation_count = 1, initial_offset = 0
        bytes.extend(encode_sleb128(1));
        bytes.extend(encode_sleb128(0));
        // group_size = 1, grouped by info + grouped by addend + has addend
        bytes.extend(encode_sleb128(1));
        bytes.extend(encode_sleb128(0b1101));
        bytes.extend(encode_sleb128(R_AARCH64_RELATIVE as i64));
        bytes.extend(encode_sleb128(0x200));
        bytes.extend(encode_sleb128(0x100));

        let relocs = parse_android_rela_aps2(&bytes).expect("parse packed relocations");
        assert_eq!(relocs.len(), 1);
        assert_eq!(relocs[0].offset, 0x100);
        assert_eq!(relocs[0].sym, 0);
        assert_eq!(relocs[0].typ, R_AARCH64_RELATIVE);
        assert_eq!(relocs[0].addend, 0x200);
    }

    #[test]
    fn applies_relative_relocation() {
        let mut data = vec![0u8; 16];
        let segments = vec![Segment {
            file_offset: 0,
            vaddr: 0,
            file_size: data.len() as u64,
            mem_size: data.len() as u64,
        }];
        let reloc = PackedRela {
            offset: 8,
            sym: 0,
            typ: R_AARCH64_RELATIVE,
            addend: 0x1234,
        };

        apply_relocation_record(&mut data, &segments, &[], reloc).expect("apply relative");
        assert_eq!(u64::from_le_bytes(data[8..16].try_into().unwrap()), 0x1234);
    }

    #[test]
    fn applies_symbol_relocation() {
        let mut data = vec![0u8; 8];
        let segments = vec![Segment {
            file_offset: 0,
            vaddr: 0,
            file_size: data.len() as u64,
            mem_size: data.len() as u64,
        }];
        let reloc = PackedRela {
            offset: 0,
            sym: 1,
            typ: R_AARCH64_ABS64,
            addend: 4,
        };

        apply_relocation_record(&mut data, &segments, &[None, Some(0x2000)], reloc)
            .expect("apply symbol relocation");
        assert_eq!(u64::from_le_bytes(data[..8].try_into().unwrap()), 0x2004);
    }
}
