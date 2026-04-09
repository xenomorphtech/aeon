use std::collections::HashMap;

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

pub fn load_raw(path: &str, base_addr: u64) -> Result<LoadedBinary, Box<dyn std::error::Error>> {
    let data = std::fs::read(path)?;
    let size = data.len() as u64;
    let text_name = ".text".to_string();

    Ok(LoadedBinary {
        data,
        text_section_file_offset: 0,
        text_section_addr: base_addr,
        text_section_size: size,
        functions: vec![FunctionInfo {
            addr: base_addr,
            size,
            name: Some("raw_text".to_string()),
        }],
        segments: vec![Segment {
            file_offset: 0,
            vaddr: base_addr,
            file_size: size,
            mem_size: size,
        }],
        sections: vec![SectionInfo {
            name: text_name,
            address: base_addr,
            size,
            file_offset: 0,
            file_size: size,
            is_alloc: true,
            is_writable: false,
            is_executable: true,
        }],
    })
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
    use object::{Object, ObjectSection, ObjectSymbol, SectionFlags, SymbolKind};

    let data = std::fs::read(path)?;

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
