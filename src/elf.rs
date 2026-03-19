use std::collections::HashMap;

pub struct FunctionInfo {
    pub addr: u64,
    pub size: u64,
    pub name: Option<String>,
}

pub struct LoadedBinary {
    pub data: Vec<u8>,
    pub text_section_file_offset: u64,
    pub text_section_addr: u64,
    pub text_section_size: u64,
    pub functions: Vec<FunctionInfo>,
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

    /// Get raw bytes for the entire .text section
    pub fn text_bytes(&self) -> &[u8] {
        let start = self.text_section_file_offset as usize;
        let end = start + self.text_section_size as usize;
        &self.data[start..end.min(self.data.len())]
    }
}

pub fn load_elf(path: &str) -> Result<LoadedBinary, Box<dyn std::error::Error>> {
    use object::{Object, ObjectSection, ObjectSymbol, SymbolKind};

    let data = std::fs::read(path)?;

    let (text_file_offset, text_addr, text_size, mut functions) = {
        let obj = object::File::parse(&data[..])?;

        // .text section
        let text = obj
            .section_by_name(".text")
            .ok_or("no .text section found")?;
        let (text_file_offset, _) = text
            .file_range()
            .ok_or("no file range for .text")?;
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

        (text_file_offset, text_addr, text_size, functions)
    };

    functions.sort_by_key(|f| f.addr);

    Ok(LoadedBinary {
        data,
        text_section_file_offset: text_file_offset,
        text_section_addr: text_addr,
        text_section_size: text_size,
        functions,
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
