use aeon::lifter;
use aeon_jit::{JitConfig, ObjectCompiler};
use aeon_reduce::pipeline::reduce_block_local;
use aeonil::{Expr, Reg, Stmt, TrapKind};
use object::build;
use object::elf;
use object::read::{ObjectSection, ObjectSymbol, RelocationFlags};
use object::{Object, RelocationEncoding, RelocationKind, RelocationTarget, SymbolKind};
use serde::Serialize;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const DEFAULT_BASE: u64 = 0x9b5f_e000;
pub const DEFAULT_DEST: u64 = 0x7000_0000_00;
pub const DEFAULT_INPUT: &str = "capture/manual/jit_exec_alias_0x9b5fe000.bin";
pub const DEFAULT_OUTPUT_ELF: &str = "capture/manual/jit_exec_alias_0x9b5fe000.translated.elf";
pub const DEFAULT_OUTPUT_OBJ: &str = "capture/manual/jit_exec_alias_0x9b5fe000.translated.o";
pub const DEFAULT_OUTPUT_MAP: &str = "capture/manual/jit_exec_alias_0x9b5fe000.translated.map.json";
pub const MAX_BLOCK_INSNS: usize = 256;
const PIC_PAGE_ALIGN: u64 = 0x1000;
const PIC_TEXT_BASE: u64 = 0x1000;
const FCMLA_8H_HELPER_NAME: &str = "aeon_fcmla_8h";
const DEFAULT_HASH_BUCKET_COUNT: u32 = 4099;
const FCMLA_8H_HELPER_CODE: &[u8] = &[
    0x09, 0x40, 0x04, 0x91, 0x29, 0x11, 0x01, 0x8b, 0x0a, 0x40, 0x04, 0x91, 0x4a, 0x11, 0x02, 0x8b,
    0x20, 0x01, 0xc0, 0x3d, 0x41, 0x01, 0xc0, 0x3d, 0x62, 0x00, 0x67, 0x9e, 0xe4, 0x00, 0x00, 0xb4,
    0x9f, 0x68, 0x01, 0xf1, 0xe0, 0x00, 0x00, 0x54, 0x9f, 0xd0, 0x02, 0xf1, 0xe0, 0x00, 0x00, 0x54,
    0x9f, 0x38, 0x04, 0xf1, 0xe0, 0x00, 0x00, 0x54, 0x20, 0x10, 0x42, 0x6f, 0x06, 0x00, 0x00, 0x14,
    0x20, 0x30, 0x42, 0x6f, 0x04, 0x00, 0x00, 0x14, 0x20, 0x50, 0x42, 0x6f, 0x02, 0x00, 0x00, 0x14,
    0x20, 0x70, 0x42, 0x6f, 0x20, 0x01, 0x80, 0x3d, 0xc0, 0x03, 0x5f, 0xd6,
];

#[derive(Debug, Clone)]
pub struct TranslationConfig {
    pub base: u64,
    pub instructions: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct TranslationCompilation {
    pub object_bytes: Vec<u8>,
    pub instruction_limit: usize,
    pub block_count: usize,
    pub trap_block_count: usize,
    pub skipped_unsupported_blocks: Vec<SkippedBlockRecord>,
    pub invalid_instructions: usize,
    pub memory_read_hook_symbol: Option<String>,
    pub trap_hook_symbol: Option<String>,
    pub branch_translate_hook_symbol: Option<String>,
    pub branch_bridge_hook_symbol: Option<String>,
    pub unknown_block_hook_symbol: Option<String>,
    pub block_enter_hook_symbol: Option<String>,
    pub trap_blocks: Vec<TrapBlockSymbolRecord>,
    pub blocks: Vec<BlockSymbolRecord>,
    pub block_ids: Vec<BlockIdRecord>,
}

#[derive(Debug, Clone)]
pub struct FullMapMetadata {
    pub input: String,
    pub output_object: String,
    pub output_elf: String,
    pub output_map: String,
    pub base: u64,
    pub dest: u64,
}

#[derive(Default)]
struct BlockBuilder {
    start: u64,
    raw_stmts: Vec<Stmt>,
}

struct FinalizedBlock {
    start: u64,
    trap: Option<(TrapKind, u16)>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TranslationMap {
    pub input: String,
    pub output_object: String,
    pub output_elf: String,
    pub base: String,
    pub dest: String,
    pub instruction_limit: usize,
    pub block_count: usize,
    pub trap_block_count: usize,
    pub skipped_unsupported_blocks: Vec<SkippedBlockRecord>,
    pub invalid_instructions: usize,
    pub memory_read_hook: Option<HookMapRecord>,
    pub trap_hook: Option<HookMapRecord>,
    pub branch_translate_hook: Option<HookMapRecord>,
    pub branch_bridge_hook: Option<HookMapRecord>,
    pub unknown_block_hook: Option<HookMapRecord>,
    pub block_enter_hook: Option<HookMapRecord>,
    pub trap_block_log: String,
    pub trap_blocks: Vec<TrapBlockRecord>,
    pub blocks: Vec<BlockMapRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CompactTranslationMap {
    pub base: String,
    pub instruction_limit: usize,
    pub block_count: usize,
    pub trap_block_count: usize,
    pub invalid_instructions: usize,
    pub memory_read_hook: Option<HookSymbolRecord>,
    pub trap_hook: Option<HookSymbolRecord>,
    pub branch_translate_hook: Option<HookSymbolRecord>,
    pub branch_bridge_hook: Option<HookSymbolRecord>,
    pub unknown_block_hook: Option<HookSymbolRecord>,
    pub block_enter_hook: Option<HookSymbolRecord>,
    pub block_map: BTreeMap<String, String>,
    pub block_id_map: BTreeMap<String, String>,
    pub trap_block_map: BTreeMap<String, CompactTrapRecord>,
}

#[derive(Debug, Clone, Serialize)]
struct CompactMapJsonlMeta<'a> {
    #[serde(rename = "t")]
    kind: &'static str,
    base: &'a str,
    instruction_limit: usize,
    block_count: usize,
    trap_block_count: usize,
    invalid_instructions: usize,
    source_size: usize,
    memory_read_hook: Option<&'a HookSymbolRecord>,
    trap_hook: Option<&'a HookSymbolRecord>,
    branch_translate_hook: Option<&'a HookSymbolRecord>,
    branch_bridge_hook: Option<&'a HookSymbolRecord>,
    unknown_block_hook: Option<&'a HookSymbolRecord>,
    block_enter_hook: Option<&'a HookSymbolRecord>,
}

#[derive(Debug, Clone, Serialize)]
struct CompactMapJsonlBlock<'a> {
    #[serde(rename = "t")]
    kind: &'static str,
    src: &'a str,
    sym: &'a str,
}

#[derive(Debug, Clone, Serialize)]
struct CompactMapJsonlBlockId<'a> {
    #[serde(rename = "t")]
    kind: &'static str,
    id: &'a str,
    src: &'a str,
}

#[derive(Debug, Clone, Serialize)]
pub struct CompactTrapRecord {
    pub kind: String,
    pub imm: String,
}

#[derive(Debug, Clone, Serialize)]
struct CompactMapJsonlTrap<'a> {
    #[serde(rename = "t")]
    kind_tag: &'static str,
    src: &'a str,
    kind: &'a str,
    imm: &'a str,
}

#[derive(Debug, Clone, Serialize)]
pub struct HookMapRecord {
    pub symbol: String,
    pub addr: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct HookSymbolRecord {
    pub symbol: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BlockMapRecord {
    pub source_block: String,
    pub translated_addr: String,
    pub symbol: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BlockSymbolRecord {
    pub source_block: u64,
    pub symbol: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BlockIdRecord {
    pub block_id: u64,
    pub source_block: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TrapBlockRecord {
    pub source_block: String,
    pub translated_addr: String,
    pub symbol: String,
    pub kind: String,
    pub imm: String,
}

#[derive(Debug, Clone)]
pub struct TrapBlockSymbolRecord {
    pub source_block: u64,
    pub symbol: String,
    pub kind: TrapKind,
    pub imm: u16,
}

#[derive(Debug, Clone, Serialize)]
pub struct SkippedBlockRecord {
    pub source_block: String,
    pub reason: String,
}

pub fn translate_blob(
    blob: &[u8],
    config: &TranslationConfig,
) -> Result<TranslationCompilation, String> {
    let available_instructions = blob.len() / 4;
    let instruction_limit = config
        .instructions
        .unwrap_or_else(|| last_nonzero_instruction_limit(blob))
        .min(available_instructions);

    let mut compiler = ObjectCompiler::new_aarch64(JitConfig {
        instrument_memory: true,
        instrument_blocks: true,
    })
    .map_err(|err| format!("object compiler init: {err}"))?;

    let mut block_count = 0usize;
    let mut skipped_unsupported_blocks = Vec::new();
    let mut trap_block_starts = BTreeMap::new();
    let mut invalid_count = 0usize;
    let mut current = BlockBuilder::default();

    for index in 0..instruction_limit {
        let offset = index * 4;
        let addr = config.base + offset as u64;
        let word = u32::from_le_bytes(blob[offset..offset + 4].try_into().unwrap());

        match bad64::decode(word, addr) {
            Ok(insn) => {
                let next_pc = Some(addr + 4);
                let result = lifter::lift(&insn, addr, next_pc);
                if current.raw_stmts.is_empty() {
                    current.start = addr;
                }
                current.raw_stmts.push(result.stmt);
                if is_terminator(current.raw_stmts.last().unwrap())
                    || current.raw_stmts.len() >= MAX_BLOCK_INSNS
                {
                    match finalize_block(&mut compiler, &mut current) {
                        Ok(record) => {
                            block_count += 1;
                            if let Some(trap) = record.trap {
                                trap_block_starts.insert(record.start, trap);
                            }
                        }
                        Err(err) => skipped_unsupported_blocks.push(err),
                    }
                }
            }
            Err(_) => {
                invalid_count += 1;
                if !current.raw_stmts.is_empty() {
                    match finalize_block(&mut compiler, &mut current) {
                        Ok(record) => {
                            block_count += 1;
                            if let Some(trap) = record.trap {
                                trap_block_starts.insert(record.start, trap);
                            }
                        }
                        Err(err) => skipped_unsupported_blocks.push(err),
                    }
                }
            }
        }
    }

    if !current.raw_stmts.is_empty() {
        match finalize_block(&mut compiler, &mut current) {
            Ok(record) => {
                block_count += 1;
                if let Some(trap) = record.trap {
                    trap_block_starts.insert(record.start, trap);
                }
            }
            Err(err) => skipped_unsupported_blocks.push(err),
        }
    }

    let artifact = compiler
        .finish()
        .map_err(|err| format!("finish object: {err}"))?;

    let blocks = artifact
        .block_symbols
        .iter()
        .map(|(src, symbol)| BlockSymbolRecord {
            source_block: *src,
            symbol: symbol.clone(),
        })
        .collect::<Vec<_>>();
    let trap_blocks = artifact
        .block_symbols
        .iter()
        .filter_map(|(src, symbol)| {
            let (kind, imm) = trap_block_starts.get(src)?;
            Some(TrapBlockSymbolRecord {
                source_block: *src,
                symbol: symbol.clone(),
                kind: *kind,
                imm: *imm,
            })
        })
        .collect::<Vec<_>>();
    let block_ids = artifact
        .block_ids
        .iter()
        .map(|(src, block_id)| BlockIdRecord {
            block_id: *block_id,
            source_block: *src,
        })
        .collect::<Vec<_>>();

    Ok(TranslationCompilation {
        object_bytes: artifact.bytes,
        instruction_limit,
        block_count,
        trap_block_count: trap_blocks.len(),
        skipped_unsupported_blocks,
        invalid_instructions: invalid_count,
        memory_read_hook_symbol: artifact.memory_read_hook_symbol,
        trap_hook_symbol: artifact.trap_hook_symbol,
        branch_translate_hook_symbol: artifact.branch_translate_hook_symbol,
        branch_bridge_hook_symbol: artifact.branch_bridge_hook_symbol,
        unknown_block_hook_symbol: artifact.unknown_block_hook_symbol,
        block_enter_hook_symbol: artifact.block_enter_hook_symbol,
        trap_blocks,
        blocks,
        block_ids,
    })
}

impl TranslationCompilation {
    pub fn compact_map(&self, base: u64) -> CompactTranslationMap {
        let mut block_map = BTreeMap::new();
        for block in &self.blocks {
            block_map.insert(format_hex(block.source_block), block.symbol.clone());
        }
        let mut block_id_map = BTreeMap::new();
        for record in &self.block_ids {
            block_id_map.insert(format_hex(record.block_id), format_hex(record.source_block));
        }
        let mut trap_block_map = BTreeMap::new();
        for trap in &self.trap_blocks {
            trap_block_map.insert(
                format_hex(trap.source_block),
                CompactTrapRecord {
                    kind: trap_kind_name(trap.kind).to_string(),
                    imm: format_hex(u64::from(trap.imm)),
                },
            );
        }
        CompactTranslationMap {
            base: format_hex(base),
            instruction_limit: self.instruction_limit,
            block_count: self.block_count,
            trap_block_count: self.trap_block_count,
            invalid_instructions: self.invalid_instructions,
            memory_read_hook: self.memory_read_hook_symbol.as_ref().map(|symbol| {
                HookSymbolRecord {
                    symbol: symbol.clone(),
                }
            }),
            trap_hook: self
                .trap_hook_symbol
                .as_ref()
                .map(|symbol| HookSymbolRecord {
                    symbol: symbol.clone(),
                }),
            branch_translate_hook: self.branch_translate_hook_symbol.as_ref().map(|symbol| {
                HookSymbolRecord {
                    symbol: symbol.clone(),
                }
            }),
            branch_bridge_hook: self.branch_bridge_hook_symbol.as_ref().map(|symbol| {
                HookSymbolRecord {
                    symbol: symbol.clone(),
                }
            }),
            unknown_block_hook: self.unknown_block_hook_symbol.as_ref().map(|symbol| {
                HookSymbolRecord {
                    symbol: symbol.clone(),
                }
            }),
            block_enter_hook: self.block_enter_hook_symbol.as_ref().map(|symbol| {
                HookSymbolRecord {
                    symbol: symbol.clone(),
                }
            }),
            block_map,
            block_id_map,
            trap_block_map,
        }
    }

    pub fn full_map(
        &self,
        metadata: &FullMapMetadata,
        symbol_map: &BTreeMap<String, u64>,
    ) -> TranslationMap {
        let trap_blocks = self
            .trap_blocks
            .iter()
            .filter_map(|record| {
                symbol_map.get(&record.symbol).map(|addr| TrapBlockRecord {
                    source_block: format_hex(record.source_block),
                    translated_addr: format_hex(*addr),
                    symbol: record.symbol.clone(),
                    kind: trap_kind_name(record.kind).to_string(),
                    imm: format_hex(u64::from(record.imm)),
                })
            })
            .collect::<Vec<_>>();
        let blocks = self
            .blocks
            .iter()
            .filter_map(|record| {
                symbol_map.get(&record.symbol).map(|addr| BlockMapRecord {
                    source_block: format_hex(record.source_block),
                    translated_addr: format_hex(*addr),
                    symbol: record.symbol.clone(),
                })
            })
            .collect::<Vec<_>>();
        let trap_block_log = trap_log_path(Path::new(&metadata.output_map))
            .display()
            .to_string();

        TranslationMap {
            input: metadata.input.clone(),
            output_object: metadata.output_object.clone(),
            output_elf: metadata.output_elf.clone(),
            base: format_hex(metadata.base),
            dest: format_hex(metadata.dest),
            instruction_limit: self.instruction_limit,
            block_count: self.block_count,
            trap_block_count: self.trap_block_count,
            skipped_unsupported_blocks: self.skipped_unsupported_blocks.clone(),
            invalid_instructions: self.invalid_instructions,
            memory_read_hook: self.memory_read_hook_symbol.as_ref().and_then(|name| {
                symbol_map.get(name).map(|addr| HookMapRecord {
                    symbol: name.clone(),
                    addr: format_hex(*addr),
                })
            }),
            trap_hook: self.trap_hook_symbol.as_ref().and_then(|name| {
                symbol_map.get(name).map(|addr| HookMapRecord {
                    symbol: name.clone(),
                    addr: format_hex(*addr),
                })
            }),
            branch_translate_hook: self.branch_translate_hook_symbol.as_ref().and_then(|name| {
                symbol_map.get(name).map(|addr| HookMapRecord {
                    symbol: name.clone(),
                    addr: format_hex(*addr),
                })
            }),
            branch_bridge_hook: self.branch_bridge_hook_symbol.as_ref().and_then(|name| {
                symbol_map.get(name).map(|addr| HookMapRecord {
                    symbol: name.clone(),
                    addr: format_hex(*addr),
                })
            }),
            unknown_block_hook: self.unknown_block_hook_symbol.as_ref().and_then(|name| {
                symbol_map.get(name).map(|addr| HookMapRecord {
                    symbol: name.clone(),
                    addr: format_hex(*addr),
                })
            }),
            block_enter_hook: self.block_enter_hook_symbol.as_ref().and_then(|name| {
                symbol_map.get(name).map(|addr| HookMapRecord {
                    symbol: name.clone(),
                    addr: format_hex(*addr),
                })
            }),
            trap_block_log,
            trap_blocks,
            blocks,
        }
    }
}

pub fn compact_map_path(output_map: &Path) -> PathBuf {
    let mut path = output_map.to_path_buf();
    let file_name = output_map
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| format!("{name}.compact.blockmap.json"))
        .unwrap_or_else(|| "compact.blockmap.json".to_string());
    path.set_file_name(file_name);
    path
}

pub fn compact_map_jsonl_path(output_map: &Path) -> PathBuf {
    let mut path = output_map.to_path_buf();
    let file_name = output_map
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| format!("{name}.compact.blockmap.jsonl"))
        .unwrap_or_else(|| "compact.blockmap.jsonl".to_string());
    path.set_file_name(file_name);
    path
}

pub fn format_compact_map_jsonl(map: &CompactTranslationMap) -> Result<String, String> {
    let mut out = String::new();
    let meta = CompactMapJsonlMeta {
        kind: "meta",
        base: &map.base,
        instruction_limit: map.instruction_limit,
        block_count: map.block_count,
        trap_block_count: map.trap_block_count,
        invalid_instructions: map.invalid_instructions,
        source_size: map.instruction_limit * 4,
        memory_read_hook: map.memory_read_hook.as_ref(),
        trap_hook: map.trap_hook.as_ref(),
        branch_translate_hook: map.branch_translate_hook.as_ref(),
        branch_bridge_hook: map.branch_bridge_hook.as_ref(),
        unknown_block_hook: map.unknown_block_hook.as_ref(),
        block_enter_hook: map.block_enter_hook.as_ref(),
    };
    writeln!(
        out,
        "{}",
        serde_json::to_string(&meta)
            .map_err(|err| format!("serialize compact jsonl meta: {err}"))?
    )
    .map_err(|err| format!("format compact jsonl meta: {err}"))?;
    for (src, sym) in &map.block_map {
        let record = CompactMapJsonlBlock {
            kind: "b",
            src,
            sym,
        };
        writeln!(
            out,
            "{}",
            serde_json::to_string(&record)
                .map_err(|err| format!("serialize compact jsonl block {src}: {err}"))?
        )
        .map_err(|err| format!("format compact jsonl block {src}: {err}"))?;
    }
    for (id, src) in &map.block_id_map {
        let record = CompactMapJsonlBlockId { kind: "i", id, src };
        writeln!(
            out,
            "{}",
            serde_json::to_string(&record)
                .map_err(|err| format!("serialize compact jsonl block id {id}: {err}"))?
        )
        .map_err(|err| format!("format compact jsonl block id {id}: {err}"))?;
    }
    for (src, trap) in &map.trap_block_map {
        let record = CompactMapJsonlTrap {
            kind_tag: "t",
            src,
            kind: &trap.kind,
            imm: &trap.imm,
        };
        writeln!(
            out,
            "{}",
            serde_json::to_string(&record)
                .map_err(|err| format!("serialize compact jsonl trap block {src}: {err}"))?
        )
        .map_err(|err| format!("format compact jsonl trap block {src}: {err}"))?;
    }
    Ok(out)
}

pub fn trap_log_path(output_map: &Path) -> PathBuf {
    let mut path = output_map.to_path_buf();
    let file_name = output_map
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| format!("{name}.trap_blocks.txt"))
        .unwrap_or_else(|| "trap_blocks.txt".to_string());
    path.set_file_name(file_name);
    path
}

pub fn format_trap_block_log(records: &[TrapBlockRecord]) -> Result<String, std::fmt::Error> {
    use std::fmt::Write;
    let mut out = String::new();
    for record in records {
        writeln!(
            out,
            "{} {} {} {} {}",
            record.source_block, record.translated_addr, record.symbol, record.kind, record.imm
        )?;
    }
    Ok(out)
}

pub fn last_nonzero_instruction_limit(blob: &[u8]) -> usize {
    let mut last_nz_word = None;
    let limit = blob.len() - (blob.len() % 4);
    for offset in (0..limit).step_by(4) {
        if blob[offset..offset + 4] != [0, 0, 0, 0] {
            last_nz_word = Some(offset);
        }
    }
    last_nz_word.map(|off| off / 4 + 1).unwrap_or(0)
}

pub fn link_object_with(
    input_obj: &Path,
    output_elf: &Path,
    dest: u64,
    linker: Option<&Path>,
) -> Result<(), String> {
    if let Some(linker) = linker {
        let status = Command::new(linker)
            .arg("-shared")
            .arg("-nostdlib")
            .arg("-z")
            .arg("notext")
            .arg("-Ttext")
            .arg(format!("0x{dest:x}"))
            .arg("-o")
            .arg(output_elf)
            .arg(input_obj)
            .status()
            .map_err(|err| format!("spawn linker {}: {err}", linker.display()))?;
        if !status.success() {
            return Err(format!(
                "linker {} exited with status {status}",
                linker.display()
            ));
        }
        return Ok(());
    }

    let object_bytes =
        fs::read(input_obj).map_err(|err| format!("read {}: {err}", input_obj.display()))?;
    let linked = link_object_in_process(&object_bytes)?;
    fs::write(output_elf, linked).map_err(|err| format!("write {}: {err}", output_elf.display()))
}

pub fn load_symbol_map(path: &Path) -> Result<BTreeMap<String, u64>, String> {
    let bytes = fs::read(path).map_err(|err| format!("read {}: {err}", path.display()))?;
    let file = object::File::parse(bytes.as_slice())
        .map_err(|err| format!("parse {}: {err}", path.display()))?;
    let mut out = BTreeMap::new();
    for symbol in file.symbols() {
        if symbol.kind() != object::SymbolKind::Text {
            continue;
        }
        if let Ok(name) = symbol.name() {
            out.insert(name.to_string(), symbol.address());
        }
    }
    if out.is_empty() {
        for symbol in file.dynamic_symbols() {
            if symbol.kind() != object::SymbolKind::Text {
                continue;
            }
            if let Ok(name) = symbol.name() {
                out.insert(name.to_string(), symbol.address());
            }
        }
    }
    Ok(out)
}

pub fn rebase_text_symbol_map(
    path: &Path,
    symbol_map: &BTreeMap<String, u64>,
    dest: u64,
) -> Result<BTreeMap<String, u64>, String> {
    let bytes = fs::read(path).map_err(|err| format!("read {}: {err}", path.display()))?;
    let file = object::File::parse(bytes.as_slice())
        .map_err(|err| format!("parse {}: {err}", path.display()))?;
    let text = file
        .section_by_name(".text")
        .ok_or_else(|| format!("{}: missing .text", path.display()))?;
    let text_base = text.address();
    let text_size = text.size();
    let mut rebased = BTreeMap::new();
    for (name, addr) in symbol_map {
        let rebased_addr = if *addr < text_size {
            dest.wrapping_add(*addr)
        } else if *addr >= text_base && *addr < text_base.wrapping_add(text_size) {
            dest.wrapping_add(addr.wrapping_sub(text_base))
        } else {
            *addr
        };
        rebased.insert(name.clone(), rebased_addr);
    }
    Ok(rebased)
}

pub fn format_hex(value: u64) -> String {
    format!("0x{value:x}")
}

fn link_object_in_process(input: &[u8]) -> Result<Vec<u8>, String> {
    let file =
        object::File::parse(input).map_err(|err| format!("parse relocatable object: {err}"))?;
    let text = file
        .section_by_name(".text")
        .ok_or_else(|| "relocatable object missing .text".to_string())?;
    let mut text_bytes = text
        .data()
        .map_err(|err| format!("read .text section: {err}"))?
        .to_vec();
    let fcmla_helper_offset = align_up(text_bytes.len() as u64, 4);
    text_bytes.resize(fcmla_helper_offset as usize, 0);
    text_bytes.extend_from_slice(FCMLA_8H_HELPER_CODE);
    let text_align = text.align().max(16);
    let text_index = text.index();
    let exports = collect_exported_text_symbols(&file, text_index)?;

    apply_text_relocations(
        &file,
        text_index,
        PIC_TEXT_BASE,
        fcmla_helper_offset,
        &mut text_bytes,
    )?;

    let mut builder = build::elf::Builder::new(object::Endianness::Little, true);
    builder.header.e_type = elf::ET_DYN;
    builder.header.e_machine = elf::EM_AARCH64;
    builder.header.e_phoff = 0x40;
    builder.load_align = PIC_PAGE_ALIGN;

    let section = builder.sections.add();
    section.name = b".shstrtab"[..].into();
    section.sh_type = elf::SHT_STRTAB;
    section.data = build::elf::SectionData::SectionString;

    let section = builder.sections.add();
    section.name = b".text"[..].into();
    section.sh_type = elf::SHT_PROGBITS;
    section.sh_flags = (elf::SHF_ALLOC | elf::SHF_EXECINSTR) as u64;
    section.sh_addralign = text_align;
    section.data = build::elf::SectionData::Data(text_bytes.into());
    let text_id = section.id();

    let section = builder.sections.add();
    section.name = b".dynsym"[..].into();
    section.sh_type = elf::SHT_DYNSYM;
    section.sh_flags = elf::SHF_ALLOC as u64;
    section.sh_addralign = 8;
    section.data = build::elf::SectionData::DynamicSymbol;
    let dynsym_id = section.id();

    let section = builder.sections.add();
    section.name = b".dynstr"[..].into();
    section.sh_type = elf::SHT_STRTAB;
    section.sh_flags = elf::SHF_ALLOC as u64;
    section.sh_addralign = 1;
    section.data = build::elf::SectionData::DynamicString;
    let dynstr_id = section.id();

    let section = builder.sections.add();
    section.name = b".hash"[..].into();
    section.sh_type = elf::SHT_HASH;
    section.sh_flags = elf::SHF_ALLOC as u64;
    section.sh_addralign = 8;
    section.sh_link_section = Some(dynsym_id);
    section.data = build::elf::SectionData::Hash;
    let hash_id = section.id();

    let section = builder.sections.add();
    section.name = b".dynamic"[..].into();
    section.sh_type = elf::SHT_DYNAMIC;
    section.sh_flags = elf::SHF_ALLOC as u64;
    section.sh_addralign = 8;
    section.sh_entsize = 16;
    section.sh_link_section = Some(dynstr_id);
    section.data = build::elf::SectionData::Dynamic(vec![
        build::elf::Dynamic::Auto {
            tag: elf::DT_SYMTAB,
        },
        build::elf::Dynamic::Auto {
            tag: elf::DT_STRTAB,
        },
        build::elf::Dynamic::Auto { tag: elf::DT_STRSZ },
        build::elf::Dynamic::Auto { tag: elf::DT_HASH },
        build::elf::Dynamic::Integer {
            tag: elf::DT_SYMENT,
            val: 24,
        },
    ]);
    let dynamic_id = section.id();

    for export in &exports {
        let symbol = builder.dynamic_symbols.add();
        symbol.name = export.name.as_bytes().to_vec().into();
        symbol.set_st_info(elf::STB_GLOBAL, elf::STT_FUNC);
        symbol.section = Some(text_id);
        symbol.st_value = export.offset;
        symbol.st_size = export.size;
    }
    builder.hash_bucket_count = DEFAULT_HASH_BUCKET_COUNT;

    builder.set_section_sizes();

    let segment = builder.segments.add();
    segment.p_type = elf::PT_LOAD;
    segment.p_flags = elf::PF_R | elf::PF_X;
    segment.p_offset = 0;
    segment.p_vaddr = 0;
    segment.p_paddr = 0;
    segment.p_filesz = PIC_TEXT_BASE;
    segment.p_memsz = PIC_TEXT_BASE;
    segment.p_align = PIC_PAGE_ALIGN;
    segment.append_section(builder.sections.get_mut(text_id));
    segment.append_section(builder.sections.get_mut(dynsym_id));
    segment.append_section(builder.sections.get_mut(dynstr_id));
    segment.append_section(builder.sections.get_mut(hash_id));

    let dynamic_load = builder.segments.add_load_segment(elf::PF_R, PIC_PAGE_ALIGN);
    dynamic_load.append_section(builder.sections.get_mut(dynamic_id));

    let dynamic_segment = builder.segments.add();
    dynamic_segment.p_type = elf::PT_DYNAMIC;
    dynamic_segment.p_flags = elf::PF_R;
    dynamic_segment.p_align = 8;
    dynamic_segment.append_section_range(builder.sections.get(dynamic_id));
    dynamic_segment.sections.push(dynamic_id);

    let mut buffer = Vec::new();
    builder
        .write(&mut buffer)
        .map_err(|err| format!("write shared object: {err}"))?;
    Ok(buffer)
}

#[derive(Debug)]
struct ExportedTextSymbol {
    name: String,
    offset: u64,
    size: u64,
}

fn collect_exported_text_symbols<'data>(
    file: &object::File<'data>,
    text_index: object::SectionIndex,
) -> Result<Vec<ExportedTextSymbol>, String> {
    let mut exports = Vec::new();
    for symbol in file.symbols() {
        if !symbol.is_definition() || !symbol.is_global() {
            continue;
        }
        if symbol.kind() != SymbolKind::Text {
            continue;
        }
        if symbol.section_index() != Some(text_index) {
            continue;
        }
        let name = symbol
            .name()
            .map_err(|err| format!("read symbol name: {err}"))?;
        if name.is_empty() {
            continue;
        }
        exports.push(ExportedTextSymbol {
            name: name.to_string(),
            offset: symbol.address(),
            size: symbol.size(),
        });
    }
    Ok(exports)
}

fn apply_text_relocations<'data>(
    file: &object::File<'data>,
    text_index: object::SectionIndex,
    text_vaddr: u64,
    fcmla_helper_offset: u64,
    text_bytes: &mut [u8],
) -> Result<(), String> {
    let text = file
        .section_by_index(text_index)
        .map_err(|err| format!("reload .text section: {err}"))?;
    for (offset, relocation) in text.relocations() {
        apply_text_relocation(
            file,
            text_index,
            text_vaddr,
            fcmla_helper_offset,
            text_bytes,
            offset,
            relocation,
        )?;
    }
    Ok(())
}

fn apply_text_relocation<'data>(
    file: &object::File<'data>,
    text_index: object::SectionIndex,
    text_vaddr: u64,
    fcmla_helper_offset: u64,
    text_bytes: &mut [u8],
    offset: u64,
    relocation: object::Relocation,
) -> Result<(), String> {
    let target = relocation_target_address(
        file,
        text_index,
        text_vaddr,
        fcmla_helper_offset,
        relocation.target(),
    )?;
    let addend = relocation.addend() as i128;
    let place = text_vaddr
        .checked_add(offset)
        .ok_or_else(|| format!("relocation place overflow at {offset:#x}"))?
        as i128;
    let start =
        usize::try_from(offset).map_err(|_| format!("relocation offset too large: {offset:#x}"))?;

    match (relocation.kind(), relocation.encoding(), relocation.size()) {
        (RelocationKind::Absolute, _, 64) => {
            let end = start
                .checked_add(8)
                .ok_or_else(|| format!("absolute relocation range overflow at {offset:#x}"))?;
            let value = checked_i128_to_u64(target as i128 + addend, "R_AARCH64_ABS64")?;
            text_bytes[start..end].copy_from_slice(&value.to_le_bytes());
            Ok(())
        }
        (RelocationKind::PltRelative, RelocationEncoding::AArch64Call, 26) => {
            let end = start
                .checked_add(4)
                .ok_or_else(|| format!("CALL26 relocation range overflow at {offset:#x}"))?;
            let delta = target as i128 + addend - place;
            if delta % 4 != 0 {
                return Err(format!(
                    "R_AARCH64_CALL26 at {offset:#x} has unaligned delta {delta:#x}"
                ));
            }
            let min = -(1i128 << 27);
            let max = (1i128 << 27) - 4;
            if !(min..=max).contains(&delta) {
                return Err(format!(
                    "R_AARCH64_CALL26 at {offset:#x} out of range: delta {delta:#x}"
                ));
            }
            let imm26 = u32::try_from(((delta >> 2) as i64) & 0x03ff_ffff)
                .map_err(|_| format!("R_AARCH64_CALL26 immediate out of range at {offset:#x}"))?;
            let original =
                u32::from_le_bytes(text_bytes[start..end].try_into().expect("4-byte slice"));
            let patched = (original & 0xfc00_0000) | imm26;
            text_bytes[start..end].copy_from_slice(&patched.to_le_bytes());
            Ok(())
        }
        _ => {
            let description = match relocation.flags() {
                RelocationFlags::Elf { r_type } => format!("ELF relocation type {r_type}"),
                other => format!("{other:?}"),
            };
            Err(format!(
                "unsupported .text relocation at {offset:#x}: kind={:?} encoding={:?} size={} ({description})",
                relocation.kind(),
                relocation.encoding(),
                relocation.size()
            ))
        }
    }
}

fn relocation_target_address<'data>(
    file: &object::File<'data>,
    text_index: object::SectionIndex,
    text_vaddr: u64,
    fcmla_helper_offset: u64,
    target: RelocationTarget,
) -> Result<u64, String> {
    match target {
        RelocationTarget::Symbol(index) => {
            let symbol = file
                .symbol_by_index(index)
                .map_err(|err| format!("resolve relocation symbol {index:?}: {err}"))?;
            let name = symbol.name().unwrap_or("<unnamed>");
            if symbol.is_undefined() {
                if name == FCMLA_8H_HELPER_NAME {
                    return text_vaddr
                        .checked_add(fcmla_helper_offset)
                        .ok_or_else(|| format!("FCMLA helper address overflow for {name}"));
                }
                return Err(format!("unresolved relocation target {name}"));
            }
            let section = symbol
                .section_index()
                .ok_or_else(|| format!("symbol {name} missing section"))?;
            if section != text_index {
                return Err(format!(
                    "unsupported relocation target {name} in section {section:?}"
                ));
            }
            text_vaddr
                .checked_add(symbol.address())
                .ok_or_else(|| format!("symbol address overflow for {name}"))
        }
        RelocationTarget::Section(index) => {
            if index != text_index {
                return Err(format!("unsupported relocation target section {index:?}"));
            }
            Ok(text_vaddr)
        }
        RelocationTarget::Absolute => Ok(0),
        _ => Err(format!("unsupported relocation target {target:?}")),
    }
}

fn checked_i128_to_u64(value: i128, context: &str) -> Result<u64, String> {
    if !(0..=u64::MAX as i128).contains(&value) {
        return Err(format!("{context} result out of range: {value:#x}"));
    }
    Ok(value as u64)
}

fn align_up(value: u64, align: u64) -> u64 {
    debug_assert!(align.is_power_of_two());
    (value + (align - 1)) & !(align - 1)
}

fn finalize_block(
    compiler: &mut ObjectCompiler,
    current: &mut BlockBuilder,
) -> Result<FinalizedBlock, SkippedBlockRecord> {
    let start = current.start;
    let return_addr = start + (current.raw_stmts.len() as u64 * 4);
    let transformed = transform_calls_and_rets(std::mem::take(&mut current.raw_stmts), return_addr);
    current.start = 0;
    let reduced = reduce_block_local(transformed);
    let trap = match reduced.as_slice() {
        [Stmt::Trap { kind, imm }] => Some((*kind, *imm)),
        _ => None,
    };
    compiler
        .compile_block(start, &reduced)
        .map_err(|err| SkippedBlockRecord {
            source_block: format_hex(start),
            reason: err.to_string(),
        })?;
    Ok(FinalizedBlock { start, trap })
}

fn transform_calls_and_rets(stmts: Vec<Stmt>, return_addr: u64) -> Vec<Stmt> {
    let mut out = Vec::with_capacity(stmts.len() + 1);
    for stmt in stmts {
        match stmt {
            Stmt::Call { target } => {
                let target = match target {
                    Expr::Reg(Reg::X(30)) => {
                        out.push(Stmt::Assign {
                            dst: Reg::X(17),
                            src: Expr::Reg(Reg::X(30)),
                        });
                        Expr::Reg(Reg::X(17))
                    }
                    other => other,
                };
                out.push(Stmt::Assign {
                    dst: Reg::X(30),
                    src: Expr::Imm(return_addr),
                });
                out.push(Stmt::Branch { target });
            }
            Stmt::Ret => out.push(Stmt::Branch {
                target: Expr::Reg(Reg::X(30)),
            }),
            Stmt::Pair(lhs, rhs) => {
                out.extend(transform_calls_and_rets(vec![*lhs, *rhs], return_addr))
            }
            other => out.push(other),
        }
    }
    out
}

fn is_terminator(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Branch { .. }
        | Stmt::CondBranch { .. }
        | Stmt::Call { .. }
        | Stmt::Ret
        | Stmt::Trap { .. } => true,
        Stmt::Pair(lhs, rhs) => is_terminator(lhs) || is_terminator(rhs),
        _ => false,
    }
}

fn trap_kind_name(kind: TrapKind) -> &'static str {
    match kind {
        TrapKind::Brk => "brk",
        TrapKind::Udf => "udf",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use object::ObjectSymbol;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn last_nonzero_limit_is_exclusive() {
        let mut blob = vec![0u8; 0x20];
        blob[0x10..0x14].copy_from_slice(&0x1122_3344u32.to_le_bytes());
        assert_eq!(last_nonzero_instruction_limit(&blob), 5);
    }

    #[test]
    fn trap_log_path_uses_output_map_filename() {
        let path = trap_log_path(Path::new("/tmp/out.map.json"));
        assert_eq!(path, PathBuf::from("/tmp/out.map.json.trap_blocks.txt"));
    }

    #[test]
    fn compact_map_path_uses_output_map_filename() {
        let path = compact_map_path(Path::new("/tmp/out.map.json"));
        assert_eq!(
            path,
            PathBuf::from("/tmp/out.map.json.compact.blockmap.json")
        );
    }

    #[test]
    fn compact_map_jsonl_path_uses_output_map_filename() {
        let path = compact_map_jsonl_path(Path::new("/tmp/out.map.json"));
        assert_eq!(
            path,
            PathBuf::from("/tmp/out.map.json.compact.blockmap.jsonl")
        );
    }

    #[test]
    fn format_trap_block_log_emits_one_record_per_line() {
        let log = format_trap_block_log(&[
            TrapBlockRecord {
                source_block: "0x1000".to_string(),
                translated_addr: "0x7100001000".to_string(),
                symbol: "aeon_jit_block_0000000000001000_0".to_string(),
                kind: "brk".to_string(),
                imm: "0x4711".to_string(),
            },
            TrapBlockRecord {
                source_block: "0x2000".to_string(),
                translated_addr: "0x7100002000".to_string(),
                symbol: "aeon_jit_block_0000000000002000_1".to_string(),
                kind: "udf".to_string(),
                imm: "0x0".to_string(),
            },
        ])
        .expect("format");
        assert_eq!(
            log,
            "0x1000 0x7100001000 aeon_jit_block_0000000000001000_0 brk 0x4711\n\
0x2000 0x7100002000 aeon_jit_block_0000000000002000_1 udf 0x0\n"
        );
    }

    #[test]
    fn finalize_block_preserves_trap_payload() {
        let mut compiler = ObjectCompiler::new_aarch64(JitConfig {
            instrument_memory: true,
            instrument_blocks: true,
        })
        .expect("compiler");
        let mut current = BlockBuilder {
            start: 0x1000,
            raw_stmts: vec![Stmt::Trap {
                kind: TrapKind::Brk,
                imm: 0x1234,
            }],
        };
        let finalized = finalize_block(&mut compiler, &mut current).expect("finalize");
        assert_eq!(finalized.trap, Some((TrapKind::Brk, 0x1234)));
    }

    #[test]
    fn compact_map_uses_block_map_shape() {
        let compilation = TranslationCompilation {
            object_bytes: Vec::new(),
            instruction_limit: 4,
            block_count: 2,
            trap_block_count: 1,
            skipped_unsupported_blocks: Vec::new(),
            invalid_instructions: 0,
            memory_read_hook_symbol: Some("aeon_log_mem_read".to_string()),
            trap_hook_symbol: Some("aeon_log_trap".to_string()),
            branch_translate_hook_symbol: Some("aeon_translate_branch_target".to_string()),
            branch_bridge_hook_symbol: Some("aeon_bridge_branch_target".to_string()),
            unknown_block_hook_symbol: Some("aeon_unknown_block_addr".to_string()),
            block_enter_hook_symbol: Some("on_block_enter".to_string()),
            trap_blocks: vec![TrapBlockSymbolRecord {
                source_block: 0x1000,
                symbol: "trap_block".to_string(),
                kind: TrapKind::Udf,
                imm: 0,
            }],
            blocks: vec![
                BlockSymbolRecord {
                    source_block: 0x1000,
                    symbol: "block0".to_string(),
                },
                BlockSymbolRecord {
                    source_block: 0x2000,
                    symbol: "block1".to_string(),
                },
            ],
            block_ids: vec![
                BlockIdRecord {
                    block_id: 0,
                    source_block: 0x1000,
                },
                BlockIdRecord {
                    block_id: 1,
                    source_block: 0x2000,
                },
            ],
        };
        let map = compilation.compact_map(0x1000);
        assert_eq!(map.base, "0x1000");
        assert_eq!(
            map.block_map.get("0x1000").map(String::as_str),
            Some("block0")
        );
        assert_eq!(
            map.block_map.get("0x2000").map(String::as_str),
            Some("block1")
        );
        assert_eq!(
            map.branch_bridge_hook
                .as_ref()
                .map(|record| record.symbol.as_str()),
            Some("aeon_bridge_branch_target")
        );
        assert_eq!(
            map.block_enter_hook
                .as_ref()
                .map(|record| record.symbol.as_str()),
            Some("on_block_enter")
        );
        assert_eq!(
            map.block_id_map.get("0x0").map(String::as_str),
            Some("0x1000")
        );
        assert_eq!(
            map.block_id_map.get("0x1").map(String::as_str),
            Some("0x2000")
        );
        assert_eq!(
            map.trap_block_map
                .get("0x1000")
                .map(|record| record.kind.as_str()),
            Some("udf")
        );
        assert_eq!(
            map.trap_block_map
                .get("0x1000")
                .map(|record| record.imm.as_str()),
            Some("0x0")
        );
    }

    #[test]
    fn compact_map_jsonl_emits_meta_blocks_and_ids() {
        let compilation = TranslationCompilation {
            object_bytes: Vec::new(),
            instruction_limit: 4,
            block_count: 2,
            trap_block_count: 0,
            skipped_unsupported_blocks: Vec::new(),
            invalid_instructions: 1,
            memory_read_hook_symbol: Some("aeon_log_mem_read".to_string()),
            trap_hook_symbol: Some("aeon_log_trap".to_string()),
            branch_translate_hook_symbol: Some("aeon_translate_branch_target".to_string()),
            branch_bridge_hook_symbol: Some("aeon_bridge_branch_target".to_string()),
            unknown_block_hook_symbol: Some("aeon_unknown_block_addr".to_string()),
            block_enter_hook_symbol: Some("on_block_enter".to_string()),
            trap_blocks: vec![TrapBlockSymbolRecord {
                source_block: 0x1000,
                symbol: "block0".to_string(),
                kind: TrapKind::Brk,
                imm: 0x1234,
            }],
            blocks: vec![
                BlockSymbolRecord {
                    source_block: 0x1000,
                    symbol: "block0".to_string(),
                },
                BlockSymbolRecord {
                    source_block: 0x2000,
                    symbol: "block1".to_string(),
                },
            ],
            block_ids: vec![
                BlockIdRecord {
                    block_id: 0,
                    source_block: 0x1000,
                },
                BlockIdRecord {
                    block_id: 1,
                    source_block: 0x2000,
                },
            ],
        };
        let jsonl = format_compact_map_jsonl(&compilation.compact_map(0x1000)).expect("jsonl");
        let lines = jsonl.lines().collect::<Vec<_>>();
        assert!(lines[0].contains("\"t\":\"meta\""));
        assert!(lines[0].contains("\"source_size\":16"));
        assert!(lines.iter().any(|line| line.contains("\"t\":\"b\"")
            && line.contains("\"src\":\"0x1000\"")
            && line.contains("\"sym\":\"block0\"")));
        assert!(lines.iter().any(|line| line.contains("\"t\":\"i\"")
            && line.contains("\"id\":\"0x1\"")
            && line.contains("\"src\":\"0x2000\"")));
        assert!(lines.iter().any(|line| line.contains("\"t\":\"t\"")
            && line.contains("\"src\":\"0x1000\"")
            && line.contains("\"kind\":\"brk\"")
            && line.contains("\"imm\":\"0x1234\"")));
    }

    #[test]
    fn link_object_in_process_exports_translated_blocks_and_hooks() {
        let mut compiler = ObjectCompiler::new_aarch64(JitConfig {
            instrument_memory: true,
            instrument_blocks: true,
        })
        .expect("compiler");
        compiler
            .compile_block(
                0x1000,
                &[
                    Stmt::Assign {
                        dst: Reg::X(0),
                        src: Expr::Load {
                            addr: Box::new(Expr::Imm(0x2000)),
                            size: 8,
                        },
                    },
                    Stmt::Branch {
                        target: Expr::Imm(0),
                    },
                ],
            )
            .expect("compile block");
        let artifact = compiler.finish().expect("finish object");
        let linked = link_object_in_process(&artifact.bytes).expect("self-link");
        let file = object::File::parse(linked.as_slice()).expect("parse self-linked elf");
        let mut dynamic_names = Vec::new();
        for symbol in file.dynamic_symbols() {
            if let Ok(name) = symbol.name() {
                dynamic_names.push(name.to_string());
            }
        }
        assert!(dynamic_names
            .iter()
            .any(|name| name.contains("aeon_jit_block_0000000000001000")));
        assert!(dynamic_names.iter().any(|name| name == "aeon_log_mem_read"));
        assert!(dynamic_names.iter().any(|name| name == "aeon_log_trap"));
        assert!(dynamic_names
            .iter()
            .any(|name| name == "aeon_translate_branch_target"));
        assert!(dynamic_names
            .iter()
            .any(|name| name == "aeon_bridge_branch_target"));
        assert!(dynamic_names.iter().any(|name| name == "on_block_enter"));
        assert!(file.section_by_name(".hash").is_some());
    }

    #[test]
    fn link_object_in_process_resolves_fcmla_helper_without_imports() {
        let mut compiler = ObjectCompiler::new_aarch64(JitConfig::default()).expect("compiler");
        compiler
            .compile_block(
                0x1000,
                &[Stmt::Intrinsic {
                    name: "fcmla.8h".to_string(),
                    operands: vec![
                        Expr::Reg(Reg::V(0)),
                        Expr::Reg(Reg::V(1)),
                        Expr::Extract {
                            src: Box::new(Expr::Reg(Reg::V(2))),
                            lsb: 16,
                            width: 16,
                        },
                        Expr::Imm(0x5a),
                    ],
                }],
            )
            .expect("compile block");
        let artifact = compiler.finish().expect("finish object");
        let linked = link_object_in_process(&artifact.bytes).expect("self-link");
        let file = object::File::parse(linked.as_slice()).expect("parse self-linked elf");
        let unresolved_fcmla = file
            .dynamic_symbols()
            .filter_map(|symbol| symbol.name().ok().map(|name| (name.to_string(), symbol)))
            .find(|(name, symbol)| name == FCMLA_8H_HELPER_NAME && symbol.is_undefined());
        assert!(unresolved_fcmla.is_none(), "fcmla helper stayed unresolved");
    }

    #[test]
    fn rebased_symbol_map_handles_relative_dynamic_symbols() {
        let mut compiler = ObjectCompiler::new_aarch64(JitConfig {
            instrument_memory: true,
            instrument_blocks: true,
        })
        .expect("compiler");
        compiler
            .compile_block(
                0x1000,
                &[Stmt::Branch {
                    target: Expr::Imm(0),
                }],
            )
            .expect("compile block");
        let artifact = compiler.finish().expect("finish object");
        let linked = link_object_in_process(&artifact.bytes).expect("self-link");

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("aeon-self-link-{unique}.so"));
        fs::write(&path, linked).expect("write temp elf");

        let raw = load_symbol_map(&path).expect("load raw symbol map");
        let rebased = rebase_text_symbol_map(&path, &raw, DEFAULT_DEST).expect("rebase");
        let memory_read = *rebased
            .get("aeon_log_mem_read")
            .expect("memory read hook should be rebased");
        assert!(
            memory_read > DEFAULT_DEST,
            "helper symbols should not sit at module base anymore"
        );
        let bridge = *rebased
            .get("aeon_bridge_branch_target")
            .expect("branch bridge hook should be rebased");
        assert!(
            bridge > memory_read,
            "helpers should have distinct nonzero offsets"
        );

        let _ = fs::remove_file(path);
    }
}
