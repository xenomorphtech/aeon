/// Unicorn-rs based code execution sandbox for bounded snippet emulation.
/// Handles complete ARM64 instruction set including FP operations.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;

use serde::Serialize;
use unicorn_engine::unicorn_const::{Arch, HookType, Mode, Prot};
use unicorn_engine::{RegisterARM64, Unicorn};

use crate::elf::LoadedBinary;

#[derive(Debug, Clone)]
pub struct WatchpointSpec {
    pub addr: u64,
    pub size: u64,
    pub on_read: bool,
    pub on_write: bool,
    pub stop_on_hit: bool,
}

#[derive(Debug, Clone)]
pub struct RegisterPatch {
    pub name: String,
    pub value: u64,
}

#[derive(Debug, Clone)]
pub struct AddressHookSpec {
    pub addr: u64,
    pub stop_on_hit: bool,
    pub patches: Vec<RegisterPatch>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WatchpointHit {
    pub watchpoint_addr: String,
    pub access_addr: String,
    pub access_size: usize,
    pub access_type: String,
    pub registers_at_hit: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AddressHookHit {
    pub hook_addr: String,
    pub registers_at_hit: HashMap<String, String>,
    pub patches_applied: Vec<String>,
}

/// Configuration for sandbox execution
pub struct SandboxConfig {
    pub step_limit: usize,
    pub stack_addr: u64,
    pub stack_size: u64,
    pub watchpoints: Vec<WatchpointSpec>,
    pub address_hooks: Vec<AddressHookSpec>,
    pub record_pc_trace: bool,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            step_limit: 1000,
            stack_addr: 0x7fff_8000,
            stack_size: 0x8000,
            watchpoints: Vec::new(),
            address_hooks: Vec::new(),
            record_pc_trace: false,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct MemWriteRecord {
    pub addr: String,
    pub size: usize,
    pub value: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DecodedStringRecord {
    pub addr: String,
    pub text: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SandboxResult {
    pub start_addr: String,
    pub end_addr: String,
    pub steps_executed: usize,
    pub stop_reason: String,
    pub final_registers: HashMap<String, String>,
    pub memory_writes: Vec<MemWriteRecord>,
    pub decoded_strings: Vec<DecodedStringRecord>,
    pub watchpoint_hits: Vec<WatchpointHit>,
    pub address_hook_hits: Vec<AddressHookHit>,
    pub pc_trace: Vec<String>,
    pub nzcv_decoded: String,
}

fn decode_nzcv(nzcv: u64) -> String {
    let n = (nzcv >> 31) & 1;
    let z = (nzcv >> 30) & 1;
    let c = (nzcv >> 29) & 1;
    let v = (nzcv >> 28) & 1;
    format!("N={} Z={} C={} V={}", n, z, c, v)
}

fn capture_registers_snapshot(uc: &Unicorn<()>) -> HashMap<String, String> {
    let mut result = HashMap::new();

    let x_regs = [
        ("x0", RegisterARM64::X0),
        ("x1", RegisterARM64::X1),
        ("x2", RegisterARM64::X2),
        ("x3", RegisterARM64::X3),
        ("x4", RegisterARM64::X4),
        ("x5", RegisterARM64::X5),
        ("x6", RegisterARM64::X6),
        ("x7", RegisterARM64::X7),
        ("x8", RegisterARM64::X8),
        ("x9", RegisterARM64::X9),
        ("x10", RegisterARM64::X10),
        ("x11", RegisterARM64::X11),
        ("x12", RegisterARM64::X12),
        ("x13", RegisterARM64::X13),
        ("x14", RegisterARM64::X14),
        ("x15", RegisterARM64::X15),
        ("x16", RegisterARM64::X16),
        ("x17", RegisterARM64::X17),
        ("x18", RegisterARM64::X18),
        ("x19", RegisterARM64::X19),
        ("x20", RegisterARM64::X20),
        ("x21", RegisterARM64::X21),
        ("x22", RegisterARM64::X22),
        ("x23", RegisterARM64::X23),
        ("x24", RegisterARM64::X24),
        ("x25", RegisterARM64::X25),
        ("x26", RegisterARM64::X26),
        ("x27", RegisterARM64::X27),
        ("x28", RegisterARM64::X28),
        ("x29", RegisterARM64::X29),
        ("x30", RegisterARM64::X30),
    ];

    for (name, reg) in &x_regs {
        if let Ok(value) = uc.reg_read(*reg) {
            result.insert(name.to_string(), format!("0x{:x}", value));
        }
    }

    if let Ok(sp) = uc.reg_read(RegisterARM64::SP) {
        result.insert("sp".to_string(), format!("0x{:x}", sp));
    }

    if let Ok(pc) = uc.reg_read(RegisterARM64::PC) {
        result.insert("pc".to_string(), format!("0x{:x}", pc));
    }

    if let Ok(nzcv) = uc.reg_read(RegisterARM64::NZCV) {
        result.insert("nzcv".to_string(), format!("0x{:x}", nzcv));
    }

    result
}

fn name_to_register_arm64(name: &str) -> Result<RegisterARM64, String> {
    let name_lower = name.to_lowercase();
    match name_lower.as_str() {
        "x0" => Ok(RegisterARM64::X0),
        "x1" => Ok(RegisterARM64::X1),
        "x2" => Ok(RegisterARM64::X2),
        "x3" => Ok(RegisterARM64::X3),
        "x4" => Ok(RegisterARM64::X4),
        "x5" => Ok(RegisterARM64::X5),
        "x6" => Ok(RegisterARM64::X6),
        "x7" => Ok(RegisterARM64::X7),
        "x8" => Ok(RegisterARM64::X8),
        "x9" => Ok(RegisterARM64::X9),
        "x10" => Ok(RegisterARM64::X10),
        "x11" => Ok(RegisterARM64::X11),
        "x12" => Ok(RegisterARM64::X12),
        "x13" => Ok(RegisterARM64::X13),
        "x14" => Ok(RegisterARM64::X14),
        "x15" => Ok(RegisterARM64::X15),
        "x16" => Ok(RegisterARM64::X16),
        "x17" => Ok(RegisterARM64::X17),
        "x18" => Ok(RegisterARM64::X18),
        "x19" => Ok(RegisterARM64::X19),
        "x20" => Ok(RegisterARM64::X20),
        "x21" => Ok(RegisterARM64::X21),
        "x22" => Ok(RegisterARM64::X22),
        "x23" => Ok(RegisterARM64::X23),
        "x24" => Ok(RegisterARM64::X24),
        "x25" => Ok(RegisterARM64::X25),
        "x26" => Ok(RegisterARM64::X26),
        "x27" => Ok(RegisterARM64::X27),
        "x28" => Ok(RegisterARM64::X28),
        "x29" => Ok(RegisterARM64::X29),
        "x30" => Ok(RegisterARM64::X30),
        "sp" => Ok(RegisterARM64::SP),
        "pc" => Ok(RegisterARM64::PC),
        "nzcv" | "flags" => Ok(RegisterARM64::NZCV),
        _ => Err(format!("Unknown register: {}", name)),
    }
}

/// Execute a code snippet in the unicorn sandbox.
pub fn run_sandbox(
    binary: &LoadedBinary,
    start_addr: u64,
    end_addr: u64,
    initial_registers: &HashMap<String, u64>,
    initial_memory: &HashMap<u64, Vec<u8>>,
    config: &SandboxConfig,
) -> Result<SandboxResult, String> {
    // Initialize unicorn engine
    let mut uc = Unicorn::new(Arch::ARM64, Mode::LITTLE_ENDIAN)
        .map_err(|e| format!("unicorn init: {:?}", e))?;

    // Map binary segments (page-aligned)
    for seg in &binary.segments {
        let map_base = seg.vaddr & !0xFFF;
        let map_end = ((seg.vaddr + seg.mem_size + 0xFFF) & !0xFFF).max(map_base + 0x1000);
        let map_size = map_end - map_base;

        // Try to map; ignore if already mapped
        let prot = Prot::ALL;
        let _ = uc.mem_map(map_base, map_size, prot);

        // Write file data
        if seg.file_size > 0 {
            let file_data = &binary.data[seg.file_offset as usize..];
            let write_size = seg.file_size.min(file_data.len() as u64) as usize;
            let _ = uc.mem_write(seg.vaddr, &file_data[..write_size]);
        }

        // Zero-fill BSS
        if seg.mem_size > seg.file_size {
            let bss_size = (seg.mem_size - seg.file_size) as usize;
            let zeros = vec![0u8; bss_size];
            let _ = uc.mem_write(seg.vaddr + seg.file_size, &zeros);
        }
    }

    // Map stack
    let _ = uc.mem_map(config.stack_addr, config.stack_size, Prot::ALL);
    let zeros = vec![0u8; config.stack_size as usize];
    let _ = uc.mem_write(config.stack_addr, &zeros);

    // Set initial SP if not provided
    let mut regs_to_set = initial_registers.clone();
    if !regs_to_set.contains_key("sp") {
        regs_to_set.insert("sp".to_string(), config.stack_addr + config.stack_size - 16);
    }

    // Apply initial memory overlays (may require mapping)
    for (addr, data) in initial_memory {
        let map_base = addr & !0xFFF;
        let map_end = ((addr + data.len() as u64 + 0xFFF) & !0xFFF).max(map_base + 0x1000);
        let map_size = map_end - map_base;
        let _ = uc.mem_map(map_base, map_size, Prot::ALL);
        let _ = uc.mem_write(*addr, data);
    }

    // Set registers
    set_unicorn_registers(&mut uc, &regs_to_set)?;

    // Shared state for hooks
    let writes: Rc<RefCell<Vec<(u64, usize, i64)>>> = Rc::new(RefCell::new(Vec::new()));
    let steps = Rc::new(Cell::new(0usize));
    let stop_flag: Rc<RefCell<Option<String>>> = Rc::new(RefCell::new(None));
    let invalid_flag: Rc<RefCell<Option<String>>> = Rc::new(RefCell::new(None));
    let watchpoint_hits: Rc<RefCell<Vec<WatchpointHit>>> = Rc::new(RefCell::new(Vec::new()));
    let hook_hits: Rc<RefCell<Vec<AddressHookHit>>> = Rc::new(RefCell::new(Vec::new()));
    let pc_trace_raw: Rc<RefCell<Vec<u64>>> = Rc::new(RefCell::new(Vec::new()));

    // Memory write hook
    {
        let writes_h = writes.clone();
        let _ = uc.add_mem_hook(HookType::MEM_WRITE, 0, u64::MAX, move |_uc, _mt, addr, size, value| {
            writes_h.borrow_mut().push((addr, size, value));
            true
        });
    }

    // Code hook: count steps, PC trace, address hook dispatch, and detect range exit
    {
        let steps_h = steps.clone();
        let stop_h = stop_flag.clone();
        let hook_hits_h = hook_hits.clone();
        let pc_trace_h = pc_trace_raw.clone();
        let do_trace = config.record_pc_trace;
        let addr_hook_specs: Vec<AddressHookSpec> = config.address_hooks.clone();

        let _ = uc.add_code_hook(0, u64::MAX, move |uc, pc, _size| {
            steps_h.set(steps_h.get() + 1);
            if do_trace {
                pc_trace_h.borrow_mut().push(pc);
            }

            if pc < start_addr || pc >= end_addr {
                *stop_h.borrow_mut() = Some(format!("range_exit:0x{:x}", pc));
                let _ = uc.emu_stop();
                return;
            }

            for spec in &addr_hook_specs {
                if spec.addr != pc {
                    continue;
                }
                let regs_before = capture_registers_snapshot(uc);
                let mut patches_applied = Vec::new();
                for patch in &spec.patches {
                    if let Ok(reg) = name_to_register_arm64(&patch.name) {
                        if uc.reg_write(reg, patch.value).is_ok() {
                            patches_applied.push(format!("{}=0x{:x}", patch.name, patch.value));
                        }
                    }
                }
                hook_hits_h.borrow_mut().push(AddressHookHit {
                    hook_addr: format!("0x{:x}", pc),
                    registers_at_hit: regs_before,
                    patches_applied,
                });
                if spec.stop_on_hit {
                    *stop_h.borrow_mut() = Some(format!("hook_stop:0x{:x}", pc));
                    let _ = uc.emu_stop();
                    return;
                }
            }
        });
    }

    // Invalid memory hook
    {
        let inv_h = invalid_flag.clone();
        let _ = uc.add_mem_hook(
            HookType::MEM_READ_UNMAPPED | HookType::MEM_WRITE_UNMAPPED | HookType::MEM_FETCH_UNMAPPED,
            0,
            u64::MAX,
            move |uc, _mt, addr, _size, _value| {
                *inv_h.borrow_mut() = Some(format!("invalid_memory:0x{:x}", addr));
                let _ = uc.emu_stop();
                false
            },
        );
    }

    // Per-watchpoint memory hooks
    for spec in &config.watchpoints {
        let wpt_hook_type = match (spec.on_read, spec.on_write) {
            (true, true) => HookType::MEM_READ | HookType::MEM_WRITE,
            (true, false) => HookType::MEM_READ,
            (false, true) => HookType::MEM_WRITE,
            (false, false) => continue,
        };
        let wpt_hits_h = watchpoint_hits.clone();
        let stop_h = stop_flag.clone();
        let spec_addr_str = format!("0x{:x}", spec.addr);
        let stop_on_hit = spec.stop_on_hit;
        let _ = uc.add_mem_hook(
            wpt_hook_type,
            spec.addr,
            spec.addr + spec.size.saturating_sub(1),
            move |uc, mem_type, addr, size, _value| {
                use unicorn_engine::unicorn_const::MemType;
                let access_type = match mem_type {
                    MemType::READ | MemType::READ_AFTER => "read",
                    _ => "write",
                };
                wpt_hits_h.borrow_mut().push(WatchpointHit {
                    watchpoint_addr: spec_addr_str.clone(),
                    access_addr: format!("0x{:x}", addr),
                    access_size: size,
                    access_type: access_type.to_string(),
                    registers_at_hit: capture_registers_snapshot(uc),
                });
                if stop_on_hit {
                    *stop_h.borrow_mut() = Some(format!("watchpoint:0x{:x}", addr));
                    let _ = uc.emu_stop();
                }
                true
            },
        );
    }

    // Execute
    let _ = uc.emu_start(start_addr, end_addr, 0, config.step_limit);

    // Determine stop reason
    let steps_executed = steps.get();
    let stop_reason = if stop_flag.borrow().is_some() {
        stop_flag.borrow().clone().unwrap()
    } else if invalid_flag.borrow().is_some() {
        invalid_flag.borrow().clone().unwrap()
    } else if steps_executed >= config.step_limit {
        "step_limit".to_string()
    } else {
        "end_address".to_string()
    };

    // Read final registers
    let final_registers = read_all_registers(&uc)?;

    // Extract decoded strings from write addresses
    let decoded_strings = extract_decoded_strings(&uc, &writes.borrow())?;

    // Format memory writes
    let memory_writes = writes
        .borrow()
        .iter()
        .map(|(addr, size, value)| MemWriteRecord {
            addr: format!("0x{:x}", addr),
            size: *size,
            value: format!("0x{:x}", *value as u64),
        })
        .collect();

    // Format PC trace
    let pc_trace_formatted = pc_trace_raw
        .borrow()
        .iter()
        .map(|a| format!("0x{:x}", a))
        .collect();

    // Decode NZCV flags
    let nzcv_raw = uc.reg_read(RegisterARM64::NZCV).unwrap_or(0);
    let nzcv_decoded_str = decode_nzcv(nzcv_raw);

    // Extract RefCell values before struct initialization
    let watchpoint_hits_vec = watchpoint_hits.borrow().clone();
    let address_hook_hits_vec = hook_hits.borrow().clone();

    Ok(SandboxResult {
        start_addr: format!("0x{:x}", start_addr),
        end_addr: format!("0x{:x}", end_addr),
        steps_executed,
        stop_reason,
        final_registers,
        memory_writes,
        decoded_strings,
        watchpoint_hits: watchpoint_hits_vec,
        address_hook_hits: address_hook_hits_vec,
        pc_trace: pc_trace_formatted,
        nzcv_decoded: nzcv_decoded_str,
    })
}

/// Set unicorn registers from a string-keyed map
fn set_unicorn_registers(
    uc: &mut Unicorn<()>,
    regs: &HashMap<String, u64>,
) -> Result<(), String> {
    for (name, value) in regs {
        let name_lower = name.to_lowercase();
        let reg = match name_lower.as_str() {
            "x0" => RegisterARM64::X0,
            "x1" => RegisterARM64::X1,
            "x2" => RegisterARM64::X2,
            "x3" => RegisterARM64::X3,
            "x4" => RegisterARM64::X4,
            "x5" => RegisterARM64::X5,
            "x6" => RegisterARM64::X6,
            "x7" => RegisterARM64::X7,
            "x8" => RegisterARM64::X8,
            "x9" => RegisterARM64::X9,
            "x10" => RegisterARM64::X10,
            "x11" => RegisterARM64::X11,
            "x12" => RegisterARM64::X12,
            "x13" => RegisterARM64::X13,
            "x14" => RegisterARM64::X14,
            "x15" => RegisterARM64::X15,
            "x16" => RegisterARM64::X16,
            "x17" => RegisterARM64::X17,
            "x18" => RegisterARM64::X18,
            "x19" => RegisterARM64::X19,
            "x20" => RegisterARM64::X20,
            "x21" => RegisterARM64::X21,
            "x22" => RegisterARM64::X22,
            "x23" => RegisterARM64::X23,
            "x24" => RegisterARM64::X24,
            "x25" => RegisterARM64::X25,
            "x26" => RegisterARM64::X26,
            "x27" => RegisterARM64::X27,
            "x28" => RegisterARM64::X28,
            "x29" => RegisterARM64::X29,
            "x30" => RegisterARM64::X30,
            "sp" => RegisterARM64::SP,
            "pc" => RegisterARM64::PC,
            "nzcv" | "flags" => RegisterARM64::NZCV,
            _ => return Err(format!("Unknown register: {}", name)),
        };
        uc.reg_write(reg, *value)
            .map_err(|e| format!("Failed to set {}: {:?}", name, e))?;
    }
    Ok(())
}

/// Read all general-purpose registers
fn read_all_registers(uc: &Unicorn<()>) -> Result<HashMap<String, String>, String> {
    let mut result = HashMap::new();

    let x_regs = [
        ("x0", RegisterARM64::X0),
        ("x1", RegisterARM64::X1),
        ("x2", RegisterARM64::X2),
        ("x3", RegisterARM64::X3),
        ("x4", RegisterARM64::X4),
        ("x5", RegisterARM64::X5),
        ("x6", RegisterARM64::X6),
        ("x7", RegisterARM64::X7),
        ("x8", RegisterARM64::X8),
        ("x9", RegisterARM64::X9),
        ("x10", RegisterARM64::X10),
        ("x11", RegisterARM64::X11),
        ("x12", RegisterARM64::X12),
        ("x13", RegisterARM64::X13),
        ("x14", RegisterARM64::X14),
        ("x15", RegisterARM64::X15),
        ("x16", RegisterARM64::X16),
        ("x17", RegisterARM64::X17),
        ("x18", RegisterARM64::X18),
        ("x19", RegisterARM64::X19),
        ("x20", RegisterARM64::X20),
        ("x21", RegisterARM64::X21),
        ("x22", RegisterARM64::X22),
        ("x23", RegisterARM64::X23),
        ("x24", RegisterARM64::X24),
        ("x25", RegisterARM64::X25),
        ("x26", RegisterARM64::X26),
        ("x27", RegisterARM64::X27),
        ("x28", RegisterARM64::X28),
        ("x29", RegisterARM64::X29),
        ("x30", RegisterARM64::X30),
    ];

    for (name, reg) in &x_regs {
        let value = uc
            .reg_read(*reg)
            .map_err(|e| format!("Failed to read {}: {:?}", name, e))?;
        result.insert(name.to_string(), format!("0x{:x}", value));
    }

    let sp = uc
        .reg_read(RegisterARM64::SP)
        .map_err(|e| format!("Failed to read sp: {:?}", e))?;
    result.insert("sp".to_string(), format!("0x{:x}", sp));

    let pc = uc
        .reg_read(RegisterARM64::PC)
        .map_err(|e| format!("Failed to read pc: {:?}", e))?;
    result.insert("pc".to_string(), format!("0x{:x}", pc));

    let nzcv = uc
        .reg_read(RegisterARM64::NZCV)
        .map_err(|e| format!("Failed to read nzcv: {:?}", e))?;
    result.insert("nzcv".to_string(), format!("0x{:x}", nzcv));

    let v_regs = [
        ("v0", RegisterARM64::V0),
        ("v1", RegisterARM64::V1),
        ("v2", RegisterARM64::V2),
        ("v3", RegisterARM64::V3),
        ("v4", RegisterARM64::V4),
        ("v5", RegisterARM64::V5),
        ("v6", RegisterARM64::V6),
        ("v7", RegisterARM64::V7),
    ];

    for (name, reg) in &v_regs {
        match uc.reg_read_long(*reg) {
            Ok(bytes) => {
                let hex = bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>();
                result.insert(name.to_string(), hex);
            }
            Err(_) => {
                result.insert(name.to_string(), "unavailable".to_string());
            }
        }
    }

    Ok(result)
}

/// Extract null-terminated strings from written memory addresses
fn extract_decoded_strings(
    uc: &Unicorn<()>,
    writes: &[(u64, usize, i64)],
) -> Result<Vec<DecodedStringRecord>, String> {
    let mut result = Vec::new();
    let mut seen_addresses = std::collections::HashSet::new();

    for (addr, _size, _value) in writes {
        let page_addr = addr & !0xFFF;
        if !seen_addresses.insert(page_addr) {
            continue;
        }

        let mut buf = vec![0u8; 256];
        if uc.mem_read(page_addr, &mut buf).is_ok() {
            // Scan for null-terminated strings
            let mut in_string = false;
            let mut string_start = 0;
            let mut string_bytes = Vec::new();

            for (i, &byte) in buf.iter().enumerate() {
                if byte == 0 {
                    if in_string && string_bytes.len() >= 4 {
                        // Found a string
                        if let Ok(text) = String::from_utf8(string_bytes.clone()) {
                            if text.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
                                result.push(DecodedStringRecord {
                                    addr: format!("0x{:x}", page_addr + string_start as u64),
                                    text,
                                });
                            }
                        }
                    }
                    in_string = false;
                    string_bytes.clear();
                } else if byte >= 32 && byte < 127 {
                    // Printable ASCII
                    if !in_string {
                        string_start = i;
                        in_string = true;
                    }
                    string_bytes.push(byte);
                } else {
                    in_string = false;
                    string_bytes.clear();
                }
            }
        }
    }

    Ok(result)
}
