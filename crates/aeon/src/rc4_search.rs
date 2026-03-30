use std::collections::HashMap;

use ascent::ascent;
use serde_json::{json, Value};

use crate::elf::LoadedBinary;
use crate::il::*;
use crate::lifter;

// ═══════════════════════════════════════════════════════════════════════
// Datalog: behavioral RC4 detector
// ═══════════════════════════════════════════════════════════════════════

ascent! {
    pub struct Rc4Hunter;

    // ── Input facts (populated from IL dataflow analysis) ──────────

    relation byte_load(u64, u64);           // (inst_addr, dest_var)
    relation byte_store(u64, u64);          // (inst_addr, value_var)
    relation is_xor(u64, u64, u64);         // (inst_addr, src1_var, src2_var)
    relation flows_to(u64, u64);            // (producer_var, consumer_inst)
    relation in_loop(u64);                  // (inst_addr)

    // ── Derived: array swap detection ─────────────────────────────
    // Two byte loads produce val_a, val_b.
    // Two byte stores write them back cross-wired (val_b→addr_a, val_a→addr_b).

    relation swap_detected(u64, u64, u64, u64); // (load1, load2, store1, store2)
    swap_detected(l1, l2, s1, s2) <--
        byte_load(l1, va),
        byte_load(l2, vb),
        byte_store(s1, vb),        // store1 writes val_b (from load2)
        byte_store(s2, va),        // store2 writes val_a (from load1)
        flows_to(vb, s1),          // dataflow: load2 → store1
        flows_to(va, s2),          // dataflow: load1 → store2
        in_loop(l1),
        in_loop(s1),
        if l1 != l2,
        if s1 != s2;

    // ── Derived: keystream XOR ────────────────────────────────────
    // A byte loaded from memory flows into an XOR (PRGA output).

    relation keystream_xor_detected(u64); // (xor_inst_addr)
    keystream_xor_detected(xi) <--
        byte_load(_li, kb),
        is_xor(xi, kb, _),
        flows_to(kb, xi),
        in_loop(xi);
    keystream_xor_detected(xi) <--
        byte_load(_li, kb),
        is_xor(xi, _, kb),
        flows_to(kb, xi),
        in_loop(xi);
}

// ═══════════════════════════════════════════════════════════════════════
// Dataflow fact extraction from lifted IL
// ═══════════════════════════════════════════════════════════════════════

struct DataflowFacts {
    byte_loads: Vec<(u64, u64)>,  // (inst_addr, dest_var = inst_addr)
    byte_stores: Vec<(u64, u64)>, // (inst_addr, value_var)
    xors: Vec<(u64, u64, u64)>,   // (inst_addr, src1_var, src2_var)
    flows_to: Vec<(u64, u64)>,    // (producer_var, consumer_inst)
    in_loop: Vec<u64>,            // inst addrs inside loops
    has_256_bound: bool,
    has_mod256: bool,
}

fn extract_dataflow(raw_bytes: &[u8], func_addr: u64) -> DataflowFacts {
    let mut facts = DataflowFacts {
        byte_loads: Vec::new(),
        byte_stores: Vec::new(),
        xors: Vec::new(),
        flows_to: Vec::new(),
        in_loop: Vec::new(),
        has_256_bound: false,
        has_mod256: false,
    };

    // ── Pass 1: decode, lift, collect edges ──────────────────────
    let mut lifted: Vec<(u64, lifter::LiftResult)> = Vec::new();
    let mut offset = 0usize;
    let mut pc = func_addr;

    while offset + 4 <= raw_bytes.len() {
        let word = u32::from_le_bytes(raw_bytes[offset..offset + 4].try_into().unwrap());
        let next_pc = if offset + 8 <= raw_bytes.len() {
            Some(pc + 4)
        } else {
            None
        };

        if let Ok(insn) = bad64::decode(word, pc) {
            lifted.push((pc, lifter::lift(&insn, pc, next_pc)));
        }
        offset += 4;
        pc += 4;
    }

    // ── Loop detection: backward branch edges ────────────────────
    for (src_pc, result) in &lifted {
        for &target in &result.edges {
            if target < *src_pc && target >= func_addr {
                // Backward edge → all instructions in [target, src_pc] are in a loop
                for (addr, _) in &lifted {
                    if *addr >= target && *addr <= *src_pc {
                        facts.in_loop.push(*addr);
                    }
                }
            }
        }
    }

    // ── Pass 2: def-use chain building + fact extraction ─────────
    let mut def_map: HashMap<u64, u64> = HashMap::new(); // canonical_reg_id → defining inst addr

    for (inst_pc, result) in &lifted {
        let pc = *inst_pc;
        process_stmt(&result.stmt, pc, &mut def_map, &mut facts);
    }

    facts
}

/// Process a single statement: extract reads → flows_to, classify, update def_map
fn process_stmt(stmt: &Stmt, pc: u64, def_map: &mut HashMap<u64, u64>, facts: &mut DataflowFacts) {
    match stmt {
        Stmt::Assign { dst, src } => {
            // Collect all register reads from src → flows_to
            collect_reads(src, pc, def_map, facts);

            // Check for constants in the expression
            scan_constants(src, facts);

            // Classify: byte load?
            if is_byte_load(src) {
                facts.byte_loads.push((pc, pc)); // dest_var = inst addr
            }

            // Classify: XOR?
            if let Expr::Xor(a, b) = src {
                let src1 = primary_reg(a)
                    .and_then(|r| def_map.get(&reg_canon(&r)).copied())
                    .unwrap_or(0);
                let src2 = primary_reg(b)
                    .and_then(|r| def_map.get(&reg_canon(&r)).copied())
                    .unwrap_or(0);
                if src1 != 0 && src2 != 0 {
                    facts.xors.push((pc, src1, src2));
                }
            }

            // Update def_map: this instruction defines dst
            def_map.insert(reg_canon(dst), pc);
        }

        Stmt::Store { addr, value, size } => {
            collect_reads(addr, pc, def_map, facts);
            collect_reads(value, pc, def_map, facts);
            scan_constants(addr, facts);
            scan_constants(value, facts);

            if *size == 1 {
                // Byte store — extract value variable from def_map
                if let Some(r) = primary_reg(value) {
                    if let Some(&producer) = def_map.get(&reg_canon(&r)) {
                        facts.byte_stores.push((pc, producer));
                    }
                }
            }
        }

        Stmt::SetFlags { expr } => {
            collect_reads(expr, pc, def_map, facts);
            scan_constants(expr, facts);
        }

        Stmt::Pair(a, b) => {
            process_stmt(a, pc, def_map, facts);
            process_stmt(b, pc + 1, def_map, facts); // +1 to distinguish sub-stmts
        }

        Stmt::CondBranch { cond, .. } => match cond {
            BranchCond::Zero(e) | BranchCond::NotZero(e) => {
                collect_reads(e, pc, def_map, facts);
            }
            BranchCond::BitZero(e, _) | BranchCond::BitNotZero(e, _) => {
                collect_reads(e, pc, def_map, facts);
            }
            _ => {}
        },

        Stmt::Intrinsic { operands, .. } => {
            for op in operands {
                collect_reads(op, pc, def_map, facts);
                scan_constants(op, facts);
            }
        }

        _ => {}
    }
}

/// Walk an expression tree, emit flows_to for every register read
fn collect_reads(
    expr: &Expr,
    consumer_pc: u64,
    def_map: &HashMap<u64, u64>,
    facts: &mut DataflowFacts,
) {
    match expr {
        Expr::Reg(r) => {
            if let Some(&producer) = def_map.get(&reg_canon(r)) {
                facts.flows_to.push((producer, consumer_pc));
            }
        }
        Expr::Add(a, b)
        | Expr::Sub(a, b)
        | Expr::Mul(a, b)
        | Expr::Div(a, b)
        | Expr::UDiv(a, b)
        | Expr::And(a, b)
        | Expr::Or(a, b)
        | Expr::Xor(a, b)
        | Expr::Shl(a, b)
        | Expr::Lsr(a, b)
        | Expr::Asr(a, b)
        | Expr::Ror(a, b)
        | Expr::FAdd(a, b)
        | Expr::FSub(a, b)
        | Expr::FMul(a, b)
        | Expr::FDiv(a, b)
        | Expr::FMax(a, b)
        | Expr::FMin(a, b) => {
            collect_reads(a, consumer_pc, def_map, facts);
            collect_reads(b, consumer_pc, def_map, facts);
        }
        Expr::Neg(a)
        | Expr::Not(a)
        | Expr::Abs(a)
        | Expr::FNeg(a)
        | Expr::FAbs(a)
        | Expr::FSqrt(a)
        | Expr::FCvt(a)
        | Expr::IntToFloat(a)
        | Expr::FloatToInt(a)
        | Expr::Clz(a)
        | Expr::Cls(a)
        | Expr::Rev(a)
        | Expr::Rbit(a) => {
            collect_reads(a, consumer_pc, def_map, facts);
        }
        Expr::Load { addr, .. } => {
            collect_reads(addr, consumer_pc, def_map, facts);
        }
        Expr::SignExtend { src, .. } | Expr::ZeroExtend { src, .. } | Expr::Extract { src, .. } => {
            collect_reads(src, consumer_pc, def_map, facts);
        }
        Expr::Insert { dst, src, .. } => {
            collect_reads(dst, consumer_pc, def_map, facts);
            collect_reads(src, consumer_pc, def_map, facts);
        }
        Expr::CondSelect {
            if_true, if_false, ..
        } => {
            collect_reads(if_true, consumer_pc, def_map, facts);
            collect_reads(if_false, consumer_pc, def_map, facts);
        }
        Expr::Intrinsic { operands, .. } => {
            for op in operands {
                collect_reads(op, consumer_pc, def_map, facts);
            }
        }
        _ => {} // Imm, FImm, AdrpImm, etc.
    }
}

/// Scan expression for 256 constant and AND 0xff
fn scan_constants(expr: &Expr, facts: &mut DataflowFacts) {
    match expr {
        Expr::Imm(256) => {
            facts.has_256_bound = true;
        }
        Expr::And(a, b) => {
            if matches!(a.as_ref(), Expr::Imm(0xff)) || matches!(b.as_ref(), Expr::Imm(0xff)) {
                facts.has_mod256 = true;
            }
            scan_constants(a, facts);
            scan_constants(b, facts);
        }
        Expr::Sub(a, b) => {
            scan_constants(a, facts);
            scan_constants(b, facts);
        }
        Expr::Add(a, b)
        | Expr::Mul(a, b)
        | Expr::Or(a, b)
        | Expr::Xor(a, b)
        | Expr::Shl(a, b)
        | Expr::Lsr(a, b) => {
            scan_constants(a, facts);
            scan_constants(b, facts);
        }
        Expr::Load { addr, .. } => {
            scan_constants(addr, facts);
        }
        Expr::SignExtend { src, .. } | Expr::ZeroExtend { src, .. } => {
            scan_constants(src, facts);
        }
        _ => {}
    }
}

fn is_byte_load(expr: &Expr) -> bool {
    match expr {
        Expr::Load { size: 1, .. } => true,
        Expr::SignExtend { src, .. } | Expr::ZeroExtend { src, .. } => is_byte_load(src),
        _ => false,
    }
}

fn primary_reg(expr: &Expr) -> Option<Reg> {
    match expr {
        Expr::Reg(r) => Some(r.clone()),
        _ => None,
    }
}

/// Map W(n)/X(n) to same canonical ID (they alias the same physical register)
fn reg_canon(r: &Reg) -> u64 {
    match r {
        Reg::X(n) | Reg::W(n) => *n as u64,
        Reg::V(n) | Reg::Q(n) | Reg::D(n) | Reg::S(n) | Reg::H(n) | Reg::VByte(n) => 32 + *n as u64,
        Reg::SP => 64,
        Reg::XZR => 65,
        Reg::Flags => 66,
        Reg::PC => 67,
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Two-phase search
// ═══════════════════════════════════════════════════════════════════════

pub fn search(binary: &LoadedBinary) -> Value {
    let mut phase1_count = 0u64;
    let mut phase2_count = 0u64;
    let mut verified: Vec<Value> = Vec::new();

    for func in &binary.functions {
        // Size filter: RC4 is compact
        if func.size < 48 || func.size > 4000 {
            continue;
        }

        let raw_bytes = match binary.function_bytes(func) {
            Some(b) => b,
            None => continue,
        };

        // ── Phase 1: cheap pre-filter on extracted facts ─────────
        let facts = extract_dataflow(raw_bytes, func.addr);

        // Must have the structural minimum for a swap
        if facts.byte_loads.len() < 2 || facts.byte_stores.len() < 2 {
            continue;
        }
        // Must have some loop
        if facts.in_loop.is_empty() {
            continue;
        }

        phase1_count += 1;

        // ── Phase 2: Datalog behavioral verification ─────────────
        let mut hunter = Rc4Hunter::default();

        for &(addr, dest) in &facts.byte_loads {
            hunter.byte_load.push((addr, dest));
        }
        for &(addr, val) in &facts.byte_stores {
            hunter.byte_store.push((addr, val));
        }
        for &(addr, s1, s2) in &facts.xors {
            hunter.is_xor.push((addr, s1, s2));
        }
        for &(prod, cons) in &facts.flows_to {
            hunter.flows_to.push((prod, cons));
        }
        for &addr in &facts.in_loop {
            hunter.in_loop.push((addr,));
        }

        hunter.run();

        if hunter.swap_detected.is_empty() {
            continue;
        }

        phase2_count += 1;

        // ── Build result for this verified candidate ─────────────
        let has_ks_xor = !hunter.keystream_xor_detected.is_empty();
        let kind = if has_ks_xor {
            "RC4_PRGA (swap + keystream XOR)"
        } else if facts.has_256_bound && facts.has_mod256 {
            "RC4_KSA (swap + 256 loop + mod256)"
        } else {
            "swap_pattern (unconfirmed)"
        };

        let swaps: Vec<Value> = hunter
            .swap_detected
            .iter()
            .take(3)
            .map(|(l1, l2, s1, s2)| {
                json!({
                    "load1": format!("0x{:x}", l1),
                    "load2": format!("0x{:x}", l2),
                    "store1": format!("0x{:x}", s1),
                    "store2": format!("0x{:x}", s2),
                })
            })
            .collect();

        let xor_sites: Vec<String> = hunter
            .keystream_xor_detected
            .iter()
            .map(|(a,)| format!("0x{:x}", a))
            .collect();

        // Full IL listing for the candidate
        let listing = disassemble_function(raw_bytes, func.addr);

        verified.push(json!({
            "address": format!("0x{:x}", func.addr),
            "size": func.size,
            "name": func.name.as_deref().unwrap_or("(unnamed)"),
            "classification": kind,
            "evidence": {
                "swap_instances": swaps,
                "keystream_xor_sites": xor_sites,
                "has_256_bound": facts.has_256_bound,
                "has_mod256": facts.has_mod256,
                "byte_loads": facts.byte_loads.len(),
                "byte_stores": facts.byte_stores.len(),
                "flows_to_edges": facts.flows_to.len(),
                "loop_instructions": facts.in_loop.len(),
            },
            "il_listing": listing,
        }));
    }

    json!({
        "search": "rc4_behavioral",
        "method": "datalog_subgraph_isomorphism",
        "phase1_prefiltered": phase1_count,
        "phase2_verified": phase2_count,
        "candidates": verified,
    })
}

fn disassemble_function(raw_bytes: &[u8], func_addr: u64) -> Vec<Value> {
    let mut listing = Vec::new();
    let mut offset = 0usize;
    let mut pc = func_addr;

    while offset + 4 <= raw_bytes.len() {
        let word = u32::from_le_bytes(raw_bytes[offset..offset + 4].try_into().unwrap());
        let next_pc = if offset + 8 <= raw_bytes.len() {
            Some(pc + 4)
        } else {
            None
        };

        let entry = if let Ok(insn) = bad64::decode(word, pc) {
            let result = lifter::lift(&insn, pc, next_pc);
            json!({
                "addr": format!("0x{:x}", pc),
                "asm": result.disasm,
                "il": format!("{:?}", result.stmt),
            })
        } else {
            json!({ "addr": format!("0x{:x}", pc), "asm": "(invalid)", "il": "Nop" })
        };

        listing.push(entry);
        offset += 4;
        pc += 4;
    }

    listing
}
