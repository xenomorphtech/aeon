use std::collections::{BTreeMap, HashSet};

use aeon_reduce::env::RegisterEnv;

use serde::Serialize;

use crate::elf::{FunctionInfo, LoadedBinary};
use crate::il::{Expr, Reg, Stmt};
use crate::lifter;

const MAX_CONSTRUCTOR_CALL_DEPTH: usize = 4;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PointerTargetKind {
    Function,
    Code,
    Data,
    Unknown,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ObjectPointerField {
    pub instruction_addr: u64,
    pub field_offset: u64,
    pub size: u8,
    pub value_addr: u64,
    pub target_kind: PointerTargetKind,
    pub target_name: Option<String>,
    pub string_preview: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ConstructorObjectLayout {
    pub query_addr: u64,
    pub function_addr: u64,
    pub function_size: u64,
    pub object_base_register: String,
    pub pointer_writes: Vec<ObjectPointerField>,
    pub final_pointer_fields: Vec<ObjectPointerField>,
}

pub fn analyze_constructor_object_layout(
    binary: &LoadedBinary,
    func: &FunctionInfo,
    query_addr: u64,
) -> ConstructorObjectLayout {
    let mut active_functions = HashSet::new();
    let pointer_writes = collect_pointer_writes(binary, func, true, 0, &mut active_functions);

    let mut final_fields = BTreeMap::new();
    for field in &pointer_writes {
        final_fields.insert(field.field_offset, field.clone());
    }

    ConstructorObjectLayout {
        query_addr,
        function_addr: func.addr,
        function_size: func.size,
        object_base_register: "x0".to_string(),
        pointer_writes,
        final_pointer_fields: final_fields.into_values().collect(),
    }
}

fn process_stmt(
    stmt: &Stmt,
    instruction_addr: u64,
    env: &mut RegisterEnv,
    pointer_writes: &mut Vec<ObjectPointerField>,
    binary: &LoadedBinary,
    follow_constructor_calls: bool,
    depth: usize,
    active_functions: &mut HashSet<u64>,
) {
    match stmt {
        Stmt::Assign { dst, src } => {
            let resolved = env.resolve(src);
            env.assign(dst.clone(), resolved);
        }
        Stmt::Store { addr, value, size } => {
            let resolved_addr = env.resolve(addr);
            let resolved_value = env.resolve(value);

            if let Some(field_offset) = extract_object_offset(&resolved_addr) {
                if let Some(field) = object_pointer_field(
                    instruction_addr,
                    field_offset,
                    *size,
                    &resolved_value,
                    binary,
                ) {
                    pointer_writes.push(field);
                }
            }
        }
        Stmt::Pair(lhs, rhs) => {
            process_stmt(
                lhs,
                instruction_addr,
                env,
                pointer_writes,
                binary,
                follow_constructor_calls,
                depth,
                active_functions,
            );
            process_stmt(
                rhs,
                instruction_addr,
                env,
                pointer_writes,
                binary,
                follow_constructor_calls,
                depth,
                active_functions,
            );
        }
        Stmt::Call {
            target: Expr::Imm(target),
        } => {
            if follow_constructor_calls {
                propagate_constructor_call(
                    *target,
                    env,
                    pointer_writes,
                    binary,
                    depth,
                    active_functions,
                );
            }
            env.invalidate_caller_saved();
        }
        Stmt::Call { .. } => env.invalidate_caller_saved(),
        _ => {}
    }
}

fn collect_pointer_writes(
    binary: &LoadedBinary,
    func: &FunctionInfo,
    follow_constructor_calls: bool,
    depth: usize,
    active_functions: &mut HashSet<u64>,
) -> Vec<ObjectPointerField> {
    let raw_bytes = binary.function_bytes(func).unwrap_or(&[]);
    let mut env = RegisterEnv::with_binding(Reg::X(0), object_base_expr());
    let mut pointer_writes = Vec::new();

    active_functions.insert(func.addr);

    let mut offset = 0usize;
    let mut pc = func.addr;
    while offset + 4 <= raw_bytes.len() {
        let word = u32::from_le_bytes(raw_bytes[offset..offset + 4].try_into().unwrap());
        let next_pc = if offset + 8 <= raw_bytes.len() {
            Some(pc + 4)
        } else {
            None
        };

        let stmt = match bad64::decode(word, pc) {
            Ok(insn) => lifter::lift(&insn, pc, next_pc).stmt,
            Err(_) => Stmt::Nop,
        };
        process_stmt(
            &stmt,
            pc,
            &mut env,
            &mut pointer_writes,
            binary,
            follow_constructor_calls,
            depth,
            active_functions,
        );

        offset += 4;
        pc += 4;
    }

    active_functions.remove(&func.addr);
    pointer_writes
}

fn propagate_constructor_call(
    target_addr: u64,
    env: &RegisterEnv,
    pointer_writes: &mut Vec<ObjectPointerField>,
    binary: &LoadedBinary,
    depth: usize,
    active_functions: &mut HashSet<u64>,
) {
    if depth >= MAX_CONSTRUCTOR_CALL_DEPTH {
        return;
    }

    let resolved_x0 = env.resolve(&Expr::Reg(Reg::X(0)));
    let Some(base_offset) = extract_object_offset(&resolved_x0) else {
        return;
    };

    let Some(callee) = binary
        .functions
        .iter()
        .find(|func| func.addr == target_addr)
    else {
        return;
    };

    if active_functions.contains(&callee.addr) || !looks_like_constructor(binary, callee) {
        return;
    }

    let callee_fields = collect_pointer_writes(binary, callee, true, depth + 1, active_functions);
    for mut field in callee_fields {
        if let Some(adjusted_offset) = field.field_offset.checked_add(base_offset) {
            field.field_offset = adjusted_offset;
            pointer_writes.push(field);
        }
    }
}

fn looks_like_constructor(binary: &LoadedBinary, func: &FunctionInfo) -> bool {
    let mut active_functions = HashSet::new();
    collect_pointer_writes(binary, func, false, 0, &mut active_functions)
        .iter()
        .any(|field| field.field_offset == 0)
}

fn extract_object_offset(expr: &Expr) -> Option<u64> {
    match expr {
        Expr::Reg(Reg::X(0)) => Some(0),
        Expr::Intrinsic { name, operands }
            if name == "__aeon_object_base" && operands.is_empty() =>
        {
            Some(0)
        }
        Expr::Add(lhs, rhs) => {
            if let Some(base) = extract_object_offset(lhs) {
                return immediate_value(rhs).and_then(|offset| base.checked_add(offset));
            }
            if let Some(base) = extract_object_offset(rhs) {
                return immediate_value(lhs).and_then(|offset| base.checked_add(offset));
            }
            None
        }
        Expr::Sub(lhs, rhs) => {
            let base = extract_object_offset(lhs)?;
            let offset = immediate_value(rhs)?;
            base.checked_sub(offset)
        }
        Expr::ZeroExtend { src, .. } | Expr::SignExtend { src, .. } => extract_object_offset(src),
        _ => None,
    }
}

fn immediate_value(expr: &Expr) -> Option<u64> {
    match expr {
        Expr::Imm(value) => Some(*value),
        Expr::ZeroExtend { src, .. } | Expr::SignExtend { src, .. } => immediate_value(src),
        _ => None,
    }
}

fn object_pointer_field(
    instruction_addr: u64,
    field_offset: u64,
    size: u8,
    value: &Expr,
    binary: &LoadedBinary,
) -> Option<ObjectPointerField> {
    let value_addr = pointer_value(value)?;
    let (target_kind, target_name) = classify_pointer(binary, value_addr);

    Some(ObjectPointerField {
        instruction_addr,
        field_offset,
        size,
        value_addr,
        target_kind,
        target_name,
        string_preview: string_preview(binary, value_addr),
    })
}

fn pointer_value(expr: &Expr) -> Option<u64> {
    match expr {
        Expr::AdrpImm(addr) | Expr::AdrImm(addr) | Expr::Imm(addr) => Some(*addr),
        Expr::Add(lhs, rhs) => {
            if let Some(base) = pointer_value(lhs) {
                return immediate_value(rhs).and_then(|offset| base.checked_add(offset));
            }
            if let Some(base) = pointer_value(rhs) {
                return immediate_value(lhs).and_then(|offset| base.checked_add(offset));
            }
            None
        }
        Expr::Sub(lhs, rhs) => {
            let base = pointer_value(lhs)?;
            let offset = immediate_value(rhs)?;
            base.checked_sub(offset)
        }
        Expr::ZeroExtend { src, .. } | Expr::SignExtend { src, .. } => pointer_value(src),
        _ => None,
    }
}

fn classify_pointer(binary: &LoadedBinary, addr: u64) -> (PointerTargetKind, Option<String>) {
    if let Some(func) = binary.function_containing(addr) {
        let kind = if func.addr == addr {
            PointerTargetKind::Function
        } else {
            PointerTargetKind::Code
        };
        return (kind, func.name.clone());
    }

    if binary.vaddr_to_file_offset(addr).is_some() {
        return (PointerTargetKind::Data, None);
    }

    (PointerTargetKind::Unknown, None)
}

fn string_preview(binary: &LoadedBinary, addr: u64) -> Option<String> {
    let value = binary.read_string(addr, 64)?;
    if value.len() < 3 {
        return None;
    }
    if value.chars().all(|ch| ch.is_ascii_graphic() || ch == ' ') {
        Some(value)
    } else {
        None
    }
}

fn object_base_expr() -> Expr {
    Expr::Intrinsic {
        name: "__aeon_object_base".to_string(),
        operands: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{analyze_constructor_object_layout, ConstructorObjectLayout};
    use crate::elf::load_elf;

    fn load_known_layout() -> Option<ConstructorObjectLayout> {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let binary_path = manifest_dir.join("../../libUnreal.so");
        if !binary_path.exists() {
            return None;
        }

        let binary = load_elf(binary_path.to_str().unwrap()).ok()?;
        let func = binary.function_containing(0x05e66990)?;
        Some(analyze_constructor_object_layout(&binary, func, 0x05e66990))
    }

    #[test]
    fn constructor_layout_finds_known_pointer_fields() {
        let Some(layout) = load_known_layout() else {
            return;
        };

        let offsets: Vec<u64> = layout
            .final_pointer_fields
            .iter()
            .map(|field| field.field_offset)
            .collect();

        assert_eq!(offsets, vec![0, 32, 280, 296]);
        assert!(layout
            .final_pointer_fields
            .iter()
            .all(|field| field.value_addr != 0));

        let propagated = layout
            .final_pointer_fields
            .iter()
            .find(|field| field.field_offset == 296)
            .expect("expected propagated subobject field");
        assert_eq!(propagated.instruction_addr, 0x5e597d0);
    }
}
