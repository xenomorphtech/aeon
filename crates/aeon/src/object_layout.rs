use std::collections::{BTreeMap, HashMap, HashSet};

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
    env: &mut HashMap<Reg, Expr>,
    pointer_writes: &mut Vec<ObjectPointerField>,
    binary: &LoadedBinary,
    follow_constructor_calls: bool,
    depth: usize,
    active_functions: &mut HashSet<u64>,
) {
    match stmt {
        Stmt::Assign { dst, src } => {
            let resolved = resolve_expr(src, env, &mut HashSet::new(), 12);
            assign_register(env, dst.clone(), resolved);
        }
        Stmt::Store { addr, value, size } => {
            let resolved_addr = resolve_expr(addr, env, &mut HashSet::new(), 12);
            let resolved_value = resolve_expr(value, env, &mut HashSet::new(), 12);

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
            invalidate_caller_saved(env);
        }
        Stmt::Call { .. } => invalidate_caller_saved(env),
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
    let mut env = HashMap::from([(Reg::X(0), object_base_expr())]);
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
    env: &HashMap<Reg, Expr>,
    pointer_writes: &mut Vec<ObjectPointerField>,
    binary: &LoadedBinary,
    depth: usize,
    active_functions: &mut HashSet<u64>,
) {
    if depth >= MAX_CONSTRUCTOR_CALL_DEPTH {
        return;
    }

    let resolved_x0 = resolve_expr(&Expr::Reg(Reg::X(0)), env, &mut HashSet::new(), 12);
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

fn assign_register(env: &mut HashMap<Reg, Expr>, dst: Reg, value: Expr) {
    match dst {
        Reg::X(n) => {
            env.remove(&Reg::W(n));
            env.insert(Reg::X(n), value);
        }
        Reg::W(n) => {
            env.remove(&Reg::X(n));
            env.insert(Reg::W(n), value);
        }
        reg => {
            env.insert(reg, value);
        }
    }
}

fn invalidate_caller_saved(env: &mut HashMap<Reg, Expr>) {
    for index in 0..=18 {
        env.remove(&Reg::X(index));
        env.remove(&Reg::W(index));
    }
    env.remove(&Reg::Flags);
}

fn resolve_expr(
    expr: &Expr,
    env: &HashMap<Reg, Expr>,
    visited: &mut HashSet<Reg>,
    depth: usize,
) -> Expr {
    if depth == 0 {
        return expr.clone();
    }

    match expr {
        Expr::Reg(reg) => {
            if visited.contains(reg) {
                return Expr::Reg(reg.clone());
            }
            let Some(mapped) = env.get(reg) else {
                return Expr::Reg(reg.clone());
            };
            visited.insert(reg.clone());
            let resolved = resolve_expr(mapped, env, visited, depth - 1);
            visited.remove(reg);
            resolved
        }
        Expr::Load { addr, size } => Expr::Load {
            addr: Box::new(resolve_expr(addr, env, visited, depth - 1)),
            size: *size,
        },
        Expr::Add(lhs, rhs) => Expr::Add(
            Box::new(resolve_expr(lhs, env, visited, depth - 1)),
            Box::new(resolve_expr(rhs, env, visited, depth - 1)),
        ),
        Expr::Sub(lhs, rhs) => Expr::Sub(
            Box::new(resolve_expr(lhs, env, visited, depth - 1)),
            Box::new(resolve_expr(rhs, env, visited, depth - 1)),
        ),
        Expr::Mul(lhs, rhs) => Expr::Mul(
            Box::new(resolve_expr(lhs, env, visited, depth - 1)),
            Box::new(resolve_expr(rhs, env, visited, depth - 1)),
        ),
        Expr::Div(lhs, rhs) => Expr::Div(
            Box::new(resolve_expr(lhs, env, visited, depth - 1)),
            Box::new(resolve_expr(rhs, env, visited, depth - 1)),
        ),
        Expr::UDiv(lhs, rhs) => Expr::UDiv(
            Box::new(resolve_expr(lhs, env, visited, depth - 1)),
            Box::new(resolve_expr(rhs, env, visited, depth - 1)),
        ),
        Expr::Neg(inner) => Expr::Neg(Box::new(resolve_expr(inner, env, visited, depth - 1))),
        Expr::Abs(inner) => Expr::Abs(Box::new(resolve_expr(inner, env, visited, depth - 1))),
        Expr::And(lhs, rhs) => Expr::And(
            Box::new(resolve_expr(lhs, env, visited, depth - 1)),
            Box::new(resolve_expr(rhs, env, visited, depth - 1)),
        ),
        Expr::Or(lhs, rhs) => Expr::Or(
            Box::new(resolve_expr(lhs, env, visited, depth - 1)),
            Box::new(resolve_expr(rhs, env, visited, depth - 1)),
        ),
        Expr::Xor(lhs, rhs) => Expr::Xor(
            Box::new(resolve_expr(lhs, env, visited, depth - 1)),
            Box::new(resolve_expr(rhs, env, visited, depth - 1)),
        ),
        Expr::Not(inner) => Expr::Not(Box::new(resolve_expr(inner, env, visited, depth - 1))),
        Expr::Shl(lhs, rhs) => Expr::Shl(
            Box::new(resolve_expr(lhs, env, visited, depth - 1)),
            Box::new(resolve_expr(rhs, env, visited, depth - 1)),
        ),
        Expr::Lsr(lhs, rhs) => Expr::Lsr(
            Box::new(resolve_expr(lhs, env, visited, depth - 1)),
            Box::new(resolve_expr(rhs, env, visited, depth - 1)),
        ),
        Expr::Asr(lhs, rhs) => Expr::Asr(
            Box::new(resolve_expr(lhs, env, visited, depth - 1)),
            Box::new(resolve_expr(rhs, env, visited, depth - 1)),
        ),
        Expr::Ror(lhs, rhs) => Expr::Ror(
            Box::new(resolve_expr(lhs, env, visited, depth - 1)),
            Box::new(resolve_expr(rhs, env, visited, depth - 1)),
        ),
        Expr::SignExtend { src, from_bits } => Expr::SignExtend {
            src: Box::new(resolve_expr(src, env, visited, depth - 1)),
            from_bits: *from_bits,
        },
        Expr::ZeroExtend { src, from_bits } => Expr::ZeroExtend {
            src: Box::new(resolve_expr(src, env, visited, depth - 1)),
            from_bits: *from_bits,
        },
        Expr::Extract { src, lsb, width } => Expr::Extract {
            src: Box::new(resolve_expr(src, env, visited, depth - 1)),
            lsb: *lsb,
            width: *width,
        },
        Expr::Insert {
            dst,
            src,
            lsb,
            width,
        } => Expr::Insert {
            dst: Box::new(resolve_expr(dst, env, visited, depth - 1)),
            src: Box::new(resolve_expr(src, env, visited, depth - 1)),
            lsb: *lsb,
            width: *width,
        },
        Expr::FAdd(lhs, rhs) => Expr::FAdd(
            Box::new(resolve_expr(lhs, env, visited, depth - 1)),
            Box::new(resolve_expr(rhs, env, visited, depth - 1)),
        ),
        Expr::FSub(lhs, rhs) => Expr::FSub(
            Box::new(resolve_expr(lhs, env, visited, depth - 1)),
            Box::new(resolve_expr(rhs, env, visited, depth - 1)),
        ),
        Expr::FMul(lhs, rhs) => Expr::FMul(
            Box::new(resolve_expr(lhs, env, visited, depth - 1)),
            Box::new(resolve_expr(rhs, env, visited, depth - 1)),
        ),
        Expr::FDiv(lhs, rhs) => Expr::FDiv(
            Box::new(resolve_expr(lhs, env, visited, depth - 1)),
            Box::new(resolve_expr(rhs, env, visited, depth - 1)),
        ),
        Expr::FNeg(inner) => Expr::FNeg(Box::new(resolve_expr(inner, env, visited, depth - 1))),
        Expr::FAbs(inner) => Expr::FAbs(Box::new(resolve_expr(inner, env, visited, depth - 1))),
        Expr::FSqrt(inner) => Expr::FSqrt(Box::new(resolve_expr(inner, env, visited, depth - 1))),
        Expr::FMax(lhs, rhs) => Expr::FMax(
            Box::new(resolve_expr(lhs, env, visited, depth - 1)),
            Box::new(resolve_expr(rhs, env, visited, depth - 1)),
        ),
        Expr::FMin(lhs, rhs) => Expr::FMin(
            Box::new(resolve_expr(lhs, env, visited, depth - 1)),
            Box::new(resolve_expr(rhs, env, visited, depth - 1)),
        ),
        Expr::FCvt(inner) => Expr::FCvt(Box::new(resolve_expr(inner, env, visited, depth - 1))),
        Expr::IntToFloat(inner) => {
            Expr::IntToFloat(Box::new(resolve_expr(inner, env, visited, depth - 1)))
        }
        Expr::FloatToInt(inner) => {
            Expr::FloatToInt(Box::new(resolve_expr(inner, env, visited, depth - 1)))
        }
        Expr::CondSelect {
            cond,
            if_true,
            if_false,
        } => Expr::CondSelect {
            cond: *cond,
            if_true: Box::new(resolve_expr(if_true, env, visited, depth - 1)),
            if_false: Box::new(resolve_expr(if_false, env, visited, depth - 1)),
        },
        Expr::Clz(inner) => Expr::Clz(Box::new(resolve_expr(inner, env, visited, depth - 1))),
        Expr::Cls(inner) => Expr::Cls(Box::new(resolve_expr(inner, env, visited, depth - 1))),
        Expr::Rev(inner) => Expr::Rev(Box::new(resolve_expr(inner, env, visited, depth - 1))),
        Expr::Rbit(inner) => Expr::Rbit(Box::new(resolve_expr(inner, env, visited, depth - 1))),
        Expr::Intrinsic { name, operands } => Expr::Intrinsic {
            name: name.clone(),
            operands: operands
                .iter()
                .map(|operand| resolve_expr(operand, env, visited, depth - 1))
                .collect(),
        },
        Expr::Imm(_) | Expr::FImm(_) | Expr::AdrpImm(_) | Expr::AdrImm(_) | Expr::MrsRead(_) => {
            expr.clone()
        }
    }
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
