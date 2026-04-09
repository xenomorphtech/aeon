use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::{json, Value};

use crate::il::{Expr, Stmt};
use crate::lifter;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StatementClass {
    ProperIl,
    Intrinsic,
    Nop,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct OpcodeFrequency {
    pub opcode: String,
    pub count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageStats {
    pub total_instructions: u64,
    pub decode_errors: u64,
    pub proper_il: u64,
    pub intrinsic: u64,
    pub nop: u64,
    pub intrinsic_opcode_breakdown: Vec<OpcodeFrequency>,
}

impl CoverageStats {
    pub fn to_json(
        &self,
        total_functions: usize,
        named_functions: usize,
        text_section_addr: u64,
        text_section_size: u64,
    ) -> Value {
        json!({
            "total_instructions": self.total_instructions,
            "decode_errors": self.decode_errors,
            "decode_error_pct": percent(self.decode_errors, self.total_instructions, 4),
            "proper_il": self.proper_il,
            "proper_il_pct": percent(self.proper_il, self.total_instructions, 2),
            "intrinsic": self.intrinsic,
            "intrinsic_pct": percent(self.intrinsic, self.total_instructions, 2),
            "nop": self.nop,
            "nop_pct": percent(self.nop, self.total_instructions, 2),
            "intrinsic_opcode_breakdown": self.intrinsic_opcode_breakdown,
            "total_functions": total_functions,
            "named_functions": named_functions,
            "text_section_addr": format!("0x{:x}", text_section_addr),
            "text_section_size": format!("0x{:x}", text_section_size),
        })
    }
}

pub fn analyze_lift_coverage(text: &[u8], base_addr: u64) -> CoverageStats {
    let mut total_instructions: u64 = 0;
    let mut decode_errors: u64 = 0;
    let mut proper_il: u64 = 0;
    let mut intrinsic: u64 = 0;
    let mut nop: u64 = 0;
    let mut intrinsic_opcodes: BTreeMap<String, u64> = BTreeMap::new();

    let mut offset = 0usize;
    let mut pc = base_addr;

    while offset + 4 <= text.len() {
        let word = u32::from_le_bytes(text[offset..offset + 4].try_into().unwrap());
        total_instructions += 1;

        match bad64::decode(word, pc) {
            Ok(insn) => {
                let result = lifter::lift(&insn, pc, Some(pc + 4));
                match classify_stmt(&result.stmt) {
                    StatementClass::ProperIl => proper_il += 1,
                    StatementClass::Intrinsic => {
                        intrinsic += 1;
                        let opcode = insn.op().mnem().to_string();
                        *intrinsic_opcodes.entry(opcode).or_default() += 1;
                    }
                    StatementClass::Nop => nop += 1,
                }
            }
            Err(_) => decode_errors += 1,
        }

        offset += 4;
        pc += 4;
    }

    let mut intrinsic_opcode_breakdown: Vec<_> = intrinsic_opcodes
        .into_iter()
        .map(|(opcode, count)| OpcodeFrequency { opcode, count })
        .collect();
    intrinsic_opcode_breakdown
        .sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.opcode.cmp(&b.opcode)));

    CoverageStats {
        total_instructions,
        decode_errors,
        proper_il,
        intrinsic,
        nop,
        intrinsic_opcode_breakdown,
    }
}

fn classify_stmt(stmt: &Stmt) -> StatementClass {
    if stmt_is_nop_like(stmt) {
        StatementClass::Nop
    } else if stmt_contains_intrinsic(stmt) {
        StatementClass::Intrinsic
    } else {
        StatementClass::ProperIl
    }
}

fn stmt_is_nop_like(stmt: &Stmt) -> bool {
    matches!(stmt, Stmt::Nop)
        || matches!(
            stmt,
            Stmt::Intrinsic { name, .. }
                if matches!(
                    name.as_str(),
                    "nop"
                        | "yield"
                        | "hint"
                        | "paciasp"
                        | "autiasp"
                        | "bti"
                        | "xpaclri"
                        | "prfm"
                        | "prfum"
                        | "clrex"
                )
        )
}

fn stmt_contains_intrinsic(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Assign { src, .. } => expr_contains_intrinsic(src),
        Stmt::Store { addr, value, .. } => {
            expr_contains_intrinsic(addr) || expr_contains_intrinsic(value)
        }
        Stmt::Branch { target } | Stmt::Call { target } => expr_contains_intrinsic(target),
        Stmt::CondBranch { cond, target, .. } => {
            branch_cond_contains_intrinsic(cond) || expr_contains_intrinsic(target)
        }
        Stmt::Pair(lhs, rhs) => stmt_contains_intrinsic(lhs) || stmt_contains_intrinsic(rhs),
        Stmt::SetFlags { expr } => expr_contains_intrinsic(expr),
        Stmt::Intrinsic { .. } => true,
        Stmt::Ret | Stmt::Nop | Stmt::Barrier(_) | Stmt::Trap { .. } => false,
    }
}

fn branch_cond_contains_intrinsic(cond: &crate::il::BranchCond) -> bool {
    match cond {
        crate::il::BranchCond::Flag(_) => false,
        crate::il::BranchCond::Zero(expr) | crate::il::BranchCond::NotZero(expr) => {
            expr_contains_intrinsic(expr)
        }
        crate::il::BranchCond::BitZero(expr, _) | crate::il::BranchCond::BitNotZero(expr, _) => {
            expr_contains_intrinsic(expr)
        }
        crate::il::BranchCond::Compare { lhs, rhs, .. } => {
            expr_contains_intrinsic(lhs) || expr_contains_intrinsic(rhs)
        }
    }
}

fn expr_contains_intrinsic(expr: &Expr) -> bool {
    match expr {
        Expr::Intrinsic { .. } => true,
        Expr::Load { addr, .. } => expr_contains_intrinsic(addr),
        Expr::Add(lhs, rhs)
        | Expr::Sub(lhs, rhs)
        | Expr::Mul(lhs, rhs)
        | Expr::Div(lhs, rhs)
        | Expr::UDiv(lhs, rhs)
        | Expr::And(lhs, rhs)
        | Expr::Or(lhs, rhs)
        | Expr::Xor(lhs, rhs)
        | Expr::Shl(lhs, rhs)
        | Expr::Lsr(lhs, rhs)
        | Expr::Asr(lhs, rhs)
        | Expr::Ror(lhs, rhs)
        | Expr::FAdd(lhs, rhs)
        | Expr::FSub(lhs, rhs)
        | Expr::FMul(lhs, rhs)
        | Expr::FDiv(lhs, rhs)
        | Expr::FMax(lhs, rhs)
        | Expr::FMin(lhs, rhs) => expr_contains_intrinsic(lhs) || expr_contains_intrinsic(rhs),
        Expr::Neg(expr)
        | Expr::Abs(expr)
        | Expr::Not(expr)
        | Expr::FNeg(expr)
        | Expr::FAbs(expr)
        | Expr::FSqrt(expr)
        | Expr::FCvt(expr)
        | Expr::IntToFloat(expr)
        | Expr::FloatToInt(expr)
        | Expr::Clz(expr)
        | Expr::Cls(expr)
        | Expr::Rev(expr)
        | Expr::Rbit(expr) => expr_contains_intrinsic(expr),
        Expr::SignExtend { src, .. } | Expr::ZeroExtend { src, .. } | Expr::Extract { src, .. } => {
            expr_contains_intrinsic(src)
        }
        Expr::Insert { dst, src, .. } => {
            expr_contains_intrinsic(dst) || expr_contains_intrinsic(src)
        }
        Expr::CondSelect {
            if_true, if_false, ..
        } => expr_contains_intrinsic(if_true) || expr_contains_intrinsic(if_false),
        Expr::Compare { lhs, rhs, .. } => {
            expr_contains_intrinsic(lhs) || expr_contains_intrinsic(rhs)
        }
        Expr::Reg(_)
        | Expr::Imm(_)
        | Expr::FImm(_)
        | Expr::AdrpImm(_)
        | Expr::AdrImm(_)
        | Expr::StackSlot { .. }
        | Expr::MrsRead(_) => false,
    }
}

fn percent(count: u64, total: u64, decimals: usize) -> String {
    if total == 0 {
        return format!("{:.*}%", decimals, 0.0);
    }
    format!("{:.*}%", decimals, count as f64 / total as f64 * 100.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn coverage_from_words(words: &[u32]) -> CoverageStats {
        let text: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        analyze_lift_coverage(&text, 0x1000)
    }

    #[test]
    fn reports_intrinsic_opcode_breakdown_sorted_by_frequency() {
        let stats = coverage_from_words(&[
            0x72b0_8ac8, // movk w8, #0x8456, lsl #16
            0xf295_02e3, // movk x3, #0xa817
            0x5309_60c0, // ubfx w0, w6, #9, #16
            0xd503_201f, // nop
            0x7a57_00c1, // ccmp w6, w23, #1, eq
        ]);

        assert_eq!(stats.total_instructions, 5);
        assert_eq!(stats.decode_errors, 0);
        assert_eq!(stats.intrinsic, 2);
        assert_eq!(stats.nop, 1);
        assert_eq!(stats.proper_il, 2);
        assert_eq!(
            stats.intrinsic_opcode_breakdown,
            vec![OpcodeFrequency {
                opcode: "movk".to_string(),
                count: 2,
            }]
        );
    }
}
