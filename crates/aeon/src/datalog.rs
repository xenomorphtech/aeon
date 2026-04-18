use ascent::ascent;
use crate::function_ir::DecodedFunction;
use crate::api::reg_name;
use aeonil::Stmt;

/// Per-function Datalog program for IL-level analysis.
/// Extracts facts from lifted IL statements and computes:
/// - CFG reachability within a function
/// - Register definitions and uses
/// - Memory reads/writes
/// - Data flow (def-reaches-use via CFG)
ascent! {
    pub struct FunctionDatalog;

    // ─── Input relations ─────────────────────────────────────────────────
    /// (func_addr, inst_addr) — instruction belongs to function
    relation inst_in_func(u64, u64);
    /// (src_addr, dst_addr) — CFG edge from src to dst instruction
    relation cfg_edge(u64, u64);
    /// (inst_addr, reg_name) — instruction defines a register
    relation defines(u64, String);
    /// (inst_addr, reg_name) — instruction uses a register
    relation uses_reg(u64, String);
    /// (inst_addr, size) — instruction reads memory
    relation reads_mem(u64, u8);
    /// (inst_addr, size) — instruction writes memory
    relation writes_mem(u64, u8);
    /// (call_site_addr, callee_addr) — direct function call
    relation direct_call(u64, u64);

    // ─── Derived: CFG reachability ───────────────────────────────────────
    /// (func, src, dst) — CFG edge where both endpoints are in the same func
    relation internal_edge(u64, u64, u64);
    internal_edge(func, src, dst) <--
        cfg_edge(src, dst),
        inst_in_func(func, src),
        inst_in_func(func, dst);

    /// (func, src, dst) — transitive reachability in function's CFG
    relation reachable(u64, u64, u64);
    reachable(func, src, dst) <-- internal_edge(func, src, dst);
    reachable(func, src, dst) <--
        reachable(func, src, mid),
        internal_edge(func, mid, dst);

    /// (func, addr) — instruction with no outgoing CFG edges in function
    relation terminal(u64, u64);
    terminal(func, addr) <--
        inst_in_func(func, addr),
        !internal_edge(func, addr, _);

    // ─── Derived: Data flow (def reaches use via CFG) ────────────────────
    /// (def_addr, reg, use_addr) — register value flows from def to use
    relation flows_to(u64, String, u64);
    flows_to(def_addr, reg, use_addr) <--
        defines(def_addr, reg),
        uses_reg(use_addr, reg),
        inst_in_func(func, def_addr),
        inst_in_func(func, use_addr),
        reachable(func, def_addr, use_addr);
}

/// Cross-function Datalog program for call graph analysis.
/// Computes transitive reachability in the function call graph.
ascent! {
    pub struct CrossFunctionDatalog;

    // ─── Input relations ─────────────────────────────────────────────────
    /// (caller_func, callee_func, call_site) — direct function call
    relation call_edge(u64, u64, u64);

    // ─── Derived: Call graph reachability ────────────────────────────────
    /// (caller, callee) — function callee is transitively reachable from caller
    relation can_reach(u64, u64);
    can_reach(a, b) <-- call_edge(a, b, _);
    can_reach(a, c) <--
        can_reach(a, b),
        call_edge(b, c, _);
}

/// Extract per-instruction facts from a decoded function.
pub(crate) fn extract_function_facts(
    prog: &mut FunctionDatalog,
    func_addr: u64,
    decoded: &DecodedFunction,
) {
    for instr in &decoded.instructions {
        let addr = instr.addr;

        // Register instruction as belonging to the function
        prog.inst_in_func.push((func_addr, addr));

        // Extract CFG edges
        for &edge_target in &instr.edges {
            prog.cfg_edge.push((addr, edge_target));
        }

        // Walk the statement tree to extract facts
        extract_stmt_facts(prog, addr, &instr.stmt);
    }
}

/// Extract direct call edges across all functions (for cross-function analysis).
pub(crate) fn extract_cross_function_facts(
    prog: &mut CrossFunctionDatalog,
    func_addr: u64,
    decoded: &DecodedFunction,
) {
    for instr in &decoded.instructions {
        let addr = instr.addr;
        extract_direct_calls(prog, func_addr, addr, &instr.stmt);
    }
}

// ─── Private helpers ─────────────────────────────────────────────────────

/// Walk a Stmt tree, extracting facts into the per-function program.
fn extract_stmt_facts(prog: &mut FunctionDatalog, addr: u64, stmt: &Stmt) {
    use aeonil::Stmt;
    match stmt {
        Stmt::Assign { dst, src } => {
            // Register definition
            prog.defines.push((addr, reg_name(dst)));
            // Register uses in source expression
            collect_expr_uses(prog, addr, src);
        }
        Stmt::Store { addr: addr_expr, value, size } => {
            // Memory write
            prog.writes_mem.push((addr, *size));
            // Register uses in address and value expressions
            collect_expr_uses(prog, addr, addr_expr);
            collect_expr_uses(prog, addr, value);
        }
        Stmt::Call { target } => {
            // Direct call edges are extracted separately by extract_direct_calls
            // But still need to record register uses in the target expression
            collect_expr_uses(prog, addr, target);
        }
        Stmt::Branch { target } => {
            collect_expr_uses(prog, addr, target);
        }
        Stmt::CondBranch {
            cond,
            target,
            fallthrough: _,
        } => {
            // Register uses in condition and target
            collect_branch_cond_uses(prog, addr, cond);
            collect_expr_uses(prog, addr, target);
        }
        Stmt::Ret => {}
        Stmt::Nop => {}
        Stmt::SetFlags { expr } => {
            collect_expr_uses(prog, addr, expr);
        }
        Stmt::Barrier(_) => {}
        Stmt::Trap { .. } => {}
        Stmt::Pair(a, b) => {
            // Some instructions decode to two statements
            extract_stmt_facts(prog, addr, a);
            extract_stmt_facts(prog, addr, b);
        }
        Stmt::Intrinsic { operands, .. } => {
            for op in operands {
                collect_expr_uses(prog, addr, op);
            }
        }
    }
}

/// Extract direct function calls from a statement.
fn extract_direct_calls(
    prog: &mut CrossFunctionDatalog,
    func_addr: u64,
    call_site: u64,
    stmt: &Stmt,
) {
    use aeonil::Stmt;
    match stmt {
        Stmt::Call {
            target: aeonil::Expr::Imm(callee),
        } => {
            prog.call_edge.push((func_addr, *callee, call_site));
        }
        Stmt::Pair(a, b) => {
            extract_direct_calls(prog, func_addr, call_site, a);
            extract_direct_calls(prog, func_addr, call_site, b);
        }
        _ => {}
    }
}

/// Recursively collect all register uses from an expression.
fn collect_expr_uses(prog: &mut FunctionDatalog, addr: u64, expr: &aeonil::Expr) {
    use aeonil::Expr;
    match expr {
        Expr::Reg(r) => {
            prog.uses_reg.push((addr, reg_name(r)));
        }
        Expr::Load {
            addr: inner_addr,
            size,
        } => {
            // Record memory read
            prog.reads_mem.push((addr, *size));
            // Recursively check address expression
            collect_expr_uses(prog, addr, inner_addr);
        }
        // Binary arithmetic and logical operations
        Expr::Add(l, r)
        | Expr::Sub(l, r)
        | Expr::Mul(l, r)
        | Expr::Div(l, r)
        | Expr::UDiv(l, r)
        | Expr::And(l, r)
        | Expr::Or(l, r)
        | Expr::Xor(l, r)
        | Expr::Shl(l, r)
        | Expr::Lsr(l, r)
        | Expr::Asr(l, r)
        | Expr::Ror(l, r)
        | Expr::FAdd(l, r)
        | Expr::FSub(l, r)
        | Expr::FMul(l, r)
        | Expr::FDiv(l, r)
        | Expr::FMax(l, r)
        | Expr::FMin(l, r) => {
            collect_expr_uses(prog, addr, l);
            collect_expr_uses(prog, addr, r);
        }
        // Unary operations
        Expr::Neg(e)
        | Expr::Not(e)
        | Expr::Abs(e)
        | Expr::FNeg(e)
        | Expr::FAbs(e)
        | Expr::FSqrt(e)
        | Expr::Clz(e)
        | Expr::Cls(e)
        | Expr::Rbit(e)
        | Expr::Rev(e) => {
            collect_expr_uses(prog, addr, e);
        }
        // Extension operations
        Expr::SignExtend { src, .. } | Expr::ZeroExtend { src, .. } => {
            collect_expr_uses(prog, addr, src);
        }
        // Bitfield operations
        Expr::Extract { src, .. } => {
            collect_expr_uses(prog, addr, src);
        }
        Expr::Insert { dst, src, .. } => {
            collect_expr_uses(prog, addr, dst);
            collect_expr_uses(prog, addr, src);
        }
        // Conditional operations
        Expr::CondSelect {
            if_true,
            if_false,
            ..
        } => {
            collect_expr_uses(prog, addr, if_true);
            collect_expr_uses(prog, addr, if_false);
        }
        Expr::Compare { lhs, rhs, .. } => {
            collect_expr_uses(prog, addr, lhs);
            collect_expr_uses(prog, addr, rhs);
        }
        // Floating-point conversion operations
        Expr::FCvt(_)
        | Expr::IntToFloat(_)
        | Expr::FloatToInt(_) => {
            // These are unary-like but might have different structure
            // Safe to ignore for now as they wrap other expressions
        }
        // Intrinsic operations with operands
        Expr::Intrinsic { operands, .. } => {
            for op in operands {
                collect_expr_uses(prog, addr, op);
            }
        }
        // Leaf expressions (constants, immediate values, etc.)
        Expr::Imm(_)
        | Expr::FImm(_)
        | Expr::AdrpImm(_)
        | Expr::AdrImm(_)
        | Expr::MrsRead(_)
        | Expr::StackSlot { .. } => {
            // No registers to extract
        }
    }
}

/// Recursively collect register uses from a branch condition.
fn collect_branch_cond_uses(
    prog: &mut FunctionDatalog,
    addr: u64,
    cond: &aeonil::BranchCond,
) {
    use aeonil::BranchCond;
    match cond {
        BranchCond::Flag(_) => {
            // Flags register is implicitly used, but not in an Expr
        }
        BranchCond::Zero(e)
        | BranchCond::NotZero(e)
        | BranchCond::BitZero(e, _)
        | BranchCond::BitNotZero(e, _) => {
            collect_expr_uses(prog, addr, e);
        }
        BranchCond::Compare { lhs, rhs, .. } => {
            collect_expr_uses(prog, addr, lhs);
            collect_expr_uses(prog, addr, rhs);
        }
    }
}
