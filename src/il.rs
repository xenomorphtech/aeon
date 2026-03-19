/// AeonIL — a BNIL-like intermediate language for ARM64.

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Reg {
    X(u8),      // 64-bit general purpose
    W(u8),      // 32-bit general purpose
    SP,         // stack pointer
    PC,         // program counter
    XZR,        // zero register
    Flags,      // NZCV condition flags
    V(u8),      // 128-bit SIMD vector
    Q(u8),      // 128-bit (alias of V)
    D(u8),      // 64-bit FP / SIMD scalar
    S(u8),      // 32-bit FP / SIMD scalar
    H(u8),      // 16-bit FP
    VByte(u8),  // 8-bit SIMD scalar
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Condition {
    EQ, NE, CS, CC, MI, PL, VS, VC, HI, LS, GE, LT, GT, LE, AL, NV,
}

#[derive(Debug, Clone, PartialEq)]
pub enum BranchCond {
    Flag(Condition),
    Zero(Expr),
    NotZero(Expr),
    BitZero(Expr, u8),
    BitNotZero(Expr, u8),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    // Basics
    Reg(Reg),
    Imm(u64),
    FImm(f64),

    // Memory
    Load { addr: Box<Expr>, size: u8 },

    // Arithmetic
    Add(Box<Expr>, Box<Expr>),
    Sub(Box<Expr>, Box<Expr>),
    Mul(Box<Expr>, Box<Expr>),
    Div(Box<Expr>, Box<Expr>),
    UDiv(Box<Expr>, Box<Expr>),
    Neg(Box<Expr>),
    Abs(Box<Expr>),

    // Logic
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Xor(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),

    // Shift
    Shl(Box<Expr>, Box<Expr>),
    Lsr(Box<Expr>, Box<Expr>),
    Asr(Box<Expr>, Box<Expr>),
    Ror(Box<Expr>, Box<Expr>),

    // Extension
    SignExtend { src: Box<Expr>, from_bits: u8 },
    ZeroExtend { src: Box<Expr>, from_bits: u8 },

    // Bitfield
    Extract { src: Box<Expr>, lsb: u8, width: u8 },
    Insert { dst: Box<Expr>, src: Box<Expr>, lsb: u8, width: u8 },

    // Floating point
    FAdd(Box<Expr>, Box<Expr>),
    FSub(Box<Expr>, Box<Expr>),
    FMul(Box<Expr>, Box<Expr>),
    FDiv(Box<Expr>, Box<Expr>),
    FNeg(Box<Expr>),
    FAbs(Box<Expr>),
    FSqrt(Box<Expr>),
    FMax(Box<Expr>, Box<Expr>),
    FMin(Box<Expr>, Box<Expr>),
    FCvt(Box<Expr>),
    IntToFloat(Box<Expr>),
    FloatToInt(Box<Expr>),

    // Conditional
    CondSelect { cond: Condition, if_true: Box<Expr>, if_false: Box<Expr> },

    // Misc
    Clz(Box<Expr>),
    Cls(Box<Expr>),
    Rev(Box<Expr>),
    Rbit(Box<Expr>),

    // Address computation
    AdrpImm(u64),
    AdrImm(u64),

    // System register read
    MrsRead(String),

    // Catch-all for complex/SIMD/rare operations
    Intrinsic { name: String, operands: Vec<Expr> },
}

#[derive(Debug, Clone, PartialEq)]
pub enum Stmt {
    Assign { dst: Reg, src: Expr },
    Store { addr: Expr, value: Expr, size: u8 },
    Branch { target: Expr },
    CondBranch { cond: BranchCond, target: Expr, fallthrough: u64 },
    Call { target: Expr },
    Ret,
    Nop,
    Pair(Box<Stmt>, Box<Stmt>),
    SetFlags { expr: Expr },
    Barrier(String),
    Trap,
    Intrinsic { name: String, operands: Vec<Expr> },
}

// ── Expression constructors (reduce Box noise) ─────────────────────────

pub fn e_add(a: Expr, b: Expr) -> Expr { Expr::Add(Box::new(a), Box::new(b)) }
pub fn e_sub(a: Expr, b: Expr) -> Expr { Expr::Sub(Box::new(a), Box::new(b)) }
pub fn e_mul(a: Expr, b: Expr) -> Expr { Expr::Mul(Box::new(a), Box::new(b)) }
pub fn e_div(a: Expr, b: Expr) -> Expr { Expr::Div(Box::new(a), Box::new(b)) }
pub fn e_udiv(a: Expr, b: Expr) -> Expr { Expr::UDiv(Box::new(a), Box::new(b)) }
pub fn e_neg(a: Expr) -> Expr { Expr::Neg(Box::new(a)) }
pub fn e_abs(a: Expr) -> Expr { Expr::Abs(Box::new(a)) }
pub fn e_and(a: Expr, b: Expr) -> Expr { Expr::And(Box::new(a), Box::new(b)) }
pub fn e_or(a: Expr, b: Expr) -> Expr { Expr::Or(Box::new(a), Box::new(b)) }
pub fn e_xor(a: Expr, b: Expr) -> Expr { Expr::Xor(Box::new(a), Box::new(b)) }
pub fn e_not(a: Expr) -> Expr { Expr::Not(Box::new(a)) }
pub fn e_shl(a: Expr, b: Expr) -> Expr { Expr::Shl(Box::new(a), Box::new(b)) }
pub fn e_lsr(a: Expr, b: Expr) -> Expr { Expr::Lsr(Box::new(a), Box::new(b)) }
pub fn e_asr(a: Expr, b: Expr) -> Expr { Expr::Asr(Box::new(a), Box::new(b)) }
pub fn e_ror(a: Expr, b: Expr) -> Expr { Expr::Ror(Box::new(a), Box::new(b)) }
pub fn e_sign_extend(src: Expr, from: u8) -> Expr { Expr::SignExtend { src: Box::new(src), from_bits: from } }
pub fn e_zero_extend(src: Expr, from: u8) -> Expr { Expr::ZeroExtend { src: Box::new(src), from_bits: from } }
pub fn e_extract(src: Expr, lsb: u8, width: u8) -> Expr { Expr::Extract { src: Box::new(src), lsb, width } }
pub fn e_insert(dst: Expr, src: Expr, lsb: u8, width: u8) -> Expr { Expr::Insert { dst: Box::new(dst), src: Box::new(src), lsb, width } }
pub fn e_load(addr: Expr, size: u8) -> Expr { Expr::Load { addr: Box::new(addr), size } }
pub fn e_fadd(a: Expr, b: Expr) -> Expr { Expr::FAdd(Box::new(a), Box::new(b)) }
pub fn e_fsub(a: Expr, b: Expr) -> Expr { Expr::FSub(Box::new(a), Box::new(b)) }
pub fn e_fmul(a: Expr, b: Expr) -> Expr { Expr::FMul(Box::new(a), Box::new(b)) }
pub fn e_fdiv(a: Expr, b: Expr) -> Expr { Expr::FDiv(Box::new(a), Box::new(b)) }
pub fn e_fneg(a: Expr) -> Expr { Expr::FNeg(Box::new(a)) }
pub fn e_fabs(a: Expr) -> Expr { Expr::FAbs(Box::new(a)) }
pub fn e_fsqrt(a: Expr) -> Expr { Expr::FSqrt(Box::new(a)) }
pub fn e_fmax(a: Expr, b: Expr) -> Expr { Expr::FMax(Box::new(a), Box::new(b)) }
pub fn e_fmin(a: Expr, b: Expr) -> Expr { Expr::FMin(Box::new(a), Box::new(b)) }
pub fn e_fcvt(a: Expr) -> Expr { Expr::FCvt(Box::new(a)) }
pub fn e_int_to_float(a: Expr) -> Expr { Expr::IntToFloat(Box::new(a)) }
pub fn e_float_to_int(a: Expr) -> Expr { Expr::FloatToInt(Box::new(a)) }
pub fn e_clz(a: Expr) -> Expr { Expr::Clz(Box::new(a)) }
pub fn e_cls(a: Expr) -> Expr { Expr::Cls(Box::new(a)) }
pub fn e_rev(a: Expr) -> Expr { Expr::Rev(Box::new(a)) }
pub fn e_rbit(a: Expr) -> Expr { Expr::Rbit(Box::new(a)) }
pub fn e_cond_select(cond: Condition, t: Expr, f: Expr) -> Expr {
    Expr::CondSelect { cond, if_true: Box::new(t), if_false: Box::new(f) }
}
pub fn e_intrinsic(name: &str, ops: Vec<Expr>) -> Expr {
    Expr::Intrinsic { name: name.to_string(), operands: ops }
}

pub fn reg_size(r: &Reg) -> u8 {
    match r {
        Reg::X(_) | Reg::D(_) => 8,
        Reg::W(_) | Reg::S(_) => 4,
        Reg::H(_) => 2,
        Reg::VByte(_) => 1,
        Reg::V(_) | Reg::Q(_) => 16,
        Reg::SP | Reg::PC | Reg::XZR => 8,
        Reg::Flags => 4,
    }
}
