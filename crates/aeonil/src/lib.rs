/// AeonIL — a BNIL-like intermediate language for ARM64.

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Reg {
    X(u8),     // 64-bit general purpose
    W(u8),     // 32-bit general purpose
    SP,        // stack pointer
    PC,        // program counter
    XZR,       // zero register
    Flags,     // NZCV condition flags
    V(u8),     // 128-bit SIMD vector
    Q(u8),     // 128-bit (alias of V)
    D(u8),     // 64-bit FP / SIMD scalar
    S(u8),     // 32-bit FP / SIMD scalar
    H(u8),     // 16-bit FP
    VByte(u8), // 8-bit SIMD scalar
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Condition {
    EQ,
    NE,
    CS,
    CC,
    MI,
    PL,
    VS,
    VC,
    HI,
    LS,
    GE,
    LT,
    GT,
    LE,
    AL,
    NV,
}

#[derive(Debug, Clone, PartialEq)]
pub enum BranchCond {
    Flag(Condition),
    Zero(Expr),
    NotZero(Expr),
    BitZero(Expr, u8),
    BitNotZero(Expr, u8),
    Compare {
        cond: Condition,
        lhs: Box<Expr>,
        rhs: Box<Expr>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    // Basics
    Reg(Reg),
    Imm(u64),
    FImm(f64),

    // Memory
    Load {
        addr: Box<Expr>,
        size: u8,
    },

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
    SignExtend {
        src: Box<Expr>,
        from_bits: u8,
    },
    ZeroExtend {
        src: Box<Expr>,
        from_bits: u8,
    },

    // Bitfield
    Extract {
        src: Box<Expr>,
        lsb: u8,
        width: u8,
    },
    Insert {
        dst: Box<Expr>,
        src: Box<Expr>,
        lsb: u8,
        width: u8,
    },

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
    CondSelect {
        cond: Condition,
        if_true: Box<Expr>,
        if_false: Box<Expr>,
    },
    Compare {
        cond: Condition,
        lhs: Box<Expr>,
        rhs: Box<Expr>,
    },

    // Misc
    Clz(Box<Expr>),
    Cls(Box<Expr>),
    Rev(Box<Expr>),
    Rbit(Box<Expr>),

    // Address computation
    AdrpImm(u64),
    AdrImm(u64),

    // Stack slot
    StackSlot {
        offset: i64,
        size: u8,
    },

    // System register read
    MrsRead(String),

    // Catch-all for complex/SIMD/rare operations
    Intrinsic {
        name: String,
        operands: Vec<Expr>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum Stmt {
    Assign {
        dst: Reg,
        src: Expr,
    },
    Store {
        addr: Expr,
        value: Expr,
        size: u8,
    },
    Branch {
        target: Expr,
    },
    CondBranch {
        cond: BranchCond,
        target: Expr,
        fallthrough: u64,
    },
    Call {
        target: Expr,
    },
    Ret,
    Nop,
    Pair(Box<Stmt>, Box<Stmt>),
    SetFlags {
        expr: Expr,
    },
    Barrier(String),
    Trap,
    Intrinsic {
        name: String,
        operands: Vec<Expr>,
    },
}

// Expression constructors

pub fn e_add(a: Expr, b: Expr) -> Expr {
    Expr::Add(Box::new(a), Box::new(b))
}
pub fn e_sub(a: Expr, b: Expr) -> Expr {
    Expr::Sub(Box::new(a), Box::new(b))
}
pub fn e_mul(a: Expr, b: Expr) -> Expr {
    Expr::Mul(Box::new(a), Box::new(b))
}
pub fn e_div(a: Expr, b: Expr) -> Expr {
    Expr::Div(Box::new(a), Box::new(b))
}
pub fn e_udiv(a: Expr, b: Expr) -> Expr {
    Expr::UDiv(Box::new(a), Box::new(b))
}
pub fn e_neg(a: Expr) -> Expr {
    Expr::Neg(Box::new(a))
}
pub fn e_abs(a: Expr) -> Expr {
    Expr::Abs(Box::new(a))
}
pub fn e_and(a: Expr, b: Expr) -> Expr {
    Expr::And(Box::new(a), Box::new(b))
}
pub fn e_or(a: Expr, b: Expr) -> Expr {
    Expr::Or(Box::new(a), Box::new(b))
}
pub fn e_xor(a: Expr, b: Expr) -> Expr {
    Expr::Xor(Box::new(a), Box::new(b))
}
pub fn e_not(a: Expr) -> Expr {
    Expr::Not(Box::new(a))
}
pub fn e_shl(a: Expr, b: Expr) -> Expr {
    Expr::Shl(Box::new(a), Box::new(b))
}
pub fn e_lsr(a: Expr, b: Expr) -> Expr {
    Expr::Lsr(Box::new(a), Box::new(b))
}
pub fn e_asr(a: Expr, b: Expr) -> Expr {
    Expr::Asr(Box::new(a), Box::new(b))
}
pub fn e_ror(a: Expr, b: Expr) -> Expr {
    Expr::Ror(Box::new(a), Box::new(b))
}
pub fn e_sign_extend(src: Expr, from: u8) -> Expr {
    Expr::SignExtend {
        src: Box::new(src),
        from_bits: from,
    }
}
pub fn e_zero_extend(src: Expr, from: u8) -> Expr {
    Expr::ZeroExtend {
        src: Box::new(src),
        from_bits: from,
    }
}
pub fn e_extract(src: Expr, lsb: u8, width: u8) -> Expr {
    Expr::Extract {
        src: Box::new(src),
        lsb,
        width,
    }
}
pub fn e_insert(dst: Expr, src: Expr, lsb: u8, width: u8) -> Expr {
    Expr::Insert {
        dst: Box::new(dst),
        src: Box::new(src),
        lsb,
        width,
    }
}
pub fn e_load(addr: Expr, size: u8) -> Expr {
    Expr::Load {
        addr: Box::new(addr),
        size,
    }
}
pub fn e_fadd(a: Expr, b: Expr) -> Expr {
    Expr::FAdd(Box::new(a), Box::new(b))
}
pub fn e_fsub(a: Expr, b: Expr) -> Expr {
    Expr::FSub(Box::new(a), Box::new(b))
}
pub fn e_fmul(a: Expr, b: Expr) -> Expr {
    Expr::FMul(Box::new(a), Box::new(b))
}
pub fn e_fdiv(a: Expr, b: Expr) -> Expr {
    Expr::FDiv(Box::new(a), Box::new(b))
}
pub fn e_fneg(a: Expr) -> Expr {
    Expr::FNeg(Box::new(a))
}
pub fn e_fabs(a: Expr) -> Expr {
    Expr::FAbs(Box::new(a))
}
pub fn e_fsqrt(a: Expr) -> Expr {
    Expr::FSqrt(Box::new(a))
}
pub fn e_fmax(a: Expr, b: Expr) -> Expr {
    Expr::FMax(Box::new(a), Box::new(b))
}
pub fn e_fmin(a: Expr, b: Expr) -> Expr {
    Expr::FMin(Box::new(a), Box::new(b))
}
pub fn e_fcvt(a: Expr) -> Expr {
    Expr::FCvt(Box::new(a))
}
pub fn e_int_to_float(a: Expr) -> Expr {
    Expr::IntToFloat(Box::new(a))
}
pub fn e_float_to_int(a: Expr) -> Expr {
    Expr::FloatToInt(Box::new(a))
}
pub fn e_clz(a: Expr) -> Expr {
    Expr::Clz(Box::new(a))
}
pub fn e_cls(a: Expr) -> Expr {
    Expr::Cls(Box::new(a))
}
pub fn e_rev(a: Expr) -> Expr {
    Expr::Rev(Box::new(a))
}
pub fn e_rbit(a: Expr) -> Expr {
    Expr::Rbit(Box::new(a))
}
pub fn e_cond_select(cond: Condition, t: Expr, f: Expr) -> Expr {
    Expr::CondSelect {
        cond,
        if_true: Box::new(t),
        if_false: Box::new(f),
    }
}
pub fn e_intrinsic(name: &str, ops: Vec<Expr>) -> Expr {
    Expr::Intrinsic {
        name: name.to_string(),
        operands: ops,
    }
}
pub fn e_compare(cond: Condition, lhs: Expr, rhs: Expr) -> Expr {
    Expr::Compare { cond, lhs: Box::new(lhs), rhs: Box::new(rhs) }
}
pub fn e_stack_slot(offset: i64, size: u8) -> Expr {
    Expr::StackSlot { offset, size }
}

impl Expr {
    /// Apply `f` to every immediate sub-expression, returning a new `Expr`.
    pub fn map_subexprs<F: Fn(&Expr) -> Expr>(&self, f: F) -> Expr {
        match self {
            // Leaf nodes — no children
            Expr::Reg(_)
            | Expr::Imm(_)
            | Expr::FImm(_)
            | Expr::AdrpImm(_)
            | Expr::AdrImm(_)
            | Expr::MrsRead(_)
            | Expr::StackSlot { .. } => self.clone(),

            // Unary nodes
            Expr::Neg(a) => Expr::Neg(Box::new(f(a))),
            Expr::Abs(a) => Expr::Abs(Box::new(f(a))),
            Expr::Not(a) => Expr::Not(Box::new(f(a))),
            Expr::FNeg(a) => Expr::FNeg(Box::new(f(a))),
            Expr::FAbs(a) => Expr::FAbs(Box::new(f(a))),
            Expr::FSqrt(a) => Expr::FSqrt(Box::new(f(a))),
            Expr::FCvt(a) => Expr::FCvt(Box::new(f(a))),
            Expr::IntToFloat(a) => Expr::IntToFloat(Box::new(f(a))),
            Expr::FloatToInt(a) => Expr::FloatToInt(Box::new(f(a))),
            Expr::Clz(a) => Expr::Clz(Box::new(f(a))),
            Expr::Cls(a) => Expr::Cls(Box::new(f(a))),
            Expr::Rev(a) => Expr::Rev(Box::new(f(a))),
            Expr::Rbit(a) => Expr::Rbit(Box::new(f(a))),

            // Binary nodes
            Expr::Add(a, b) => Expr::Add(Box::new(f(a)), Box::new(f(b))),
            Expr::Sub(a, b) => Expr::Sub(Box::new(f(a)), Box::new(f(b))),
            Expr::Mul(a, b) => Expr::Mul(Box::new(f(a)), Box::new(f(b))),
            Expr::Div(a, b) => Expr::Div(Box::new(f(a)), Box::new(f(b))),
            Expr::UDiv(a, b) => Expr::UDiv(Box::new(f(a)), Box::new(f(b))),
            Expr::And(a, b) => Expr::And(Box::new(f(a)), Box::new(f(b))),
            Expr::Or(a, b) => Expr::Or(Box::new(f(a)), Box::new(f(b))),
            Expr::Xor(a, b) => Expr::Xor(Box::new(f(a)), Box::new(f(b))),
            Expr::Shl(a, b) => Expr::Shl(Box::new(f(a)), Box::new(f(b))),
            Expr::Lsr(a, b) => Expr::Lsr(Box::new(f(a)), Box::new(f(b))),
            Expr::Asr(a, b) => Expr::Asr(Box::new(f(a)), Box::new(f(b))),
            Expr::Ror(a, b) => Expr::Ror(Box::new(f(a)), Box::new(f(b))),
            Expr::FAdd(a, b) => Expr::FAdd(Box::new(f(a)), Box::new(f(b))),
            Expr::FSub(a, b) => Expr::FSub(Box::new(f(a)), Box::new(f(b))),
            Expr::FMul(a, b) => Expr::FMul(Box::new(f(a)), Box::new(f(b))),
            Expr::FDiv(a, b) => Expr::FDiv(Box::new(f(a)), Box::new(f(b))),
            Expr::FMax(a, b) => Expr::FMax(Box::new(f(a)), Box::new(f(b))),
            Expr::FMin(a, b) => Expr::FMin(Box::new(f(a)), Box::new(f(b))),
            Expr::Compare { cond, lhs, rhs } => Expr::Compare {
                cond: *cond,
                lhs: Box::new(f(lhs)),
                rhs: Box::new(f(rhs)),
            },

            // Extension
            Expr::SignExtend { src, from_bits } => Expr::SignExtend {
                src: Box::new(f(src)),
                from_bits: *from_bits,
            },
            Expr::ZeroExtend { src, from_bits } => Expr::ZeroExtend {
                src: Box::new(f(src)),
                from_bits: *from_bits,
            },

            // Bitfield
            Expr::Extract { src, lsb, width } => Expr::Extract {
                src: Box::new(f(src)),
                lsb: *lsb,
                width: *width,
            },
            Expr::Insert { dst, src, lsb, width } => Expr::Insert {
                dst: Box::new(f(dst)),
                src: Box::new(f(src)),
                lsb: *lsb,
                width: *width,
            },

            // Memory
            Expr::Load { addr, size } => Expr::Load {
                addr: Box::new(f(addr)),
                size: *size,
            },

            // Conditional
            Expr::CondSelect { cond, if_true, if_false } => Expr::CondSelect {
                cond: *cond,
                if_true: Box::new(f(if_true)),
                if_false: Box::new(f(if_false)),
            },

            // Intrinsic
            Expr::Intrinsic { name, operands } => Expr::Intrinsic {
                name: name.clone(),
                operands: operands.iter().map(|op| f(op)).collect(),
            },
        }
    }
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
