//! Core SSA types -- defines `SsaVar` (versioned variable), `SsaExpr`,
//! `SsaStmt`, `SsaBranchCond`, and supporting register location/width types.

use aeonil::Condition;

pub type BlockId = u32;

/// Canonical hardware register location, abstracting over aliased views.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegLocation {
    Gpr(u8), // General-purpose 0..31
    Fpr(u8), // SIMD/FP 0..31
    Sp,
    Flags,
}

/// Width at which a location is accessed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RegWidth {
    W8 = 1,
    W16 = 2,
    W32 = 4,
    W64 = 8,
    W128 = 16,
    Full = 0, // inherent width (SP, Flags)
}

/// SSA variable: a versioned definition of a register location.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SsaVar {
    pub loc: RegLocation,
    pub version: u32,
    pub width: RegWidth,
}

/// Convert an aeonil Reg to its canonical location and width.
pub fn reg_to_location(r: &aeonil::Reg) -> (RegLocation, RegWidth) {
    use aeonil::Reg;
    match r {
        Reg::X(n) => (RegLocation::Gpr(*n), RegWidth::W64),
        Reg::W(n) => (RegLocation::Gpr(*n), RegWidth::W32),
        Reg::V(n) | Reg::Q(n) => (RegLocation::Fpr(*n), RegWidth::W128),
        Reg::D(n) => (RegLocation::Fpr(*n), RegWidth::W64),
        Reg::S(n) => (RegLocation::Fpr(*n), RegWidth::W32),
        Reg::H(n) => (RegLocation::Fpr(*n), RegWidth::W16),
        Reg::VByte(n) => (RegLocation::Fpr(*n), RegWidth::W8),
        Reg::SP => (RegLocation::Sp, RegWidth::Full),
        Reg::Flags => (RegLocation::Flags, RegWidth::Full),
        Reg::PC | Reg::XZR => panic!("PC and XZR are not SSA-tracked"),
    }
}

impl RegLocation {
    pub fn full_width(&self) -> RegWidth {
        match self {
            RegLocation::Gpr(_) => RegWidth::W64,
            RegLocation::Fpr(_) => RegWidth::W128,
            RegLocation::Sp | RegLocation::Flags => RegWidth::Full,
        }
    }
}

impl RegWidth {
    pub fn bits(&self) -> u8 {
        match self {
            RegWidth::W8 => 8,
            RegWidth::W16 => 16,
            RegWidth::W32 => 32,
            RegWidth::W64 => 64,
            RegWidth::W128 => 128,
            RegWidth::Full => 64,
        }
    }
}

// ---------------------------------------------------------------------------
// SSA IL types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum SsaExpr {
    Var(SsaVar),
    Imm(u64),
    FImm(f64),
    Load {
        addr: Box<SsaExpr>,
        size: u8,
    },
    Add(Box<SsaExpr>, Box<SsaExpr>),
    Sub(Box<SsaExpr>, Box<SsaExpr>),
    Mul(Box<SsaExpr>, Box<SsaExpr>),
    Div(Box<SsaExpr>, Box<SsaExpr>),
    UDiv(Box<SsaExpr>, Box<SsaExpr>),
    Neg(Box<SsaExpr>),
    Abs(Box<SsaExpr>),
    And(Box<SsaExpr>, Box<SsaExpr>),
    Or(Box<SsaExpr>, Box<SsaExpr>),
    Xor(Box<SsaExpr>, Box<SsaExpr>),
    Not(Box<SsaExpr>),
    Shl(Box<SsaExpr>, Box<SsaExpr>),
    Lsr(Box<SsaExpr>, Box<SsaExpr>),
    Asr(Box<SsaExpr>, Box<SsaExpr>),
    Ror(Box<SsaExpr>, Box<SsaExpr>),
    SignExtend {
        src: Box<SsaExpr>,
        from_bits: u8,
    },
    ZeroExtend {
        src: Box<SsaExpr>,
        from_bits: u8,
    },
    Extract {
        src: Box<SsaExpr>,
        lsb: u8,
        width: u8,
    },
    Insert {
        dst: Box<SsaExpr>,
        src: Box<SsaExpr>,
        lsb: u8,
        width: u8,
    },
    // FP ops
    FAdd(Box<SsaExpr>, Box<SsaExpr>),
    FSub(Box<SsaExpr>, Box<SsaExpr>),
    FMul(Box<SsaExpr>, Box<SsaExpr>),
    FDiv(Box<SsaExpr>, Box<SsaExpr>),
    FNeg(Box<SsaExpr>),
    FAbs(Box<SsaExpr>),
    FSqrt(Box<SsaExpr>),
    FMax(Box<SsaExpr>, Box<SsaExpr>),
    FMin(Box<SsaExpr>, Box<SsaExpr>),
    FCvt(Box<SsaExpr>),
    IntToFloat(Box<SsaExpr>),
    FloatToInt(Box<SsaExpr>),
    // Misc
    Clz(Box<SsaExpr>),
    Cls(Box<SsaExpr>),
    Rev(Box<SsaExpr>),
    Rbit(Box<SsaExpr>),
    CondSelect {
        cond: Condition,
        if_true: Box<SsaExpr>,
        if_false: Box<SsaExpr>,
    },
    Compare {
        cond: Condition,
        lhs: Box<SsaExpr>,
        rhs: Box<SsaExpr>,
    },
    StackSlot {
        offset: i64,
        size: u8,
    },
    MrsRead(String),
    Intrinsic {
        name: String,
        operands: Vec<SsaExpr>,
    },
    Phi(Vec<(BlockId, SsaVar)>),
    AdrpImm(u64),
    AdrImm(u64),
}

#[derive(Debug, Clone, PartialEq)]
pub enum SsaBranchCond {
    Flag(Condition, SsaVar), // reads a specific flags version
    Zero(SsaExpr),
    NotZero(SsaExpr),
    BitZero(SsaExpr, u8),
    BitNotZero(SsaExpr, u8),
    Compare {
        cond: Condition,
        lhs: Box<SsaExpr>,
        rhs: Box<SsaExpr>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum SsaStmt {
    Assign {
        dst: SsaVar,
        src: SsaExpr,
    },
    Store {
        addr: SsaExpr,
        value: SsaExpr,
        size: u8,
    },
    Branch {
        target: SsaExpr,
    },
    CondBranch {
        cond: SsaBranchCond,
        target: SsaExpr,
        fallthrough: BlockId,
    },
    Call {
        target: SsaExpr,
    },
    Ret,
    Nop,
    SetFlags {
        src: SsaVar,
        expr: SsaExpr,
    },
    Barrier(String),
    Trap,
    Intrinsic {
        name: String,
        operands: Vec<SsaExpr>,
    },
    Pair(Box<SsaStmt>, Box<SsaStmt>),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reg_to_location_gpr64() {
        let (loc, w) = reg_to_location(&aeonil::Reg::X(5));
        assert_eq!(loc, RegLocation::Gpr(5));
        assert_eq!(w, RegWidth::W64);
    }

    #[test]
    fn reg_to_location_gpr32() {
        let (loc, w) = reg_to_location(&aeonil::Reg::W(10));
        assert_eq!(loc, RegLocation::Gpr(10));
        assert_eq!(w, RegWidth::W32);
    }

    #[test]
    fn reg_to_location_fpr() {
        let (loc, w) = reg_to_location(&aeonil::Reg::D(3));
        assert_eq!(loc, RegLocation::Fpr(3));
        assert_eq!(w, RegWidth::W64);

        let (loc2, w2) = reg_to_location(&aeonil::Reg::S(7));
        assert_eq!(loc2, RegLocation::Fpr(7));
        assert_eq!(w2, RegWidth::W32);
    }

    #[test]
    fn reg_to_location_sp() {
        let (loc, w) = reg_to_location(&aeonil::Reg::SP);
        assert_eq!(loc, RegLocation::Sp);
        assert_eq!(w, RegWidth::Full);
    }

    #[test]
    fn reg_to_location_flags() {
        let (loc, w) = reg_to_location(&aeonil::Reg::Flags);
        assert_eq!(loc, RegLocation::Flags);
        assert_eq!(w, RegWidth::Full);
    }

    #[test]
    #[should_panic(expected = "PC and XZR are not SSA-tracked")]
    fn reg_to_location_xzr_panics() {
        reg_to_location(&aeonil::Reg::XZR);
    }

    #[test]
    #[should_panic(expected = "PC and XZR are not SSA-tracked")]
    fn reg_to_location_pc_panics() {
        reg_to_location(&aeonil::Reg::PC);
    }

    #[test]
    fn full_width() {
        assert_eq!(RegLocation::Gpr(0).full_width(), RegWidth::W64);
        assert_eq!(RegLocation::Fpr(0).full_width(), RegWidth::W128);
        assert_eq!(RegLocation::Sp.full_width(), RegWidth::Full);
    }

    #[test]
    fn reg_width_bits() {
        assert_eq!(RegWidth::W8.bits(), 8);
        assert_eq!(RegWidth::W16.bits(), 16);
        assert_eq!(RegWidth::W32.bits(), 32);
        assert_eq!(RegWidth::W64.bits(), 64);
        assert_eq!(RegWidth::W128.bits(), 128);
        assert_eq!(RegWidth::Full.bits(), 64);
    }

    #[test]
    fn ssa_var_equality() {
        let v1 = SsaVar {
            loc: RegLocation::Gpr(0),
            version: 1,
            width: RegWidth::W64,
        };
        let v2 = SsaVar {
            loc: RegLocation::Gpr(0),
            version: 1,
            width: RegWidth::W64,
        };
        let v3 = SsaVar {
            loc: RegLocation::Gpr(0),
            version: 2,
            width: RegWidth::W64,
        };
        assert_eq!(v1, v2);
        assert_ne!(v1, v3);
    }

    #[test]
    fn reg_width_ordering() {
        assert!(RegWidth::Full < RegWidth::W8);
        assert!(RegWidth::W8 < RegWidth::W16);
        assert!(RegWidth::W16 < RegWidth::W32);
        assert!(RegWidth::W32 < RegWidth::W64);
        assert!(RegWidth::W64 < RegWidth::W128);
    }
}
