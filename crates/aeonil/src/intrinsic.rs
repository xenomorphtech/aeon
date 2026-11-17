//! Typed intrinsic names.
//!
//! The lifter names intrinsics after the ARM64 mnemonic, optionally followed by
//! a vector arrangement (`"add.2d"`, `"bif.8b"`). [`IntrinsicName`] parses that
//! text once, at construction, so backends match on [`IntrinsicOp`] and read a
//! structured [`VectorArrangement`] instead of each re-parsing the string.
//!
//! The original text is kept: it is what gets displayed and serialised, and it
//! is the only identity an operation outside [`IntrinsicOp`] has.

use std::fmt;
use std::ops::Deref;

macro_rules! intrinsic_ops {
    ($($variant:ident => $text:literal),* $(,)?) => {
        /// The operation an intrinsic performs, independent of arrangement.
        ///
        /// `Other` covers every mnemonic no backend gives semantics to; use
        /// [`IntrinsicName::as_str`] to tell those apart.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum IntrinsicOp {
            $($variant,)*
            Other,
        }

        impl IntrinsicOp {
            /// Every operation with a known mnemonic, in declaration order.
            pub const KNOWN: &'static [IntrinsicOp] = &[$(IntrinsicOp::$variant,)*];

            /// Classify a base mnemonic (the part before any `.arrangement`).
            pub fn from_base_name(base: &str) -> Self {
                match base {
                    $($text => Self::$variant,)*
                    _ => Self::Other,
                }
            }

            /// The base mnemonic, or `None` for `Other`.
            pub fn base_name(self) -> Option<&'static str> {
                match self {
                    $(Self::$variant => Some($text),)*
                    Self::Other => None,
                }
            }
        }
    };
}

intrinsic_ops! {
    // Scalar integer
    Movk => "movk",
    Smulh => "smulh",
    Umulh => "umulh",
    Adc => "adc",
    Sbc => "sbc",
    Ngc => "ngc",
    // Flag-setting carry arithmetic. These are statements, not expressions:
    // the result and the new flags both depend on the old carry, so neither
    // can be computed after the other has been written.
    Adcs => "adcs",
    Sbcs => "sbcs",
    Ngcs => "ngcs",
    Rev16 => "rev16",
    Rev32 => "rev32",
    Extr => "extr",

    // Bitfield
    Ubfx => "ubfx",
    Ubfiz => "ubfiz",
    Sbfx => "sbfx",
    Sbfiz => "sbfiz",
    Bfi => "bfi",
    Bfxil => "bfxil",

    // CRC32
    Crc32b => "crc32b",
    Crc32h => "crc32h",
    Crc32w => "crc32w",
    Crc32x => "crc32x",
    Crc32cb => "crc32cb",
    Crc32ch => "crc32ch",
    Crc32cw => "crc32cw",
    Crc32cx => "crc32cx",

    // Hints and other statements without data-flow semantics
    Nop => "nop",
    Yield => "yield",
    Hint => "hint",
    Paciasp => "paciasp",
    Autiasp => "autiasp",
    Bti => "bti",
    Xpaclri => "xpaclri",
    Prfm => "prfm",
    Prfum => "prfum",
    Clrex => "clrex",

    // System
    Msr => "msr",
    Sys => "sys",

    // Pseudo-operand: a register list such as `{v0.16b, v1.16b}`
    MultiReg => "multi_reg",

    // Floating point
    Fccmp => "fccmp",
    Fccmpe => "fccmpe",
    Fnmadd => "fnmadd",
    Fnmsub => "fnmsub",
    Frintz => "frintz",
    Frintm => "frintm",
    Frintp => "frintp",
    Frintn => "frintn",
    Frinta => "frinta",
    Frintx => "frintx",
    Scvtf => "scvtf",
    Ucvtf => "ucvtf",
    Fcvtzs => "fcvtzs",
    Fcvtzu => "fcvtzu",
    Fcvtms => "fcvtms",
    Fcvtmu => "fcvtmu",
    Fcvtps => "fcvtps",
    Fcvtpu => "fcvtpu",
    Fcvtns => "fcvtns",
    Fcvtnu => "fcvtnu",
    Fcvtas => "fcvtas",
    Fcvtau => "fcvtau",
    Fcmla => "fcmla",
    Fmulx => "fmulx",
    // Vector forms; the scalar forms are `Expr::FAdd` and friends.
    Fadd => "fadd",
    Fsub => "fsub",
    Fmul => "fmul",
    Fdiv => "fdiv",

    // SIMD bitwise
    And => "and",
    Orr => "orr",
    Eor => "eor",
    Orn => "orn",
    Bic => "bic",
    Bsl => "bsl",
    Bit => "bit",
    Bif => "bif",
    Mvn => "mvn",
    Not => "not",
    Cnt => "cnt",

    // SIMD moves, loads and stores
    Movi => "movi",
    Mvni => "mvni",
    Dup => "dup",
    Umov => "umov",
    Ld1 => "ld1",
    Ld1r => "ld1r",
    St1 => "st1",

    // SIMD arithmetic and compare
    Add => "add",
    Sub => "sub",
    Mul => "mul",
    Neg => "neg",
    Abs => "abs",
    Mov => "mov",
    Cmeq => "cmeq",
    Cmhi => "cmhi",
    Cmhs => "cmhs",
    Cmgt => "cmgt",
    Cmge => "cmge",
    Umax => "umax",
    Umin => "umin",
    Smax => "smax",
    Smin => "smin",
    Rev64 => "rev64",
    Mla => "mla",
    Mls => "mls",
    Umull => "umull",
    Umull2 => "umull2",
    Smull => "smull",
    Smull2 => "smull2",
    Umlal => "umlal",
    Umlal2 => "umlal2",
    Smlal => "smlal",
    Smlal2 => "smlal2",
    Umlsl => "umlsl",
    Umlsl2 => "umlsl2",
    Smlsl => "smlsl",
    Smlsl2 => "smlsl2",
    Sqrdmlah => "sqrdmlah",
    Sqrdmlsh => "sqrdmlsh",

    // SIMD narrowing, permutes and table lookup
    Xtn => "xtn",
    Xtn2 => "xtn2",
    Zip1 => "zip1",
    Zip2 => "zip2",
    Uzp1 => "uzp1",
    Uzp2 => "uzp2",
    Trn1 => "trn1",
    Trn2 => "trn2",
    Ext => "ext",
    Tbl => "tbl",
    Tbx => "tbx",

    // SIMD reductions: one result from all lanes, or from adjacent pairs
    Addv => "addv",
    Umaxv => "umaxv",
    Uminv => "uminv",
    Smaxv => "smaxv",
    Sminv => "sminv",
    Uaddlv => "uaddlv",
    Saddlv => "saddlv",
    Addp => "addp",

    // SIMD shifts
    Shl => "shl",
    Sshr => "sshr",
    Ushr => "ushr",
    Urshr => "urshr",
    Usra => "usra",
    Ursra => "ursra",
    Sli => "sli",
    Sri => "sri",
    Sqshlu => "sqshlu",
    Uqshl => "uqshl",
    Uxtl => "uxtl",
    Uxtl2 => "uxtl2",
    Sxtl => "sxtl",
    Sxtl2 => "sxtl2",
    Ushll => "ushll",
    Ushll2 => "ushll2",
    Sshll => "sshll",
    Sshll2 => "sshll2",
    Uqrshrn2 => "uqrshrn2",
}

/// A SIMD arrangement such as `2d` (two 64-bit lanes) or `16b`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VectorArrangement {
    pub lanes: u8,
    pub lane_bits: u8,
}

impl VectorArrangement {
    /// Parse an arrangement suffix: a lane count followed by one of `b`, `h`,
    /// `s` or `d`. The arrangement must fit a 128-bit register.
    pub fn parse(suffix: &str) -> Option<Self> {
        let split = suffix.find(|ch: char| !ch.is_ascii_digit())?;
        let lanes = suffix[..split].parse::<u8>().ok()?;
        let lane_bits = match &suffix[split..] {
            "b" => 8,
            "h" => 16,
            "s" => 32,
            "d" => 64,
            _ => return None,
        };
        let active_bytes = lanes.checked_mul(lane_bits / 8)?;
        if active_bytes == 0 || active_bytes > 16 {
            return None;
        }
        Some(Self { lanes, lane_bits })
    }

    /// Bytes of the register the arrangement covers (1..=16).
    pub fn active_bytes(self) -> u8 {
        self.lanes * (self.lane_bits / 8)
    }
}

/// An intrinsic's name: its text plus the operation and arrangement parsed
/// from it.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct IntrinsicName {
    text: String,
    op: IntrinsicOp,
    arrangement: Option<VectorArrangement>,
}

impl IntrinsicName {
    pub fn new(text: impl Into<String>) -> Self {
        let text = text.into();
        let (base, suffix) = split_name(&text);
        let op = IntrinsicOp::from_base_name(base);
        let arrangement = suffix.and_then(VectorArrangement::parse);
        Self {
            text,
            op,
            arrangement,
        }
    }

    /// The full name as lifted, e.g. `"add.2d"`.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    pub fn op(&self) -> IntrinsicOp {
        self.op
    }

    /// The mnemonic without its arrangement, e.g. `"add"`.
    pub fn base(&self) -> &str {
        split_name(&self.text).0
    }

    /// The raw text after the first `.`, whether or not it is an arrangement.
    pub fn suffix(&self) -> Option<&str> {
        split_name(&self.text).1
    }

    pub fn arrangement(&self) -> Option<VectorArrangement> {
        self.arrangement
    }
}

fn split_name(text: &str) -> (&str, Option<&str>) {
    match text.split_once('.') {
        Some((base, suffix)) => (base, Some(suffix)),
        None => (text, None),
    }
}

impl Deref for IntrinsicName {
    type Target = str;

    fn deref(&self) -> &str {
        &self.text
    }
}

impl AsRef<str> for IntrinsicName {
    fn as_ref(&self) -> &str {
        &self.text
    }
}

/// Formats exactly as the underlying string, so `{:?}` output of IL is the
/// same as when names were plain `String`s.
impl fmt::Debug for IntrinsicName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.text, f)
    }
}

impl fmt::Display for IntrinsicName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

impl From<&str> for IntrinsicName {
    fn from(text: &str) -> Self {
        Self::new(text)
    }
}

impl From<String> for IntrinsicName {
    fn from(text: String) -> Self {
        Self::new(text)
    }
}

impl From<&String> for IntrinsicName {
    fn from(text: &String) -> Self {
        Self::new(text.as_str())
    }
}

impl From<IntrinsicName> for String {
    fn from(name: IntrinsicName) -> Self {
        name.text
    }
}

impl PartialEq<str> for IntrinsicName {
    fn eq(&self, other: &str) -> bool {
        self.text == other
    }
}

impl PartialEq<&str> for IntrinsicName {
    fn eq(&self, other: &&str) -> bool {
        self.text == *other
    }
}

impl PartialEq<String> for IntrinsicName {
    fn eq(&self, other: &String) -> bool {
        &self.text == other
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_op_and_arrangement() {
        let name = IntrinsicName::new("add.2d");
        assert_eq!(name.op(), IntrinsicOp::Add);
        assert_eq!(name.base(), "add");
        assert_eq!(name.suffix(), Some("2d"));
        assert_eq!(
            name.arrangement(),
            Some(VectorArrangement {
                lanes: 2,
                lane_bits: 64
            })
        );
        assert_eq!(name.arrangement().unwrap().active_bytes(), 16);
    }

    #[test]
    fn scalar_name_has_no_arrangement() {
        let name = IntrinsicName::new("movk");
        assert_eq!(name.op(), IntrinsicOp::Movk);
        assert_eq!(name.suffix(), None);
        assert_eq!(name.arrangement(), None);
    }

    #[test]
    fn unknown_mnemonic_is_other_but_keeps_its_text() {
        let name = IntrinsicName::new("tpidr_el0");
        assert_eq!(name.op(), IntrinsicOp::Other);
        assert_eq!(name, "tpidr_el0");
        assert_eq!(name.to_string(), "tpidr_el0");
    }

    #[test]
    fn rejects_arrangements_wider_than_a_register() {
        assert_eq!(VectorArrangement::parse("4d"), None);
        assert_eq!(VectorArrangement::parse("0b"), None);
        assert_eq!(VectorArrangement::parse("2x"), None);
        assert_eq!(VectorArrangement::parse("d"), None);
        assert_eq!(IntrinsicName::new("add.4d").arrangement(), None);
    }

    #[test]
    fn every_known_op_round_trips_through_its_mnemonic() {
        for op in IntrinsicOp::KNOWN {
            let base = op.base_name().expect("known op has a mnemonic");
            assert_eq!(IntrinsicOp::from_base_name(base), *op);
            assert_eq!(IntrinsicName::new(format!("{base}.16b")).op(), *op);
        }
        assert_eq!(IntrinsicOp::Other.base_name(), None);
    }

    #[test]
    fn debug_matches_plain_string() {
        let name = IntrinsicName::new("bif.8b");
        assert_eq!(format!("{name:?}"), format!("{:?}", "bif.8b"));
    }
}
