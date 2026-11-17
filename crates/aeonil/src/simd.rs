//! Lane-mapping rules for SIMD intrinsics.
//!
//! These describe which source lanes a result lane is computed from. They
//! hold no arithmetic, so every backend can share them and none can disagree
//! about, say, which lanes `uzp2` selects.

use crate::IntrinsicOp;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WidenMode {
    /// `[dst, src]` or `[dst, src, #shift]`: extend, then shift left.
    Shift,
    /// `[dst, a, b]`: extend both, multiply.
    Mul,
    /// As `Mul`, added to the destination lane.
    MulAdd,
    /// As `Mul`, subtracted from the destination lane.
    MulSub,
}

/// A widening operation: each result lane is computed from a source lane of
/// half its width, taken from the low or the high half of the source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WidenSpec {
    pub signed: bool,
    pub high: bool,
    pub mode: WidenMode,
}

pub fn widen_spec(op: IntrinsicOp) -> Option<WidenSpec> {
    use WidenMode::{Mul, MulAdd, MulSub, Shift};
    let (signed, high, mode) = match op {
        IntrinsicOp::Uxtl | IntrinsicOp::Ushll => (false, false, Shift),
        IntrinsicOp::Uxtl2 | IntrinsicOp::Ushll2 => (false, true, Shift),
        IntrinsicOp::Sxtl | IntrinsicOp::Sshll => (true, false, Shift),
        IntrinsicOp::Sxtl2 | IntrinsicOp::Sshll2 => (true, true, Shift),
        IntrinsicOp::Umull => (false, false, Mul),
        IntrinsicOp::Umull2 => (false, true, Mul),
        IntrinsicOp::Smull => (true, false, Mul),
        IntrinsicOp::Smull2 => (true, true, Mul),
        IntrinsicOp::Umlal => (false, false, MulAdd),
        IntrinsicOp::Umlal2 => (false, true, MulAdd),
        IntrinsicOp::Smlal => (true, false, MulAdd),
        IntrinsicOp::Smlal2 => (true, true, MulAdd),
        IntrinsicOp::Umlsl => (false, false, MulSub),
        IntrinsicOp::Umlsl2 => (false, true, MulSub),
        IntrinsicOp::Smlsl => (true, false, MulSub),
        IntrinsicOp::Smlsl2 => (true, true, MulSub),
        _ => return None,
    };
    Some(WidenSpec { signed, high, mode })
}

/// Where lane `lane` of a permute's result comes from: whether it is the
/// second source, and which lane of it. `lanes` is the arrangement's lane
/// count and `imm` the offset of `ext`.
pub fn permute_source(op: IntrinsicOp, lanes: u8, lane: u8, imm: u8) -> Option<(bool, u8)> {
    if lanes < 2 || lane >= lanes {
        return None;
    }
    let half = lanes / 2;
    let odd = lane % 2 == 1;
    Some(match op {
        IntrinsicOp::Zip1 => (odd, lane / 2),
        IntrinsicOp::Zip2 => (odd, half + lane / 2),
        IntrinsicOp::Uzp1 => (lane >= half, 2 * (lane % half)),
        IntrinsicOp::Uzp2 => (lane >= half, 2 * (lane % half) + 1),
        IntrinsicOp::Trn1 => (odd, lane - u8::from(odd)),
        IntrinsicOp::Trn2 => (odd, lane + 1 - u8::from(odd)),
        IntrinsicOp::Ext => {
            let index = lane.checked_add(imm)?;
            if index < lanes {
                (false, index)
            } else if index - lanes < lanes {
                (true, index - lanes)
            } else {
                return None;
            }
        }
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sources(op: IntrinsicOp, lanes: u8, imm: u8) -> Vec<(bool, u8)> {
        (0..lanes)
            .map(|lane| permute_source(op, lanes, lane, imm).unwrap())
            .collect()
    }

    #[test]
    fn permutes_select_the_documented_lanes() {
        let (a, b) = (false, true);
        assert_eq!(
            sources(IntrinsicOp::Zip1, 4, 0),
            [(a, 0), (b, 0), (a, 1), (b, 1)]
        );
        assert_eq!(
            sources(IntrinsicOp::Zip2, 4, 0),
            [(a, 2), (b, 2), (a, 3), (b, 3)]
        );
        assert_eq!(
            sources(IntrinsicOp::Uzp1, 4, 0),
            [(a, 0), (a, 2), (b, 0), (b, 2)]
        );
        assert_eq!(
            sources(IntrinsicOp::Uzp2, 4, 0),
            [(a, 1), (a, 3), (b, 1), (b, 3)]
        );
        assert_eq!(
            sources(IntrinsicOp::Trn1, 4, 0),
            [(a, 0), (b, 0), (a, 2), (b, 2)]
        );
        assert_eq!(
            sources(IntrinsicOp::Trn2, 4, 0),
            [(a, 1), (b, 1), (a, 3), (b, 3)]
        );
        assert_eq!(
            sources(IntrinsicOp::Ext, 4, 3),
            [(a, 3), (b, 0), (b, 1), (b, 2)]
        );
        assert_eq!(permute_source(IntrinsicOp::Ext, 4, 0, 200), None);
        assert_eq!(permute_source(IntrinsicOp::Add, 4, 0, 0), None);
    }

    #[test]
    fn widening_ops_name_their_half_and_signedness() {
        let spec = widen_spec(IntrinsicOp::Smlsl2).unwrap();
        assert!(spec.signed && spec.high);
        assert_eq!(spec.mode, WidenMode::MulSub);
        let spec = widen_spec(IntrinsicOp::Uxtl).unwrap();
        assert!(!spec.signed && !spec.high);
        assert_eq!(spec.mode, WidenMode::Shift);
        assert_eq!(widen_spec(IntrinsicOp::Add), None);
    }
}
