//! SIMD intrinsics that are not a plain lane-by-lane map: widening,
//! narrowing, permutes, table lookup, reductions, vector conversions and the
//! `ld1`/`st1` family.
//!
//! The arithmetic is in free functions over the 16 bytes of a register; the
//! `Executor` methods at the end read the operands and write the result.
//! Which lanes feed which is decided by `aeonil::simd`, shared with the JIT.

use aeonil::simd::{permute_source, widen_spec, WidenMode};
use aeonil::{Expr, IntrinsicName, IntrinsicOp, Reg, Stmt, VectorArrangement};

use super::{
    clear_all_simd_aliases, default_nan_if_generated, expr_reg_operand, float_to_int_mode,
    panic_on_unsupported_expr, propagated_nan, round_float, simd_index, vector_bytes_from_value,
    vector_dup, vector_operand_bytes, BlockStop, Executor, FloatBinary, Value,
};

type Bytes = [u8; 16];

const FULL: VectorArrangement = VectorArrangement {
    lanes: 16,
    lane_bits: 8,
};

fn lane(bytes: &Bytes, index: usize, lane_bytes: usize) -> u64 {
    let mut buf = [0u8; 8];
    buf[..lane_bytes].copy_from_slice(&bytes[index * lane_bytes..(index + 1) * lane_bytes]);
    u64::from_le_bytes(buf)
}

fn set_lane(bytes: &mut Bytes, index: usize, lane_bytes: usize, value: u64) {
    bytes[index * lane_bytes..(index + 1) * lane_bytes]
        .copy_from_slice(&value.to_le_bytes()[..lane_bytes]);
}

fn extend(value: u64, bits: u8, signed: bool) -> u64 {
    if signed && bits < 64 {
        let unused = 64 - u32::from(bits);
        (((value << unused) as i64) >> unused) as u64
    } else {
        value
    }
}

/// `arrangement` is the destination's; the sources have lanes half as wide.
fn widen(
    op: IntrinsicOp,
    arrangement: VectorArrangement,
    old_dst: &Bytes,
    src: &Bytes,
    factor: Option<&Bytes>,
    shift: u32,
) -> Option<Bytes> {
    let spec = widen_spec(op)?;
    if arrangement.lane_bits < 16 || arrangement.active_bytes() != 16 {
        return None;
    }
    let wide = usize::from(arrangement.lane_bits / 8);
    let narrow = wide / 2;
    let narrow_bits = arrangement.lane_bits / 2;
    let lanes = usize::from(arrangement.lanes);
    let first = if spec.high { lanes } else { 0 };

    let mut out = [0u8; 16];
    for index in 0..lanes {
        let value = extend(lane(src, first + index, narrow), narrow_bits, spec.signed);
        let value = match spec.mode {
            WidenMode::Shift => value.checked_shl(shift).unwrap_or(0),
            mode => {
                let factor = extend(lane(factor?, first + index, narrow), narrow_bits, spec.signed);
                let product = value.wrapping_mul(factor);
                let acc = lane(old_dst, index, wide);
                match mode {
                    WidenMode::MulAdd => acc.wrapping_add(product),
                    WidenMode::MulSub => acc.wrapping_sub(product),
                    _ => product,
                }
            }
        };
        set_lane(&mut out, index, wide, value);
    }
    Some(out)
}

/// `xtn` fills the low half and clears the high half; `xtn2` fills the high
/// half and keeps the low half of the destination.
fn narrow(arrangement: VectorArrangement, old_dst: &Bytes, src: &Bytes, high: bool) -> Option<Bytes> {
    if arrangement.lane_bits > 32 {
        return None;
    }
    let bytes = usize::from(arrangement.lane_bits / 8);
    let count = 8 / bytes;
    let mut out = if high { *old_dst } else { [0u8; 16] };
    if high {
        out[8..].fill(0);
    }
    for index in 0..count {
        let target = index + if high { count } else { 0 };
        set_lane(&mut out, target, bytes, lane(src, index, bytes * 2));
    }
    Some(out)
}

fn permute(
    op: IntrinsicOp,
    arrangement: VectorArrangement,
    first: &Bytes,
    second: &Bytes,
    imm: u8,
) -> Option<Bytes> {
    let bytes = usize::from(arrangement.lane_bits / 8);
    let mut out = [0u8; 16];
    for index in 0..arrangement.lanes {
        let (from_second, source) = permute_source(op, arrangement.lanes, index, imm)?;
        let from = if from_second { second } else { first };
        set_lane(
            &mut out,
            usize::from(index),
            bytes,
            lane(from, usize::from(source), bytes),
        );
    }
    Some(out)
}

/// An index past the table gives 0 (`tbl`) or the old destination byte
/// (`tbx`, when `old_dst` is given).
fn table_lookup(
    arrangement: VectorArrangement,
    table: &[Bytes],
    indices: &Bytes,
    old_dst: Option<&Bytes>,
) -> Bytes {
    let mut out = [0u8; 16];
    for index in 0..usize::from(arrangement.lanes) {
        let wanted = usize::from(indices[index]);
        out[index] = match table.get(wanted / 16) {
            Some(register) => register[wanted % 16],
            None => old_dst.map_or(0, |old| old[index]),
        };
    }
    out
}

/// The reduced value and its width in bits.
fn reduce(op: IntrinsicOp, arrangement: VectorArrangement, src: &Bytes) -> Option<(u64, u8)> {
    let bits = arrangement.lane_bits;
    let bytes = usize::from(bits / 8);
    let signed = matches!(
        op,
        IntrinsicOp::Smaxv | IntrinsicOp::Sminv | IntrinsicOp::Saddlv
    );
    let long = matches!(op, IntrinsicOp::Uaddlv | IntrinsicOp::Saddlv);
    let result_bits = if long { bits.checked_mul(2)? } else { bits };
    if result_bits > 64 {
        return None;
    }
    let mut lanes =
        (0..usize::from(arrangement.lanes)).map(|index| extend(lane(src, index, bytes), bits, signed));
    let first = lanes.next()?;
    let value = lanes.fold(first, |acc, value| match op {
        IntrinsicOp::Umaxv => acc.max(value),
        IntrinsicOp::Uminv => acc.min(value),
        IntrinsicOp::Smaxv => (acc as i64).max(value as i64) as u64,
        IntrinsicOp::Sminv => (acc as i64).min(value as i64) as u64,
        _ => acc.wrapping_add(value),
    });
    Some((value, result_bits))
}

fn pairwise_add(arrangement: VectorArrangement, first: &Bytes, second: &Bytes) -> Bytes {
    let bytes = usize::from(arrangement.lane_bits / 8);
    let lanes = usize::from(arrangement.lanes);
    let half = lanes / 2;
    let mut out = [0u8; 16];
    for index in 0..lanes {
        let source = if index < half { first } else { second };
        let pair = 2 * (index % half);
        let sum = lane(source, pair, bytes).wrapping_add(lane(source, pair + 1, bytes));
        set_lane(&mut out, index, bytes, sum);
    }
    out
}

fn decode_float(raw: u64, bits: u32) -> f64 {
    if bits == 32 {
        f64::from(f32::from_bits(raw as u32))
    } else {
        f64::from_bits(raw)
    }
}

fn encode_float_bits(value: f64, bits: u32) -> u64 {
    if bits == 32 {
        u64::from((value as f32).to_bits())
    } else {
        value.to_bits()
    }
}

/// One lane of a vector `fadd`/`fsub`/`fmul`/`fdiv`. `bits` must be 32 or
/// 64; half-precision lanes are not modelled.
pub(super) fn float_lane(op: FloatBinary, lhs: u64, rhs: u64, bits: u32) -> u64 {
    let (lhs, rhs) = (decode_float(lhs, bits), decode_float(rhs, bits));
    if let Some(nan) = propagated_nan(lhs, rhs) {
        return encode_float_bits(nan, bits);
    }
    let result = match op {
        FloatBinary::Add => lhs + rhs,
        FloatBinary::Sub => lhs - rhs,
        FloatBinary::Mul => lhs * rhs,
        FloatBinary::Div => lhs / rhs,
        FloatBinary::Max => lhs.max(rhs),
        FloatBinary::Min => lhs.min(rhs),
    };
    encode_float_bits(default_nan_if_generated(result, false), bits)
}

/// One lane of a vector int-to-float or float-to-int conversion.
fn convert_lane(op: IntrinsicOp, raw: u64, bits: u32) -> Option<u64> {
    let narrow = bits == 32;
    Some(match op {
        IntrinsicOp::Scvtf if narrow => u64::from((raw as u32 as i32 as f32).to_bits()),
        IntrinsicOp::Scvtf => (raw as i64 as f64).to_bits(),
        IntrinsicOp::Ucvtf if narrow => u64::from((raw as u32 as f32).to_bits()),
        IntrinsicOp::Ucvtf => (raw as f64).to_bits(),
        _ => {
            let (rounding, signed) = float_to_int_mode(op)?;
            let rounded = round_float(decode_float(raw, bits), rounding);
            // Rust's float-to-int casts saturate and map NaN to 0, as
            // AArch64 does.
            match (signed, narrow) {
                (true, true) => u64::from(rounded as i32 as u32),
                (true, false) => rounded as i64 as u64,
                (false, true) => u64::from(rounded as u32),
                (false, false) => rounded as u64,
            }
        }
    })
}

/// The registers of a `multi_reg` operand such as `{v0.16b, v1.16b}`.
fn register_list(expr: &Expr) -> Option<Vec<Reg>> {
    let Expr::Intrinsic { name, operands } = expr else {
        return None;
    };
    if name.op() != IntrinsicOp::MultiReg || operands.is_empty() {
        return None;
    }
    operands
        .iter()
        .map(|operand| expr_reg_operand(operand).filter(|reg| simd_index(reg).is_some()))
        .collect()
}

impl Executor<'_> {
    /// The 16 bytes of a SIMD register operand, or `None` if unknown.
    fn vector_source(&mut self, expr: &Expr) -> Option<Bytes> {
        let value = self.eval_expr(expr);
        vector_operand_bytes(expr, value, FULL)
    }

    fn write_vector(&mut self, dst: &Reg, value: Option<Bytes>) {
        let Some(index) = simd_index(dst) else {
            return;
        };
        let value = match value {
            Some(bytes) => Value::U128(u128::from_le_bytes(bytes)),
            None => Value::Unknown,
        };
        clear_all_simd_aliases(&mut self.registers, index);
        self.registers.insert(Reg::V(index), value);
    }

    /// Runs one of this module's statement intrinsics, operands
    /// `[dst, sources...]`. Returns `None` if `name` is not one of them,
    /// otherwise whether execution should continue.
    pub(super) fn execute_vector_intrinsic(
        &mut self,
        name: &IntrinsicName,
        operands: &[Expr],
    ) -> Option<bool> {
        let op = name.op();
        if matches!(op, IntrinsicOp::Ld1 | IntrinsicOp::St1 | IntrinsicOp::Ld1r) {
            return Some(self.execute_simd_memory_intrinsic(name, operands));
        }
        let handled = widen_spec(op).is_some()
            || matches!(
                op,
                IntrinsicOp::Xtn
                    | IntrinsicOp::Xtn2
                    | IntrinsicOp::Zip1
                    | IntrinsicOp::Zip2
                    | IntrinsicOp::Uzp1
                    | IntrinsicOp::Uzp2
                    | IntrinsicOp::Trn1
                    | IntrinsicOp::Trn2
                    | IntrinsicOp::Ext
                    | IntrinsicOp::Tbl
                    | IntrinsicOp::Tbx
                    | IntrinsicOp::Addv
                    | IntrinsicOp::Umaxv
                    | IntrinsicOp::Uminv
                    | IntrinsicOp::Smaxv
                    | IntrinsicOp::Sminv
                    | IntrinsicOp::Uaddlv
                    | IntrinsicOp::Saddlv
                    | IntrinsicOp::Addp
            );
        if !handled {
            return None;
        }

        let Some(dst) = operands
            .first()
            .and_then(expr_reg_operand)
            .filter(|reg| simd_index(reg).is_some())
        else {
            panic!("aeon emulation expected a SIMD destination for `{name}`");
        };
        let Some(arrangement) = name.arrangement() else {
            panic!("aeon emulation is missing SIMD arrangement for `{name}`");
        };
        let result = self.eval_vector_intrinsic(op, arrangement, operands);
        self.write_vector(&dst, result);
        Some(true)
    }

    fn eval_vector_intrinsic(
        &mut self,
        op: IntrinsicOp,
        arrangement: VectorArrangement,
        operands: &[Expr],
    ) -> Option<Bytes> {
        let source = |executor: &mut Self, index: usize| {
            let expr = operands.get(index)?;
            executor.vector_source(expr)
        };
        if let Some(spec) = widen_spec(op) {
            let old_dst = source(self, 0);
            let src = source(self, 1)?;
            if spec.mode == WidenMode::Shift {
                let shift = match operands.get(2) {
                    None => 0,
                    Some(expr) => u32::try_from(self.eval_expr(expr).as_u64()?).ok()?,
                };
                return widen(op, arrangement, &[0; 16], &src, None, shift);
            }
            // The other factor is a vector or one lane used for every lane.
            let narrow = VectorArrangement {
                lanes: arrangement.lanes.checked_mul(2)?,
                lane_bits: arrangement.lane_bits / 2,
            };
            let expr = operands.get(2)?;
            let value = self.eval_expr(expr);
            let factor = vector_operand_bytes(expr, value, narrow)?;
            let old_dst = if spec.mode == WidenMode::Mul {
                [0; 16]
            } else {
                old_dst?
            };
            return widen(op, arrangement, &old_dst, &src, Some(&factor), 0);
        }
        match op {
            IntrinsicOp::Xtn => narrow(arrangement, &[0; 16], &source(self, 1)?, false),
            IntrinsicOp::Xtn2 => {
                let old_dst = source(self, 0)?;
                narrow(arrangement, &old_dst, &source(self, 1)?, true)
            }
            IntrinsicOp::Zip1
            | IntrinsicOp::Zip2
            | IntrinsicOp::Uzp1
            | IntrinsicOp::Uzp2
            | IntrinsicOp::Trn1
            | IntrinsicOp::Trn2
            | IntrinsicOp::Ext => {
                let first = source(self, 1)?;
                let second = source(self, 2)?;
                let imm = match operands.get(3) {
                    None => 0,
                    Some(expr) => u8::try_from(self.eval_expr(expr).as_u64()?).ok()?,
                };
                permute(op, arrangement, &first, &second, imm)
            }
            IntrinsicOp::Tbl | IntrinsicOp::Tbx => {
                let registers = register_list(operands.get(1)?)?;
                let table: Option<Vec<Bytes>> = registers
                    .into_iter()
                    .map(|reg| self.vector_source(&Expr::Reg(reg)))
                    .collect();
                let indices = source(self, 2)?;
                let old_dst = if op == IntrinsicOp::Tbx {
                    Some(source(self, 0)?)
                } else {
                    None
                };
                Some(table_lookup(arrangement, &table?, &indices, old_dst.as_ref()))
            }
            IntrinsicOp::Addp if operands.len() == 3 => {
                let first = source(self, 1)?;
                let second = source(self, 2)?;
                Some(pairwise_add(arrangement, &first, &second))
            }
            _ => {
                let (value, bits) = reduce(op, arrangement, &source(self, 1)?)?;
                let mut out = [0u8; 16];
                set_lane(&mut out, 0, usize::from(bits / 8), value);
                Some(out)
            }
        }
    }

    /// `scvtf.2d`, `fcvtzs.4s` and the like: an expression intrinsic whose
    /// one operand is converted lane by lane.
    pub(super) fn eval_vector_conversion(
        &mut self,
        expr: &Expr,
        name: &IntrinsicName,
        operand: &Expr,
    ) -> Value {
        let op = name.op();
        let arrangement = match name.arrangement() {
            Some(arrangement) if matches!(arrangement.lane_bits, 32 | 64) => arrangement,
            _ => panic_on_unsupported_expr(expr),
        };
        if !matches!(op, IntrinsicOp::Scvtf | IntrinsicOp::Ucvtf) && float_to_int_mode(op).is_none() {
            panic_on_unsupported_expr(expr);
        }
        let Some(source) = self.vector_source(operand) else {
            return Value::Unknown;
        };
        let bytes = usize::from(arrangement.lane_bits / 8);
        let mut out = [0u8; 16];
        for index in 0..usize::from(arrangement.lanes) {
            let raw = lane(&source, index, bytes);
            match convert_lane(op, raw, u32::from(arrangement.lane_bits)) {
                Some(value) => set_lane(&mut out, index, bytes, value),
                None => return Value::Unknown,
            }
        }
        Value::U128(u128::from_le_bytes(out))
    }

    /// `ld1`, `st1` and `ld1r`, operands `[{registers}, base]` or
    /// `[{registers}, base, post_index]`. Consecutive registers use
    /// consecutive memory. Returns whether execution should continue.
    fn execute_simd_memory_intrinsic(&mut self, name: &IntrinsicName, operands: &[Expr]) -> bool {
        let op = name.op();
        let Some(arrangement) = name.arrangement() else {
            panic!("aeon emulation is missing SIMD arrangement for `{name}`");
        };
        let (Some(registers), Some(base)) =
            (operands.first().and_then(register_list), operands.get(1))
        else {
            panic!("aeon emulation expected a register list and a base for `{name}`");
        };
        let size = if op == IntrinsicOp::Ld1r {
            arrangement.lane_bits / 8
        } else {
            arrangement.active_bytes()
        };

        for (position, reg) in registers.into_iter().enumerate() {
            let addr = match position {
                0 => base.clone(),
                _ => Expr::Add(
                    Box::new(base.clone()),
                    Box::new(Expr::Imm(position as u64 * u64::from(size))),
                ),
            };
            if op == IntrinsicOp::St1 {
                let Some(index) = simd_index(&reg) else {
                    continue;
                };
                let source = if size == 16 {
                    Reg::V(index)
                } else {
                    Reg::D(index)
                };
                let store = Stmt::Store {
                    addr,
                    value: Expr::Reg(source),
                    size,
                };
                if !self.execute_stmt(&store) {
                    return false;
                }
                continue;
            }
            let loaded = self.eval_expr(&Expr::Load {
                addr: Box::new(addr),
                size,
            });
            if !matches!(self.stop, BlockStop::Completed) {
                return false;
            }
            let value = if op == IntrinsicOp::Ld1r {
                vector_dup(loaded, arrangement).map(u128::to_le_bytes)
            } else {
                vector_bytes_from_value(&loaded).map(|mut bytes| {
                    bytes[usize::from(size)..].fill(0);
                    bytes
                })
            };
            self.write_vector(&reg, value);
        }

        match (operands.get(2), expr_reg_operand(base)) {
            (Some(post_index), Some(base_reg)) => self.execute_stmt(&Stmt::Assign {
                dst: base_reg.clone(),
                src: Expr::Add(Box::new(Expr::Reg(base_reg)), Box::new(post_index.clone())),
            }),
            _ => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arrangement(lanes: u8, lane_bits: u8) -> VectorArrangement {
        VectorArrangement { lanes, lane_bits }
    }

    fn counting() -> Bytes {
        std::array::from_fn(|index| index as u8)
    }

    #[test]
    fn widen_takes_the_named_half_and_extends() {
        let mut src = [0u8; 16];
        src[0] = 0x80;
        src[8] = 0xff;
        let low = widen(IntrinsicOp::Sxtl, arrangement(8, 16), &[0; 16], &src, None, 0).unwrap();
        assert_eq!(&low[..2], &[0x80, 0xff]);
        let high = widen(IntrinsicOp::Uxtl2, arrangement(8, 16), &[0; 16], &src, None, 4).unwrap();
        assert_eq!(&high[..2], &[0xf0, 0x0f]);
    }

    #[test]
    fn narrow_keeps_or_clears_the_other_half() {
        let src = counting();
        let old = [0xaa; 16];
        let low = narrow(arrangement(8, 8), &old, &src, false).unwrap();
        assert_eq!(low, [0, 2, 4, 6, 8, 10, 12, 14, 0, 0, 0, 0, 0, 0, 0, 0]);
        let high = narrow(arrangement(16, 8), &old, &src, true).unwrap();
        assert_eq!(&high[..8], &[0xaa; 8]);
        assert_eq!(&high[8..], &[0, 2, 4, 6, 8, 10, 12, 14]);
    }

    #[test]
    fn table_lookup_handles_out_of_range_indices() {
        let table = [counting().map(|byte| byte + 0x10)];
        let mut indices = [0u8; 16];
        indices[1] = 15;
        indices[2] = 16;
        let old = [0x77; 16];
        let tbl = table_lookup(arrangement(16, 8), &table, &indices, None);
        assert_eq!(&tbl[..3], &[0x10, 0x1f, 0]);
        let tbx = table_lookup(arrangement(16, 8), &table, &indices, Some(&old));
        assert_eq!(&tbx[..3], &[0x10, 0x1f, 0x77]);
    }

    #[test]
    fn reductions_report_their_result_width() {
        let src = [0xff; 16];
        assert_eq!(
            reduce(IntrinsicOp::Uaddlv, arrangement(16, 8), &src),
            Some((16 * 0xff, 16))
        );
        assert_eq!(
            reduce(IntrinsicOp::Addv, arrangement(16, 8), &src).map(|(value, bits)| (value & 0xff, bits)),
            Some((0xf0, 8))
        );
        assert_eq!(
            reduce(IntrinsicOp::Smaxv, arrangement(16, 8), &counting())
                .map(|(value, bits)| (value & 0xff, bits)),
            Some((15, 8))
        );
    }
}
