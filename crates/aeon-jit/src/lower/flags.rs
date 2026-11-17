use crate::imports::Imports;
use crate::lower::LoweringState;
use crate::JitError;
use aeonil::{Condition, Expr};
use cranelift_codegen::ir::condcodes::{FloatCC, IntCC};
use cranelift_codegen::ir::types::{self};
use cranelift_codegen::ir::{InstBuilder, Type, Value};
use cranelift_frontend::FunctionBuilder;
use cranelift_module::Module;

impl LoweringState {
    pub(crate) fn lower_compare_condition(
        &mut self,
        module: &mut impl Module,
        builder: &mut FunctionBuilder<'_>,
        imports: &Imports,
        cond: Condition,
        lhs: &Expr,
        rhs: &Expr,
    ) -> Result<Value, JitError> {
        let inferred = self
            .infer_expr_type(lhs)
            .or_else(|| self.infer_expr_type(rhs));
        if matches!(inferred, Some(types::F32 | types::F64)) {
            let ty = self.resolve_float_type(inferred, None)?;
            let lhs = self.lower_expr(module, builder, imports, lhs, Some(ty))?;
            let rhs = self.lower_expr(module, builder, imports, rhs, Some(ty))?;
            let lhs = self.coerce_float(builder, lhs, ty)?;
            let rhs = self.coerce_float(builder, rhs, ty)?;
            let cc = self.float_cc(cond)?;
            Ok(builder.ins().fcmp(cc, lhs.value, rhs.value))
        } else {
            let ty = self.resolve_int_type(inferred, None)?;
            let lhs = self.lower_expr(module, builder, imports, lhs, Some(ty))?;
            let rhs = self.lower_expr(module, builder, imports, rhs, Some(ty))?;
            let lhs = self.coerce_int(builder, lhs, ty)?;
            let rhs = self.coerce_int(builder, rhs, ty)?;
            match self.int_cc(cond) {
                Some(cc) => Ok(builder.ins().icmp(cc, lhs.value, rhs.value)),
                None => {
                    let flags = self.compute_sub_flags(builder, lhs.value, rhs.value, ty)?;
                    self.eval_flags_condition(builder, flags, cond)
                }
            }
        }
    }

    pub(crate) fn lower_flags_expr(
        &mut self,
        module: &mut impl Module,
        builder: &mut FunctionBuilder<'_>,
        imports: &Imports,
        expr: &Expr,
    ) -> Result<Value, JitError> {
        if let Some(ty) = self.infer_expr_type(expr).filter(|ty| ty.is_float()) {
            // The lifter writes FCMP as `SetFlags(FSub(a, b))`. The flags are
            // those of the comparison, not of the difference's bit pattern.
            let Expr::FSub(lhs, rhs) = expr else {
                return Err(JitError::UnsupportedExpr("float flags expression"));
            };
            let lhs = self.lower_expr(module, builder, imports, lhs, Some(ty))?;
            let lhs = self.coerce_float(builder, lhs, ty)?;
            let rhs = self.lower_expr(module, builder, imports, rhs, Some(ty))?;
            let rhs = self.coerce_float(builder, rhs, ty)?;
            return Ok(self.compute_fcmp_flags(builder, lhs.value, rhs.value));
        }
        match expr {
            Expr::Imm(bits) => Ok(builder.ins().iconst(types::I64, *bits as i64)),
            Expr::CondSelect {
                cond,
                if_true,
                if_false,
            } => {
                let flags = self.read_flags(builder)?;
                let cond = self.eval_flags_condition(builder, flags, *cond)?;
                let if_true = self.lower_flags_expr(module, builder, imports, if_true)?;
                let if_false = self.lower_flags_expr(module, builder, imports, if_false)?;
                Ok(builder.ins().select(cond, if_true, if_false))
            }
            Expr::Add(lhs, rhs) => {
                let ty = self.resolve_int_type(None, Some(expr))?;
                let lhs = self.lower_expr(module, builder, imports, lhs, Some(ty))?;
                let rhs = self.lower_expr(module, builder, imports, rhs, Some(ty))?;
                let lhs = self.coerce_int(builder, lhs, ty)?;
                let rhs = self.coerce_int(builder, rhs, ty)?;
                self.compute_add_flags(builder, lhs.value, rhs.value, ty)
            }
            Expr::Sub(lhs, rhs) => {
                let ty = self.resolve_int_type(None, Some(expr))?;
                let lhs = self.lower_expr(module, builder, imports, lhs, Some(ty))?;
                let rhs = self.lower_expr(module, builder, imports, rhs, Some(ty))?;
                let lhs = self.coerce_int(builder, lhs, ty)?;
                let rhs = self.coerce_int(builder, rhs, ty)?;
                self.compute_sub_flags(builder, lhs.value, rhs.value, ty)
            }
            Expr::And(lhs, rhs) => {
                let ty = self.resolve_int_type(None, Some(expr))?;
                let lhs = self.lower_expr(module, builder, imports, lhs, Some(ty))?;
                let rhs = self.lower_expr(module, builder, imports, rhs, Some(ty))?;
                let lhs = self.coerce_int(builder, lhs, ty)?;
                let rhs = self.coerce_int(builder, rhs, ty)?;
                let result = builder.ins().band(lhs.value, rhs.value);
                self.pack_nzcv(builder, result, ty, None, None)
            }
            _ => {
                let ty = self.resolve_int_type(None, Some(expr))?;
                let value = self.lower_expr(module, builder, imports, expr, Some(ty))?;
                let value = self.coerce_int(builder, value, ty)?;
                self.pack_nzcv(builder, value.value, ty, None, None)
            }
        }
    }

    /// NZCV after an AArch64 floating-point compare: less 1000, equal 0110,
    /// greater 0010, unordered 0011.
    pub(crate) fn compute_fcmp_flags(
        &mut self,
        builder: &mut FunctionBuilder<'_>,
        lhs: Value,
        rhs: Value,
    ) -> Value {
        let less = builder.ins().fcmp(FloatCC::LessThan, lhs, rhs);
        let equal = builder.ins().fcmp(FloatCC::Equal, lhs, rhs);
        let greater = builder.ins().fcmp(FloatCC::GreaterThan, lhs, rhs);
        let if_less = builder.ins().iconst(types::I64, 0b1000);
        let if_equal = builder.ins().iconst(types::I64, 0b0110);
        let if_greater = builder.ins().iconst(types::I64, 0b0010);
        let unordered = builder.ins().iconst(types::I64, 0b0011);
        let flags = builder.ins().select(greater, if_greater, unordered);
        let flags = builder.ins().select(equal, if_equal, flags);
        builder.ins().select(less, if_less, flags)
    }

    /// `lhs + rhs + carry_in` with its NZCV. ADCS passes the operands as they
    /// are; SBCS and NGCS pass the inverted subtrahend.
    pub(crate) fn compute_add_with_carry(
        &mut self,
        builder: &mut FunctionBuilder<'_>,
        lhs: Value,
        rhs: Value,
        ty: Type,
    ) -> Result<(Value, Value), JitError> {
        let flags = self.read_flags(builder)?;
        let carry_in = self.extract_flag(builder, flags, 1);
        let carry_in = builder.ins().uextend(ty, carry_in);
        let partial = builder.ins().iadd(lhs, rhs);
        let carry_a = builder.ins().icmp(IntCC::UnsignedLessThan, partial, lhs);
        let result = builder.ins().iadd(partial, carry_in);
        let carry_b = builder.ins().icmp(IntCC::UnsignedLessThan, result, partial);
        let carry = builder.ins().bor(carry_a, carry_b);
        // Signed overflow: both operands differ in sign from the result.
        let lhs_changed = builder.ins().bxor(lhs, result);
        let rhs_changed = builder.ins().bxor(rhs, result);
        let both_changed = builder.ins().band(lhs_changed, rhs_changed);
        let overflow = self.is_negative(builder, both_changed, ty)?;
        let flags = self.pack_nzcv(builder, result, ty, Some(carry), Some(overflow))?;
        Ok((result, flags))
    }

    pub(crate) fn compute_add_flags(
        &mut self,
        builder: &mut FunctionBuilder<'_>,
        lhs: Value,
        rhs: Value,
        ty: Type,
    ) -> Result<Value, JitError> {
        let result = builder.ins().iadd(lhs, rhs);
        let carry = builder.ins().icmp(IntCC::UnsignedLessThan, result, lhs);
        let lhs_neg = self.is_negative(builder, lhs, ty)?;
        let rhs_neg = self.is_negative(builder, rhs, ty)?;
        let res_neg = self.is_negative(builder, result, ty)?;
        let same_sign = builder.ins().icmp(IntCC::Equal, lhs_neg, rhs_neg);
        let sign_changed = builder.ins().icmp(IntCC::NotEqual, lhs_neg, res_neg);
        let overflow = builder.ins().band(same_sign, sign_changed);
        self.pack_nzcv(builder, result, ty, Some(carry), Some(overflow))
    }

    pub(crate) fn compute_sub_flags(
        &mut self,
        builder: &mut FunctionBuilder<'_>,
        lhs: Value,
        rhs: Value,
        ty: Type,
    ) -> Result<Value, JitError> {
        let result = builder.ins().isub(lhs, rhs);
        let carry = builder
            .ins()
            .icmp(IntCC::UnsignedGreaterThanOrEqual, lhs, rhs);
        let lhs_neg = self.is_negative(builder, lhs, ty)?;
        let rhs_neg = self.is_negative(builder, rhs, ty)?;
        let res_neg = self.is_negative(builder, result, ty)?;
        let operands_differ = builder.ins().icmp(IntCC::NotEqual, lhs_neg, rhs_neg);
        let sign_changed = builder.ins().icmp(IntCC::NotEqual, lhs_neg, res_neg);
        let overflow = builder.ins().band(operands_differ, sign_changed);
        self.pack_nzcv(builder, result, ty, Some(carry), Some(overflow))
    }

    pub(crate) fn pack_nzcv(
        &mut self,
        builder: &mut FunctionBuilder<'_>,
        result: Value,
        ty: Type,
        carry: Option<Value>,
        overflow: Option<Value>,
    ) -> Result<Value, JitError> {
        let n = self.is_negative(builder, result, ty)?;
        let zero = self.zero_for_type(builder, ty)?;
        let z = builder.ins().icmp(IntCC::Equal, result, zero);
        let c = carry.unwrap_or_else(|| builder.ins().iconst(types::I8, 0));
        let v = overflow.unwrap_or_else(|| builder.ins().iconst(types::I8, 0));
        let n = builder.ins().uextend(types::I64, n);
        let z = builder.ins().uextend(types::I64, z);
        let c = builder.ins().uextend(types::I64, c);
        let v = builder.ins().uextend(types::I64, v);
        let n = builder.ins().ishl_imm(n, 3);
        let z = builder.ins().ishl_imm(z, 2);
        let c = builder.ins().ishl_imm(c, 1);
        let nz = builder.ins().bor(n, z);
        let cv = builder.ins().bor(c, v);
        Ok(builder.ins().bor(nz, cv))
    }

    pub(crate) fn eval_flags_condition(
        &mut self,
        builder: &mut FunctionBuilder<'_>,
        flags: Value,
        cond: Condition,
    ) -> Result<Value, JitError> {
        let n = self.extract_flag(builder, flags, 3);
        let z = self.extract_flag(builder, flags, 2);
        let c = self.extract_flag(builder, flags, 1);
        let v = self.extract_flag(builder, flags, 0);
        let one = builder.ins().iconst(types::I8, 1);
        let zero = builder.ins().iconst(types::I8, 0);
        let not = |b: &mut FunctionBuilder<'_>, value: Value| b.ins().bxor(value, one);
        Ok(match cond {
            Condition::EQ => z,
            Condition::NE => not(builder, z),
            Condition::CS => c,
            Condition::CC => not(builder, c),
            Condition::MI => n,
            Condition::PL => not(builder, n),
            Condition::VS => v,
            Condition::VC => not(builder, v),
            Condition::HI => {
                let not_z = not(builder, z);
                builder.ins().band(c, not_z)
            }
            Condition::LS => {
                let not_c = not(builder, c);
                builder.ins().bor(not_c, z)
            }
            Condition::GE => builder.ins().icmp(IntCC::Equal, n, v),
            Condition::LT => builder.ins().icmp(IntCC::NotEqual, n, v),
            Condition::GT => {
                let not_z = not(builder, z);
                let nv_equal = builder.ins().icmp(IntCC::Equal, n, v);
                builder.ins().band(not_z, nv_equal)
            }
            Condition::LE => {
                let nv_not_equal = builder.ins().icmp(IntCC::NotEqual, n, v);
                builder.ins().bor(z, nv_not_equal)
            }
            Condition::AL => one,
            Condition::NV => zero,
        })
    }
}
