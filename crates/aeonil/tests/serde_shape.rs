//! The wire shape of the IL: serde's default (externally tagged) form.
#![cfg(feature = "serde")]

use aeonil::{e_add, e_load, BranchCond, Condition, Expr, Reg, Stmt};
use serde_json::json;

#[test]
fn statements_serialise_in_serdes_default_shape() {
    let stmt = Stmt::Assign {
        dst: Reg::X(8),
        src: e_add(e_load(Expr::Reg(Reg::SP), 8), Expr::Imm(0x10)),
    };
    assert_eq!(
        serde_json::to_value(&stmt).unwrap(),
        json!({
            "Assign": {
                "dst": { "X": 8 },
                "src": { "Add": [
                    { "Load": { "addr": { "Reg": "SP" }, "size": 8 } },
                    { "Imm": 16 }
                ] }
            }
        })
    );
    assert_eq!(serde_json::to_value(Stmt::Ret).unwrap(), json!("Ret"));
}

#[test]
fn intrinsic_names_are_their_text() {
    let stmt = Stmt::Intrinsic {
        name: "add.2d".into(),
        operands: vec![Expr::Reg(Reg::V(1))],
    };
    assert_eq!(
        serde_json::to_value(&stmt).unwrap(),
        json!({ "Intrinsic": { "name": "add.2d", "operands": [{ "Reg": { "V": 1 } }] } })
    );
}

#[test]
fn il_round_trips() {
    let stmts = vec![
        Stmt::SetFlags {
            expr: Expr::Sub(Box::new(Expr::Reg(Reg::W(0))), Box::new(Expr::Imm(u64::MAX))),
        },
        Stmt::CondBranch {
            cond: BranchCond::Compare {
                cond: Condition::HI,
                lhs: Box::new(Expr::Reg(Reg::X(1))),
                rhs: Box::new(Expr::StackSlot { offset: -16, size: 8 }),
            },
            target: Expr::Imm(0x1000),
            fallthrough: 0x104,
        },
        Stmt::Intrinsic {
            name: "ld1.16b".into(),
            operands: vec![Expr::Intrinsic {
                name: "multi_reg".into(),
                operands: vec![Expr::Reg(Reg::V(0))],
            }],
        },
    ];
    let text = serde_json::to_string(&stmts).unwrap();
    let back: Vec<Stmt> = serde_json::from_str(&text).unwrap();
    assert_eq!(back, stmts);
}
