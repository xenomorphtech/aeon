//! Reduce paired load/store instructions (LDP/STP) -- flattens `Stmt::Pair`
//! nodes into sequential statements.

use aeonil::Stmt;

/// Flatten all `Stmt::Pair` nodes in a statement list into sequential statements.
/// Handles nested pairs recursively.
pub fn flatten_pairs(stmts: Vec<Stmt>) -> Vec<Stmt> {
    let mut out = Vec::with_capacity(stmts.len());
    for stmt in stmts {
        flatten_stmt(stmt, &mut out);
    }
    out
}

fn flatten_stmt(stmt: Stmt, out: &mut Vec<Stmt>) {
    match stmt {
        Stmt::Pair(a, b) => {
            flatten_stmt(*a, out);
            flatten_stmt(*b, out);
        }
        other => out.push(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aeonil::{e_add, e_load, Expr, Reg};

    #[test]
    fn pair_ldp_flattens() {
        let input = vec![Stmt::Pair(
            Box::new(Stmt::Assign {
                dst: Reg::X(1),
                src: e_load(Expr::Reg(Reg::SP), 8),
            }),
            Box::new(Stmt::Assign {
                dst: Reg::X(2),
                src: e_load(e_add(Expr::Reg(Reg::SP), Expr::Imm(8)), 8),
            }),
        )];
        let result = flatten_pairs(input);
        assert_eq!(result.len(), 2);
        assert_eq!(
            result[0],
            Stmt::Assign {
                dst: Reg::X(1),
                src: e_load(Expr::Reg(Reg::SP), 8),
            }
        );
        assert_eq!(
            result[1],
            Stmt::Assign {
                dst: Reg::X(2),
                src: e_load(e_add(Expr::Reg(Reg::SP), Expr::Imm(8)), 8),
            }
        );
    }

    #[test]
    fn pair_stp_flattens() {
        let input = vec![Stmt::Pair(
            Box::new(Stmt::Store {
                addr: Expr::Reg(Reg::SP),
                value: Expr::Reg(Reg::X(3)),
                size: 8,
            }),
            Box::new(Stmt::Store {
                addr: e_add(Expr::Reg(Reg::SP), Expr::Imm(8)),
                value: Expr::Reg(Reg::X(4)),
                size: 8,
            }),
        )];
        let result = flatten_pairs(input);
        assert_eq!(result.len(), 2);
        assert_eq!(
            result[0],
            Stmt::Store {
                addr: Expr::Reg(Reg::SP),
                value: Expr::Reg(Reg::X(3)),
                size: 8,
            }
        );
        assert_eq!(
            result[1],
            Stmt::Store {
                addr: e_add(Expr::Reg(Reg::SP), Expr::Imm(8)),
                value: Expr::Reg(Reg::X(4)),
                size: 8,
            }
        );
    }

    #[test]
    fn pair_nested() {
        let a = Stmt::Assign {
            dst: Reg::X(0),
            src: Expr::Imm(1),
        };
        let b = Stmt::Assign {
            dst: Reg::X(1),
            src: Expr::Imm(2),
        };
        let c = Stmt::Assign {
            dst: Reg::X(2),
            src: Expr::Imm(3),
        };
        let input = vec![Stmt::Pair(
            Box::new(Stmt::Pair(Box::new(a.clone()), Box::new(b.clone()))),
            Box::new(c.clone()),
        )];
        let result = flatten_pairs(input);
        assert_eq!(result.len(), 3);
        assert_eq!(result[0], a);
        assert_eq!(result[1], b);
        assert_eq!(result[2], c);
    }

    #[test]
    fn pair_mixed() {
        let assign = Stmt::Assign {
            dst: Reg::X(5),
            src: e_load(Expr::Reg(Reg::SP), 8),
        };
        let store = Stmt::Store {
            addr: e_add(Expr::Reg(Reg::SP), Expr::Imm(16)),
            value: Expr::Reg(Reg::X(6)),
            size: 8,
        };
        let input = vec![Stmt::Pair(
            Box::new(assign.clone()),
            Box::new(store.clone()),
        )];
        let result = flatten_pairs(input);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], assign);
        assert_eq!(result[1], store);
    }

    #[test]
    fn non_pair_passthrough() {
        let stmts = vec![
            Stmt::Assign {
                dst: Reg::X(7),
                src: Expr::Imm(42),
            },
            Stmt::Store {
                addr: Expr::Reg(Reg::SP),
                value: Expr::Reg(Reg::X(8)),
                size: 8,
            },
        ];
        let result = flatten_pairs(stmts.clone());
        assert_eq!(result, stmts);
    }
}
