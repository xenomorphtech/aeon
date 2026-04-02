//! Reduction environment -- tracks register state, known constants, and alias
//! information used by individual reduction passes.  Holds the working context
//! that is threaded through each pass in the pipeline.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};

use aeonil::{Expr, Reg};

/// Forward symbolic register state tracker.
/// Handles ARM64 W/X register aliasing: writing W(n) invalidates X(n) and vice versa.
pub struct RegisterEnv {
    bindings: HashMap<Reg, Expr>,
    def_index: HashMap<Reg, usize>,
}

impl RegisterEnv {
    /// Create an empty environment.
    pub fn new() -> Self {
        Self {
            bindings: HashMap::new(),
            def_index: HashMap::new(),
        }
    }

    /// Create an environment with one initial binding.
    pub fn with_binding(reg: Reg, expr: Expr) -> Self {
        let mut env = Self::new();
        env.assign(reg, expr);
        env
    }

    /// Insert a binding, handling W/X aliasing.
    ///
    /// - If dst is `X(n)`: remove `W(n)` from both maps, insert `X(n)`
    /// - If dst is `W(n)`: remove `X(n)` from both maps, insert `W(n)`
    /// - Otherwise: just insert
    pub fn assign(&mut self, dst: Reg, value: Expr) {
        match dst {
            Reg::X(n) => {
                self.bindings.remove(&Reg::W(n));
                self.def_index.remove(&Reg::W(n));
            }
            Reg::W(n) => {
                self.bindings.remove(&Reg::X(n));
                self.def_index.remove(&Reg::X(n));
            }
            _ => {}
        }
        // Remove any stale def_index for the dst being overwritten.
        self.def_index.remove(&dst);
        self.bindings.insert(dst, value);
    }

    /// Same as `assign`, but also sets `def_index[dst] = index`.
    pub fn assign_at(&mut self, dst: Reg, value: Expr, index: usize) {
        self.assign(dst.clone(), value);
        self.def_index.insert(dst, index);
    }

    /// Only sets def_index (no expression binding). Still handles W/X aliasing
    /// for def_index entries.
    pub fn mark_def(&mut self, dst: Reg, index: usize) {
        match dst {
            Reg::X(n) => {
                self.def_index.remove(&Reg::W(n));
            }
            Reg::W(n) => {
                self.def_index.remove(&Reg::X(n));
            }
            _ => {}
        }
        self.def_index.insert(dst, index);
    }

    /// Direct lookup in bindings.
    pub fn lookup(&self, reg: &Reg) -> Option<&Expr> {
        self.bindings.get(reg)
    }

    /// Lookup in def_index. Handles W/X canonicalization: if looking up X(n)
    /// and not found, also try W(n), and vice versa.
    pub fn def_index(&self, reg: &Reg) -> Option<usize> {
        if let Some(&idx) = self.def_index.get(reg) {
            return Some(idx);
        }
        // Try the alias
        match reg {
            Reg::X(n) => self.def_index.get(&Reg::W(*n)).copied(),
            Reg::W(n) => self.def_index.get(&Reg::X(*n)).copied(),
            _ => None,
        }
    }

    /// Recursively substitute register references with known values.
    /// Uses a default depth limit of 12.
    pub fn resolve(&self, expr: &Expr) -> Expr {
        self.resolve_with_depth(expr, 12)
    }

    /// Recursively substitute register references with known values,
    /// with a configurable depth limit.
    pub fn resolve_with_depth(&self, expr: &Expr, max_depth: usize) -> Expr {
        let visited = RefCell::new(HashSet::new());
        self.resolve_inner(expr, &visited, max_depth)
    }

    fn resolve_inner(&self, expr: &Expr, visited: &RefCell<HashSet<Reg>>, depth: usize) -> Expr {
        if depth == 0 {
            return expr.clone();
        }

        match expr {
            Expr::Reg(reg) => {
                if visited.borrow().contains(reg) {
                    return Expr::Reg(reg.clone());
                }
                let Some(mapped) = self.bindings.get(reg) else {
                    return Expr::Reg(reg.clone());
                };
                visited.borrow_mut().insert(reg.clone());
                let resolved = self.resolve_inner(mapped, visited, depth - 1);
                visited.borrow_mut().remove(reg);
                resolved
            }
            other => {
                other.map_subexprs(|sub| self.resolve_inner(sub, visited, depth - 1))
            }
        }
    }

    /// Remove X0-X18, W0-W18, and Flags from both bindings and def_index.
    pub fn invalidate_caller_saved(&mut self) {
        for n in 0..=18 {
            self.bindings.remove(&Reg::X(n));
            self.bindings.remove(&Reg::W(n));
            self.def_index.remove(&Reg::X(n));
            self.def_index.remove(&Reg::W(n));
        }
        self.bindings.remove(&Reg::Flags);
        self.def_index.remove(&Reg::Flags);
    }

    /// Remove a single register (and its W/X alias) from both maps.
    pub fn remove(&mut self, reg: &Reg) {
        self.bindings.remove(reg);
        self.def_index.remove(reg);
        match reg {
            Reg::X(n) => {
                self.bindings.remove(&Reg::W(*n));
                self.def_index.remove(&Reg::W(*n));
            }
            Reg::W(n) => {
                self.bindings.remove(&Reg::X(*n));
                self.def_index.remove(&Reg::X(*n));
            }
            _ => {}
        }
    }

    /// Clear all state.
    pub fn clear(&mut self) {
        self.bindings.clear();
        self.def_index.clear();
    }
}

impl Default for RegisterEnv {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aeonil::{e_add, Expr, Reg};

    #[test]
    fn w_write_invalidates_x() {
        let mut env = RegisterEnv::new();
        env.assign(Reg::X(0), Expr::Imm(100));
        env.assign(Reg::W(0), Expr::Imm(42));
        assert_eq!(env.lookup(&Reg::X(0)), None);
        assert_eq!(env.lookup(&Reg::W(0)), Some(&Expr::Imm(42)));
    }

    #[test]
    fn x_write_invalidates_w() {
        let mut env = RegisterEnv::new();
        env.assign(Reg::W(0), Expr::Imm(100));
        env.assign(Reg::X(0), Expr::Imm(99));
        assert_eq!(env.lookup(&Reg::W(0)), None);
        assert_eq!(env.lookup(&Reg::X(0)), Some(&Expr::Imm(99)));
    }

    #[test]
    fn assign_overwrites() {
        let mut env = RegisterEnv::new();
        env.assign(Reg::X(0), Expr::Imm(1));
        env.assign(Reg::X(0), Expr::Imm(2));
        assert_eq!(env.lookup(&Reg::X(0)), Some(&Expr::Imm(2)));
    }

    #[test]
    fn resolve_substitutes() {
        let mut env = RegisterEnv::new();
        env.assign(Reg::X(0), Expr::Imm(42));
        let expr = e_add(Expr::Reg(Reg::X(0)), Expr::Imm(1));
        let resolved = env.resolve(&expr);
        assert_eq!(resolved, e_add(Expr::Imm(42), Expr::Imm(1)));
    }

    #[test]
    fn resolve_transitive() {
        let mut env = RegisterEnv::new();
        env.assign(Reg::X(0), Expr::Reg(Reg::X(1)));
        env.assign(Reg::X(1), Expr::Imm(5));
        let resolved = env.resolve(&Expr::Reg(Reg::X(0)));
        assert_eq!(resolved, Expr::Imm(5));
    }

    #[test]
    fn resolve_depth_limit() {
        // Build a chain: X(0) -> X(1) -> X(2) -> ... -> X(14) -> Imm(999)
        let mut env = RegisterEnv::new();
        for i in 0..14 {
            env.assign(Reg::X(i), Expr::Reg(Reg::X(i + 1)));
        }
        env.assign(Reg::X(14), Expr::Imm(999));

        // With default depth 12, we cannot fully resolve a chain of length 15.
        let resolved = env.resolve(&Expr::Reg(Reg::X(0)));
        // Should NOT reach Imm(999) since chain length (15 hops) exceeds depth 12.
        assert_ne!(resolved, Expr::Imm(999));
        // It should stop at some Reg in the chain.
        match &resolved {
            Expr::Reg(Reg::X(n)) => assert!(*n > 0, "should have partially resolved"),
            _ => panic!("expected a Reg after depth exhaustion, got {:?}", resolved),
        }
    }

    #[test]
    fn resolve_cyclic() {
        let mut env = RegisterEnv::new();
        env.assign(Reg::X(0), Expr::Reg(Reg::X(1)));
        env.assign(Reg::X(1), Expr::Reg(Reg::X(0)));
        // Must terminate without panic.
        let resolved = env.resolve(&Expr::Reg(Reg::X(0)));
        // The cycle should be broken; result is some Reg.
        match &resolved {
            Expr::Reg(_) => {} // fine
            _ => panic!("expected Reg after cycle break, got {:?}", resolved),
        }
    }

    #[test]
    fn invalidate_caller_saved_clears_low() {
        let mut env = RegisterEnv::new();
        env.assign(Reg::X(0), Expr::Imm(1));
        env.assign(Reg::X(18), Expr::Imm(2));
        env.assign(Reg::X(19), Expr::Imm(3));
        env.assign(Reg::X(29), Expr::Imm(4));
        env.invalidate_caller_saved();
        assert_eq!(env.lookup(&Reg::X(0)), None);
        assert_eq!(env.lookup(&Reg::X(18)), None);
        assert_eq!(env.lookup(&Reg::X(19)), Some(&Expr::Imm(3)));
        assert_eq!(env.lookup(&Reg::X(29)), Some(&Expr::Imm(4)));
    }

    #[test]
    fn def_index_tracks() {
        let mut env = RegisterEnv::new();
        env.assign_at(Reg::X(0), Expr::Imm(1), 42);
        assert_eq!(env.def_index(&Reg::X(0)), Some(42));
    }

    #[test]
    fn def_index_alias() {
        let mut env = RegisterEnv::new();
        env.assign_at(Reg::W(5), Expr::Imm(1), 100);
        // Looking up X(5) should fall back to W(5) via alias.
        assert_eq!(env.def_index(&Reg::X(5)), Some(100));
    }

    #[test]
    fn mark_def_no_binding() {
        let mut env = RegisterEnv::new();
        env.mark_def(Reg::X(3), 50);
        assert_eq!(env.lookup(&Reg::X(3)), None);
        assert_eq!(env.def_index(&Reg::X(3)), Some(50));
    }

    #[test]
    fn with_binding_works() {
        let env = RegisterEnv::with_binding(Reg::X(0), Expr::Imm(7));
        assert_eq!(env.lookup(&Reg::X(0)), Some(&Expr::Imm(7)));
    }

    #[test]
    fn sp_not_aliased() {
        let mut env = RegisterEnv::new();
        env.assign(Reg::SP, Expr::Imm(0x1000));
        assert_eq!(env.lookup(&Reg::SP), Some(&Expr::Imm(0x1000)));
        // SP shouldn't interfere with any X or W register.
        env.assign(Reg::X(0), Expr::Imm(1));
        assert_eq!(env.lookup(&Reg::SP), Some(&Expr::Imm(0x1000)));
        assert_eq!(env.lookup(&Reg::X(0)), Some(&Expr::Imm(1)));
    }
}
