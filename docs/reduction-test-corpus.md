# LLIL to MLIL Reduction Test Corpus

Correctness-first test corpus for reductions that transform sequences of low-level IL statements into middle-level IL statements, targeting ARM64 code.

## Background

The lifter produces one `Stmt` per ARM64 instruction -- a low-level IL with explicit hardware registers, implicit flag dependencies, and no multi-instruction combining. A middle-level IL resolves multi-instruction idioms into single semantic operations: ADRP+ADD becomes a resolved address, SetFlags+CondBranch becomes an explicit comparison branch, MOVZ+MOVK chains become a single constant.

## Architecture

### New crate: `crates/aeon-reduce/`

Depends on `aeonil` only. No `aeon`, no `bad64`, no `bevy_ecs`. Reductions operate on `Vec<Stmt>` -- no binary fixtures, all tests are self-contained programmatic constructions.

```
crates/aeon-reduce/
  Cargo.toml
  src/
    lib.rs             # pub mod declarations, top-level reduce_block()
    env.rs             # RegisterEnv: forward symbolic state
    reduce_pair.rs     # Stmt::Pair flattening
    reduce_const.rs    # Constant folding & identities
    reduce_adrp.rs     # ADRP+ADD -> resolved address
    reduce_movk.rs     # MOVZ+MOVK chain -> single constant
    reduce_flags.rs    # SetFlags fusion + dead flag elimination
    reduce_ext.rs      # Extension folding, W/X aliasing
    reduce_stack.rs    # Stack slot recognition
    pipeline.rs        # Ordered multi-pass composition
    ssa/
      mod.rs           # SSA types, module declarations
      types.rs         # SsaVar, SsaExpr, SsaStmt, RegLocation, RegWidth
      cfg.rs           # BasicBlock, SsaFunction, CFG construction
      construct.rs     # Braun algorithm: SSA construction
      convert.rs       # Stmt/Expr -> SsaStmt/SsaExpr conversion
      domtree.rs       # Dominator tree computation
      use_def.rs       # UseDef map: SsaVar -> uses/def locations
      dce.rs           # Dead code elimination
      copy_prop.rs     # Copy propagation + phi simplification
      sccp.rs          # Sparse conditional constant propagation
      cse.rs           # Common subexpression elimination
      dead_branch.rs   # Dead branch and unreachable block elimination
      pipeline.rs      # Cross-block pass ordering and fixed-point driver
  tests/
    integration.rs     # End-to-end realistic sequences
```

### MLIL type strategy: extend aeonil

Add new variants rather than forking the type hierarchy:

- `BranchCond::Compare { cond: Condition, lhs: Box<Expr>, rhs: Box<Expr> }` -- fused SetFlags+CondBranch
- `Expr::Compare { cond: Condition, lhs: Box<Expr>, rhs: Box<Expr> }` -- fused SetFlags+CSEL/CSET
- `Expr::StackSlot { offset: i64, size: u8 }` -- recognized stack variable access

The LLIL-specific constructs (`SetFlags`, `AdrpImm`, `Intrinsic("movk", ...)`) are simply absent from well-reduced MLIL output.

### Pass architecture

Each intra-block pass is `fn(Vec<Stmt>) -> Vec<Stmt>`, composed in a fixed pipeline. Cross-block passes operate on `SsaFunction` after SSA construction.

## RegisterEnv

Generalized from existing patterns in `pointer_analysis.rs:1335` (`assign_register`), `object_layout.rs:228` (identical copy), and `rc4_search.rs:333` (`reg_canon`).

```rust
pub struct RegisterEnv {
    bindings: HashMap<Reg, Expr>,
    def_index: HashMap<Reg, usize>,
}
```

Key methods:
- `assign(dst, value)` -- W/X aliasing: `assign(W(n), ...)` invalidates `X(n)` and vice versa
- `assign_at(dst, value, index)` -- same + records defining statement index
- `mark_def(dst, index)` -- records def index without expression binding (for rc4_search use case)
- `lookup(reg)` -- returns current binding
- `def_index(reg)` -- returns defining statement index, with W/X canonicalization
- `resolve(expr)` -- recursively substitutes known register values (depth-limited)
- `invalidate_caller_saved()` -- clears X0-X18/W0-W18 + Flags

Also add `Expr::map_subexprs(&self, f)` to `aeonil` to eliminate the ~150-line match arms duplicated across `resolve_expr` implementations.

---

## Part 1: Intra-Block Reductions

### 1. Pair Flattening

Structural decomposition of `Stmt::Pair` (produced by LDP/STP) into sequential statements.

| Test | Input | Expected |
|------|-------|----------|
| `pair_ldp_flattens` | `Pair(Assign(X1,Load(..)), Assign(X2,Load(..)))` | `[Assign(X1,..), Assign(X2,..)]` |
| `pair_stp_flattens` | `Pair(Store(..), Store(..))` | `[Store(..), Store(..)]` |
| `pair_nested` | `Pair(Pair(A, B), C)` | `[A, B, C]` |
| `pair_mixed` | `Pair(Assign(..), Store(..))` | `[Assign(..), Store(..)]` |
| `non_pair_passthrough` | `[Assign(..), Store(..)]` | unchanged |

### 2. Constant Folding

Single-expression rewrites. Arithmetic on known constants, identity elimination, annihilation.

| Test | Input | Expected |
|------|-------|----------|
| `fold_add_imm` | `Add(Imm(3), Imm(5))` | `Imm(8)` |
| `fold_sub_imm` | `Sub(Imm(10), Imm(3))` | `Imm(7)` |
| `fold_shl_imm` | `Shl(Imm(1), Imm(16))` | `Imm(0x10000)` |
| `fold_lsr_imm` | `Lsr(Imm(0x10000), Imm(16))` | `Imm(1)` |
| `fold_and_imm` | `And(Imm(0xFF), Imm(0x0F))` | `Imm(0x0F)` |
| `fold_or_imm` | `Or(Imm(0xF0), Imm(0x0F))` | `Imm(0xFF)` |
| `fold_xor_self` | `Xor(Imm(0xFF), Imm(0xFF))` | `Imm(0)` |
| `fold_nested` | `Add(Imm(1), Sub(Imm(5), Imm(2)))` | `Imm(4)` |
| `fold_in_assign` | `Assign(X0, Add(Imm(1), Imm(2)))` | `Assign(X0, Imm(3))` |
| `fold_in_store_addr` | `Store(Add(Imm(A),Imm(B)), val, sz)` | `Store(Imm(A+B), val, sz)` |
| `identity_add_zero` | `Add(Reg(X0), Imm(0))` | `Reg(X0)` |
| `identity_mul_one` | `Mul(Reg(X0), Imm(1))` | `Reg(X0)` |
| `annihilate_mul_zero` | `Mul(Reg(X0), Imm(0))` | `Imm(0)` |
| `no_fold_reg` | `Add(Reg(X0), Imm(5))` | unchanged |
| `wrap_u64_overflow` | `Add(Imm(u64::MAX), Imm(1))` | `Imm(0)` |

### 3. ADRP+ADD Resolution

ARM64 uses ADRP to load a page-aligned address, then ADD to add the page offset. The lifter produces `Expr::AdrpImm(page_addr)` and a subsequent `Add(Reg(Xn), Imm(offset))`. Resolution combines them into a single `Imm(resolved_addr)`.

| Test | Input Sequence | Expected |
|------|----------------|----------|
| `adrp_add_resolves` | `[Assign(X0, AdrpImm(0x12345000)), Assign(X0, Add(Reg(X0), Imm(0x678)))]` | `[Assign(X0, Imm(0x12345678))]` |
| `adrp_add_different_regs` | ADRP->X0, ADD X1<-X0+off | both survive, X0 substituted into ADD src |
| `adrp_add_interleaved` | ADRP X0, unrelated Assign(X1,..), ADD X0,X0,#off | resolves (X0 not clobbered) |
| `adrp_add_clobbered` | ADRP X0, Assign(X0, other), ADD X0,X0,#off | no resolution |
| `adrp_add_into_load` | `ADRP X0; LDR X0,[X0,#off]` | `Assign(X0, Load(Imm(resolved), 8))` |
| `adrp_two_independent` | two ADRP+ADD sequences on different regs | both resolve |
| `adrp_page_boundary` | `AdrpImm(0xFFFFF000) + 0xFFF` | `Imm(0xFFFFFFFF)` |

### 4. MOVZ+MOVK Chain Resolution

ARM64 builds wide constants across multiple instructions. MOVZ loads with zero-extend, MOVK inserts 16-bit chunks at shifted positions. The lifter produces MOVK as `Intrinsic("movk", [Reg(Xn), shifted_imm])` where `shifted_imm` has the shift already applied.

| Test | Input Sequence | Expected |
|------|----------------|----------|
| `movz_movk_2step` | MOVZ X0,#lo16 + MOVK X0,#hi16,LSL#16 | single `Imm(combined)` |
| `movz_movk_4step` | MOVZ + 3x MOVK (full 64-bit constant) | single `Imm` |
| `movz_movk_partial` | MOVZ + 1 MOVK | single `Imm` (32-bit value) |
| `movz_movk_clobbered` | MOVZ X0, other write to X0, MOVK X0 | chain broken |
| `movk_shift_correctness` | verify each shift amount (0, 16, 32, 48) inserts bits correctly |
| `movz_movk_w_register` | MOVZ W0 + MOVK W0 | works with 32-bit semantics |

### 5. SetFlags + CondBranch Fusion

The lifter produces `SetFlags { expr: Sub(X8, Imm(1)) }` for CMP and `CondBranch { cond: Flag(NE), ... }` for B.NE. Fusion replaces the implicit flag dependency with an explicit `BranchCond::Compare`.

| Test | Input Sequence | Expected |
|------|----------------|----------|
| `cmp_bne_fuses` | `SetFlags(Sub(X8,Imm(1))), CondBranch(Flag(NE),tgt,ft)` | `CondBranch(Compare(NE,X8,Imm(1)),tgt,ft)` |
| `cmp_beq_fuses` | same with EQ | fused |
| `cmn_bmi_fuses` | `SetFlags(Add(X0,X1))` + `Flag(MI)` | fused |
| `tst_beq_fuses` | `SetFlags(And(X0,Imm(0xFF)))` + `Flag(EQ)` | fused |
| `cmp_with_nop_between` | SetFlags, Nop, CondBranch | fuses (Nop doesn't touch flags) |
| `cmp_with_assign_between` | SetFlags, Assign(X1,..), CondBranch | fuses (Assign doesn't touch flags) |
| `double_setflags` | SetFlags, SetFlags, CondBranch | second fuses, first becomes dead |
| `cbz_ignores_flags` | `SetFlags(..), CondBranch(Zero(X0),..)` | SetFlags dead, CBZ unchanged |
| `fcmp_bge_fuses` | `SetFlags(FSub(D0,D1))` + `Flag(GE)` | fused (floating-point compare) |

### 6. SetFlags + CSEL/CSET Fusion

Same flag-fusion principle applied to conditional select instructions.

| Test | Input | Expected |
|------|-------|----------|
| `cmp_cset_fuses` | `SetFlags(Sub(X8,X9)), Assign(W10, CondSelect(CS,Imm(1),Imm(0)))` | fused with `Expr::Compare` |
| `cmp_csel_fuses` | `SetFlags(Sub(X0,X1)), Assign(X2, CondSelect(LT,X3,X4))` | fused |

### 7. Dead Flag Elimination

Remove `SetFlags` statements that have no consumer before the next `SetFlags` or end of block.

| Test | Input | Expected |
|------|-------|----------|
| `dead_setflags_removed` | `SetFlags, SetFlags, CondBranch` | first SetFlags removed |
| `setflags_before_cbz` | `SetFlags(..), CondBranch(Zero(..))` | SetFlags removed (CBZ reads register, not flags) |
| `setflags_at_block_end` | `SetFlags` as last statement | removed |
| `live_setflags_consumed` | `SetFlags, CondBranch(Flag(..))` | fused, not dead |

### 8. Extension Folding

Simplify redundant sign/zero extensions.

| Test | Input | Expected |
|------|-------|----------|
| `zext_of_zext` | `ZeroExtend(ZeroExtend(X,8),16)` | `ZeroExtend(X,8)` |
| `sext_of_sext` | `SignExtend(SignExtend(X,8),16)` | `SignExtend(X,8)` |
| `zext_of_imm` | `ZeroExtend(Imm(0xFF),8)` | `Imm(0xFF)` |
| `sext_of_imm` | `SignExtend(Imm(0x80),8)` | `Imm(0xFFFFFFFFFFFFFF80)` |

### 9. W/X Aliasing (RegisterEnv)

ARM64 W-register writes zero the upper 32 bits of the corresponding X register.

| Test | Scenario | Expected |
|------|----------|----------|
| `w_write_invalidates_x` | assign W(0), lookup X(0) | None |
| `x_write_invalidates_w` | assign X(0), lookup W(0) | None |
| `sp_wsp_alias` | assign SP, lookup SP | found |

### Intra-Block Pipeline

```
reduce_block(stmts) =
  1. flatten_pairs        (structural)
  2. fold_constants       (expression-level)
  3. resolve_adrp_add     (multi-stmt, RegisterEnv)
  4. resolve_movk_chain   (multi-stmt, RegisterEnv)
  5. fold_constants       (again -- ADRP/MOVK may produce foldable exprs)
  6. fuse_flags           (multi-stmt, flag tracking)
  7. eliminate_dead_flags  (liveness)
  8. fold_extensions      (expression-level)
  9. recognize_stack_frame (prologue detection + slot rewrite)
```

### Intra-Block Integration Tests

| Test | Sequence | Exercises |
|------|----------|-----------|
| `real_adrp_add_ldr` | ADRP X8,page; ADD X8,X8,#off; LDR X0,[X8] | ADRP resolution + constant fold in load addr |
| `real_cmp_bne` | CMP W8,#1; B.NE target (from lifter test words 0x7100051f, 0x54000201) | flag fusion |
| `real_movz_movk_4step` | four-instruction 64-bit constant materialization | MOVK chain + constant fold |
| `real_ldp_cmp_bcc` | LDP X0,X1,[SP]; CMP X0,X1; B.LT target | pair flatten + flag fusion |
| `real_function_prologue` | STP X29,X30,[SP,#-16]!; MOV X29,SP | pair flatten |

---

## Part 2: Stack Slot Recognition

### Prologue Detection

ARM64 function prologues follow well-known patterns. Detection operates on the first N statements of a function's flattened `Vec<Stmt>`.

Standard pattern after pair flattening:
```
Store(Add(SP, Imm(neg_offset)), X29, 8)   // save FP
Store(Add(SP, Imm(neg_offset+8)), X30, 8) // save LR
Assign(X29, Reg(SP))                       // establish frame pointer
```

The lifter converts signed offsets to unsigned via `imm_to_u64`, so negative offsets appear as large `Imm` values (e.g., `Imm(0xFFFFFFFFFFFFFFF0)` for -16). Interpret as `i64` to recover the signed offset.

```rust
pub struct PrologueInfo {
    pub frame_size: u64,
    pub has_frame_pointer: bool,
    pub prologue_end: usize,
    pub saved_regs: Vec<(Reg, i64)>,
}
```

| Test | Input | Expected |
|------|-------|----------|
| `prologue_standard_fp` | STP X29,X30 + MOV X29,SP | `frame_size=16, has_fp=true, saved=[X29@0, X30@8]` |
| `prologue_large_frame` | STP X29,X30 with -96, SUB SP,SP,#64 additional | `frame_size=160, has_fp=true` |
| `prologue_no_fp` | `SUB SP,SP,#32` only | `frame_size=32, has_fp=false` |
| `prologue_extra_callee_saved` | STP X29,X30 + STP X19,X20 + STP X21,X22 | detects all 6 saved regs |
| `prologue_leaf_no_save` | `SUB SP,SP,#16` | `frame_size=16, has_fp=false, saved=[]` |
| `prologue_not_detected` | starts with `Assign(X0, Imm(42))` | `None` |

### SP-Relative Slot Rewriting

After prologue detection, rewrite SP/FP-relative memory accesses to `Expr::StackSlot { offset, size }`.

Canonical offset = signed interpretation of the unsigned immediate in `Add(Reg(SP), Imm(v))`. For FP-relative: `Add(Reg(X29), Imm(v))` uses the same canonical space since X29 = SP post-prologue.

| Test | Input | Expected |
|------|-------|----------|
| `sp_load_becomes_slot` | `Assign(X0, Load(Add(SP, Imm(8)), 8))` | `Assign(X0, Load(StackSlot(8, 8)))` |
| `sp_store_becomes_slot` | `Store(Add(SP, Imm(16)), W0, 4)` | `Store(StackSlot(16, 4), W0, 4)` |
| `sp_zero_offset` | `Load(Reg(SP), 8)` | `Load(StackSlot(0, 8))` |
| `non_sp_unchanged` | `Load(Add(X8, Imm(16)), 8)` | unchanged |
| `fp_negative_offset` | `Store(Add(X29, Imm(0xFFFFFFFFFFFFFFFC)), W1, 4)` | `Store(StackSlot(-4, 4), ...)` |
| `fp_positive_offset` | `Load(Add(X29, Imm(8)), 8)` | `Load(StackSlot(8, 8))` |
| `no_fp_x29_not_rewritten` | function without FP setup; X29 used as GPR | X29 accesses NOT rewritten |

### Stack Slot Typing

Inferred from usage patterns after slot collection.

```rust
pub enum SlotType {
    Unknown,
    Integer { size: u8, signed: Option<bool> },
    Float { size: u8 },
    Pointer,
    Aggregate { total_size: u64 },
}
```

| Test | Evidence | Inferred Type |
|------|----------|---------------|
| `type_signed_from_ldrsw` | `SignExtend(Load(StackSlot(4,4)),32)` | `Integer{size:4, signed:true}` |
| `type_unsigned_from_ldrb` | `ZeroExtend(Load(StackSlot(7,1)),8)` | `Integer{size:1, signed:false}` |
| `type_pointer_from_deref` | load from slot, then use as Load addr | `Pointer` |
| `type_float_from_dreg` | `Assign(D(0), Load(StackSlot(8,8)))` | `Float{size:8}` |

---

## Part 3: SSA Construction

SSA construction runs AFTER intra-block reductions. The clean reduced IL means fewer SSA variables and cleaner phi nodes.

### SSA Variable Representation

Separate `SsaVar` type -- hardware registers mapped to canonical locations with width tracking.

```rust
pub enum RegLocation { Gpr(u8), Fpr(u8), Sp, Flags }
pub enum RegWidth { W8, W16, W32, W64, W128, Full }

pub struct SsaVar {
    pub loc: RegLocation,
    pub version: u32,
    pub width: RegWidth,
}
```

Conversion from `Reg`: `X(n)/W(n)` -> `Gpr(n)` with appropriate width. This mirrors `reg_canon` from `rc4_search.rs:333` but adds width tracking.

### SSA IL Types

Parallel types that replace `Reg` references with `SsaVar`:

```rust
pub enum SsaExpr {
    Var(SsaVar),
    Imm(u64),
    FImm(f64),
    Load { addr: Box<SsaExpr>, size: u8 },
    Add(Box<SsaExpr>, Box<SsaExpr>),
    // ... mirrors Expr variants ...
    Phi(Vec<(BlockId, SsaVar)>),
}

pub enum SsaStmt {
    Assign { dst: SsaVar, src: SsaExpr },
    Store { addr: SsaExpr, value: SsaExpr, size: u8 },
    Branch { target: SsaExpr },
    CondBranch { cond: SsaBranchCond, target: SsaExpr, fallthrough: BlockId },
    Call { target: SsaExpr },
    Ret,
    Nop,
}
```

### CFG Representation

```rust
pub type BlockId = u32;

pub struct BasicBlock {
    pub id: BlockId,
    pub addr: u64,
    pub stmts: Vec<SsaStmt>,       // phi nodes first
    pub successors: Vec<BlockId>,
    pub predecessors: Vec<BlockId>,
}

pub struct SsaFunction {
    pub entry: BlockId,
    pub blocks: Vec<BasicBlock>,
    pub block_map: HashMap<u64, BlockId>,
}
```

CFG construction input: `Vec<(u64, Stmt, Vec<u64>)>` -- exactly what `engine.rs:226-239` already collects.

### SSA Algorithm: Braun et al.

Braun "Simple and Efficient Construction of SSA Form" (2013). Single pass, no dominance frontier precomputation, produces pruned SSA by construction. All blocks sealed upfront (all predecessors known from CFG).

Core operations:
- `write_variable(block, loc, var)` -- record definition
- `read_variable(block, loc) -> SsaVar` -- look up current def, recurse to predecessors, insert phi if needed
- `try_remove_trivial_phi(phi) -> SsaVar` -- if all operands are the same (ignoring self), replace with that value

### W/X Aliasing in SSA

All aliases share the same `RegLocation`. GPR slots always tracked at W64 width:
- **Narrow write**: `W(n) = expr` becomes `Gpr(n)_vN = ZeroExtend(expr, 32)` at W64 width
- **Narrow read**: reading `W(n)` when last def was W64 becomes `Extract(Gpr(n)_vN, 0, 32)`
- **Wide write/read**: `X(n)` operations use W64 directly

Same pattern for SIMD: `S(n)` writes zero-extend to W128, narrow reads extract.

### Flags in SSA

`Flags` is `RegLocation::Flags`, versioned like any register. `SetFlags` writes a new version, `CondBranch(Flag(..))` reads the current version. After flag fusion in intra-block reductions, most flag dependencies are resolved -- unfused ones are handled naturally by SSA versioning.

### Memory

Not in SSA for v1. Loads/stores preserve original order. Future: stack-promoted variables can be converted to SSA via mem2reg after stack slot recognition.

### SSA Construction Tests

**CFG:**

| Test | Input | Validates |
|------|-------|-----------|
| `cfg_straight_line` | 3 sequential assigns | single block |
| `cfg_diamond` | if-then-else with merge | 4 blocks, correct pred/succ |
| `cfg_loop` | backward branch | back edge, correct predecessors |
| `cfg_multi_exit` | two Ret instructions | two terminal blocks |

**Variable versioning:**

| Test | Input | Validates |
|------|-------|-----------|
| `ssa_single_def` | `X0 = Imm(42)` | `gpr0_v1`, no phi |
| `ssa_two_defs` | `X0 = 1; X0 = 2` | `gpr0_v1`, `gpr0_v2` |
| `ssa_use_before_def` | `X1 = Add(X0, 1)` (X0 is param) | `gpr0_v0` (entry version) |
| `ssa_def_use_chain` | `X0=1; X1=X0; X0=2; X2=X0` | X1 uses v1, X2 uses v2 |

**Phi placement:**

| Test | Input | Validates |
|------|-------|-----------|
| `phi_diamond` | X0=1 in then, X0=2 in else | phi at merge |
| `phi_loop_header` | X0 defined before loop, modified in body | phi at header |
| `phi_trivial_removed` | both branches assign same value | no phi |
| `phi_nested_loops` | two nested loops modifying X0 | phi at both headers |
| `phi_self_ref` | loop back-edge is self-referential | phi simplified |

**W/X aliasing:**

| Test | Input | Validates |
|------|-------|-----------|
| `wx_write_w_read_x` | `W(0)=42; use X(0)` | read gets ZeroExtend |
| `wx_write_x_read_w` | `X(0)=0x100000042; use W(0)` | read gets Extract |
| `wx_phi_after_split` | then: W(0)=1, else: X(0)=2, merge: use X(0) | phi merges, both at W64 |

**Flags:**

| Test | Input | Validates |
|------|-------|-----------|
| `flags_versions` | two sequential SetFlags | two versions of Flags |
| `flags_condbranch_reads` | SetFlags then CondBranch(Flag(NE)) | reads correct version |
| `flags_cbz_no_read` | SetFlags then CondBranch(Zero(X0)) | flags version not read |

**Edge cases:**

| Test | Input | Validates |
|------|-------|-----------|
| `xzr_becomes_imm0` | `Add(XZR, Imm(1))` | XZR -> Imm(0) |
| `call_clobbers` | Call then X0 read | X0 gets new version after call |
| `empty_function` | only Ret | single block, entry versions |

---

## Part 4: Cross-Block SSA Reductions

These operate on `SsaFunction` after SSA construction, exploiting unique definitions, explicit def-use chains, and phi nodes.

### Shared Infrastructure

**Dominator tree** (`domtree.rs`): Cooper-Harvey-Kennedy iterative algorithm.

```rust
pub struct DomTree {
    idom: HashMap<BlockId, BlockId>,
    children: HashMap<BlockId, Vec<BlockId>>,
    rpo: Vec<BlockId>,
}
```

**Use-Def map** (`use_def.rs`): maps each `SsaVar` to its unique definition site and all use sites. Maintained incrementally by passes.

```rust
pub struct StmtLocation { pub block: BlockId, pub stmt_idx: usize }

pub struct UseDefMap {
    defs: HashMap<SsaVar, StmtLocation>,
    uses: HashMap<SsaVar, HashSet<StmtLocation>>,
}
```

### 10. Dead Code Elimination (DCE)

Worklist-based: remove assignments where the defined variable has zero uses. Cascade: removing a dead def may make its operands' defs dead. Preserve side effects (Store, Call, Branch, Ret).

| Test | Input SSA | Expected |
|------|-----------|----------|
| `dce_unused_assign` | `v1 = Imm(42)` with no uses | removed |
| `dce_preserves_store` | `Store(addr, v1, 4)` | survives |
| `dce_preserves_call` | `Call(target)` | survives |
| `dce_cascading` | `v1=Imm(1); v2=Add(v1,v1); v3=Mul(v2,Imm(2))` all unused | all removed |
| `dce_dead_phi` | `v3=Phi((A,v1),(C,v2))` unused | removed |
| `dce_partial_cascade` | `v1=Imm(1); v2=Add(v1,2)` v2 unused, v1 used by Store | v2 removed, v1 survives |

### 11. Copy Propagation

When `v2 = v1` (src is bare Var), replace all uses of v2 with v1. Transitive chains resolved. Phi simplification: if all operands (ignoring self-references) are the same variable, replace phi with copy.

| Test | Input SSA | Expected |
|------|-----------|----------|
| `copy_simple` | `v2=Var(v1); Store(addr,v2,4)` | Store uses v1; v2 dead |
| `copy_transitive` | `v2=Var(v1); v3=Var(v2); Store(addr,v3,4)` | Store uses v1 |
| `phi_trivial` | `v3=Phi((A,v1),(B,v1))` | `v3=Var(v1)` then propagated |
| `phi_self_ref` | `v3=Phi((A,v1),(B,v3))` | `v3=Var(v1)` |
| `phi_distinct` | `v3=Phi((A,v1),(B,v2))` v1!=v2 | unchanged |
| `copy_width_mismatch` | `v2:W64=Var(v1:W32)` | not propagated |

### 12. Sparse Conditional Constant Propagation (SCCP)

Wegman-Zadeck algorithm with dual worklist (SSA edges + CFG edges). Lattice: Top -> Constant(u64) -> Bottom.

Key insight: phi operands from non-executable edges are ignored (treated as Top), so dead paths don't pollute constants.

| Test | Input SSA | Expected |
|------|-----------|----------|
| `sccp_const_assign` | `v1=Imm(42); v2=Add(v1,Imm(8))` | `v2=Imm(50)` |
| `sccp_transitive` | `v1=Imm(2); v2=Mul(v1,Imm(3)); v3=Add(v2,Imm(1))` | `v3=Imm(7)` |
| `sccp_phi_same_const` | `v1=Imm(5)` in A, `v2=Imm(5)` in B, `v3=Phi((A,v1),(B,v2))` | `v3=Imm(5)` |
| `sccp_phi_different` | `v3=Phi((A,Imm(5)),(B,Imm(7)))` | v3 stays non-constant |
| `sccp_unreachable_arm` | A always branches to C, `v3=Phi((A,v1),(B,v2))` B unreachable | `v3=Imm(v1_val)` |
| `sccp_dead_branch` | `v1=Imm(1); CondBranch(Compare(EQ,v1,Imm(0)),tgt,ft)` | replaced with `Branch(ft)` |
| `sccp_non_const_load` | `v1=Load(addr,8)` | v1 stays non-constant |
| `sccp_overflow_wraps` | `v1=Imm(u64::MAX); v2=Add(v1,Imm(1))` | `v2=Imm(0)` |

### 13. Common Subexpression Elimination (CSE)

Dominator-tree walk with scoped hash table. When two assignments compute the same expression (same op, same SSA operand variables), and the first dominates the second, replace the second with a reference to the first.

Commutative operations (`Add`, `Mul`, `And`, `Or`, `Xor`) are canonicalized by sorting operand variable IDs. Loads and intrinsics are excluded (opaque semantics).

| Test | Input SSA | Expected |
|------|-----------|----------|
| `cse_same_block` | `v1=Add(v0,vk); v2=Add(v0,vk)` | v2 replaced with v1 |
| `cse_dominated` | block A: `v1=Mul(va,vb)`, block B (dominated): `v2=Mul(va,vb)` | v2 replaced |
| `cse_not_dominated` | v1 in B, v2 in C, B does not dominate C | both survive |
| `cse_commutative` | `v1=Add(va,vb); v2=Add(vb,va)` | v2 replaced |
| `cse_sub_not_commutative` | `v1=Sub(va,vb); v2=Sub(vb,va)` | both survive |
| `cse_no_load_dedup` | two `Load(addr,4)` with store between | both survive |

### 14. Dead Branch/Block Elimination

After SCCP resolves branch conditions, replace conditional branches with unconditional ones. Remove unreachable blocks. Clean up phi nodes (remove operands from dead predecessors; simplify trivial phis).

| Test | Input SSA | Expected |
|------|-----------|----------|
| `dead_branch_const_true` | `CondBranch(Imm(1),target,ft)` | `Branch(target)` |
| `dead_branch_const_false` | `CondBranch(Imm(0),target,ft)` | `Branch(ft)` |
| `unreachable_block_removed` | block with no predecessors after edge removal | removed |
| `phi_cleanup` | `v3=Phi((A,v1),(B,v2))`, edge B removed | `v3=v1` |
| `cascade_unreachable` | dead block's successor also becomes unreachable | both removed |
| `diamond_one_arm_dead` | constant condition, one arm removed, phi simplified | |

### Cross-Block Pipeline

```rust
pub fn optimize_ssa(func: &mut SsaFunction) {
    let mut use_def = UseDefMap::build(func);
    let mut changed = true;
    while changed {
        changed = false;
        changed |= sccp::run(func, &mut use_def);
        changed |= dead_branch::run(func, &mut use_def);
        changed |= copy_prop::run(func, &mut use_def);
        let dom_tree = DomTree::build(func);
        changed |= cse::run(func, &dom_tree, &mut use_def);
        changed |= dce::run(func, &mut use_def);
    }
    sweep_nops(func);
}
```

Typically converges in 2-3 iterations. Safety bound: 10 iterations max.

---

## Part 5: RegisterEnv Refactoring

Unify the three independent register tracking implementations into `RegisterEnv`.

### Current Duplication

| File | Pattern | Lines |
|------|---------|-------|
| `pointer_analysis.rs:1335` | `HashMap<Reg,Expr>` + `assign_register` + `resolve_expr` | ~190 |
| `object_layout.rs:228` | identical copy of the above | ~190 |
| `rc4_search.rs:333` | `HashMap<u64,u64>` via `reg_canon` + `def_map` | ~85 |

Total: ~465 lines of duplicated register tracking logic.

### Migration

**Dependency change**: `aeon/Cargo.toml` gains `aeon-reduce = { path = "../aeon-reduce" }`.

**pointer_analysis.rs** and **object_layout.rs**:
- `HashMap::new()` -> `RegisterEnv::new()`
- `resolve_expr(expr, env, &mut HashSet::new(), 12)` -> `env.resolve(expr)`
- `assign_register(env, dst, val)` -> `env.assign(dst, val)`
- `invalidate_caller_saved(env)` -> `env.invalidate_caller_saved()`
- Delete `assign_register`, `invalidate_caller_saved`, `resolve_expr` (~380 lines removed)

**rc4_search.rs**:
- `def_map.insert(reg_canon(dst), pc)` -> `env.mark_def(dst, pc)`
- `def_map.get(&reg_canon(r))` -> `env.def_index(r)`
- Delete `reg_canon` (~12 lines removed)

No public API changes. All existing tests must pass unchanged.

### Migration Order

| Step | What | Risk |
|------|------|------|
| 1 | `Expr::map_subexprs` in aeonil | additive, no breakage |
| 2 | RegisterEnv in aeon-reduce (if not done) | new code |
| 3 | Add `mark_def`/`def_index` to RegisterEnv | new code |
| 4 | Add `aeon-reduce` dep to `aeon` | build change |
| 5 | Migrate `object_layout.rs` (smallest) | low risk |
| 6 | Migrate `pointer_analysis.rs` (largest) | medium risk |
| 7 | Migrate `rc4_search.rs` (different pattern) | medium risk |

---

## Full Implementation Order

All steps across all parts, with dependencies:

| Step | What | Depends On | Part |
|------|------|-----------|------|
| 1 | Create `crates/aeon-reduce/` scaffold, add to workspace | -- | 1 |
| 2 | Add `Compare` variants + `StackSlot` variant + `map_subexprs` to `aeonil` | -- | 1,2,5 |
| 3 | Implement `env.rs` (RegisterEnv) + `mark_def`/`def_index` + tests | 2 | 1,5 |
| 4 | Implement `reduce_pair.rs` + tests | 1 | 1 |
| 5 | Implement `reduce_const.rs` + tests | 1 | 1 |
| 6 | Implement `reduce_adrp.rs` + tests | 3, 5 | 1 |
| 7 | Implement `reduce_movk.rs` + tests | 3, 5 | 1 |
| 8 | Implement `reduce_flags.rs` + tests | 2, 3 | 1 |
| 9 | Implement `reduce_ext.rs` + tests | 1 | 1 |
| 10 | Implement `reduce_stack.rs` (prologue + slot rewrite) + tests | 3 | 2 |
| 11 | Implement `pipeline.rs` (intra-block) + integration tests | 4-10 | 1,2 |
| 12 | Add `aeon-reduce` dep to `aeon`, migrate `object_layout.rs` | 3 | 5 |
| 13 | Migrate `pointer_analysis.rs` | 12 | 5 |
| 14 | Migrate `rc4_search.rs` | 12 | 5 |
| 15 | Implement `ssa/types.rs` + `ssa/convert.rs` | 2 | 3 |
| 16 | Implement `ssa/cfg.rs` (CFG construction) + tests | 15 | 3 |
| 17 | Implement `ssa/construct.rs` (Braun SSA) + tests | 15, 16 | 3 |
| 18 | Implement `ssa/domtree.rs` + tests | 16 | 4 |
| 19 | Implement `ssa/use_def.rs` + tests | 15 | 4 |
| 20 | Implement `ssa/dce.rs` + tests | 19 | 4 |
| 21 | Implement `ssa/copy_prop.rs` + tests | 19 | 4 |
| 22 | Implement `ssa/dead_branch.rs` + tests | 19 | 4 |
| 23 | Implement `ssa/sccp.rs` + tests | 19 | 4 |
| 24 | Implement `ssa/cse.rs` + tests | 18, 19 | 4 |
| 25 | Implement `ssa/pipeline.rs` (cross-block) + integration tests | 20-24 | 4 |

**Parallelism**: Steps 4+5 parallel. Steps 6-10 parallel after 3. Steps 12-14 parallel after 3. Steps 15-16 parallel with 4-14. Steps 20-23 parallel after 19. Step 24 after 18+19.

## Verification

```bash
cargo test -p aeon-reduce                    # all reduction + SSA tests
cargo test -p aeon-reduce reduce_adrp        # specific category
cargo test -p aeon-reduce ssa                # all SSA tests
cargo test --workspace                       # ensure nothing breaks
```
