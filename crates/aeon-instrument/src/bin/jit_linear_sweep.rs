use aeon::lifter;
use aeon_reduce::pipeline::reduce_block_local;
use aeonil::{BranchCond, Condition, Expr, Reg, Stmt, TrapKind};
use serde::Serialize;
use std::env;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

const DEFAULT_BASE: u64 = 0x9b5f_e000;
const DEFAULT_INSTRUCTION_LIMIT: usize = 0x50_000;
const MAX_BLOCK_INSNS: usize = 256;

fn main() -> Result<(), String> {
    let config = Config::parse(env::args().skip(1))?;
    let blob =
        fs::read(&config.input).map_err(|err| format!("read {}: {err}", config.input.display()))?;
    if blob.len() < 4 {
        return Err(format!(
            "{} is too small to contain ARM64 instructions",
            config.input.display()
        ));
    }

    let available_instructions = blob.len() / 4;
    let instruction_limit = config.instructions.min(available_instructions);
    let summary_path = summary_path(&config.output);
    let invalid_path = invalid_path(&config.output);
    let output_file = File::create(&config.output)
        .map_err(|err| format!("create {}: {err}", config.output.display()))?;
    let mut writer = BufWriter::new(output_file);
    let invalid_file = File::create(&invalid_path)
        .map_err(|err| format!("create {}: {err}", invalid_path.display()))?;
    let mut invalid_writer = BufWriter::new(invalid_file);

    let mut block_count = 0usize;
    let mut decoded_count = 0usize;
    let mut invalid_count = 0usize;
    let mut unterminated_blocks = 0usize;
    let mut roundtrip_ok_blocks = 0usize;
    let mut roundtrip_failed_blocks = 0usize;
    let mut current_block: Option<BlockBuilder> = None;

    for index in 0..instruction_limit {
        let offset = index * 4;
        let addr = config.base + offset as u64;
        let word = u32::from_le_bytes(blob[offset..offset + 4].try_into().unwrap());

        match bad64::decode(word, addr) {
            Ok(insn) => {
                let next_pc = Some(addr + 4);
                let result = lifter::lift(&insn, addr, next_pc);
                let terminator = is_terminator(&result.stmt);
                let terminator_kind = classify_terminator(&result.stmt);
                let edges = static_successors(&result.stmt, next_pc);

                decoded_count += 1;
                let block = current_block.get_or_insert_with(|| BlockBuilder::new(addr));
                block.push(InstructionRecord {
                    addr: format_hex(addr),
                    word: format!("0x{word:08x}"),
                    disasm: result.disasm,
                    il: format_stmt(&result.stmt),
                    terminator,
                    terminator_kind,
                    edges: edges.into_iter().map(format_hex).collect(),
                });
                block.raw_stmts.push(result.stmt);

                if terminator || block.raw_stmts.len() >= MAX_BLOCK_INSNS {
                    let roundtrip_ok = finalize_block(
                        &mut writer,
                        current_block.take().unwrap(),
                        addr + 4,
                        if terminator { terminator_kind } else { None },
                    )?;
                    block_count += 1;
                    if roundtrip_ok {
                        roundtrip_ok_blocks += 1;
                    } else {
                        roundtrip_failed_blocks += 1;
                    }
                    if !terminator {
                        unterminated_blocks += 1;
                    }
                }
            }
            Err(_) => {
                invalid_count += 1;
                let invalid = InvalidInstructionRecord {
                    addr: format_hex(addr),
                    offset: format_hex(offset as u64),
                    word: format!("0x{word:08x}"),
                    bytes_le: format_bytes_le(word),
                };
                serde_json::to_writer(&mut invalid_writer, &invalid)
                    .map_err(|err| format!("serialize invalid 0x{addr:x}: {err}"))?;
                invalid_writer
                    .write_all(b"\n")
                    .map_err(|err| format!("write invalid 0x{addr:x}: {err}"))?;
                if let Some(block) = current_block.take() {
                    let roundtrip_ok =
                        finalize_block(&mut writer, block, addr, Some("decode_boundary"))?;
                    block_count += 1;
                    if roundtrip_ok {
                        roundtrip_ok_blocks += 1;
                    } else {
                        roundtrip_failed_blocks += 1;
                    }
                    unterminated_blocks += 1;
                }
            }
        }
    }

    let end_addr = config.base + (instruction_limit * 4) as u64;
    if let Some(block) = current_block.take() {
        let roundtrip_ok = finalize_block(&mut writer, block, end_addr, Some("sweep_end"))?;
        block_count += 1;
        if roundtrip_ok {
            roundtrip_ok_blocks += 1;
        } else {
            roundtrip_failed_blocks += 1;
        }
        unterminated_blocks += 1;
    }
    writer
        .flush()
        .map_err(|err| format!("flush {}: {err}", config.output.display()))?;
    invalid_writer
        .flush()
        .map_err(|err| format!("flush {}: {err}", invalid_path.display()))?;

    let summary = SweepSummary {
        input: config.input.display().to_string(),
        base: format_hex(config.base),
        instruction_limit,
        available_instructions,
        range_end: format_hex(end_addr),
        decoded_instructions: decoded_count,
        invalid_instructions: invalid_count,
        block_count,
        unterminated_blocks,
        roundtrip_ok_blocks,
        roundtrip_failed_blocks,
        output: config.output.display().to_string(),
    };
    fs::write(
        &summary_path,
        serde_json::to_vec_pretty(&summary)
            .map_err(|err| format!("serialize summary {}: {err}", summary_path.display()))?,
    )
    .map_err(|err| format!("write {}: {err}", summary_path.display()))?;

    println!(
        "wrote {} blocks from {} decoded instructions ({} invalid) to {}",
        block_count,
        decoded_count,
        invalid_count,
        config.output.display()
    );
    println!("invalid dump: {}", invalid_path.display());
    println!("summary: {}", summary_path.display());
    Ok(())
}

struct Config {
    input: PathBuf,
    output: PathBuf,
    base: u64,
    instructions: usize,
}

impl Config {
    fn parse<I>(mut args: I) -> Result<Self, String>
    where
        I: Iterator<Item = String>,
    {
        let mut input = PathBuf::from("capture/manual/jit_exec_alias_0x9b5fe000.bin");
        let mut output =
            PathBuf::from("capture/manual/jit_exec_alias_0x9b5fe000.first_0x50000_blocks.il.jsonl");
        let mut base = DEFAULT_BASE;
        let mut instructions = DEFAULT_INSTRUCTION_LIMIT;

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--input" => {
                    input = PathBuf::from(next_arg(&mut args, "--input")?);
                }
                "--output" => {
                    output = PathBuf::from(next_arg(&mut args, "--output")?);
                }
                "--base" => {
                    base = parse_u64(&next_arg(&mut args, "--base")?)?;
                }
                "--instructions" => {
                    instructions = parse_usize(&next_arg(&mut args, "--instructions")?)?;
                }
                "--help" | "-h" => {
                    print_usage();
                    std::process::exit(0);
                }
                other => {
                    return Err(format!("unknown argument: {other}"));
                }
            }
        }

        Ok(Self {
            input,
            output,
            base,
            instructions,
        })
    }
}

#[derive(Serialize)]
struct SweepSummary {
    input: String,
    output: String,
    base: String,
    instruction_limit: usize,
    available_instructions: usize,
    range_end: String,
    decoded_instructions: usize,
    invalid_instructions: usize,
    block_count: usize,
    unterminated_blocks: usize,
    roundtrip_ok_blocks: usize,
    roundtrip_failed_blocks: usize,
}

#[derive(Serialize)]
struct InvalidInstructionRecord {
    addr: String,
    offset: String,
    word: String,
    bytes_le: String,
}

#[derive(Serialize)]
struct BlockRecord {
    start: String,
    end: String,
    instruction_count: usize,
    stop_reason: String,
    jitted_block_asm: Vec<String>,
    jitted_block_il: Vec<String>,
    block_il: Vec<String>,
    roundtrip_ok: bool,
    roundtrip_diff: Option<RoundtripDiffRecord>,
    instructions: Vec<InstructionRecord>,
}

#[derive(Serialize)]
struct RoundtripDiffRecord {
    expected_jitted_il: Vec<String>,
    lowered_jitted_il: Vec<String>,
    refolded_jitted_il: Vec<String>,
}

#[derive(Serialize)]
struct InstructionRecord {
    addr: String,
    word: String,
    disasm: String,
    il: String,
    terminator: bool,
    terminator_kind: Option<&'static str>,
    edges: Vec<String>,
}

struct BlockBuilder {
    start: u64,
    raw_stmts: Vec<Stmt>,
    instructions: Vec<InstructionRecord>,
}

impl BlockBuilder {
    fn new(start: u64) -> Self {
        Self {
            start,
            raw_stmts: Vec::new(),
            instructions: Vec::new(),
        }
    }

    fn push(&mut self, instruction: InstructionRecord) {
        self.instructions.push(instruction);
    }
}

fn finalize_block(
    writer: &mut BufWriter<File>,
    block: BlockBuilder,
    end: u64,
    stop_reason: Option<&'static str>,
) -> Result<bool, String> {
    let return_addr = block.start + (block.raw_stmts.len() as u64 * 4);
    let jitted_stmts = transform_calls_and_rets(block.raw_stmts, return_addr);
    let reduced_jitted = reduce_block_local(jitted_stmts);
    let roundtrip = verify_jitted_roundtrip(&reduced_jitted);
    let jitted_block_asm = format_block_arm64(&reduced_jitted);
    let jitted_block_il = reduced_jitted.iter().map(format_stmt).collect();
    let block_il = simplify_stmts_for_display(reduced_jitted.clone())
        .into_iter()
        .map(|stmt| format_stmt(&stmt))
        .collect();

    let roundtrip_ok = roundtrip.is_none();
    let record = BlockRecord {
        start: format_hex(block.start),
        end: format_hex(end),
        instruction_count: block.instructions.len(),
        stop_reason: stop_reason.unwrap_or("fallthrough_limit").to_string(),
        jitted_block_asm,
        jitted_block_il,
        block_il,
        roundtrip_ok,
        roundtrip_diff: roundtrip,
        instructions: block.instructions,
    };

    serde_json::to_writer(&mut *writer, &record)
        .map_err(|err| format!("serialize block 0x{:x}: {err}", block.start))?;
    writer
        .write_all(b"\n")
        .map_err(|err| format!("write block 0x{:x}: {err}", block.start))?;
    Ok(roundtrip_ok)
}

fn transform_calls_and_rets(stmts: Vec<Stmt>, return_addr: u64) -> Vec<Stmt> {
    let mut out = Vec::with_capacity(stmts.len() + 1);
    for stmt in stmts {
        match stmt {
            Stmt::Call { target } => {
                let target = match target {
                    Expr::Reg(Reg::X(30)) => {
                        out.push(Stmt::Assign {
                            dst: Reg::X(17),
                            src: Expr::Reg(Reg::X(30)),
                        });
                        Expr::Reg(Reg::X(17))
                    }
                    other => other,
                };
                out.push(Stmt::Assign {
                    dst: Reg::X(30),
                    src: Expr::Imm(return_addr),
                });
                out.push(Stmt::Branch { target });
            }
            Stmt::Ret => {
                out.push(Stmt::Branch {
                    target: Expr::Reg(Reg::X(30)),
                });
            }
            Stmt::Pair(lhs, rhs) => {
                out.extend(transform_calls_and_rets(vec![*lhs, *rhs], return_addr));
            }
            other => out.push(other),
        }
    }
    normalize_self_update_sequences(out)
}

#[derive(Default)]
struct DisplayEnv {
    regs: Vec<(Reg, Expr)>,
}

impl DisplayEnv {
    fn set(&mut self, reg: Reg, expr: Expr) {
        self.regs.retain(|(candidate, _)| candidate != &reg);
        self.regs.push((reg, expr));
    }

    fn invalidate_loaded_values(&mut self) {
        self.regs.retain(|(_, expr)| !expr_contains_load(expr));
    }

    fn find_addr_reg(&self, imm: u64) -> Option<Reg> {
        self.regs.iter().rev().find_map(|(reg, expr)| {
            if matches!(reg, Reg::X(_) | Reg::SP | Reg::PC)
                && matches!(expr, Expr::Imm(v) if *v == imm)
            {
                Some(reg.clone())
            } else {
                None
            }
        })
    }

    fn find_matching_expr(
        &self,
        expr: &Expr,
        exclude_root_reg: Option<&Reg>,
        is_root: bool,
    ) -> Option<Reg> {
        if matches!(expr, Expr::Imm(_) | Expr::Reg(_)) {
            return None;
        }
        self.regs.iter().rev().find_map(|(reg, value)| {
            if is_root && exclude_root_reg == Some(reg) {
                return None;
            }
            if value == expr {
                Some(reg.clone())
            } else {
                None
            }
        })
    }
}

fn simplify_stmts_for_display(stmts: Vec<Stmt>) -> Vec<Stmt> {
    let mut env = DisplayEnv::default();
    let mut out = Vec::with_capacity(stmts.len());

    for stmt in stmts {
        match stmt {
            Stmt::Assign { dst, src } => {
                let canonical = rewrite_expr_for_env(src, &env, true, None, true);
                let previous_display = out.last().and_then(|stmt| match stmt {
                    Stmt::Assign { dst: prev_dst, src } if prev_dst == &dst => Some(src.clone()),
                    _ => None,
                });
                let self_rewritten = if let Some(previous) = previous_display.as_ref() {
                    replace_exact_subexpr(canonical.clone(), previous, &Expr::Reg(dst.clone()))
                } else {
                    canonical.clone()
                };
                let display =
                    rewrite_expr_for_display(self_rewritten, &env, false, Some(&dst), true);
                if !expr_contains_reg(&display, &dst)
                    && matches!(out.last(), Some(Stmt::Assign { dst: prev, .. }) if prev == &dst)
                {
                    out.pop();
                }
                let display_stmts = expand_display_assign(dst.clone(), display);
                out.extend(display_stmts);
                env.set(dst, canonical);
            }
            Stmt::Store { .. } => {
                let simplified = simplify_stmt_for_display(stmt, &env);
                out.push(simplified);
                env.invalidate_loaded_values();
            }
            other => out.push(simplify_stmt_for_display(other, &env)),
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transform_call_via_x30_preserves_old_target() {
        let stmts = transform_calls_and_rets(
            vec![Stmt::Call {
                target: Expr::Reg(Reg::X(30)),
            }],
            0x1234,
        );
        assert_eq!(
            stmts,
            vec![
                Stmt::Assign {
                    dst: Reg::X(17),
                    src: Expr::Reg(Reg::X(30)),
                },
                Stmt::Assign {
                    dst: Reg::X(30),
                    src: Expr::Imm(0x1234),
                },
                Stmt::Branch {
                    target: Expr::Reg(Reg::X(17)),
                },
            ]
        );
    }

    #[test]
    fn display_pipeline_preserves_blr_x30_target() {
        let stmts = vec![
            Stmt::Assign {
                dst: Reg::X(30),
                src: Expr::Load {
                    addr: Box::new(Expr::Add(
                        Box::new(Expr::Reg(Reg::X(0))),
                        Box::new(Expr::Imm(0x18)),
                    )),
                    size: 8,
                },
            },
            Stmt::Call {
                target: Expr::Reg(Reg::X(30)),
            },
        ];
        let rendered =
            simplify_stmts_for_display(reduce_block_local(transform_calls_and_rets(stmts, 0x1234)));
        assert_eq!(
            rendered,
            vec![
                Stmt::Assign {
                    dst: Reg::X(30),
                    src: Expr::Load {
                        addr: Box::new(Expr::Add(
                            Box::new(Expr::Reg(Reg::X(0))),
                            Box::new(Expr::Imm(0x18)),
                        )),
                        size: 8,
                    },
                },
                Stmt::Assign {
                    dst: Reg::X(17),
                    src: Expr::Reg(Reg::X(30)),
                },
                Stmt::Assign {
                    dst: Reg::X(30),
                    src: Expr::Imm(0x1234),
                },
                Stmt::Branch {
                    target: Expr::Reg(Reg::X(17)),
                },
            ]
        );
    }

    #[test]
    fn jitted_renderer_materializes_folded_constant_with_movk_chain() {
        let stmts = vec![Stmt::Assign {
            dst: Reg::X(16),
            src: Expr::Imm(0x76ace00560),
        }];
        assert_eq!(
            format_block_arm64(&stmts),
            vec![
                "mov x16, #0x560".to_string(),
                "movk x16, #0xace0, lsl #0x10".to_string(),
                "movk x16, #0x76, lsl #0x20".to_string(),
            ]
        );
    }

    #[test]
    fn jitted_renderer_preserves_wzr_width_for_loads() {
        let stmt = Stmt::Assign {
            dst: Reg::XZR,
            src: Expr::Load {
                addr: Box::new(Expr::Reg(Reg::X(16))),
                size: 4,
            },
        };
        assert_eq!(format_stmt_arm64(&stmt), "ldr wzr, [x16]");
    }

    #[test]
    fn jitted_renderer_renders_shifted_sub_immediate() {
        let stmt = Stmt::Assign {
            dst: Reg::X(16),
            src: Expr::Sub(
                Box::new(Expr::Reg(Reg::SP)),
                Box::new(Expr::Shl(
                    Box::new(Expr::Imm(0x2)),
                    Box::new(Expr::Imm(0xc)),
                )),
            ),
        };
        assert_eq!(format_stmt_arm64(&stmt), "sub x16, sp, #0x2, lsl #0xc");
    }

    #[test]
    fn jitted_renderer_reconstructs_preindexed_stack_store() {
        let stmts = vec![
            Stmt::Store {
                addr: Expr::Add(
                    Box::new(Expr::Reg(Reg::SP)),
                    Box::new(Expr::Imm((-0x60i64) as u64)),
                ),
                value: Expr::Reg(Reg::X(0)),
                size: 8,
            },
            Stmt::Assign {
                dst: Reg::SP,
                src: Expr::Add(
                    Box::new(Expr::Reg(Reg::SP)),
                    Box::new(Expr::Imm((-0x60i64) as u64)),
                ),
            },
        ];
        assert_eq!(
            format_block_arm64(&stmts),
            vec!["str x0, [sp, #-0x60]!".to_string()]
        );
    }

    #[test]
    fn jitted_renderer_reconstructs_store_pair() {
        let stmts = vec![
            Stmt::Store {
                addr: Expr::Add(Box::new(Expr::Reg(Reg::SP)), Box::new(Expr::Imm(0x20))),
                value: Expr::Reg(Reg::X(21)),
                size: 8,
            },
            Stmt::Store {
                addr: Expr::Add(
                    Box::new(Expr::Add(
                        Box::new(Expr::Reg(Reg::SP)),
                        Box::new(Expr::Imm(0x20)),
                    )),
                    Box::new(Expr::Imm(0x8)),
                ),
                value: Expr::Reg(Reg::X(22)),
                size: 8,
            },
        ];
        assert_eq!(
            format_block_arm64(&stmts),
            vec!["stp x21, x22, [sp, #0x20]".to_string()]
        );
    }

    #[test]
    fn trap_renderer_preserves_kind_and_immediate() {
        let stmt = Stmt::Trap {
            kind: TrapKind::Brk,
            imm: 0x4711,
        };
        assert_eq!(format_stmt(&stmt), "brk 0x4711");
        assert_eq!(format_stmt_arm64(&stmt), "brk #0x4711");
    }

    #[test]
    fn roundtrip_verifier_accepts_folded_movk_materialization() {
        let stmts = vec![Stmt::Assign {
            dst: Reg::X(16),
            src: Expr::Imm(0x76ace00560),
        }];
        assert!(verify_jitted_roundtrip(&stmts).is_none());
    }

    #[test]
    fn roundtrip_verifier_accepts_preindex_and_pair_patterns() {
        let stmts = vec![
            Stmt::Store {
                addr: Expr::Add(
                    Box::new(Expr::Reg(Reg::SP)),
                    Box::new(Expr::Imm((-0x60i64) as u64)),
                ),
                value: Expr::Reg(Reg::X(0)),
                size: 8,
            },
            Stmt::Assign {
                dst: Reg::SP,
                src: Expr::Add(
                    Box::new(Expr::Reg(Reg::SP)),
                    Box::new(Expr::Imm((-0x60i64) as u64)),
                ),
            },
            Stmt::Store {
                addr: Expr::Add(Box::new(Expr::Reg(Reg::SP)), Box::new(Expr::Imm(0x20))),
                value: Expr::Reg(Reg::X(21)),
                size: 8,
            },
            Stmt::Store {
                addr: Expr::Add(
                    Box::new(Expr::Add(
                        Box::new(Expr::Reg(Reg::SP)),
                        Box::new(Expr::Imm(0x20)),
                    )),
                    Box::new(Expr::Imm(0x8)),
                ),
                value: Expr::Reg(Reg::X(22)),
                size: 8,
            },
        ];
        assert!(verify_jitted_roundtrip(&stmts).is_none());
    }

    #[test]
    fn jitted_renderer_formats_explicit_movk_assignments() {
        let stmts = vec![
            Stmt::Assign {
                dst: Reg::X(8),
                src: Expr::Intrinsic {
                    name: "movk".to_string(),
                    operands: vec![Expr::Reg(Reg::X(8)), Expr::Imm(0xace0_0000)],
                },
            },
            Stmt::Assign {
                dst: Reg::X(8),
                src: Expr::Intrinsic {
                    name: "movk".to_string(),
                    operands: vec![
                        Expr::Intrinsic {
                            name: "movk".to_string(),
                            operands: vec![Expr::Reg(Reg::X(8)), Expr::Imm(0xace0_0000)],
                        },
                        Expr::Imm(0x76_0000_0000),
                    ],
                },
            },
        ];
        assert_eq!(
            format_block_arm64(&stmts),
            vec![
                "movk x8, #0xace0, lsl #0x10".to_string(),
                "movk x8, #0x76, lsl #0x20".to_string(),
            ]
        );
    }

    #[test]
    fn jitted_renderer_collapses_successive_imm_materialization_steps() {
        let stmts = vec![
            Stmt::Assign {
                dst: Reg::X(16),
                src: Expr::Imm(0x560),
            },
            Stmt::Assign {
                dst: Reg::X(16),
                src: Expr::Imm(0xace0_0560),
            },
            Stmt::Assign {
                dst: Reg::X(16),
                src: Expr::Imm(0x76_ace0_0560),
            },
        ];
        assert_eq!(
            format_block_arm64(&stmts),
            vec![
                "mov x16, #0x560".to_string(),
                "movk x16, #0xace0, lsl #0x10".to_string(),
                "movk x16, #0x76, lsl #0x20".to_string(),
            ]
        );
    }

    #[test]
    fn roundtrip_verifier_accepts_self_load_chain_display_equivalence() {
        let stmts = vec![
            Stmt::Assign {
                dst: Reg::X(17),
                src: Expr::Load {
                    addr: Box::new(Expr::Imm(0x9b5ff358)),
                    size: 8,
                },
            },
            Stmt::Assign {
                dst: Reg::X(0),
                src: Expr::Load {
                    addr: Box::new(Expr::Add(
                        Box::new(Expr::Reg(Reg::X(0))),
                        Box::new(Expr::Imm(0x80)),
                    )),
                    size: 8,
                },
            },
            Stmt::Assign {
                dst: Reg::X(0),
                src: Expr::Load {
                    addr: Box::new(Expr::Add(
                        Box::new(Expr::Load {
                            addr: Box::new(Expr::Add(
                                Box::new(Expr::Reg(Reg::X(0))),
                                Box::new(Expr::Imm(0x80)),
                            )),
                            size: 8,
                        }),
                        Box::new(Expr::Imm(0x10)),
                    )),
                    size: 8,
                },
            },
            Stmt::Assign {
                dst: Reg::X(30),
                src: Expr::Load {
                    addr: Box::new(Expr::Add(
                        Box::new(Expr::Load {
                            addr: Box::new(Expr::Add(
                                Box::new(Expr::Load {
                                    addr: Box::new(Expr::Add(
                                        Box::new(Expr::Reg(Reg::X(0))),
                                        Box::new(Expr::Imm(0x80)),
                                    )),
                                    size: 8,
                                }),
                                Box::new(Expr::Imm(0x10)),
                            )),
                            size: 8,
                        }),
                        Box::new(Expr::Imm(0x18)),
                    )),
                    size: 8,
                },
            },
            Stmt::Assign {
                dst: Reg::X(17),
                src: Expr::Load {
                    addr: Box::new(Expr::Add(
                        Box::new(Expr::Load {
                            addr: Box::new(Expr::Add(
                                Box::new(Expr::Load {
                                    addr: Box::new(Expr::Add(
                                        Box::new(Expr::Load {
                                            addr: Box::new(Expr::Add(
                                                Box::new(Expr::Load {
                                                    addr: Box::new(Expr::Add(
                                                        Box::new(Expr::Reg(Reg::X(0))),
                                                        Box::new(Expr::Imm(0x80)),
                                                    )),
                                                    size: 8,
                                                }),
                                                Box::new(Expr::Imm(0x10)),
                                            )),
                                            size: 8,
                                        }),
                                        Box::new(Expr::Imm(0x80)),
                                    )),
                                    size: 8,
                                }),
                                Box::new(Expr::Imm(0x10)),
                            )),
                            size: 8,
                        }),
                        Box::new(Expr::Imm(0x18)),
                    )),
                    size: 8,
                },
            },
            Stmt::Assign {
                dst: Reg::X(30),
                src: Expr::Imm(0x9b5ff1d0),
            },
            Stmt::Branch {
                target: Expr::Load {
                    addr: Box::new(Expr::Add(
                        Box::new(Expr::Load {
                            addr: Box::new(Expr::Add(
                                Box::new(Expr::Load {
                                    addr: Box::new(Expr::Add(
                                        Box::new(Expr::Load {
                                            addr: Box::new(Expr::Add(
                                                Box::new(Expr::Load {
                                                    addr: Box::new(Expr::Add(
                                                        Box::new(Expr::Load {
                                                            addr: Box::new(Expr::Add(
                                                                Box::new(Expr::Load {
                                                                    addr: Box::new(Expr::Add(
                                                                        Box::new(Expr::Reg(
                                                                            Reg::X(0),
                                                                        )),
                                                                        Box::new(Expr::Imm(0x80)),
                                                                    )),
                                                                    size: 8,
                                                                }),
                                                                Box::new(Expr::Imm(0x10)),
                                                            )),
                                                            size: 8,
                                                        }),
                                                        Box::new(Expr::Imm(0x80)),
                                                    )),
                                                    size: 8,
                                                }),
                                                Box::new(Expr::Imm(0x10)),
                                            )),
                                            size: 8,
                                        }),
                                        Box::new(Expr::Imm(0x80)),
                                    )),
                                    size: 8,
                                }),
                                Box::new(Expr::Imm(0x10)),
                            )),
                            size: 8,
                        }),
                        Box::new(Expr::Imm(0x18)),
                    )),
                    size: 8,
                },
            },
        ];
        assert!(verify_jitted_roundtrip(&stmts).is_none());
    }
}

fn simplify_stmt_for_display(stmt: Stmt, env: &DisplayEnv) -> Stmt {
    match stmt {
        Stmt::Assign { dst, src } => {
            let canonical = rewrite_expr_for_display(src, env, true, None, true);
            let display = rewrite_expr_for_display(canonical.clone(), env, false, Some(&dst), true);
            Stmt::Assign { dst, src: display }
        }
        Stmt::Store { addr, value, size } => Stmt::Store {
            addr: rewrite_expr_for_display(addr, env, true, None, true),
            value: rewrite_expr_for_display(value, env, false, None, true),
            size,
        },
        Stmt::Branch { target } => Stmt::Branch {
            target: rewrite_expr_for_display(target, env, false, None, true),
        },
        Stmt::CondBranch {
            cond,
            target,
            fallthrough,
        } => Stmt::CondBranch {
            cond: rewrite_branch_cond_for_display(cond, env),
            target: rewrite_expr_for_display(target, env, false, None, true),
            fallthrough,
        },
        Stmt::Call { target } => Stmt::Call {
            target: rewrite_expr_for_display(target, env, false, None, true),
        },
        Stmt::Pair(lhs, rhs) => Stmt::Pair(
            Box::new(simplify_stmt_for_display(*lhs, env)),
            Box::new(simplify_stmt_for_display(*rhs, env)),
        ),
        Stmt::SetFlags { expr } => Stmt::SetFlags {
            expr: rewrite_expr_for_display(expr, env, false, None, true),
        },
        Stmt::Intrinsic { name, operands } => Stmt::Intrinsic {
            name,
            operands: operands
                .into_iter()
                .map(|expr| rewrite_expr_for_display(expr, env, false, None, true))
                .collect(),
        },
        other => other,
    }
}

fn rewrite_branch_cond_for_display(cond: BranchCond, env: &DisplayEnv) -> BranchCond {
    match cond {
        BranchCond::Flag(cond) => BranchCond::Flag(cond),
        BranchCond::Zero(expr) => {
            BranchCond::Zero(rewrite_expr_for_display(expr, env, false, None, true))
        }
        BranchCond::NotZero(expr) => {
            BranchCond::NotZero(rewrite_expr_for_display(expr, env, false, None, true))
        }
        BranchCond::BitZero(expr, bit) => {
            BranchCond::BitZero(rewrite_expr_for_display(expr, env, false, None, true), bit)
        }
        BranchCond::BitNotZero(expr, bit) => {
            BranchCond::BitNotZero(rewrite_expr_for_display(expr, env, false, None, true), bit)
        }
        BranchCond::Compare { cond, lhs, rhs } => BranchCond::Compare {
            cond,
            lhs: Box::new(rewrite_expr_for_display(*lhs, env, false, None, true)),
            rhs: Box::new(rewrite_expr_for_display(*rhs, env, false, None, true)),
        },
    }
}

fn rewrite_expr_for_env(
    expr: Expr,
    env: &DisplayEnv,
    rewrite_addr_immediates: bool,
    exclude_root_reg: Option<&Reg>,
    is_root: bool,
) -> Expr {
    rewrite_expr_for_display_inner(
        expr,
        env,
        rewrite_addr_immediates,
        exclude_root_reg,
        is_root,
        false,
    )
}

fn rewrite_expr_for_display(
    expr: Expr,
    env: &DisplayEnv,
    rewrite_addr_immediates: bool,
    exclude_root_reg: Option<&Reg>,
    is_root: bool,
) -> Expr {
    rewrite_expr_for_display_inner(
        expr,
        env,
        rewrite_addr_immediates,
        exclude_root_reg,
        is_root,
        true,
    )
}

fn rewrite_expr_for_display_inner(
    expr: Expr,
    env: &DisplayEnv,
    rewrite_addr_immediates: bool,
    exclude_root_reg: Option<&Reg>,
    is_root: bool,
    allow_root_alias: bool,
) -> Expr {
    let rewritten = expr.map_subexprs(|sub| {
        rewrite_expr_for_display_inner(
            sub.clone(),
            env,
            rewrite_addr_immediates,
            exclude_root_reg,
            false,
            allow_root_alias,
        )
    });

    if rewrite_addr_immediates {
        if let Expr::Imm(value) = rewritten {
            if let Some(reg) = env.find_addr_reg(value) {
                return Expr::Reg(reg);
            }
            return Expr::Imm(value);
        }
    }

    if is_root && !allow_root_alias {
        return rewritten;
    }

    if let Some(reg) = env.find_matching_expr(&rewritten, exclude_root_reg, is_root) {
        Expr::Reg(reg)
    } else {
        rewritten
    }
}

fn expr_contains_load(expr: &Expr) -> bool {
    match expr {
        Expr::Load { .. } => true,
        Expr::Add(lhs, rhs)
        | Expr::Sub(lhs, rhs)
        | Expr::Mul(lhs, rhs)
        | Expr::Div(lhs, rhs)
        | Expr::UDiv(lhs, rhs)
        | Expr::And(lhs, rhs)
        | Expr::Or(lhs, rhs)
        | Expr::Xor(lhs, rhs)
        | Expr::Shl(lhs, rhs)
        | Expr::Lsr(lhs, rhs)
        | Expr::Asr(lhs, rhs)
        | Expr::Ror(lhs, rhs)
        | Expr::FAdd(lhs, rhs)
        | Expr::FSub(lhs, rhs)
        | Expr::FMul(lhs, rhs)
        | Expr::FDiv(lhs, rhs)
        | Expr::FMax(lhs, rhs)
        | Expr::FMin(lhs, rhs)
        | Expr::Compare { lhs, rhs, .. } => expr_contains_load(lhs) || expr_contains_load(rhs),
        Expr::Neg(src)
        | Expr::Abs(src)
        | Expr::Not(src)
        | Expr::FNeg(src)
        | Expr::FAbs(src)
        | Expr::FSqrt(src)
        | Expr::FCvt(src)
        | Expr::IntToFloat(src)
        | Expr::FloatToInt(src)
        | Expr::Clz(src)
        | Expr::Cls(src)
        | Expr::Rev(src)
        | Expr::Rbit(src) => expr_contains_load(src),
        Expr::SignExtend { src, .. } | Expr::ZeroExtend { src, .. } | Expr::Extract { src, .. } => {
            expr_contains_load(src)
        }
        Expr::Insert { dst, src, .. } => expr_contains_load(dst) || expr_contains_load(src),
        Expr::CondSelect {
            if_true, if_false, ..
        } => expr_contains_load(if_true) || expr_contains_load(if_false),
        Expr::Intrinsic { operands, .. } => operands.iter().any(expr_contains_load),
        _ => false,
    }
}

fn expr_contains_reg(expr: &Expr, target: &Reg) -> bool {
    match expr {
        Expr::Reg(reg) => reg == target,
        Expr::Load { addr, .. } => expr_contains_reg(addr, target),
        Expr::Add(lhs, rhs)
        | Expr::Sub(lhs, rhs)
        | Expr::Mul(lhs, rhs)
        | Expr::Div(lhs, rhs)
        | Expr::UDiv(lhs, rhs)
        | Expr::And(lhs, rhs)
        | Expr::Or(lhs, rhs)
        | Expr::Xor(lhs, rhs)
        | Expr::Shl(lhs, rhs)
        | Expr::Lsr(lhs, rhs)
        | Expr::Asr(lhs, rhs)
        | Expr::Ror(lhs, rhs)
        | Expr::FAdd(lhs, rhs)
        | Expr::FSub(lhs, rhs)
        | Expr::FMul(lhs, rhs)
        | Expr::FDiv(lhs, rhs)
        | Expr::FMax(lhs, rhs)
        | Expr::FMin(lhs, rhs)
        | Expr::Compare { lhs, rhs, .. } => {
            expr_contains_reg(lhs, target) || expr_contains_reg(rhs, target)
        }
        Expr::Neg(src)
        | Expr::Abs(src)
        | Expr::Not(src)
        | Expr::FNeg(src)
        | Expr::FAbs(src)
        | Expr::FSqrt(src)
        | Expr::FCvt(src)
        | Expr::IntToFloat(src)
        | Expr::FloatToInt(src)
        | Expr::Clz(src)
        | Expr::Cls(src)
        | Expr::Rev(src)
        | Expr::Rbit(src) => expr_contains_reg(src, target),
        Expr::SignExtend { src, .. } | Expr::ZeroExtend { src, .. } | Expr::Extract { src, .. } => {
            expr_contains_reg(src, target)
        }
        Expr::Insert { dst, src, .. } => {
            expr_contains_reg(dst, target) || expr_contains_reg(src, target)
        }
        Expr::CondSelect {
            if_true, if_false, ..
        } => expr_contains_reg(if_true, target) || expr_contains_reg(if_false, target),
        Expr::Intrinsic { operands, .. } => {
            operands.iter().any(|expr| expr_contains_reg(expr, target))
        }
        _ => false,
    }
}

fn replace_exact_subexpr(expr: Expr, needle: &Expr, replacement: &Expr) -> Expr {
    if &expr == needle {
        return replacement.clone();
    }

    match expr {
        Expr::Load { addr, size } => Expr::Load {
            addr: Box::new(replace_exact_subexpr(*addr, needle, replacement)),
            size,
        },
        Expr::Add(lhs, rhs) => Expr::Add(
            Box::new(replace_exact_subexpr(*lhs, needle, replacement)),
            Box::new(replace_exact_subexpr(*rhs, needle, replacement)),
        ),
        Expr::Sub(lhs, rhs) => Expr::Sub(
            Box::new(replace_exact_subexpr(*lhs, needle, replacement)),
            Box::new(replace_exact_subexpr(*rhs, needle, replacement)),
        ),
        Expr::Mul(lhs, rhs) => Expr::Mul(
            Box::new(replace_exact_subexpr(*lhs, needle, replacement)),
            Box::new(replace_exact_subexpr(*rhs, needle, replacement)),
        ),
        Expr::Div(lhs, rhs) => Expr::Div(
            Box::new(replace_exact_subexpr(*lhs, needle, replacement)),
            Box::new(replace_exact_subexpr(*rhs, needle, replacement)),
        ),
        Expr::UDiv(lhs, rhs) => Expr::UDiv(
            Box::new(replace_exact_subexpr(*lhs, needle, replacement)),
            Box::new(replace_exact_subexpr(*rhs, needle, replacement)),
        ),
        Expr::Neg(src) => Expr::Neg(Box::new(replace_exact_subexpr(*src, needle, replacement))),
        Expr::Abs(src) => Expr::Abs(Box::new(replace_exact_subexpr(*src, needle, replacement))),
        Expr::And(lhs, rhs) => Expr::And(
            Box::new(replace_exact_subexpr(*lhs, needle, replacement)),
            Box::new(replace_exact_subexpr(*rhs, needle, replacement)),
        ),
        Expr::Or(lhs, rhs) => Expr::Or(
            Box::new(replace_exact_subexpr(*lhs, needle, replacement)),
            Box::new(replace_exact_subexpr(*rhs, needle, replacement)),
        ),
        Expr::Xor(lhs, rhs) => Expr::Xor(
            Box::new(replace_exact_subexpr(*lhs, needle, replacement)),
            Box::new(replace_exact_subexpr(*rhs, needle, replacement)),
        ),
        Expr::Not(src) => Expr::Not(Box::new(replace_exact_subexpr(*src, needle, replacement))),
        Expr::Shl(lhs, rhs) => Expr::Shl(
            Box::new(replace_exact_subexpr(*lhs, needle, replacement)),
            Box::new(replace_exact_subexpr(*rhs, needle, replacement)),
        ),
        Expr::Lsr(lhs, rhs) => Expr::Lsr(
            Box::new(replace_exact_subexpr(*lhs, needle, replacement)),
            Box::new(replace_exact_subexpr(*rhs, needle, replacement)),
        ),
        Expr::Asr(lhs, rhs) => Expr::Asr(
            Box::new(replace_exact_subexpr(*lhs, needle, replacement)),
            Box::new(replace_exact_subexpr(*rhs, needle, replacement)),
        ),
        Expr::Ror(lhs, rhs) => Expr::Ror(
            Box::new(replace_exact_subexpr(*lhs, needle, replacement)),
            Box::new(replace_exact_subexpr(*rhs, needle, replacement)),
        ),
        Expr::SignExtend { src, from_bits } => Expr::SignExtend {
            src: Box::new(replace_exact_subexpr(*src, needle, replacement)),
            from_bits,
        },
        Expr::ZeroExtend { src, from_bits } => Expr::ZeroExtend {
            src: Box::new(replace_exact_subexpr(*src, needle, replacement)),
            from_bits,
        },
        Expr::Extract { src, lsb, width } => Expr::Extract {
            src: Box::new(replace_exact_subexpr(*src, needle, replacement)),
            lsb,
            width,
        },
        Expr::Insert {
            dst,
            src,
            lsb,
            width,
        } => Expr::Insert {
            dst: Box::new(replace_exact_subexpr(*dst, needle, replacement)),
            src: Box::new(replace_exact_subexpr(*src, needle, replacement)),
            lsb,
            width,
        },
        Expr::FAdd(lhs, rhs) => Expr::FAdd(
            Box::new(replace_exact_subexpr(*lhs, needle, replacement)),
            Box::new(replace_exact_subexpr(*rhs, needle, replacement)),
        ),
        Expr::FSub(lhs, rhs) => Expr::FSub(
            Box::new(replace_exact_subexpr(*lhs, needle, replacement)),
            Box::new(replace_exact_subexpr(*rhs, needle, replacement)),
        ),
        Expr::FMul(lhs, rhs) => Expr::FMul(
            Box::new(replace_exact_subexpr(*lhs, needle, replacement)),
            Box::new(replace_exact_subexpr(*rhs, needle, replacement)),
        ),
        Expr::FDiv(lhs, rhs) => Expr::FDiv(
            Box::new(replace_exact_subexpr(*lhs, needle, replacement)),
            Box::new(replace_exact_subexpr(*rhs, needle, replacement)),
        ),
        Expr::FNeg(src) => Expr::FNeg(Box::new(replace_exact_subexpr(*src, needle, replacement))),
        Expr::FAbs(src) => Expr::FAbs(Box::new(replace_exact_subexpr(*src, needle, replacement))),
        Expr::FSqrt(src) => Expr::FSqrt(Box::new(replace_exact_subexpr(*src, needle, replacement))),
        Expr::FMax(lhs, rhs) => Expr::FMax(
            Box::new(replace_exact_subexpr(*lhs, needle, replacement)),
            Box::new(replace_exact_subexpr(*rhs, needle, replacement)),
        ),
        Expr::FMin(lhs, rhs) => Expr::FMin(
            Box::new(replace_exact_subexpr(*lhs, needle, replacement)),
            Box::new(replace_exact_subexpr(*rhs, needle, replacement)),
        ),
        Expr::FCvt(src) => Expr::FCvt(Box::new(replace_exact_subexpr(*src, needle, replacement))),
        Expr::IntToFloat(src) => {
            Expr::IntToFloat(Box::new(replace_exact_subexpr(*src, needle, replacement)))
        }
        Expr::FloatToInt(src) => {
            Expr::FloatToInt(Box::new(replace_exact_subexpr(*src, needle, replacement)))
        }
        Expr::CondSelect {
            cond,
            if_true,
            if_false,
        } => Expr::CondSelect {
            cond,
            if_true: Box::new(replace_exact_subexpr(*if_true, needle, replacement)),
            if_false: Box::new(replace_exact_subexpr(*if_false, needle, replacement)),
        },
        Expr::Compare { cond, lhs, rhs } => Expr::Compare {
            cond,
            lhs: Box::new(replace_exact_subexpr(*lhs, needle, replacement)),
            rhs: Box::new(replace_exact_subexpr(*rhs, needle, replacement)),
        },
        Expr::Clz(src) => Expr::Clz(Box::new(replace_exact_subexpr(*src, needle, replacement))),
        Expr::Cls(src) => Expr::Cls(Box::new(replace_exact_subexpr(*src, needle, replacement))),
        Expr::Rev(src) => Expr::Rev(Box::new(replace_exact_subexpr(*src, needle, replacement))),
        Expr::Rbit(src) => Expr::Rbit(Box::new(replace_exact_subexpr(*src, needle, replacement))),
        Expr::Intrinsic { name, operands } => Expr::Intrinsic {
            name,
            operands: operands
                .into_iter()
                .map(|operand| replace_exact_subexpr(operand, needle, replacement))
                .collect(),
        },
        other => other,
    }
}

fn expand_display_assign(dst: Reg, src: Expr) -> Vec<Stmt> {
    if let Expr::And(lhs, rhs) = &src {
        if let Expr::Add(add_lhs, add_rhs) = lhs.as_ref() {
            if matches!(add_lhs.as_ref(), Expr::Reg(reg) if reg == &dst) {
                return vec![
                    Stmt::Assign {
                        dst: dst.clone(),
                        src: Expr::Add(
                            Box::new(Expr::Reg(dst.clone())),
                            Box::new((**add_rhs).clone()),
                        ),
                    },
                    Stmt::Assign {
                        dst: dst.clone(),
                        src: Expr::And(Box::new(Expr::Reg(dst.clone())), Box::new((**rhs).clone())),
                    },
                ];
            }
        }
        if matches!(lhs.as_ref(), Expr::Reg(reg) if reg == &dst) {
            return vec![Stmt::Assign {
                dst: dst.clone(),
                src: Expr::And(Box::new(Expr::Reg(dst.clone())), Box::new((**rhs).clone())),
            }];
        }
    }

    if let Expr::Add(lhs, rhs) = &src {
        if matches!(lhs.as_ref(), Expr::Reg(reg) if reg == &dst) {
            return vec![Stmt::Assign {
                dst: dst.clone(),
                src: Expr::Add(Box::new(Expr::Reg(dst.clone())), Box::new((**rhs).clone())),
            }];
        }
    }

    vec![Stmt::Assign { dst, src }]
}

fn normalize_self_update_sequences(stmts: Vec<Stmt>) -> Vec<Stmt> {
    let mut out = Vec::with_capacity(stmts.len());
    let mut index = 0usize;

    while index < stmts.len() {
        let Some(Stmt::Assign {
            dst,
            src: previous_src,
        }) = stmts.get(index).cloned()
        else {
            out.push(stmts[index].clone());
            index += 1;
            continue;
        };

        let Some(Stmt::Assign {
            dst: next_dst,
            src: next_src,
        }) = stmts.get(index + 1).cloned()
        else {
            out.push(Stmt::Assign {
                dst,
                src: previous_src,
            });
            index += 1;
            continue;
        };

        if dst != next_dst || !expr_contains_subexpr(&next_src, &previous_src) {
            out.push(Stmt::Assign {
                dst,
                src: previous_src,
            });
            index += 1;
            continue;
        }

        out.push(Stmt::Assign {
            dst: dst.clone(),
            src: previous_src.clone(),
        });
        let rewritten_next =
            replace_exact_subexpr(next_src.clone(), &previous_src, &Expr::Reg(dst.clone()));
        out.extend(expand_display_assign(dst.clone(), rewritten_next));

        index += 2;
        while index < stmts.len() {
            if matches!(stmts.get(index), Some(Stmt::Assign { dst: later_dst, .. }) if later_dst == &dst)
            {
                break;
            }
            out.push(rewrite_stmt_exact_subexpr(
                stmts[index].clone(),
                &next_src,
                &Expr::Reg(dst.clone()),
            ));
            index += 1;
        }
    }

    out
}

fn rewrite_stmt_exact_subexpr(stmt: Stmt, needle: &Expr, replacement: &Expr) -> Stmt {
    match stmt {
        Stmt::Assign { dst, src } => Stmt::Assign {
            dst,
            src: replace_exact_subexpr(src, needle, replacement),
        },
        Stmt::Store { addr, value, size } => Stmt::Store {
            addr: replace_exact_subexpr(addr, needle, replacement),
            value: replace_exact_subexpr(value, needle, replacement),
            size,
        },
        Stmt::Branch { target } => Stmt::Branch {
            target: replace_exact_subexpr(target, needle, replacement),
        },
        Stmt::CondBranch {
            cond,
            target,
            fallthrough,
        } => Stmt::CondBranch {
            cond: rewrite_branch_cond_exact_subexpr(cond, needle, replacement),
            target: replace_exact_subexpr(target, needle, replacement),
            fallthrough,
        },
        Stmt::Call { target } => Stmt::Call {
            target: replace_exact_subexpr(target, needle, replacement),
        },
        Stmt::Pair(lhs, rhs) => Stmt::Pair(
            Box::new(rewrite_stmt_exact_subexpr(*lhs, needle, replacement)),
            Box::new(rewrite_stmt_exact_subexpr(*rhs, needle, replacement)),
        ),
        Stmt::SetFlags { expr } => Stmt::SetFlags {
            expr: replace_exact_subexpr(expr, needle, replacement),
        },
        Stmt::Intrinsic { name, operands } => Stmt::Intrinsic {
            name,
            operands: operands
                .into_iter()
                .map(|operand| replace_exact_subexpr(operand, needle, replacement))
                .collect(),
        },
        other => other,
    }
}

fn rewrite_branch_cond_exact_subexpr(
    cond: BranchCond,
    needle: &Expr,
    replacement: &Expr,
) -> BranchCond {
    match cond {
        BranchCond::Flag(cond) => BranchCond::Flag(cond),
        BranchCond::Zero(expr) => {
            BranchCond::Zero(replace_exact_subexpr(expr, needle, replacement))
        }
        BranchCond::NotZero(expr) => {
            BranchCond::NotZero(replace_exact_subexpr(expr, needle, replacement))
        }
        BranchCond::BitZero(expr, bit) => {
            BranchCond::BitZero(replace_exact_subexpr(expr, needle, replacement), bit)
        }
        BranchCond::BitNotZero(expr, bit) => {
            BranchCond::BitNotZero(replace_exact_subexpr(expr, needle, replacement), bit)
        }
        BranchCond::Compare { cond, lhs, rhs } => BranchCond::Compare {
            cond,
            lhs: Box::new(replace_exact_subexpr(*lhs, needle, replacement)),
            rhs: Box::new(replace_exact_subexpr(*rhs, needle, replacement)),
        },
    }
}

fn expr_contains_subexpr(expr: &Expr, needle: &Expr) -> bool {
    if expr == needle {
        return true;
    }

    match expr {
        Expr::Load { addr, .. } => expr_contains_subexpr(addr, needle),
        Expr::Add(lhs, rhs)
        | Expr::Sub(lhs, rhs)
        | Expr::Mul(lhs, rhs)
        | Expr::Div(lhs, rhs)
        | Expr::UDiv(lhs, rhs)
        | Expr::And(lhs, rhs)
        | Expr::Or(lhs, rhs)
        | Expr::Xor(lhs, rhs)
        | Expr::Shl(lhs, rhs)
        | Expr::Lsr(lhs, rhs)
        | Expr::Asr(lhs, rhs)
        | Expr::Ror(lhs, rhs)
        | Expr::FAdd(lhs, rhs)
        | Expr::FSub(lhs, rhs)
        | Expr::FMul(lhs, rhs)
        | Expr::FDiv(lhs, rhs)
        | Expr::FMax(lhs, rhs)
        | Expr::FMin(lhs, rhs)
        | Expr::Compare { lhs, rhs, .. } => {
            expr_contains_subexpr(lhs, needle) || expr_contains_subexpr(rhs, needle)
        }
        Expr::Neg(src)
        | Expr::Abs(src)
        | Expr::Not(src)
        | Expr::FNeg(src)
        | Expr::FAbs(src)
        | Expr::FSqrt(src)
        | Expr::FCvt(src)
        | Expr::IntToFloat(src)
        | Expr::FloatToInt(src)
        | Expr::Clz(src)
        | Expr::Cls(src)
        | Expr::Rev(src)
        | Expr::Rbit(src) => expr_contains_subexpr(src, needle),
        Expr::SignExtend { src, .. } | Expr::ZeroExtend { src, .. } | Expr::Extract { src, .. } => {
            expr_contains_subexpr(src, needle)
        }
        Expr::Insert { dst, src, .. } => {
            expr_contains_subexpr(dst, needle) || expr_contains_subexpr(src, needle)
        }
        Expr::CondSelect {
            if_true, if_false, ..
        } => expr_contains_subexpr(if_true, needle) || expr_contains_subexpr(if_false, needle),
        Expr::Intrinsic { operands, .. } => operands
            .iter()
            .any(|operand| expr_contains_subexpr(operand, needle)),
        _ => false,
    }
}

fn static_successors(stmt: &Stmt, next_pc: Option<u64>) -> Vec<u64> {
    match stmt {
        Stmt::Branch {
            target: Expr::Imm(target),
        } => vec![*target],
        Stmt::CondBranch {
            target: Expr::Imm(target),
            fallthrough,
            ..
        } => vec![*target, *fallthrough],
        Stmt::Call {
            target: Expr::Imm(target),
        } => next_pc
            .into_iter()
            .chain(std::iter::once(*target))
            .collect(),
        Stmt::Pair(lhs, rhs) => {
            let mut out = static_successors(lhs, next_pc);
            out.extend(static_successors(rhs, next_pc));
            out
        }
        _ => Vec::new(),
    }
}

fn is_terminator(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Branch { .. }
        | Stmt::CondBranch { .. }
        | Stmt::Call { .. }
        | Stmt::Ret
        | Stmt::Trap { .. } => true,
        Stmt::Pair(lhs, rhs) => is_terminator(lhs) || is_terminator(rhs),
        _ => false,
    }
}

fn classify_terminator(stmt: &Stmt) -> Option<&'static str> {
    match stmt {
        Stmt::Branch { target } => match target {
            Expr::Imm(_) => Some("direct_branch"),
            _ => Some("dynamic_branch"),
        },
        Stmt::CondBranch { .. } => Some("cond_branch"),
        Stmt::Call { target } => match target {
            Expr::Imm(_) => Some("direct_call"),
            _ => Some("dynamic_call"),
        },
        Stmt::Ret => Some("return"),
        Stmt::Trap { .. } => Some("trap"),
        Stmt::Pair(lhs, rhs) => classify_terminator(rhs).or_else(|| classify_terminator(lhs)),
        _ => None,
    }
}

fn format_stmt(stmt: &Stmt) -> String {
    match stmt {
        Stmt::Assign { dst, src } => format!("{} = {}", format_reg(dst), format_expr(src)),
        Stmt::Store { addr, value, size } => {
            format!(
                "store{}({}, {})",
                size * 8,
                format_expr(addr),
                format_expr(value)
            )
        }
        Stmt::Branch { target } => format!("branch {}", format_expr(target)),
        Stmt::CondBranch {
            cond,
            target,
            fallthrough,
        } => format!(
            "branch_if {} -> {}, else 0x{fallthrough:x}",
            format_branch_cond(cond),
            format_expr(target)
        ),
        Stmt::Call { target } => format!("call {}", format_expr(target)),
        Stmt::Ret => "ret".to_string(),
        Stmt::Nop => "nop".to_string(),
        Stmt::Pair(lhs, rhs) => format!("{} ; {}", format_stmt(lhs), format_stmt(rhs)),
        Stmt::SetFlags { expr } => format!("flags = {}", format_expr(expr)),
        Stmt::Barrier(name) => format!("barrier {name}"),
        Stmt::Trap { kind, imm } => format!("{} 0x{imm:x}", trap_kind_name(*kind)),
        Stmt::Intrinsic { name, operands } => format!(
            "{}({})",
            name,
            operands
                .iter()
                .map(format_expr)
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

fn format_stmt_arm64(stmt: &Stmt) -> String {
    match stmt {
        Stmt::Assign { dst, src } => {
            format_assign_arm64(dst, src).unwrap_or_else(|| format!("; il {}", format_stmt(stmt)))
        }
        Stmt::Store { addr, value, size } => format_store_arm64(addr, value, (*size).into())
            .unwrap_or_else(|| format!("; il {}", format_stmt(stmt))),
        Stmt::Branch { target } => match target {
            Expr::Reg(reg) => format!("br {}", format_reg(reg)),
            Expr::Imm(value) => format!("b 0x{value:x}"),
            other => format!("br {}", format_expr_arm64(other)),
        },
        Stmt::CondBranch {
            cond,
            target,
            fallthrough: _,
        } => format_cond_branch_arm64(cond, target)
            .unwrap_or_else(|| format!("; il {}", format_stmt(stmt))),
        Stmt::Call { target } => match target {
            Expr::Reg(reg) => format!("blr {}", format_reg(reg)),
            Expr::Imm(value) => format!("bl 0x{value:x}"),
            other => format!("blr {}", format_expr_arm64(other)),
        },
        Stmt::Ret => "ret".to_string(),
        Stmt::Nop => "nop".to_string(),
        Stmt::Pair(lhs, rhs) => format!("{} ; {}", format_stmt_arm64(lhs), format_stmt_arm64(rhs)),
        Stmt::SetFlags { expr } => match expr {
            Expr::Compare { cond: _, lhs, rhs } => {
                format!("cmp {}, {}", format_expr_arm64(lhs), format_expr_arm64(rhs))
            }
            other => format!("; flags = {}", format_expr(other)),
        },
        Stmt::Barrier(name) => name.clone(),
        Stmt::Trap { kind, imm } => format!("{} #0x{imm:x}", trap_kind_name(*kind)),
        Stmt::Intrinsic { .. } => format!("; il {}", format_stmt(stmt)),
    }
}

fn format_block_arm64(stmts: &[Stmt]) -> Vec<String> {
    let mut out = Vec::new();
    let mut index = 0usize;

    while index < stmts.len() {
        if let Some((rendered, consumed)) = format_stmt_window_arm64(&stmts[index..]) {
            out.extend(rendered);
            index += consumed;
            continue;
        }

        out.push(format_stmt_arm64(&stmts[index]));
        index += 1;
    }

    out
}

fn verify_jitted_roundtrip(reduced_jitted: &[Stmt]) -> Option<RoundtripDiffRecord> {
    let lowered = lower_jitted_block_roundtrip(reduced_jitted);
    let expected = simplify_stmts_for_display(reduced_jitted.to_vec());
    let canonical_lowered = simplify_stmts_for_display(lowered.clone());
    if canonical_lowered == expected {
        return None;
    }
    let refolded = reduce_block_local(lowered.clone());
    let canonical_refolded = simplify_stmts_for_display(refolded.clone());
    if canonical_refolded == expected {
        None
    } else {
        Some(RoundtripDiffRecord {
            expected_jitted_il: expected.iter().map(format_stmt).collect(),
            lowered_jitted_il: canonical_lowered.iter().map(format_stmt).collect(),
            refolded_jitted_il: canonical_refolded.iter().map(format_stmt).collect(),
        })
    }
}

fn lower_jitted_block_roundtrip(stmts: &[Stmt]) -> Vec<Stmt> {
    let mut out = Vec::new();
    let mut index = 0usize;

    while index < stmts.len() {
        if let Some((lowered, consumed)) = lower_stmt_window_roundtrip(&stmts[index..]) {
            out.extend(lowered);
            index += consumed;
            continue;
        }
        out.push(stmts[index].clone());
        index += 1;
    }

    out
}

fn lower_stmt_window_roundtrip(window: &[Stmt]) -> Option<(Vec<Stmt>, usize)> {
    if format_preindexed_stack_store_arm64(window).is_some() {
        return Some((window[..2].to_vec(), 2));
    }
    if format_store_pair_arm64(window).is_some() {
        return Some((window[..2].to_vec(), 2));
    }
    if let Some(stmt) = window.first() {
        if let Some(lowered) = lower_assign_roundtrip(stmt) {
            return Some((lowered, 1));
        }
    }
    None
}

fn lower_assign_roundtrip(stmt: &Stmt) -> Option<Vec<Stmt>> {
    let Stmt::Assign { dst, src } = stmt else {
        return None;
    };
    let Expr::Imm(_) = src else {
        return None;
    };
    match dst {
        Reg::X(_) | Reg::W(_) => Some(vec![stmt.clone()]),
        _ => None,
    }
}

fn format_stmt_window_arm64(window: &[Stmt]) -> Option<(Vec<String>, usize)> {
    if let Some(rendered) = format_preindexed_stack_store_arm64(window) {
        return Some((vec![rendered], 2));
    }
    if let Some(rendered) = format_store_pair_arm64(window) {
        return Some((vec![rendered], 2));
    }
    if let Some((rendered, consumed)) = format_materialize_chain_window_arm64(window) {
        return Some((rendered, consumed));
    }
    if let Some(rendered) = format_assign_multi_arm64(window.first()?) {
        return Some((rendered, 1));
    }
    None
}

fn format_assign_multi_arm64(stmt: &Stmt) -> Option<Vec<String>> {
    match stmt {
        Stmt::Assign {
            dst: Reg::X(_) | Reg::W(_),
            src: Expr::Imm(value),
        } => Some(materialize_imm_arm64_lines(dst_reg(stmt)?, *value)),
        _ => None,
    }
}

fn dst_reg(stmt: &Stmt) -> Option<Reg> {
    match stmt {
        Stmt::Assign { dst, .. } => Some(dst.clone()),
        _ => None,
    }
}

fn materialize_imm_arm64_lines(dst: Reg, value: u64) -> Vec<String> {
    let width = match dst {
        Reg::W(_) => 32,
        _ => 64,
    };
    let masked = if width == 32 {
        value & 0xffff_ffff
    } else {
        value
    };

    let mut chunks = Vec::new();
    let lanes = if width == 32 { 2 } else { 4 };
    for lane in 0..lanes {
        let shift = lane * 16;
        let chunk = ((masked >> shift) & 0xffff) as u16;
        if chunk != 0 || chunks.is_empty() {
            chunks.push((shift as u32, chunk));
        }
    }
    if chunks.is_empty() {
        chunks.push((0, 0));
    }

    let mut out = Vec::new();
    let (first_shift, first_chunk) = chunks[0];
    if first_shift == 0 {
        out.push(format!("mov {}, #0x{:x}", format_reg(&dst), first_chunk));
    } else {
        out.push(format!(
            "movz {}, #0x{:x}, lsl #0x{:x}",
            format_reg(&dst),
            first_chunk,
            first_shift
        ));
    }

    for &(shift, chunk) in &chunks[1..] {
        out.push(format!(
            "movk {}, #0x{:x}, lsl #0x{:x}",
            format_reg(&dst),
            chunk,
            shift
        ));
    }

    out
}

fn format_materialize_chain_window_arm64(window: &[Stmt]) -> Option<(Vec<String>, usize)> {
    let (dst, mut prev) = imm_assign(window.first()?)?;
    let mut lines = materialize_imm_arm64_lines(dst.clone(), prev);
    let mut consumed = 1usize;

    for stmt in &window[1..] {
        let Some((next_dst, next)) = imm_assign(stmt) else {
            break;
        };
        if next_dst != dst {
            break;
        }
        let step = materialize_imm_step_arm64_line(&dst, prev, next)?;
        lines.push(step);
        prev = next;
        consumed += 1;
    }

    if consumed > 1 {
        Some((lines, consumed))
    } else {
        None
    }
}

fn imm_assign(stmt: &Stmt) -> Option<(Reg, u64)> {
    let Stmt::Assign { dst, src } = stmt else {
        return None;
    };
    let Expr::Imm(value) = src else {
        return None;
    };
    match dst {
        Reg::X(_) | Reg::W(_) => Some((dst.clone(), *value)),
        _ => None,
    }
}

fn materialize_imm_step_arm64_line(dst: &Reg, prev: u64, next: u64) -> Option<String> {
    let mut changed = None;
    for lane in 0..4 {
        let shift = lane * 16;
        let prev_chunk = (prev >> shift) & 0xffff;
        let next_chunk = (next >> shift) & 0xffff;
        if prev_chunk != next_chunk {
            if changed.is_some() {
                return None;
            }
            changed = Some((next_chunk, shift as u64));
        }
    }
    let (chunk, shift) = changed?;
    Some(format!(
        "movk {}, #0x{:x}, lsl #0x{:x}",
        format_reg(dst),
        chunk,
        shift
    ))
}

fn format_preindexed_stack_store_arm64(window: &[Stmt]) -> Option<String> {
    let [Stmt::Store { addr, value, size }, Stmt::Assign { dst, src }, ..] = window else {
        return None;
    };
    if dst != &Reg::SP {
        return None;
    }
    let (base_reg, offset) = match_add_reg_imm(addr)?;
    if base_reg != Reg::SP {
        return None;
    }
    let (sp_base, sp_off) = match_add_reg_imm(src)?;
    if sp_base != Reg::SP || sp_off != offset {
        return None;
    }
    Some(format!(
        "{} {}, [{}{}, {}]!",
        store_mnemonic((*size).into()),
        format_value_reg_for_store(value, (*size).into())?,
        format_reg(&Reg::SP),
        "",
        format_signed_imm(offset)
    ))
}

fn format_store_pair_arm64(window: &[Stmt]) -> Option<String> {
    let [Stmt::Store {
        addr: addr0,
        value: value0,
        size: size0,
    }, Stmt::Store {
        addr: addr1,
        value: value1,
        size: size1,
    }, ..] = window
    else {
        return None;
    };
    if size0 != size1 || *size0 != 8 {
        return None;
    }
    let (base0, off0) = match_add_reg_imm(addr0)?;
    let (base1, off1) = match_add_reg_imm(addr1)?;
    if base0 != base1 || off1 != off0 + 8 {
        return None;
    }
    Some(format!(
        "stp {}, {}, [{}{}, {}]",
        format_value_reg_for_store(value0, 8)?,
        format_value_reg_for_store(value1, 8)?,
        format_reg(&base0),
        "",
        format_signed_imm(off0)
    ))
}

fn match_add_reg_imm(expr: &Expr) -> Option<(Reg, i64)> {
    match expr {
        Expr::Reg(reg) => Some((reg.clone(), 0)),
        Expr::Add(lhs, rhs) => {
            if let Expr::Imm(imm) = rhs.as_ref() {
                if let Some((reg, off)) = match_add_reg_imm(lhs) {
                    return Some((reg, off + (*imm as i64)));
                }
            }
            None
        }
        Expr::Sub(lhs, rhs) => {
            if let Expr::Imm(imm) = rhs.as_ref() {
                if let Some((reg, off)) = match_add_reg_imm(lhs) {
                    return Some((reg, off - (*imm as i64)));
                }
            }
            None
        }
        _ => None,
    }
}

fn format_signed_imm(value: i64) -> String {
    if value < 0 {
        format!("#-0x{:x}", value.unsigned_abs())
    } else {
        format!("#0x{:x}", value as u64)
    }
}

fn format_value_reg_for_store(value: &Expr, size: usize) -> Option<String> {
    match value {
        Expr::Reg(reg) => Some(format_reg_for_access(reg, size, false)),
        Expr::Imm(0) => Some(zero_reg_for_size(size).to_string()),
        _ => None,
    }
}

fn format_assign_arm64(dst: &Reg, src: &Expr) -> Option<String> {
    match src {
        Expr::Reg(src_reg) => Some(format!("mov {}, {}", format_reg(dst), format_reg(src_reg))),
        Expr::Imm(value) => Some(format!("mov {}, #0x{value:x}", format_reg(dst))),
        Expr::Intrinsic { name, operands } if name == "movk" => {
            format_movk_assign_arm64(dst, operands)
        }
        Expr::Load { addr, size } => Some(format!(
            "{} {}, {}",
            load_mnemonic((*size).into()),
            format_reg_for_access(dst, (*size).into(), true),
            format_mem_operand(addr)
        )),
        Expr::Sub(lhs, rhs) => {
            if let Expr::Reg(base) = lhs.as_ref() {
                if let Expr::Shl(shl_lhs, shl_rhs) = rhs.as_ref() {
                    if let (Expr::Imm(imm), Expr::Imm(shift)) = (shl_lhs.as_ref(), shl_rhs.as_ref())
                    {
                        return Some(format!(
                            "sub {}, {}, #0x{:x}, lsl #0x{:x}",
                            format_reg(dst),
                            format_reg(base),
                            imm,
                            shift
                        ));
                    }
                }
                if base == dst {
                    return Some(format!(
                        "sub {}, {}, {}",
                        format_reg(dst),
                        format_reg(dst),
                        format_expr_arm64(rhs)
                    ));
                }
            }
            None
        }
        Expr::Add(lhs, rhs) if matches!(lhs.as_ref(), Expr::Reg(reg) if reg == dst) => {
            Some(format!(
                "add {}, {}, {}",
                format_reg(dst),
                format_reg(dst),
                format_expr_arm64(rhs)
            ))
        }
        Expr::And(lhs, rhs) if matches!(lhs.as_ref(), Expr::Reg(reg) if reg == dst) => {
            Some(format!(
                "and {}, {}, {}",
                format_reg(dst),
                format_reg(dst),
                format_expr_arm64(rhs)
            ))
        }
        Expr::Or(lhs, rhs) if matches!(lhs.as_ref(), Expr::Reg(reg) if reg == dst) => {
            Some(format!(
                "orr {}, {}, {}",
                format_reg(dst),
                format_reg(dst),
                format_expr_arm64(rhs)
            ))
        }
        Expr::Xor(lhs, rhs) if matches!(lhs.as_ref(), Expr::Reg(reg) if reg == dst) => {
            Some(format!(
                "eor {}, {}, {}",
                format_reg(dst),
                format_reg(dst),
                format_expr_arm64(rhs)
            ))
        }
        _ => None,
    }
}

fn format_movk_assign_arm64(dst: &Reg, operands: &[Expr]) -> Option<String> {
    let [_, value] = operands else {
        return None;
    };
    let (chunk, shift) = decode_movk_lane(value)?;
    Some(format!(
        "movk {}, #0x{:x}, lsl #0x{:x}",
        format_reg(dst),
        chunk,
        shift
    ))
}

fn decode_movk_lane(expr: &Expr) -> Option<(u64, u64)> {
    match expr {
        Expr::Shl(lhs, rhs) => {
            let (Expr::Imm(chunk), Expr::Imm(shift)) = (lhs.as_ref(), rhs.as_ref()) else {
                return None;
            };
            Some((*chunk, *shift))
        }
        Expr::Imm(value) => {
            let mut found = None;
            for lane in 0..4 {
                let shift = lane * 16;
                let chunk = (value >> shift) & 0xffff;
                if chunk != 0 {
                    if found.is_some() {
                        return None;
                    }
                    found = Some((chunk, shift as u64));
                }
            }
            found.or(Some((0, 0)))
        }
        _ => None,
    }
}

fn format_store_arm64(addr: &Expr, value: &Expr, size: usize) -> Option<String> {
    match value {
        Expr::Reg(reg) => Some(format!(
            "{} {}, {}",
            store_mnemonic(size),
            format_reg_for_access(reg, size, false),
            format_mem_operand(addr)
        )),
        Expr::Imm(0) => Some(format!(
            "{} {}, {}",
            store_mnemonic(size),
            zero_reg_for_size(size),
            format_mem_operand(addr)
        )),
        _ => None,
    }
}

fn format_cond_branch_arm64(cond: &BranchCond, target: &Expr) -> Option<String> {
    let target_str = format_branch_target_arm64(target);
    match cond {
        BranchCond::Flag(cond) => Some(format!("b.{} {}", format_condition(*cond), target_str)),
        BranchCond::Zero(expr) => Some(format!("cbz {}, {}", format_expr_arm64(expr), target_str)),
        BranchCond::NotZero(expr) => {
            Some(format!("cbnz {}, {}", format_expr_arm64(expr), target_str))
        }
        BranchCond::BitZero(expr, bit) => Some(format!(
            "tbz {}, #{}, {}",
            format_expr_arm64(expr),
            bit,
            target_str
        )),
        BranchCond::BitNotZero(expr, bit) => Some(format!(
            "tbnz {}, #{}, {}",
            format_expr_arm64(expr),
            bit,
            target_str
        )),
        BranchCond::Compare { cond, lhs, rhs } => Some(format!(
            "cmp {}, {} ; b.{} {}",
            format_expr_arm64(lhs),
            format_expr_arm64(rhs),
            format_condition(*cond),
            target_str
        )),
    }
}

fn format_branch_target_arm64(target: &Expr) -> String {
    match target {
        Expr::Imm(value) => format!("0x{value:x}"),
        Expr::Reg(reg) => format_reg(reg),
        other => format_expr_arm64(other),
    }
}

fn format_expr_arm64(expr: &Expr) -> String {
    match expr {
        Expr::Reg(reg) => format_reg(reg),
        Expr::Imm(value) => format!("#0x{value:x}"),
        Expr::Load { addr, size } => {
            format!(
                "{} {}",
                load_mnemonic((*size).into()),
                format_mem_operand(addr)
            )
        }
        Expr::Add(lhs, rhs) => format!("{}, {}", format_expr_arm64(lhs), format_expr_arm64(rhs)),
        Expr::Sub(lhs, rhs) => format!("{}, {}", format_expr_arm64(lhs), format_expr_arm64(rhs)),
        _ => format_expr(expr),
    }
}

fn format_mem_operand(addr: &Expr) -> String {
    match addr {
        Expr::Reg(reg) => format!("[{}]", format_reg(reg)),
        Expr::Add(lhs, rhs) => {
            if let Some((base, off)) = match_add_reg_imm(addr) {
                return format!("[{}, {}]", format_reg(&base), format_signed_imm(off));
            }
            if let Expr::Reg(reg) = lhs.as_ref() {
                if let Expr::Imm(imm) = rhs.as_ref() {
                    return format!("[{}, #0x{:x}]", format_reg(reg), imm);
                }
            }
            format!("[{}]", format_expr(addr))
        }
        Expr::Sub(lhs, rhs) => {
            if let Expr::Reg(reg) = lhs.as_ref() {
                if let Expr::Imm(imm) = rhs.as_ref() {
                    return format!("[{}, #-0x{:x}]", format_reg(reg), imm);
                }
            }
            format!("[{}]", format_expr(addr))
        }
        _ => format!("[{}]", format_expr(addr)),
    }
}

fn load_mnemonic(size: usize) -> &'static str {
    match size {
        1 => "ldrb",
        2 => "ldrh",
        4 => "ldr",
        8 => "ldr",
        16 => "ldr",
        _ => "ldr",
    }
}

fn store_mnemonic(size: usize) -> &'static str {
    match size {
        1 => "strb",
        2 => "strh",
        4 => "str",
        8 => "str",
        16 => "str",
        _ => "str",
    }
}

fn zero_reg_for_size(size: usize) -> &'static str {
    match size {
        1 | 2 | 4 => "wzr",
        _ => "xzr",
    }
}

fn format_reg_for_access(reg: &Reg, size: usize, is_load: bool) -> String {
    match reg {
        Reg::XZR if size <= 4 => "wzr".to_string(),
        Reg::X(index) if size <= 4 && is_load => format!("w{index}"),
        Reg::X(index) if size <= 4 && !is_load => format!("w{index}"),
        _ => format_reg(reg),
    }
}

fn format_branch_cond(cond: &BranchCond) -> String {
    match cond {
        BranchCond::Flag(cond) => format_condition(*cond).to_string(),
        BranchCond::Zero(expr) => format!("zero({})", format_expr(expr)),
        BranchCond::NotZero(expr) => format!("not_zero({})", format_expr(expr)),
        BranchCond::BitZero(expr, bit) => format!("bit_zero({}, {})", format_expr(expr), bit),
        BranchCond::BitNotZero(expr, bit) => {
            format!("bit_not_zero({}, {})", format_expr(expr), bit)
        }
        BranchCond::Compare { cond, lhs, rhs } => format!(
            "cmp.{}({}, {})",
            format_condition(*cond),
            format_expr(lhs),
            format_expr(rhs)
        ),
    }
}

fn format_condition(cond: Condition) -> &'static str {
    match cond {
        Condition::EQ => "eq",
        Condition::NE => "ne",
        Condition::CS => "cs",
        Condition::CC => "cc",
        Condition::MI => "mi",
        Condition::PL => "pl",
        Condition::VS => "vs",
        Condition::VC => "vc",
        Condition::HI => "hi",
        Condition::LS => "ls",
        Condition::GE => "ge",
        Condition::LT => "lt",
        Condition::GT => "gt",
        Condition::LE => "le",
        Condition::AL => "al",
        Condition::NV => "nv",
    }
}

fn trap_kind_name(kind: TrapKind) -> &'static str {
    match kind {
        TrapKind::Brk => "brk",
        TrapKind::Udf => "udf",
    }
}

fn format_expr(expr: &Expr) -> String {
    match expr {
        Expr::Reg(reg) => format_reg(reg),
        Expr::Imm(value) => format!("0x{value:x}"),
        Expr::FImm(value) => format!("{value:?}"),
        Expr::Load { addr, size } => format!("load{}({})", size * 8, format_expr(addr)),
        Expr::Add(lhs, rhs) => format!("add({}, {})", format_expr(lhs), format_expr(rhs)),
        Expr::Sub(lhs, rhs) => format!("sub({}, {})", format_expr(lhs), format_expr(rhs)),
        Expr::Mul(lhs, rhs) => format!("mul({}, {})", format_expr(lhs), format_expr(rhs)),
        Expr::Div(lhs, rhs) => format!("sdiv({}, {})", format_expr(lhs), format_expr(rhs)),
        Expr::UDiv(lhs, rhs) => format!("udiv({}, {})", format_expr(lhs), format_expr(rhs)),
        Expr::Neg(src) => format!("neg({})", format_expr(src)),
        Expr::Abs(src) => format!("abs({})", format_expr(src)),
        Expr::And(lhs, rhs) => format!("and({}, {})", format_expr(lhs), format_expr(rhs)),
        Expr::Or(lhs, rhs) => format!("or({}, {})", format_expr(lhs), format_expr(rhs)),
        Expr::Xor(lhs, rhs) => format!("xor({}, {})", format_expr(lhs), format_expr(rhs)),
        Expr::Not(src) => format!("not({})", format_expr(src)),
        Expr::Shl(lhs, rhs) => format!("shl({}, {})", format_expr(lhs), format_expr(rhs)),
        Expr::Lsr(lhs, rhs) => format!("lsr({}, {})", format_expr(lhs), format_expr(rhs)),
        Expr::Asr(lhs, rhs) => format!("asr({}, {})", format_expr(lhs), format_expr(rhs)),
        Expr::Ror(lhs, rhs) => format!("ror({}, {})", format_expr(lhs), format_expr(rhs)),
        Expr::SignExtend { src, from_bits } => {
            format!("sx{}({})", from_bits, format_expr(src))
        }
        Expr::ZeroExtend { src, from_bits } => {
            format!("zx{}({})", from_bits, format_expr(src))
        }
        Expr::Extract { src, lsb, width } => {
            format!("extract({}, {}, {})", format_expr(src), lsb, width)
        }
        Expr::Insert {
            dst,
            src,
            lsb,
            width,
        } => format!(
            "insert({}, {}, {}, {})",
            format_expr(dst),
            format_expr(src),
            lsb,
            width
        ),
        Expr::FAdd(lhs, rhs) => format!("fadd({}, {})", format_expr(lhs), format_expr(rhs)),
        Expr::FSub(lhs, rhs) => format!("fsub({}, {})", format_expr(lhs), format_expr(rhs)),
        Expr::FMul(lhs, rhs) => format!("fmul({}, {})", format_expr(lhs), format_expr(rhs)),
        Expr::FDiv(lhs, rhs) => format!("fdiv({}, {})", format_expr(lhs), format_expr(rhs)),
        Expr::FNeg(src) => format!("fneg({})", format_expr(src)),
        Expr::FAbs(src) => format!("fabs({})", format_expr(src)),
        Expr::FSqrt(src) => format!("fsqrt({})", format_expr(src)),
        Expr::FMax(lhs, rhs) => format!("fmax({}, {})", format_expr(lhs), format_expr(rhs)),
        Expr::FMin(lhs, rhs) => format!("fmin({}, {})", format_expr(lhs), format_expr(rhs)),
        Expr::FCvt(src) => format!("fcvt({})", format_expr(src)),
        Expr::IntToFloat(src) => format!("int_to_float({})", format_expr(src)),
        Expr::FloatToInt(src) => format!("float_to_int({})", format_expr(src)),
        Expr::CondSelect {
            cond,
            if_true,
            if_false,
        } => format!(
            "csel.{}({}, {})",
            format_condition(*cond),
            format_expr(if_true),
            format_expr(if_false)
        ),
        Expr::Compare { cond, lhs, rhs } => format!(
            "cmp.{}({}, {})",
            format_condition(*cond),
            format_expr(lhs),
            format_expr(rhs)
        ),
        Expr::Clz(src) => format!("clz({})", format_expr(src)),
        Expr::Cls(src) => format!("cls({})", format_expr(src)),
        Expr::Rev(src) => format!("rev({})", format_expr(src)),
        Expr::Rbit(src) => format!("rbit({})", format_expr(src)),
        Expr::AdrpImm(value) => format!("adrp(0x{value:x})"),
        Expr::AdrImm(value) => format!("adr(0x{value:x})"),
        Expr::StackSlot { offset, size } => format!("stack[{}]:{}", offset, size * 8),
        Expr::MrsRead(name) => format!("mrs({name})"),
        Expr::Intrinsic { name, operands } => format!(
            "{}({})",
            name,
            operands
                .iter()
                .map(format_expr)
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

fn format_reg(reg: &Reg) -> String {
    match reg {
        Reg::X(index) => format!("x{index}"),
        Reg::W(index) => format!("w{index}"),
        Reg::SP => "sp".to_string(),
        Reg::PC => "pc".to_string(),
        Reg::XZR => "xzr".to_string(),
        Reg::Flags => "nzcv".to_string(),
        Reg::V(index) => format!("v{index}"),
        Reg::Q(index) => format!("q{index}"),
        Reg::D(index) => format!("d{index}"),
        Reg::S(index) => format!("s{index}"),
        Reg::H(index) => format!("h{index}"),
        Reg::VByte(index) => format!("b{index}"),
    }
}

fn parse_u64(raw: &str) -> Result<u64, String> {
    if let Some(hex) = raw.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).map_err(|err| format!("parse hex u64 {raw}: {err}"))
    } else {
        raw.parse::<u64>()
            .map_err(|err| format!("parse u64 {raw}: {err}"))
    }
}

fn parse_usize(raw: &str) -> Result<usize, String> {
    if let Some(hex) = raw.strip_prefix("0x") {
        usize::from_str_radix(hex, 16).map_err(|err| format!("parse hex usize {raw}: {err}"))
    } else {
        raw.parse::<usize>()
            .map_err(|err| format!("parse usize {raw}: {err}"))
    }
}

fn next_arg<I>(args: &mut I, flag: &str) -> Result<String, String>
where
    I: Iterator<Item = String>,
{
    args.next()
        .ok_or_else(|| format!("missing value for {flag}"))
}

fn format_hex(value: u64) -> String {
    format!("0x{value:x}")
}

fn summary_path(output: &Path) -> PathBuf {
    let mut rendered = output.as_os_str().to_os_string();
    rendered.push(".summary.json");
    PathBuf::from(rendered)
}

fn invalid_path(output: &Path) -> PathBuf {
    let mut rendered = output.as_os_str().to_os_string();
    rendered.push(".invalid.jsonl");
    PathBuf::from(rendered)
}

fn format_bytes_le(word: u32) -> String {
    let bytes = word.to_le_bytes();
    format!(
        "{:02x} {:02x} {:02x} {:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3]
    )
}

fn print_usage() {
    eprintln!(
        "usage: jit_linear_sweep [--input PATH] [--output PATH] [--base ADDR] [--instructions COUNT]"
    );
}
