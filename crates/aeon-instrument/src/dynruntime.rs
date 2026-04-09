// Dynamic JIT runtime
//
// This is the lightweight exact-PC execution layer we want for live JIT
// diversion. Unlike the translated-ELF path, it does not require a
// precomputed block map. It lazily compiles blocks from the exact current PC
// using DynCfg, then executes them through aeon-jit.

use aeon_jit::{JitCompiler, JitContext};

use crate::context::MemoryProvider;
use crate::dyncfg::DynCfg;
use crate::dynffi::AEON_DYN_BAIL_SENTINEL;

fn dyn_trace_path() -> &'static str {
    #[cfg(target_os = "android")]
    {
        "/data/user/0/com.netmarble.thered/files/aeon_dyn_runtime.log"
    }
    #[cfg(not(target_os = "android"))]
    {
        "/tmp/aeon_dyn_runtime.log"
    }
}

fn dyn_trace_line(message: &str) {
    use std::io::Write;
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dyn_trace_path())
    {
        let _ = writeln!(file, "{message}");
    }
}

fn dyn_trace_ctx(label: &str, ctx: &JitContext) {
    dyn_trace_line(&format!(
        "{label} pc=0x{:x} sp=0x{:x} lr=0x{:x} x0=0x{:x} x1=0x{:x} x2=0x{:x} x8=0x{:x} x19=0x{:x} x20=0x{:x} x21=0x{:x} x22=0x{:x} x23=0x{:x} x24=0x{:x} x28=0x{:x}",
        ctx.pc,
        ctx.sp,
        ctx.x[30],
        ctx.x[0],
        ctx.x[1],
        ctx.x[2],
        ctx.x[8],
        ctx.x[19],
        ctx.x[20],
        ctx.x[21],
        ctx.x[22],
        ctx.x[23],
        ctx.x[24],
        ctx.x[28],
    ));
}

#[derive(Debug, Clone, Copy)]
pub struct DynamicRuntimeConfig {
    pub max_steps: usize,
    pub code_range: Option<(u64, u64)>,
}

impl Default for DynamicRuntimeConfig {
    fn default() -> Self {
        Self {
            max_steps: 4096,
            code_range: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DynamicRuntimeStop {
    Halted,
    MaxSteps,
    CodeRangeExit(u64),
    LiftError(u64, String),
}

#[derive(Debug, Clone)]
pub struct DynamicRuntimeResult {
    pub start_pc: u64,
    pub final_pc: u64,
    pub steps: usize,
    pub path: Vec<u64>,
    pub compiled_blocks: usize,
    pub stop: DynamicRuntimeStop,
}

pub struct DynamicRuntime {
    cfg: DynCfg,
}

impl DynamicRuntime {
    pub fn new() -> Self {
        Self { cfg: DynCfg::new() }
    }

    pub fn compiler_mut(&mut self) -> &mut JitCompiler {
        self.cfg.compiler_mut()
    }

    pub fn block_count(&self) -> usize {
        self.cfg.block_count()
    }

    pub fn has_block(&self, addr: u64) -> bool {
        self.cfg.has_block(addr)
    }

    pub fn source_for_block_id(&self, block_id: u64) -> Option<u64> {
        self.cfg.addresses().into_iter().find(|addr| {
            self.cfg
                .get_block(*addr)
                .map(|block| block.block_id == block_id)
                .unwrap_or(false)
        })
    }

    pub fn run(
        &mut self,
        ctx: &mut JitContext,
        memory: &dyn MemoryProvider,
        config: DynamicRuntimeConfig,
    ) -> DynamicRuntimeResult {
        let start_pc = ctx.pc;
        let mut path = Vec::new();
        let mut steps = 0usize;
        dyn_trace_line(&format!(
            "run start_pc=0x{start_pc:x} max_steps={} range={:?}",
            config.max_steps, config.code_range
        ));

        loop {
            let pc = ctx.pc;
            dyn_trace_line(&format!("step={steps} pc=0x{pc:x}"));
            dyn_trace_ctx("step_ctx", ctx);
            if let Some((start, end)) = config.code_range {
                if pc < start || pc >= end {
                    dyn_trace_line(&format!("stop=code_range_exit pc=0x{pc:x}"));
                    return DynamicRuntimeResult {
                        start_pc,
                        final_pc: pc,
                        steps,
                        path,
                        compiled_blocks: self.cfg.block_count(),
                        stop: DynamicRuntimeStop::CodeRangeExit(pc),
                    };
                }
            }

            if steps >= config.max_steps {
                dyn_trace_line(&format!("stop=max_steps pc=0x{pc:x}"));
                return DynamicRuntimeResult {
                    start_pc,
                    final_pc: pc,
                    steps,
                    path,
                    compiled_blocks: self.cfg.block_count(),
                    stop: DynamicRuntimeStop::MaxSteps,
                };
            }

            let block = match self.cfg.get_or_compile(pc, memory) {
                Ok(block) => {
                    dyn_trace_line(&format!(
                        "compiled addr=0x{:x} id=0x{:x} size=0x{:x} term={:?}",
                        block.addr, block.block_id, block.size_bytes, block.terminator
                    ));
                    block
                }
                Err(err) => {
                    dyn_trace_line(&format!("stop=lift_error pc=0x{pc:x} err={err:?}"));
                    return DynamicRuntimeResult {
                        start_pc,
                        final_pc: pc,
                        steps,
                        path,
                        compiled_blocks: self.cfg.block_count(),
                        stop: DynamicRuntimeStop::LiftError(pc, format!("{err:?}")),
                    };
                }
            };

            path.push(block.addr);
            dyn_trace_line(&format!("enter addr=0x{:x}", block.addr));
            dyn_trace_ctx("enter_ctx", ctx);
            let mut next_pc = unsafe { (block.entry)(ctx as *mut JitContext) };
            if matches!(block.terminator, crate::dyncfg::BlockTerminator::Return) {
                next_pc = ctx.x[30];
            }
            steps += 1;
            dyn_trace_line(&format!("leave addr=0x{:x} next=0x{next_pc:x}", block.addr));
            dyn_trace_ctx("leave_ctx", ctx);

            if next_pc == AEON_DYN_BAIL_SENTINEL {
                let bail_pc = ctx.pc;
                dyn_trace_line(&format!("stop=bridge_bail pc=0x{bail_pc:x}"));
                return DynamicRuntimeResult {
                    start_pc,
                    final_pc: bail_pc,
                    steps,
                    path,
                    compiled_blocks: self.cfg.block_count(),
                    stop: DynamicRuntimeStop::CodeRangeExit(bail_pc),
                };
            }

            if next_pc == 0 {
                ctx.pc = 0;
                dyn_trace_line("stop=halted");
                return DynamicRuntimeResult {
                    start_pc,
                    final_pc: 0,
                    steps,
                    path,
                    compiled_blocks: self.cfg.block_count(),
                    stop: DynamicRuntimeStop::Halted,
                };
            }

            ctx.pc = next_pc;
        }
    }
}

impl Default for DynamicRuntime {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::SnapshotMemory;

    fn push_word(buf: &mut Vec<u8>, word: u32) {
        buf.extend_from_slice(&word.to_le_bytes());
    }

    #[test]
    fn run_starts_from_exact_mid_block_pc() {
        let mut mem = SnapshotMemory::new();
        let mut code = Vec::new();
        push_word(&mut code, 0xd2800020); // mov x0, #1
        push_word(&mut code, 0xd2800041); // mov x1, #2
        push_word(&mut code, 0xd65f03c0); // ret
        mem.add_region(0x1000, code);

        let mut ctx = JitContext::default();
        ctx.pc = 0x1004;
        ctx.x[30] = 0;

        let mut runtime = DynamicRuntime::new();
        let result = runtime.run(
            &mut ctx,
            &mem,
            DynamicRuntimeConfig {
                max_steps: 8,
                code_range: Some((0x1000, 0x2000)),
            },
        );

        assert_eq!(result.stop, DynamicRuntimeStop::Halted);
        assert_eq!(result.steps, 1);
        assert_eq!(result.path, vec![0x1004]);
        assert_eq!(ctx.pc, 0);
        assert_eq!(ctx.x[0], 0);
        assert_eq!(ctx.x[1], 2);
        assert!(!runtime.has_block(0x1000));
        assert!(runtime.has_block(0x1004));
    }

    #[test]
    fn run_compiles_direct_callee_and_exact_post_call_pc() {
        let mut mem = SnapshotMemory::new();

        let mut caller = Vec::new();
        push_word(&mut caller, 0x94000400); // bl 0x2000
        push_word(&mut caller, 0xd2800041); // mov x1, #2
        push_word(&mut caller, 0xd280001e); // mov x30, #0
        push_word(&mut caller, 0xd65f03c0); // ret
        mem.add_region(0x1000, caller);

        let mut callee = Vec::new();
        push_word(&mut callee, 0xd28000a2); // mov x2, #5
        push_word(&mut callee, 0xd65f03c0); // ret
        mem.add_region(0x2000, callee);

        let mut ctx = JitContext::default();
        ctx.pc = 0x1000;
        ctx.x[30] = 0;

        let mut runtime = DynamicRuntime::new();
        let result = runtime.run(
            &mut ctx,
            &mem,
            DynamicRuntimeConfig {
                max_steps: 8,
                code_range: Some((0x1000, 0x4000)),
            },
        );

        assert_eq!(result.stop, DynamicRuntimeStop::Halted);
        assert_eq!(result.steps, 3);
        assert_eq!(result.path, vec![0x1000, 0x2000, 0x1004]);
        assert_eq!(ctx.pc, 0);
        assert_eq!(ctx.x[1], 2);
        assert_eq!(ctx.x[2], 5);
        assert!(runtime.has_block(0x1000));
        assert!(runtime.has_block(0x2000));
        assert!(runtime.has_block(0x1004));
    }

    #[test]
    fn run_uses_x30_for_return_blocks() {
        let mut mem = SnapshotMemory::new();
        let mut code = Vec::new();
        push_word(&mut code, 0xd65f03c0); // ret
        mem.add_region(0x1000, code);

        let mut ctx = JitContext::default();
        ctx.pc = 0x1000;
        ctx.x[30] = 0x2000;

        let mut runtime = DynamicRuntime::new();
        let result = runtime.run(
            &mut ctx,
            &mem,
            DynamicRuntimeConfig {
                max_steps: 8,
                code_range: Some((0x1000, 0x1004)),
            },
        );

        assert_eq!(result.path, vec![0x1000]);
        assert_eq!(result.steps, 1);
        assert_eq!(result.final_pc, 0x2000);
        assert_eq!(ctx.pc, 0x2000);
        assert_eq!(result.stop, DynamicRuntimeStop::CodeRangeExit(0x2000));
    }
}
