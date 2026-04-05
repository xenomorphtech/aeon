// Snapshot loading for Frida captures
//
// Loads a capture directory produced by the Frida agent into a LiveContext
// that the InstrumentEngine can execute.
//
// Capture directory layout:
//   snapshot.json       - registers, region manifest, module info
//   module.bin          - raw module memory at runtime base address
//   stack.bin           - stack region around SP
//   tls.bin             - TLS block (tpidr_el0 region)
//   arg_x0.bin ...      - memory at argument register pointers
//
// The key advantage over static binary loading: memory is captured from the
// live process, so GOT entries are relocated, globals are initialized, and
// register state reflects actual function arguments.

use std::error::Error;
use std::fs;
use std::path::Path;

use aeon_jit::JitContext;
use serde::{Deserialize, Serialize};

use crate::context::{LiveContext, SnapshotMemory};

#[cfg(target_os = "android")]
const MAP_FIXED_NOREPLACE_FLAG: libc::c_int = 0x100000;
#[cfg(not(target_os = "android"))]
const MAP_FIXED_NOREPLACE_FLAG: libc::c_int = libc::MAP_FIXED_NOREPLACE;

/// Metadata for a captured memory region.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionRef {
    /// Runtime virtual address where this region was captured.
    pub address: String,
    /// Size in bytes.
    pub size: u64,
    /// Filename (relative to capture directory) containing the raw bytes.
    pub file: String,
    /// Human-readable label (module, stack, tls, arg_x0, ...).
    #[serde(default)]
    pub label: Option<String>,
}

/// Register state captured at function entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterCapture {
    /// General purpose registers x0-x30 as hex/decimal strings.
    pub x: Vec<String>,
    pub sp: String,
    pub pc: String,
    #[serde(default = "default_zero")]
    pub tpidr_el0: String,
}

fn default_zero() -> String {
    "0x0".to_string()
}

/// Full snapshot metadata (deserialized from snapshot.json).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureMetadata {
    pub function_name: String,
    #[serde(default)]
    pub module_name: Option<String>,
    #[serde(default)]
    pub module_base: Option<String>,
    #[serde(default)]
    pub module_path: Option<String>,
    #[serde(default)]
    pub target_offset: Option<String>,
    #[serde(default)]
    pub jit_base: Option<String>,
    #[serde(default)]
    pub analysis_base: Option<String>,
    #[serde(default)]
    pub code_range_start: Option<String>,
    #[serde(default)]
    pub code_range_end: Option<String>,
    pub registers: RegisterCapture,
    pub regions: Vec<RegionRef>,
    #[serde(default)]
    pub timestamp: Option<String>,
    #[serde(default)]
    pub arch: Option<String>,
}

/// Parse a number from a string that may be hex (0x...) or decimal.
fn parse_u64(s: &str) -> Result<u64, Box<dyn Error>> {
    let s = s.trim();
    if s.starts_with("0x") || s.starts_with("0X") {
        Ok(u64::from_str_radix(&s[2..], 16)?)
    } else {
        Ok(s.parse::<u64>()?)
    }
}

/// Load a Frida capture directory into a LiveContext.
///
/// Reads snapshot.json for register state and region manifest,
/// then loads each referenced binary file into a SnapshotMemory.
pub fn load_capture(dir: &Path) -> Result<(LiveContext, CaptureMetadata), Box<dyn Error>> {
    let meta_path = dir.join("snapshot.json");
    let meta_str = fs::read_to_string(&meta_path)
        .map_err(|e| format!("reading {}: {}", meta_path.display(), e))?;
    let meta: CaptureMetadata =
        serde_json::from_str(&meta_str).map_err(|e| format!("parsing snapshot.json: {}", e))?;

    // Build memory from captured regions
    let mut memory = SnapshotMemory::new();
    let mut total_bytes = 0u64;

    for region in &meta.regions {
        let addr = parse_u64(&region.address)?;
        let file_path = dir.join(&region.file);

        let data =
            fs::read(&file_path).map_err(|e| format!("reading {}: {}", file_path.display(), e))?;

        let actual_size = data.len() as u64;
        if actual_size != region.size {
            eprintln!(
                "warning: region {} expected {} bytes, got {} bytes",
                region.file, region.size, actual_size
            );
        }

        memory.add_region(addr, data);
        total_bytes += actual_size;
    }

    eprintln!(
        "loaded {} regions ({:.1} MB) from {}",
        meta.regions.len(),
        total_bytes as f64 / (1024.0 * 1024.0),
        dir.display()
    );

    // Build register state
    let mut regs = JitContext::default();

    if meta.registers.x.len() < 31 {
        return Err(format!(
            "expected 31 registers in x[], got {}",
            meta.registers.x.len()
        )
        .into());
    }
    for (i, val) in meta.registers.x.iter().enumerate().take(31) {
        regs.x[i] = parse_u64(val)?;
    }
    regs.sp = parse_u64(&meta.registers.sp)?;
    regs.pc = parse_u64(&meta.registers.pc)?;
    regs.tpidr_el0 = parse_u64(&meta.registers.tpidr_el0)?;

    let ctx = LiveContext {
        regs,
        memory: Box::new(memory),
    };

    Ok((ctx, meta))
}

/// Create a synthetic capture directory for testing.
/// Returns the directory path.
pub fn write_test_capture(
    dir: &Path,
    pc: u64,
    sp: u64,
    code: &[u8],
    code_addr: u64,
) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(dir)?;

    // Write code region
    let code_file = "code.bin";
    fs::write(dir.join(code_file), code)?;

    // Write stack region (zeroed)
    let stack_file = "stack.bin";
    let stack_size = 0x10000u64;
    let stack_addr = sp - stack_size / 2;
    fs::write(dir.join(stack_file), vec![0u8; stack_size as usize])?;

    // Write snapshot.json
    let meta = CaptureMetadata {
        function_name: "test".to_string(),
        module_name: Some("test".to_string()),
        module_base: Some(format!("0x{:x}", code_addr)),
        module_path: None,
        target_offset: None,
        jit_base: None,
        analysis_base: None,
        code_range_start: None,
        code_range_end: None,
        registers: RegisterCapture {
            x: (0..31).map(|_| "0x0".to_string()).collect(),
            sp: format!("0x{:x}", sp),
            pc: format!("0x{:x}", pc),
            tpidr_el0: format!("0x{:x}", stack_addr + 0x100),
        },
        regions: vec![
            RegionRef {
                address: format!("0x{:x}", code_addr),
                size: code.len() as u64,
                file: code_file.to_string(),
                label: Some("code".to_string()),
            },
            RegionRef {
                address: format!("0x{:x}", stack_addr),
                size: stack_size,
                file: stack_file.to_string(),
                label: Some("stack".to_string()),
            },
        ],
        timestamp: None,
        arch: Some("arm64".to_string()),
    };

    let json = serde_json::to_string_pretty(&meta)?;
    fs::write(dir.join("snapshot.json"), json)?;

    Ok(())
}

/// RAII guard for mmap'd regions at captured runtime addresses.
/// The JIT-compiled code does real x86_64 memory ops at these addresses.
pub struct MappedCapture {
    regions: Vec<(*mut std::ffi::c_void, usize)>,
}

impl MappedCapture {
    /// Map all snapshot regions at their original runtime addresses.
    /// Also allocates a host stack if no stack region was captured.
    pub fn map(
        ctx: &mut LiveContext,
        meta: &CaptureMetadata,
        capture_dir: &Path,
    ) -> Result<Self, Box<dyn Error>> {
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as u64 };
        let mut regions = Vec::new();

        for region in &meta.regions {
            let addr = parse_u64(&region.address)?;
            let file_path = capture_dir.join(&region.file);
            let data = fs::read(&file_path)?;
            if data.is_empty() {
                continue;
            }

            let start = addr & !(page_size - 1);
            let end = (addr + data.len() as u64 + page_size - 1) & !(page_size - 1);
            let len = (end - start) as usize;

            let mapped = unsafe {
                libc::mmap(
                    start as *mut std::ffi::c_void,
                    len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | MAP_FIXED_NOREPLACE_FLAG,
                    -1,
                    0,
                )
            };
            if mapped == libc::MAP_FAILED {
                eprintln!(
                    "warning: mmap failed for {} at 0x{:x}..0x{:x}: {}",
                    region.file,
                    start,
                    end,
                    std::io::Error::last_os_error()
                );
                continue;
            }
            regions.push((mapped, len));

            // Copy data into the mapped region
            unsafe {
                std::ptr::copy_nonoverlapping(data.as_ptr(), addr as *mut u8, data.len());
            }
            eprintln!(
                "mapped {} at 0x{:x} ({} bytes)",
                region.label.as_deref().unwrap_or(&region.file),
                addr,
                data.len()
            );
        }

        // Allocate host stack pages around SP if not already mapped.
        // Map individual pages to avoid overlapping with other regions.
        let sp = ctx.regs.sp;
        let sp_page = sp & !(page_size - 1);
        // Map 64 pages below SP and 4 above (256KB below + 16KB above)
        for offset in -64i64..4 {
            let page_addr = (sp_page as i64 + offset * page_size as i64) as u64;
            // Skip if this page is already within a mapped region
            let already_mapped = regions.iter().any(|&(ptr, len)| {
                let base = ptr as u64;
                page_addr >= base && page_addr < base + len as u64
            });
            if already_mapped {
                continue;
            }
            let mapped = unsafe {
                libc::mmap(
                    page_addr as *mut std::ffi::c_void,
                    page_size as usize,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | MAP_FIXED_NOREPLACE_FLAG,
                    -1,
                    0,
                )
            };
            if mapped != libc::MAP_FAILED {
                regions.push((mapped, page_size as usize));
            }
        }
        eprintln!("mapped stack pages around SP 0x{:x}", sp);

        Ok(Self { regions })
    }
}

impl Drop for MappedCapture {
    fn drop(&mut self) {
        for &(addr, len) in &self.regions {
            unsafe {
                libc::munmap(addr, len);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hex_and_decimal() {
        assert_eq!(parse_u64("0x1000").unwrap(), 0x1000);
        assert_eq!(parse_u64("0X1000").unwrap(), 0x1000);
        assert_eq!(parse_u64("4096").unwrap(), 4096);
        assert_eq!(parse_u64("0xDEADBEEF").unwrap(), 0xDEADBEEF);
        assert_eq!(parse_u64("0x0").unwrap(), 0);
    }

    #[test]
    fn write_and_load_capture() {
        let dir = std::env::temp_dir().join("aeon_snapshot_test");
        let _ = std::fs::remove_dir_all(&dir);

        // ARM64: MOV X0, #42; RET
        let code: Vec<u8> = vec![
            0x40, 0x05, 0x80, 0xD2, // mov x0, #42
            0xC0, 0x03, 0x5F, 0xD6, // ret
        ];
        let code_addr = 0x400000u64;
        let sp = 0x7fff0000u64;

        write_test_capture(&dir, code_addr, sp, &code, code_addr).unwrap();

        let (ctx, meta) = load_capture(&dir).unwrap();

        assert_eq!(ctx.pc(), code_addr);
        assert_eq!(ctx.regs.sp, sp);
        assert_eq!(meta.function_name, "test");
        assert_eq!(meta.regions.len(), 2);

        // Verify code bytes are readable
        let bytes = ctx.memory.read(code_addr, 4).unwrap();
        assert_eq!(bytes, &code[..4]);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
