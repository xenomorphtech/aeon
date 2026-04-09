use aeon_instrument::translate::{
    compact_map_jsonl_path, compact_map_path, format_compact_map_jsonl, format_trap_block_log,
    link_object_with, load_symbol_map, rebase_text_symbol_map, translate_blob, trap_log_path,
    FullMapMetadata, TranslationConfig, DEFAULT_BASE, DEFAULT_DEST, DEFAULT_INPUT,
    DEFAULT_OUTPUT_ELF, DEFAULT_OUTPUT_MAP, DEFAULT_OUTPUT_OBJ,
};
use std::env;
use std::fs;
use std::path::PathBuf;

fn main() -> Result<(), String> {
    let config = Config::parse(env::args().skip(1))?;
    let blob =
        fs::read(&config.input).map_err(|err| format!("read {}: {err}", config.input.display()))?;
    let compilation = translate_blob(
        &blob,
        &TranslationConfig {
            base: config.base,
            instructions: config.instructions,
        },
    )?;

    fs::write(&config.output_obj, &compilation.object_bytes)
        .map_err(|err| format!("write {}: {err}", config.output_obj.display()))?;

    let compact_map = compilation.compact_map(config.base);
    fs::write(
        &config.output_compact_map,
        serde_json::to_vec(&compact_map).map_err(|err| format!("serialize compact map: {err}"))?,
    )
    .map_err(|err| format!("write {}: {err}", config.output_compact_map.display()))?;
    fs::write(
        &config.output_compact_map_jsonl,
        format_compact_map_jsonl(&compact_map)?,
    )
    .map_err(|err| format!("write {}: {err}", config.output_compact_map_jsonl.display()))?;

    println!("wrote {}", config.output_obj.display());
    println!("compact map {}", config.output_compact_map.display());
    println!(
        "compact map jsonl {}",
        config.output_compact_map_jsonl.display()
    );

    if config.skip_link {
        println!(
            "compiled {} blocks ({} trap-only emitted, {} invalid instructions)",
            compilation.block_count, compilation.trap_block_count, compilation.invalid_instructions
        );
        println!("link step skipped");
        return Ok(());
    }

    link_object_with(
        &config.output_obj,
        &config.output_elf,
        config.dest,
        config.linker.as_deref(),
    )?;
    let symbol_map = rebase_text_symbol_map(
        &config.output_elf,
        &load_symbol_map(&config.output_elf)?,
        config.dest,
    )?;
    let metadata = FullMapMetadata {
        input: config.input.display().to_string(),
        output_object: config.output_obj.display().to_string(),
        output_elf: config.output_elf.display().to_string(),
        output_map: config.output_map.display().to_string(),
        base: config.base,
        dest: config.dest,
    };
    let full_map = compilation.full_map(&metadata, &symbol_map);
    let trap_block_log = trap_log_path(&config.output_map);
    fs::write(
        &trap_block_log,
        format_trap_block_log(&full_map.trap_blocks)
            .map_err(|err| format!("serialize trap log {}: {err}", trap_block_log.display()))?,
    )
    .map_err(|err| format!("write {}: {err}", trap_block_log.display()))?;
    fs::write(
        &config.output_map,
        serde_json::to_vec_pretty(&full_map).map_err(|err| format!("serialize map: {err}"))?,
    )
    .map_err(|err| format!("write {}: {err}", config.output_map.display()))?;

    println!("linked {}", config.output_elf.display());
    println!("map {}", config.output_map.display());
    println!("trap log {}", trap_block_log.display());
    println!(
        "compiled {} blocks ({} trap-only emitted, {} invalid instructions)",
        compilation.block_count, compilation.trap_block_count, compilation.invalid_instructions
    );
    Ok(())
}

struct Config {
    input: PathBuf,
    output_obj: PathBuf,
    output_elf: PathBuf,
    output_map: PathBuf,
    output_compact_map: PathBuf,
    output_compact_map_jsonl: PathBuf,
    base: u64,
    dest: u64,
    instructions: Option<usize>,
    linker: Option<PathBuf>,
    skip_link: bool,
}

impl Config {
    fn parse<I>(mut args: I) -> Result<Self, String>
    where
        I: Iterator<Item = String>,
    {
        let mut input = PathBuf::from(DEFAULT_INPUT);
        let mut output_obj = PathBuf::from(DEFAULT_OUTPUT_OBJ);
        let mut output_elf = PathBuf::from(DEFAULT_OUTPUT_ELF);
        let mut output_map = PathBuf::from(DEFAULT_OUTPUT_MAP);
        let mut output_compact_map = None;
        let mut output_compact_map_jsonl = None;
        let mut base = DEFAULT_BASE;
        let mut dest = DEFAULT_DEST;
        let mut instructions = None;
        let mut linker = None;
        let mut skip_link = false;

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--input" => input = PathBuf::from(next_arg(&mut args, "--input")?),
                "--output-obj" => output_obj = PathBuf::from(next_arg(&mut args, "--output-obj")?),
                "--output-elf" => output_elf = PathBuf::from(next_arg(&mut args, "--output-elf")?),
                "--output-map" => output_map = PathBuf::from(next_arg(&mut args, "--output-map")?),
                "--output-compact-map" => {
                    output_compact_map =
                        Some(PathBuf::from(next_arg(&mut args, "--output-compact-map")?))
                }
                "--output-compact-map-jsonl" => {
                    output_compact_map_jsonl = Some(PathBuf::from(next_arg(
                        &mut args,
                        "--output-compact-map-jsonl",
                    )?))
                }
                "--base" => base = parse_u64(&next_arg(&mut args, "--base")?)?,
                "--dest" => dest = parse_u64(&next_arg(&mut args, "--dest")?)?,
                "--instructions" => {
                    instructions = Some(parse_usize(&next_arg(&mut args, "--instructions")?)?)
                }
                "--linker" => linker = Some(PathBuf::from(next_arg(&mut args, "--linker")?)),
                "--skip-link" => skip_link = true,
                "--help" | "-h" => {
                    print_usage();
                    std::process::exit(0);
                }
                other => return Err(format!("unknown argument: {other}")),
            }
        }

        Ok(Self {
            input,
            output_obj,
            output_elf,
            output_compact_map: output_compact_map.unwrap_or_else(|| compact_map_path(&output_map)),
            output_compact_map_jsonl: output_compact_map_jsonl
                .unwrap_or_else(|| compact_map_jsonl_path(&output_map)),
            output_map,
            base,
            dest,
            instructions,
            linker,
            skip_link,
        })
    }
}

fn next_arg<I>(args: &mut I, flag: &str) -> Result<String, String>
where
    I: Iterator<Item = String>,
{
    args.next()
        .ok_or_else(|| format!("missing value for {flag}"))
}

fn parse_u64(value: &str) -> Result<u64, String> {
    if let Some(hex) = value.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).map_err(|err| format!("invalid u64 {value}: {err}"))
    } else {
        value
            .parse::<u64>()
            .map_err(|err| format!("invalid u64 {value}: {err}"))
    }
}

fn parse_usize(value: &str) -> Result<usize, String> {
    if let Some(hex) = value.strip_prefix("0x") {
        usize::from_str_radix(hex, 16).map_err(|err| format!("invalid usize {value}: {err}"))
    } else {
        value
            .parse::<usize>()
            .map_err(|err| format!("invalid usize {value}: {err}"))
    }
}

fn print_usage() {
    eprintln!(
        "usage: jit_translate_object [--input BIN] [--base ADDR] [--dest ADDR] [--instructions N] [--output-obj PATH] [--output-elf PATH] [--output-map PATH] [--output-compact-map PATH] [--output-compact-map-jsonl PATH] [--linker PATH] [--skip-link]"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn default_compact_map_is_sidecar_to_output_map() {
        let config = Config::parse(
            ["--output-map".to_string(), "/tmp/out.map.json".to_string()].into_iter(),
        )
        .expect("parse");
        assert_eq!(
            config.output_compact_map,
            compact_map_path(Path::new("/tmp/out.map.json"))
        );
        assert_eq!(
            config.output_compact_map_jsonl,
            compact_map_jsonl_path(Path::new("/tmp/out.map.json"))
        );
    }

    #[test]
    fn parse_skip_link_and_linker() {
        let config = Config::parse(
            [
                "--skip-link".to_string(),
                "--linker".to_string(),
                "/tmp/ld.lld".to_string(),
            ]
            .into_iter(),
        )
        .expect("parse");
        assert!(config.skip_link);
        assert_eq!(config.linker, Some(PathBuf::from("/tmp/ld.lld")));
    }
}
