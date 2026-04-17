use std::env;
use std::fs;
use std::path::PathBuf;
use std::process;

use nmss_cert::{
    compute_merkle_cert_from_windows, compute_merkle_cert_full, read_stage_buffer,
    transliterate_hex_buffer, upper_hex, MerkleCertResult, Well512, D04_DIGEST, D09_DIGEST,
};

fn usage() -> &'static str {
    "Usage: nmss-cert <mode> [options]

Modes:
  --buffer <path>
      Compute cert from a captured 1040/1041-byte stage buffer.

  --windows <d05> <d11> <d12> <d13>
      Compute cert from explicit 8-byte ASCII windows.

  --prng-state <w0,w1,...,w15> --prng-index <N>
      Full end-to-end: seed WELL512 with 16 comma-separated u32 words
      (hex, e.g. deadbeef) and an index, generate the 1040-byte buffer,
      then compute the cert.

  --well512-state <hex128> --well512-index <N>
      Legacy: 128-byte hex blob (treated as 16 × u32 LE) + index.

Options:
  --board <8chars>          Board/SoC window (default: rk3588_s)
  --advance <N>             Advance WELL512 N steps before generating buffer
  --d04-digest <hex64>      Override D04 bootstrap digest
  --d09-digest <hex64>      Override D09 bootstrap digest
  --dump-buffer             Print the transliterated 1040-byte buffer and exit
  --json                    Emit JSON output"
}

fn parse_hex_digest(s: &str) -> [u8; 32] {
    assert_eq!(s.len(), 64, "digest must be 64 hex chars, got {}", s.len());
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("invalid hex in digest");
    }
    out
}

fn parse_hex_bytes(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "hex string must have even length");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("invalid hex"))
        .collect()
}

/// Parse "deadbeef,12345678,...,abcd0123" into `[u32; 16]`.
fn parse_prng_state(s: &str) -> [u32; 16] {
    let parts: Vec<&str> = s.split(',').collect();
    assert_eq!(
        parts.len(),
        16,
        "prng-state needs exactly 16 comma-separated u32 hex words, got {}",
        parts.len()
    );
    let mut state = [0u32; 16];
    for (i, part) in parts.iter().enumerate() {
        state[i] = u32::from_str_radix(part.trim(), 16)
            .unwrap_or_else(|e| panic!("bad u32 hex at position {i}: {part:?}: {e}"));
    }
    state
}

struct Opts {
    buffer_path: Option<PathBuf>,
    windows: Option<[String; 4]>,
    prng_state: Option<[u32; 16]>,
    prng_index: Option<usize>,
    well512_state_hex: Option<String>,
    well512_index: Option<usize>,
    board: String,
    advance: usize,
    d04: [u8; 32],
    d09: [u8; 32],
    dump_buffer: bool,
    json: bool,
}

fn parse_args() -> Opts {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("{}", usage());
        process::exit(1);
    }

    let mut opts = Opts {
        buffer_path: None,
        windows: None,
        prng_state: None,
        prng_index: None,
        well512_state_hex: None,
        well512_index: None,
        board: String::from("rk3588_s"),
        advance: 0,
        d04: D04_DIGEST,
        d09: D09_DIGEST,
        dump_buffer: false,
        json: false,
    };

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--buffer" => {
                i += 1;
                opts.buffer_path = Some(PathBuf::from(&args[i]));
            }
            "--windows" => {
                opts.windows = Some([
                    args[i + 1].clone(),
                    args[i + 2].clone(),
                    args[i + 3].clone(),
                    args[i + 4].clone(),
                ]);
                i += 4;
            }
            "--prng-state" => {
                i += 1;
                opts.prng_state = Some(parse_prng_state(&args[i]));
            }
            "--prng-index" => {
                i += 1;
                opts.prng_index = Some(args[i].parse().expect("invalid prng-index"));
            }
            "--well512-state" => {
                i += 1;
                opts.well512_state_hex = Some(args[i].clone());
            }
            "--well512-index" => {
                i += 1;
                opts.well512_index = Some(args[i].parse().expect("invalid well512-index"));
            }
            "--board" => {
                i += 1;
                opts.board = args[i].clone();
            }
            "--advance" => {
                i += 1;
                opts.advance = args[i].parse().expect("invalid advance count");
            }
            "--d04-digest" => {
                i += 1;
                opts.d04 = parse_hex_digest(&args[i]);
            }
            "--d09-digest" => {
                i += 1;
                opts.d09 = parse_hex_digest(&args[i]);
            }
            "--dump-buffer" => opts.dump_buffer = true,
            "--json" => opts.json = true,
            "--help" | "-h" => {
                println!("{}", usage());
                process::exit(0);
            }
            other => {
                eprintln!("unknown argument: {other}\n");
                eprintln!("{}", usage());
                process::exit(1);
            }
        }
        i += 1;
    }
    opts
}

fn board_bytes(board: &str) -> [u8; 8] {
    board
        .as_bytes()
        .try_into()
        .unwrap_or_else(|_| panic!("board must be exactly 8 bytes, got {}", board.len()))
}

fn make_well512(opts: &Opts) -> Well512 {
    if let Some(ref state) = opts.prng_state {
        let idx = opts
            .prng_index
            .expect("--prng-index required with --prng-state");
        Well512::new(*state, idx)
    } else if let Some(ref hex) = opts.well512_state_hex {
        let idx = opts
            .well512_index
            .expect("--well512-index required with --well512-state");
        let bytes = parse_hex_bytes(hex);
        assert!(
            bytes.len() >= 64,
            "WELL512 state needs >= 64 bytes (128 hex chars for 16 u32 LE), got {}",
            bytes.len()
        );
        Well512::from_le_bytes(&bytes, idx)
    } else {
        unreachable!()
    }
}

fn run_buffer_mode(opts: &Opts) -> (Vec<u8>, String) {
    if let Some(ref path) = opts.buffer_path {
        let data = fs::read(path).unwrap_or_else(|e| {
            eprintln!("failed to read {}: {e}", path.display());
            process::exit(1);
        });
        let buf = read_stage_buffer(&data).unwrap_or_else(|e| {
            eprintln!("{e}");
            process::exit(1);
        });
        (buf.to_vec(), path.display().to_string())
    } else {
        let mut well = make_well512(opts);
        let source = format!(
            "well512(state[0]={:#010x}, index={}, advance={})",
            well.state[0], well.index, opts.advance
        );
        if opts.advance > 0 {
            well.advance(opts.advance);
        }
        let hex_buf = well.generate_hex_buffer(1040);
        (transliterate_hex_buffer(&hex_buf), source)
    }
}

fn print_buffer_result(result: &MerkleCertResult, source: &str, board: &str, json: bool) {
    if json {
        println!("{{");
        println!("  \"source\": {:?},", source);
        println!("  \"board_window\": {:?},", board);
        print_result_fields(result, true);
        println!("}}");
    } else {
        println!("source={source}");
        println!("board_window={board}");
        print_result_fields(result, false);
    }
}

fn print_result_fields(r: &MerkleCertResult, json: bool) {
    let fields = [
        (
            "d05_window",
            String::from_utf8_lossy(&r.d05_window).into_owned(),
        ),
        (
            "d11_window",
            String::from_utf8_lossy(&r.d11_window).into_owned(),
        ),
        (
            "d12_window",
            String::from_utf8_lossy(&r.d12_window).into_owned(),
        ),
        (
            "d13_window",
            String::from_utf8_lossy(&r.d13_window).into_owned(),
        ),
        ("phase2a_digest_hex", upper_hex(&r.phase2a_digest)),
        ("final_digest_hex", upper_hex(&r.final_digest)),
        ("cert_hex", r.cert_hex.clone()),
    ];
    for (i, (key, val)) in fields.iter().enumerate() {
        if json {
            let comma = if i < fields.len() - 1 { "," } else { "" };
            println!("  \"{key}\": \"{val}\"{comma}");
        } else {
            println!("{key}={val}");
        }
    }
}

fn main() {
    let opts = parse_args();
    let bw = board_bytes(&opts.board);

    // Mode: explicit windows — no buffer needed.
    if let Some(ref w) = opts.windows {
        let d05: [u8; 8] = w[0].as_bytes().try_into().expect("d05 must be 8 bytes");
        let d11: [u8; 8] = w[1].as_bytes().try_into().expect("d11 must be 8 bytes");
        let d12: [u8; 8] = w[2].as_bytes().try_into().expect("d12 must be 8 bytes");
        let d13: [u8; 8] = w[3].as_bytes().try_into().expect("d13 must be 8 bytes");
        let result = compute_merkle_cert_from_windows(
            &d05, &bw, &d11, &d12, &d13, &opts.d04, &opts.d09,
        );
        if opts.json {
            println!("{{");
            println!("  \"mode\": \"windows\",");
            println!("  \"board_window\": {:?},", opts.board);
            print_result_fields(&result, true);
            println!("}}");
        } else {
            println!("mode=windows");
            println!("board_window={}", opts.board);
            print_result_fields(&result, false);
        }
        return;
    }

    // Modes that produce a transliterated buffer: --buffer, --prng-state, --well512-state.
    if opts.buffer_path.is_some() || opts.prng_state.is_some() || opts.well512_state_hex.is_some()
    {
        let (transliterated, source) = run_buffer_mode(&opts);

        if opts.dump_buffer {
            println!("{}", String::from_utf8_lossy(&transliterated));
            return;
        }

        let result = compute_merkle_cert_full(&transliterated, &bw, &opts.d04, &opts.d09);
        print_buffer_result(&result, &source, &opts.board, opts.json);
        return;
    }

    eprintln!("no input mode specified\n");
    eprintln!("{}", usage());
    process::exit(1);
}
