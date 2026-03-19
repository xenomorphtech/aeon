use std::collections::HashMap;
use std::fs;

fn main() {
    const FILE_OFFSET: usize = 0x017c9000;
    const SIZE: usize = 0x06b3bb98;

    let data = fs::read("/home/sdancer/aeon/libUnreal.so")
        .expect("failed to read libUnreal.so");

    let end = FILE_OFFSET + SIZE;
    assert!(
        end <= data.len(),
        "binary too small: need {} bytes, have {}",
        end,
        data.len()
    );

    let text = &data[FILE_OFFSET..end];

    let mut counts: HashMap<String, u64> = HashMap::new();
    let mut decode_errors: u64 = 0;

    let words = text.len() / 4;
    for i in 0..words {
        let off = i * 4;
        let word = u32::from_le_bytes(text[off..off + 4].try_into().unwrap());
        // bad64::decode takes (word, address); use a dummy vaddr
        let vaddr: u64 = 0x017cd000 + off as u64;
        match bad64::decode(word, vaddr) {
            Ok(insn) => {
                let name = format!("{:?}", insn.op());
                *counts.entry(name).or_insert(0) += 1;
            }
            Err(_) => {
                decode_errors += 1;
            }
        }
    }

    // Sort by count descending, then name ascending for ties
    let mut sorted: Vec<(String, u64)> = counts.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));

    println!("ARM64 opcode survey of libUnreal.so .text section");
    println!("  File offset : 0x{:08x}", FILE_OFFSET);
    println!("  Size        : 0x{:08x} ({} bytes)", SIZE, SIZE);
    println!("  Total words : {}", words);
    println!("  Decode errors (undefined/data): {}", decode_errors);
    println!("  Unique opcodes: {}", sorted.len());
    println!();
    println!("{:<40} {:>12}", "OPCODE", "COUNT");
    println!("{}", "-".repeat(54));
    for (op, cnt) in &sorted {
        println!("{:<40} {:>12}", op, cnt);
    }
}
