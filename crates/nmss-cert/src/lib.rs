//! Offline NMSS cert reproducer — Merkle/SHA-256 round chain model.
//!
//! # Pipeline
//!
//! The actual `getCertValue()` pipeline (confirmed by breakpoint tracing in
//! `pipeline_capture_events.json` — zero xxHash hits during cert calls):
//!
//! 1. WELL512 PRNG generates a 1040-char uppercase hex buffer.
//! 2. Transliterate A-F → 1-6 (hex digits become decimal-only ASCII).
//! 3. Read fixed 8-byte windows at buffer offsets `0x0f`, `0x32f`, `0x394`, `0x3f3`.
//! 4. Run a 14-round SHA-256 chain (D00–D13) using traced bootstrap digests.
//! 5. Extract `digest[4..28]` as uppercase hex → the 48-char cert string.
//!
//! # xxHash64 clarification
//!
//! The xxHash64 model (16449-byte composite buffer, custom init constants) fires
//! **only** during `loadCr()` / init — 1 entry, 15 updates, 1 finalize — and is
//! NOT invoked by `getCertValue()`.

use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Buffer offset where the D05 Merkle-chain window is read (8 bytes at `0x0F`).
pub const WINDOW_D05_OFFSET: usize = 0x0F;

/// Buffer offset where the D11 detection-digit window is read (8 bytes at `0x32F`).
pub const WINDOW_D11_OFFSET: usize = 0x32F;

/// Buffer offset where the D12 detection-digit window is read (8 bytes at `0x394`).
pub const WINDOW_D12_OFFSET: usize = 0x394;

/// Buffer offset where the D13 detection-digit window is read (8 bytes at `0x3F3`).
pub const WINDOW_D13_OFFSET: usize = 0x3F3;

/// Size of every window consumed by the SHA-256 round chain.
pub const WINDOW_SIZE: usize = 8;

/// Default device/board identifier (Rockchip RK3588 — the D10 window).
pub const BOARD_WINDOW: &[u8; 8] = b"rk3588_s";

/// Bootstrap digest after round D04 (challenge/run-key hash).
///
/// This is session-specific: it depends on the run-key that was active when
/// the SHA-256 chain was traced.
pub const D04_DIGEST: [u8; 32] = hex_const(
    "CC937E2C28215FFA6B8225140B57DB0BA90E5C179BF0CAD559F91FFFB7C29C38",
);

/// Bootstrap digest after round D09 (SHA-256 padding block between phase 2a
/// and phase 2b).
pub const D09_DIGEST: [u8; 32] = hex_const(
    "0929980627E33BBAED09DA0248A00147FBD10ACB0980798ACA74BC7FD8E0D33A",
);

/// Hex alphabet used by WELL512 → hex-buffer generation.
const HEX_ALPHABET: &[u8; 16] = b"0123456789ABCDEF";

// ---------------------------------------------------------------------------
// Compile-time hex helpers
// ---------------------------------------------------------------------------

/// Convert a 64-char hex string to `[u8; 32]` at compile time.
const fn hex_const(s: &str) -> [u8; 32] {
    let b = s.as_bytes();
    assert!(b.len() == 64, "hex_const requires exactly 64 hex chars");
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (hex_nibble(b[i * 2]) << 4) | hex_nibble(b[i * 2 + 1]);
        i += 1;
    }
    out
}

const fn hex_nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'A'..=b'F' => c - b'A' + 10,
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("invalid hex nibble"),
    }
}

// ---------------------------------------------------------------------------
// WELL512 PRNG
// ---------------------------------------------------------------------------

/// WELL512a pseudo-random number generator.
///
/// State is 16 × `u32` words plus a circular index (0–15).  Each [`step`]
/// call produces one `u32` output and advances the state.
///
/// The NMSS JIT uses this PRNG to generate the 1040-char hex buffer that
/// feeds the Merkle cert chain.  The remaining gap in offline reproduction
/// is knowing the exact WELL512 state at `getCertValue()` call time.
///
/// [`step`]: Well512::step
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Well512 {
    /// The 16-word state ring.
    pub state: [u32; 16],
    /// Current index into the state ring (0–15).
    pub index: usize,
}

impl Well512 {
    /// Create a new WELL512 instance from an explicit state and index.
    ///
    /// `index` is masked to 0–15.
    pub fn new(state: [u32; 16], index: usize) -> Self {
        Self {
            state,
            index: index & 0xF,
        }
    }

    /// Deserialise state from a 64-byte little-endian blob (16 × `u32` LE).
    pub fn from_le_bytes(bytes: &[u8], index: usize) -> Self {
        assert!(bytes.len() >= 64, "need at least 64 bytes for 16 u32s");
        let mut state = [0u32; 16];
        for i in 0..16 {
            let off = i * 4;
            state[i] = u32::from_le_bytes([
                bytes[off],
                bytes[off + 1],
                bytes[off + 2],
                bytes[off + 3],
            ]);
        }
        Self::new(state, index)
    }

    /// Advance one step and return the generated `u32`.
    pub fn step(&mut self) -> u32 {
        let z0 = self.state[self.index];
        let z1 = self.state[(self.index + 13) & 0xF];
        let z2_raw = self.state[(self.index + 9) & 0xF];

        let v0 = (z1 ^ z0) ^ (z0 << 16);
        let z2 = z2_raw ^ (z2_raw >> 11);
        let v0 = v0 ^ (z1 << 15);
        let v1 = v0 ^ z2;
        self.state[self.index] = v1;

        self.index = (self.index + 15) & 0xF;
        let old = self.state[self.index];
        let mut result = old ^ z2;
        result ^= v0 << 18;
        result ^= z2 << 28;
        result ^= old << 2;
        result ^= (v1 << 5) & 0xDA442D20;
        self.state[self.index] = result;
        result
    }

    /// Advance by `n` steps, discarding output.
    pub fn advance(&mut self, n: usize) {
        for _ in 0..n {
            self.step();
        }
    }

    /// Generate a hex buffer of `length` uppercase hex characters.
    ///
    /// Each character is derived from the low nibble (`& 0xF`) of one PRNG
    /// step, mapped through `0123456789ABCDEF`.
    pub fn generate_hex_buffer(&mut self, length: usize) -> Vec<u8> {
        (0..length)
            .map(|_| {
                let value = self.step();
                HEX_ALPHABET[(value & 0xF) as usize]
            })
            .collect()
    }
}

/// Transliterate a hex buffer in-place: `A`→`1`, `B`→`2`, … `F`→`6`.
///
/// Digits `0`–`9` are kept as-is.  This matches the NMSS JIT's
/// `TRANSLIT_HEX_TO_DIGITS` table that converts the WELL512 hex output
/// into a decimal-digit-only ASCII buffer before window extraction.
pub fn transliterate_hex_buffer(hex_buf: &[u8]) -> Vec<u8> {
    hex_buf
        .iter()
        .map(|&b| match b {
            b'A' | b'a' => b'1',
            b'B' | b'b' => b'2',
            b'C' | b'c' => b'3',
            b'D' | b'd' => b'4',
            b'E' | b'e' => b'5',
            b'F' | b'f' => b'6',
            _ => b,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// SHA-256 round chain
// ---------------------------------------------------------------------------

/// Compute one SHA-256 round: `SHA256(window_8 || previous_digest_32)`.
///
/// The Merkle chain threads the digest through the *message* (not the IV):
/// each round hashes the 8-byte window concatenated with the previous 32-byte
/// digest, always starting from `SHA256_IV`.
pub fn sha256_round(window: &[u8; 8], previous_digest: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(window);
    hasher.update(previous_digest);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Output of the Merkle cert-stage computation.
#[derive(Clone, Debug)]
pub struct MerkleCertResult {
    /// 8-byte window used for D05–D08 (phase 2a, 4 repeated rounds).
    pub d05_window: [u8; 8],
    /// 8-byte detection-digit window for D11.
    pub d11_window: [u8; 8],
    /// 8-byte detection-digit window for D12.
    pub d12_window: [u8; 8],
    /// 8-byte detection-digit window for D13.
    pub d13_window: [u8; 8],
    /// Digest after phase 2a (D05–D08), before the padding round D09.
    pub phase2a_digest: [u8; 32],
    /// Final 32-byte SHA-256 digest from round D13.
    pub final_digest: [u8; 32],
    /// The 48-char uppercase hex cert: `digest[4..28].hex().upper()`.
    pub cert_hex: String,
}

/// Extract an 8-byte window from a buffer at a given offset.
fn extract_window(buffer: &[u8], offset: usize) -> [u8; 8] {
    let mut w = [0u8; 8];
    w.copy_from_slice(&buffer[offset..offset + WINDOW_SIZE]);
    w
}

/// Compute the Merkle cert from a 1040-byte transliterated detection buffer.
///
/// Uses the default bootstrap digests ([`D04_DIGEST`], [`D09_DIGEST`]) and
/// the caller-supplied board window (typically [`BOARD_WINDOW`]).
///
/// # Panics
///
/// Panics if `transliterated_buffer.len() != 1040`.
pub fn compute_merkle_cert(
    transliterated_buffer: &[u8],
    board_window: &[u8; 8],
) -> MerkleCertResult {
    compute_merkle_cert_full(
        transliterated_buffer,
        board_window,
        &D04_DIGEST,
        &D09_DIGEST,
    )
}

/// Compute the Merkle cert with explicit bootstrap digests.
///
/// This is the fully-parameterised entry point.  Use this when replaying a
/// session whose D04/D09 bootstrap digests differ from the compiled-in
/// defaults.
///
/// # Panics
///
/// Panics if `transliterated_buffer.len() != 1040`.
pub fn compute_merkle_cert_full(
    transliterated_buffer: &[u8],
    board_window: &[u8; 8],
    d04_digest: &[u8; 32],
    d09_digest: &[u8; 32],
) -> MerkleCertResult {
    assert_eq!(
        transliterated_buffer.len(),
        1040,
        "transliterated buffer must be 1040 bytes"
    );

    let d05_window = extract_window(transliterated_buffer, WINDOW_D05_OFFSET);
    let d11_window = extract_window(transliterated_buffer, WINDOW_D11_OFFSET);
    let d12_window = extract_window(transliterated_buffer, WINDOW_D12_OFFSET);
    let d13_window = extract_window(transliterated_buffer, WINDOW_D13_OFFSET);

    // Phase 2a: D05-D08 — 4 rounds with same window, chaining through digests.
    let mut phase2a = *d04_digest;
    for _ in 0..4 {
        phase2a = sha256_round(&d05_window, &phase2a);
    }

    // Phase 2b: D10-D13 — board + 3 detection windows.
    let mut digest = *d09_digest;
    for window in [board_window, &d11_window, &d12_window, &d13_window] {
        digest = sha256_round(window, &digest);
    }

    MerkleCertResult {
        d05_window,
        d11_window,
        d12_window,
        d13_window,
        phase2a_digest: phase2a,
        final_digest: digest,
        cert_hex: cert_hex_from_digest(&digest),
    }
}

/// Compute the Merkle cert from explicit traced windows (no buffer needed).
///
/// Useful when replaying from `/tmp/nmss_round_windows.txt` where individual
/// windows are known but the full 1040-byte buffer is not available.
pub fn compute_merkle_cert_from_windows(
    d05_window: &[u8; 8],
    d10_board: &[u8; 8],
    d11_window: &[u8; 8],
    d12_window: &[u8; 8],
    d13_window: &[u8; 8],
    d04_digest: &[u8; 32],
    d09_digest: &[u8; 32],
) -> MerkleCertResult {
    let mut phase2a = *d04_digest;
    for _ in 0..4 {
        phase2a = sha256_round(d05_window, &phase2a);
    }

    let mut digest = *d09_digest;
    for window in [d10_board, d11_window, d12_window, d13_window] {
        digest = sha256_round(window, &digest);
    }

    MerkleCertResult {
        d05_window: *d05_window,
        d11_window: *d11_window,
        d12_window: *d12_window,
        d13_window: *d13_window,
        phase2a_digest: phase2a,
        final_digest: digest,
        cert_hex: cert_hex_from_digest(&digest),
    }
}

/// Extract the 48-char cert from a 32-byte SHA-256 digest.
///
/// Takes bytes `[4..28]` and formats them as uppercase hex.
pub fn cert_hex_from_digest(digest: &[u8; 32]) -> String {
    let cert_bytes = &digest[4..28];
    let mut hex = String::with_capacity(48);
    for &b in cert_bytes {
        use std::fmt::Write;
        let _ = write!(hex, "{:02X}", b);
    }
    hex
}

/// Validate and borrow a captured stage buffer.
///
/// Accepts 1040 bytes directly, or 1041 bytes with a trailing NUL (which is
/// stripped).  Returns a 1040-byte slice.
pub fn read_stage_buffer(data: &[u8]) -> Result<&[u8], String> {
    match data.len() {
        1040 => Ok(data),
        1041 if data[1040] == 0 => Ok(&data[..1040]),
        n => Err(format!("expected 1040 or 1041 bytes, got {n}")),
    }
}

/// Format arbitrary bytes as uppercase hex.
pub fn upper_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{:02X}", b);
    }
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Traced round chain (from /tmp/nmss_round_windows.txt) --

    #[test]
    fn test_traced_round_chain_from_windows() {
        let result = compute_merkle_cert_from_windows(
            b"31615224",
            b"rk3588_s",
            b"02174618",
            b"25522624",
            b"51058648",
            &D04_DIGEST,
            &D09_DIGEST,
        );
        assert_eq!(
            upper_hex(&result.final_digest),
            "EA3583E73E1CC1E4C8FD4F8C60FAB2A76D41982C903FB9A4C8481F06006EB4F7"
        );
        assert_eq!(
            result.cert_hex,
            "3E1CC1E4C8FD4F8C60FAB2A76D41982C903FB9A4C8481F06"
        );
    }

    // -- Individual rounds verified against the trace digest chain --

    #[test]
    fn test_round_d10() {
        let result = sha256_round(b"rk3588_s", &D09_DIGEST);
        assert_eq!(
            upper_hex(&result),
            "DAA16D76FAB944DE46CA6579C134CAF4A659A8C0FBEA480DB03E58B9ED4A0080"
        );
    }

    #[test]
    fn test_round_d11() {
        let d10 = hex_const(
            "DAA16D76FAB944DE46CA6579C134CAF4A659A8C0FBEA480DB03E58B9ED4A0080",
        );
        let result = sha256_round(b"02174618", &d10);
        assert_eq!(
            upper_hex(&result),
            "3223D8E6379BC6F69840B032AB8E7A6077C7DE1F23F678ED8A571884EB1B84DC"
        );
    }

    #[test]
    fn test_round_d12() {
        let d11 = hex_const(
            "3223D8E6379BC6F69840B032AB8E7A6077C7DE1F23F678ED8A571884EB1B84DC",
        );
        let result = sha256_round(b"25522624", &d11);
        assert_eq!(
            upper_hex(&result),
            "240968512EA6AB9EBB6E05039E8C1A3ADAC06D169E29BE3EE2D68ADC88FF9321"
        );
    }

    #[test]
    fn test_round_d13() {
        let d12 = hex_const(
            "240968512EA6AB9EBB6E05039E8C1A3ADAC06D169E29BE3EE2D68ADC88FF9321",
        );
        let result = sha256_round(b"51058648", &d12);
        assert_eq!(
            upper_hex(&result),
            "EA3583E73E1CC1E4C8FD4F8C60FAB2A76D41982C903FB9A4C8481F06006EB4F7"
        );
    }

    #[test]
    fn test_phase2a_chain() {
        let d05_expected = hex_const(
            "2B3161D375170BAF0937919716060DB978FF4CB5B22955351B05CC7665DDF54E",
        );
        assert_eq!(sha256_round(b"31615224", &D04_DIGEST), d05_expected);

        let mut phase2a = D04_DIGEST;
        for _ in 0..4 {
            phase2a = sha256_round(b"31615224", &phase2a);
        }
        let d08_expected = hex_const(
            "F87CFA2F9024494AA1C4B5181660492CA96AAD2AEA9A6FE9A31D92FE983CFC4E",
        );
        assert_eq!(phase2a, d08_expected);
    }

    // -- Cert extraction --

    #[test]
    fn test_cert_extraction() {
        let digest = hex_const(
            "EA3583E73E1CC1E4C8FD4F8C60FAB2A76D41982C903FB9A4C8481F06006EB4F7",
        );
        let cert = cert_hex_from_digest(&digest);
        assert_eq!(cert, "3E1CC1E4C8FD4F8C60FAB2A76D41982C903FB9A4C8481F06");
        assert_eq!(cert.len(), 48);
    }

    // -- WELL512 --

    #[test]
    fn test_well512_step_advances_index() {
        let mut well = Well512::new([0x12345678u32; 16], 0);
        let v = well.step();
        assert_ne!(v, 0);
        assert_eq!(well.index, 15);
    }

    #[test]
    fn test_well512_deterministic() {
        let mut a = Well512::new([0xDEADBEEF; 16], 3);
        let mut b = a.clone();
        for _ in 0..100 {
            assert_eq!(a.step(), b.step());
        }
    }

    #[test]
    fn test_well512_generate_hex_buffer() {
        let mut well = Well512::new([0x42424242; 16], 0);
        let buf = well.generate_hex_buffer(20);
        assert_eq!(buf.len(), 20);
        for &ch in &buf {
            assert!(
                (b'0'..=b'9').contains(&ch) || (b'A'..=b'F').contains(&ch),
                "unexpected char: {ch}"
            );
        }
    }

    // -- Transliteration --

    #[test]
    fn test_transliterate() {
        assert_eq!(transliterate_hex_buffer(b"0A1B2C3D4E5F"), b"011223344556");
        assert_eq!(transliterate_hex_buffer(b"09AF"), b"0916");
    }
}
