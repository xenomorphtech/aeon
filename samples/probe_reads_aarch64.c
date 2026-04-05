/*
 * probe_reads_aarch64.c — tiny helper for known/unknown memory-read replay.
 *
 * The replay example calls probe_reads() directly with:
 *   - x0 -> dumped "known" bytes
 *   - x1 -> undumped "unknown" bytes
 *
 * That gives a deterministic validation case for the callback-based
 * classification before aiming the runner at a large process snapshot.
 */
#include <stdint.h>

uint64_t probe_reads(const uint8_t *known, const uint32_t *maybe_unknown) {
    uint64_t a = known[0];
    uint64_t b = known[3];
    uint64_t c = maybe_unknown[0];
    uint64_t d = maybe_unknown[1];

    return (a << 24) ^ (b << 16) ^ c ^ (d << 1);
}

int main(void) {
    return 0;
}
