# O-MVLL ARM Hash-Lifting Goal

This note captures the next experiment to run after syncing the `ollvm` branch.

## Goal

Clone `https://github.com/open-obfuscator/o-mvll` and use it to build a fresh set of small ARM binaries whose main payloads implement:

- SHA-256
- MD5
- SHA-1
- CRC32

## Desired Workflow

1. Clone and build O-MVLL locally.
2. Create or adapt small single-purpose sample programs so each binary exercises one hash algorithm.
3. Build ARM targets through the O-MVLL pipeline.
4. Feed the resulting binaries back into `aeon-jit` and related aeon lifting tooling.
5. Recover the lifted algorithm logic and compare how well the pipeline reconstructs each hash implementation.

## Deliverables

- A checked-out local copy of `o-mvll`
- Small ARM sample binaries for SHA-256, MD5, SHA-1, and CRC32
- Build notes or scripts for reproducing the O-MVLL builds
- `aeon-jit` lifting outputs for the hash routines
- Short analysis notes on what was recovered cleanly and what still needs manual help

## Success Criteria

- Each hash sample builds as an ARM binary through O-MVLL.
- Aeon can locate and lift the relevant hashing routines back into usable IR.
- The recovered IR is good enough to recognize the core algorithm structure for each sample.
