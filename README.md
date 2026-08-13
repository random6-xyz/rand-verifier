# rand-verifier

A learning reimplementation of the **Linux eBPF verifier** in Rust, built to grow into a differential-testing and bug-discovery framework for the real kernel verifier.

The project reimplements the verifier's way of thinking step by step — instruction/CFG validation, abstract state tracking, and path-sensitive exploration — so that every stage maps to a concept in the actual Linux verifier (`kernel/bpf/verifier.c`). The end goal is not a fully compatible clone, but a tool that can **find precision issues or bugs in the Linux eBPF verifier** and connect them to kernel selftests and upstream patches.

## Current status

The first three milestones are complete:

| Milestone | Theme | What it does |
|-----------|-------|--------------|
| **v0.1** | Structural verification | Instruction decoding, CFG construction, jump-target/subprogram boundary checks, unreachable-code detection, loop (back-edge) rejection |
| **v0.2** | Abstract interpretation | Register/stack abstract state, scalar range tracking, pointer types, spill/fill, branch refinement, execution traces |
| **v0.3** | Path-sensitive verification | Worklist exploration, branch refinement, state equivalence/subsumption (pruning), nullable pointers, helper calls, complexity limits |

The next phase — the **Meso verifier** (signed/unsigned ranges, ALU32/ALU64 semantics, tnum integration, overflow handling, bounded loops) — is planned as described in the [Roadmap](#roadmap) section below.

## Verification pipeline

A single pipeline (`BpfVerifierEnv::verify()`) runs every program through structural CFG checks and then path-sensitive exploration, which includes the abstract execution:

```text
eBPF bytecode
     │
     ▼
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  Structural  │ ──► │   Abstract   │ ──► │     Path     │
│ CFG Checks   │     │    State     │     │ Exploration  │
└──────────────┘     └──────────────┘     └──────────────┘
   structure             state              paths
     │                    │                    │
     └────────────────────┴────────────────────┘
                        ACCEPT / REJECT
```

## Architecture

The crate is a library (`rand-verifier`) plus a thin CLI binary.

| Module | Stage | Responsibility |
|--------|-------|----------------|
| `src/insn.rs` | — | Instruction representation and raw-bytecode decoding (kernel `struct bpf_insn` UAPI encoding, issue #56) |
| `src/cfg.rs` | structural | CFG checks: subprogram discovery, reachability, jump/branch target validation, back-edge (loop) rejection |
| `src/state.rs` | abstract state | Abstract register state (`Uninit`, `Scalar[min,max]`, `PtrToStack`, `PtrToCtx`, `PtrToMap`, `PtrToMapValue`, `PtrToMapValueOrNull`) and the 512-byte stack model (8-byte slots) |
| `src/exec.rs` | abstract execution | Symbolic single-instruction execution (`step`), branch range refinement, static branch verdicts (`is_branch_taken`), successor expansion |
| `src/helper.rs` | path exploration | Helper prototypes and R1..R5 argument validation (kernel convention: the CALL immediate is the helper id) |
| `src/mini.rs` | path exploration | Worklist-based path exploration, per-pc state dedup/subsumption (kernel's `is_state_visited` analog), exploration limits |
| `src/tnum.rs` | — | Tracked number abstraction (kernel's `struct tnum`); implemented but not yet wired into `RegState` (Meso) |
| `src/trace.rs` | abstract execution | Execution trace rendering |
| `src/error.rs` | — | Structured verification failures (`insn_idx` + message) and the final `Verdict` |
| `src/env.rs` | — | Program loading and the full verification pipeline |

### Key behaviors

- **Abstract state, not concrete values** — registers track `Scalar[min,max]` ranges, pointers track type + offset; `min == max` means a constant.
- **Branch refinement** — conditional branches narrow both operands on each side, and statically impossible branches are pruned.
- **State pruning** — a state subsumed by an already-analyzed state at the same pc is skipped, keeping exploration bounded (like the kernel's state lists).
- **Helper calls** — argument types are validated against prototypes, R1..R5 are clobbered after the call, R6..R9 preserved, R0 gets the return type.
- **Nullable pointers** — a `PtrToMapValueOrNull` must pass a NULL check (`jeq ptr, 0`) before use; the fall-through refines it to `PtrToMapValue`.
- **Complexity limits** — exploration is bounded by `max_states` (1024) and `max_steps` (100 000), mirroring `BPF_COMPLEXITY_LIMIT_*`.

## Building

Requires a recent Rust toolchain (edition 2024).

```sh
cargo build --release
```

## Usage

Verify a raw eBPF bytecode file:

```sh
cargo run -- <program_file>
```

```text
$ cargo run -- tests/programs/accept/scalar_constants
Verification passed

$ cargo run -- tests/programs/reject/backward_jump
verification failed at insn 0: back edge to insn 0 creates an unbounded loop
```

A verification failure is a normal result (`Ok(Verdict::Unsafe)`) — only I/O and decode-level errors abort the process.

## Instruction subset

The verifier accepts the kernel's `struct bpf_insn` encoding (8 bytes per
instruction, `[code, (src_reg << 4 | dst_reg), off_le16, imm_le32]`) — the
same bytes clang and the kernel selftests emit (issue #56):

| Opcode | Mnemonic | Semantics |
|--------|----------|-----------|
| `0xb7`/`0xbf` | `MOV64` | `rX = imm` / `rX = rY` |
| `0x07`/`0x0f` | `ADD64` | `rX += imm` / `rX += rY` (scalars and stack-pointer offsets) |
| `0x17`/`0x1f` | `SUB64` | `rX -= imm` / `rX -= rY` |
| `0x57`/`0x5f` | `AND64` | `rX &= imm` / `rX &= rY` |
| `0x47`/`0x4f` | `OR64` | `rX |= imm` / `rX |= rY` |
| `0xa7`/`0xaf` | `XOR64` | `rX ^= imm` / `rX ^= rY` |
| `0x67`/`0x6f` | `LSH64` | `rX <<= imm` / `rX <<= rY` |
| `0x77`/`0x7f` | `RSH64` | `rX >>= imm` / `rX >>= rY` |
| `0xc7`/`0xcf` | `ARSH64` | `rX s>>= imm` / `rX s>>= rY` |
| `0x04`/`0x0c` | `ADD32` | `wX += imm` / `wX += rY` (truncating, zero-extending) |
| `0x14`/`0x1c` | `SUB32` | `wX -= imm` / `wX -= rY` |
| `0x54`/`0x5c` | `AND32` | `wX &= imm` / `wX &= rY` |
| `0x44`/`0x4c` | `OR32` | `wX |= imm` / `wX |= rY` |
| `0xa4`/`0xac` | `XOR32` | `wX ^= imm` / `wX ^= rY` |
| `0x64`/`0x6c` | `LSH32` | `wX <<= imm` / `wX <<= rY` |
| `0x74`/`0x7c` | `RSH32` | `wX >>= imm` / `wX >>= rY` |
| `0xc4`/`0xcc` | `ARSH32` | `wX s>>= imm` / `wX s>>= rY` |
| `0x79` | `LD_STACK` | `rX = [r10 + off]` (8-byte, `src_reg = 10`) |
| `0x7b` | `ST_STACK` | `[r10 + off] = rX` (8-byte, `dst_reg = 10`) |
| `0x1d`…`0xdd` | compares | `if rX op rY goto +off` and `if rX op imm goto +off` — `JEQ`/`JNE`/`JGT`/`JGE`/`JLT`/`JLE` (unsigned) and `JSGT`/`JSGE`/`JSLT`/`JSLE` (signed), register (`BPF_J*_X`) and immediate (`BPF_J*_K`) forms |
| `0x05` | `JMP` | `goto +off` (`BPF_JA`) |
| `0x85` | `CALL` | helper call — `imm` is the helper id (kernel convention) |
| `0x95` | `EXIT` | terminate path |

Unknown opcodes, invalid registers and non-zero reserved fields are
rejected with structured decode errors; valid kernel opcodes outside this
subset (ldimm64, `BPF_JMP32`, store-immediate, `BPF_JSET`, 32-bit MOV,
BPF-to-BPF/kfunc calls, …) are rejected as unsupported.

## Test corpus

Raw bytecode fixtures live in `tests/programs/`:

- `tests/programs/accept/` — 29 programs that must pass
- `tests/programs/reject/` — 30 programs that must fail

Each fixture exercises one specific verification rule (uninitialized reads, stack bounds/alignment, write-before-read, invalid jumps, unbounded loops, helper argument mismatches, complexity limits, …). See [`tests/programs/README.md`](tests/programs/README.md) for the full list.

Run the test suite (161 unit tests, including the corpus):

```sh
cargo test
```

## CI

GitHub Actions runs `cargo check`, `cargo test`, `cargo fmt --check`, and `cargo clippy -D warnings` on every push/PR to `main`.

## Roadmap

The project is a research framework in progress. The next phases:

1. **Meso verifier** — signed/unsigned ranges, ALU32/ALU64, tnum in `RegState`, overflow/wraparound, alignment, bounded loops.
2. **Concrete execution engine** — an interpreter that checks the abstract state always covers the concrete results.
3. **Linux differential verifier** — run the same program through rand-verifier, the concrete interpreter, and the real Linux verifier.
4. **Verifier fuzzer** — generate eBPF programs to search for `Linux verifier: REJECT` vs `Concrete execution: SAFE` discrepancies.
5. **Failure reducer** — automatically minimize discovered testcases down to a minimal reproducer.
6. **Linux verifier analysis** — trace comparisons and precision-loss analysis on the minimal reproducer.
7. **Kernel patch** — a soundness-preserving fix for `kernel/bpf/verifier.c` plus a BPF selftest.
8. **Upstream** — submit `[PATCH bpf-next] bpf: verifier: ...` and land it.

## License

Apache-2.0 — see [`LICENSE`](LICENSE).
