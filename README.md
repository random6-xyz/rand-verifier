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
| `src/insn.rs` | — | Instruction representation and raw-bytecode decoding (simplified custom opcode set) |
| `src/cfg.rs` | structural | CFG checks: subprogram discovery, reachability, jump/branch target validation, back-edge (loop) rejection |
| `src/state.rs` | abstract state | Abstract register state (`Uninit`, `Scalar[min,max]`, `PtrToStack`, `PtrToCtx`, `PtrToMap`, `PtrToMapValue`, `PtrToMapValueOrNull`) and the 512-byte stack model (8-byte slots) |
| `src/exec.rs` | abstract execution | Symbolic single-instruction execution (`step`), branch range refinement, static branch verdicts (`is_branch_taken`), successor expansion |
| `src/helper.rs` | path exploration | Helper prototypes and R1..R5 argument validation (kernel convention: negative immediate = helper call) |
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

The current instruction subset uses a simplified custom encoding (8 bytes per instruction, not the real eBPF opcode space):

```text
[op, (src << 4 | dst), off_le16, imm_le32]
```

| Opcode | Mnemonic | Semantics |
|--------|----------|-----------|
| `0x01` | `MOV_IMM` | `rX = imm` |
| `0x02` | `MOV_REG` | `rX = rY` |
| `0x03` | `ADD_IMM` | `rX += imm` (scalars and stack-pointer offsets) |
| `0x04` | `ADD_REG` | `rX += rY` (scalars only) |
| `0x05` | `LD_STACK` | `rX = [r10 + off]` |
| `0x06` | `ST_STACK` | `[r10 + off] = rX` |
| `0x07` | `JEQ` | `if rX == rY goto +off` |
| `0x08` | `JGT` | `if rX > rY goto +off` (signed) |
| `0x09` | `JMP` | `goto +off` |
| `0x0A` | `CALL` | helper call (negative `imm`, kernel convention) |
| `0x0B` | `EXIT` | terminate path |

## Test corpus

Raw bytecode fixtures live in `tests/programs/`:

- `tests/programs/accept/` — 13 programs that must pass
- `tests/programs/reject/` — 19 programs that must fail

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
