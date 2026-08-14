# rand-verifier

A learning reimplementation of the **Linux eBPF verifier** in Rust, built to grow into a differential-testing and bug-discovery framework for the real kernel verifier.

The project reimplements the verifier's way of thinking step by step — instruction/CFG validation, abstract state tracking, and path-sensitive exploration — so that every stage maps to a concept in the actual Linux verifier (`kernel/bpf/verifier.c`). The end goal is not a fully compatible clone, but a tool that can **find precision issues or bugs in the Linux eBPF verifier** and connect them to kernel selftests and upstream patches.

## Current status

The milestones completed so far:

| Milestone | Theme | What it does |
|-----------|-------|--------------|
| **v0.1** | Structural verification | Instruction decoding, CFG construction, jump-target/subprogram boundary checks, unreachable-code detection, loop (back-edge) rejection |
| **v0.2** | Abstract interpretation | Register/stack abstract state, scalar range tracking, pointer types, spill/fill, branch refinement, execution traces |
| **v0.3** | Path-sensitive verification | Worklist exploration, branch refinement, state equivalence/subsumption (pruning), nullable pointers, helper calls, complexity limits |
| **v0.4** | Meso verifier | Signed/unsigned scalar ranges, ALU32/ALU64 semantics, tnum integration, overflow/wraparound, pointer offset/alignment, bounded loops |
| **v0.5** | Concrete execution engine | An interpreter that checks the abstract state always covers the concrete results (soundness), plus a coverage checker |
| **v0.6** | Linux differential verifier | Native eBPF input, kernel-runner via the raw `bpf()` syscall, verdict matrix vs the kernel, whitelisted design differences |
| **v0.7** | Verifier fuzzer | Deterministic program generation + seed-based mutation, oracle classification matrix, triage/dedup, campaign runner |
| **v0.8** | Failure reducer | Finding replay + reduction invariant, offset-fixed deletion, ddmin with cache/budget, CFG/operand passes, reduce CLI |
| **v0.8.1** | Precision gap closure | Root-cause of the first kernel-backed finding (mseed-5-99, #86); access-time pointer validation (#87), kernel bug-pattern catalog (#88), ldimm64/map support with kernel map creation (#89), whitelist pruned to genuine design differences plus category rules (#90). First kernel-backed mutation campaign (2000 iters): 11 findings analysed against the kernel source and resolved (3 mini model gaps fixed, 2 category whitelist rules) |

The next milestone — the **Linux verifier analysis** (v0.9) — starts from the
minimal reproducers the reducer produces.

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
- **Infinite-loop detection** — a state revisited with an identical state at a pc on a cycle is rejected (kernel `states.c`: "infinite loop detected").
- **Arithmetic-time pointer sanity** — pointer ADD/SUB addends must stay within `BPF_MAX_VAR_OFF` (1 << 28) and may not have an unbounded minimum (kernel `check_reg_sane_offset_*`); the 512-byte frame bounds themselves are validated at access time.
- **Context pointer arithmetic** — ctx ADD/SUB with a sane offset is allowed (kernel `adjust_ptr_min_max_vals` PTR_TO_CTX), like the kernel.

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

### Differential harness (Phase 3, v0.6)

Load a program into the real kernel verifier via the raw `bpf()` syscall (no libbpf):

```sh
cargo run --bin kernel_run -- tests/programs/accept/minimal_exit   # one program (disassembly + verdict)
cargo run --bin kernel_run -- --all                                 # the whole corpus
cargo run --bin kernel_run -- --strict -- <file>                    # drop all caps except CAP_BPF+CAP_NET_ADMIN
cargo run --bin kernel_run -- --log2 -- <file>                      # log_level 2 (full state dumps, kept on accept)
```

Compare rand-verifier vs the kernel on the whole corpus (verdict matrix, findings, JSON report):

```sh
cargo run --bin diff                       # table + summary; exit 1 on non-whitelisted findings
cargo run --bin diff -- --json report.json
cargo run --bin diff -- --strict           # unprivileged-equivalent comparison (drops caps)
```

The default diff runs **privileged** — the real-world baseline (root loads get the kernel's
lenient rules). Loading needs root / CAP_BPF when `kernel.unprivileged_bpf_disabled = 2`;
the runner reports EPERM with guidance. Since v0.8.1 (#90) the whitelist is a mix of
name entries and category rules, each justified against the kernel source
(`docs/DIFFERENTIAL_PLAN.md` §10, kernel/bpf/token.c, kernel/bpf/verifier.c):

- `complexity_limit` + the **Complexity category rule** — mini's exploration budget
  (max_states 1024 / max_steps) vs the kernel's much larger limits (intentional);
  category-applied so fuzzer-generated complexity programs are covered too
- `stack_write_before_read` + the **privileged stack-leniency category rule** — privileged
  loads allow uninit stack reads (`allow_uninit_stack`) and indirect reads over spilled
  pointers (`allow_ptr_leaks`); `bpf_ns_capable` treats CAP_SYS_ADMIN as a superset of
  every BPF cap (kernel/bpf/token.c). Uninit *register* reads stay findings

The `computed_offset_*` / `pointer_reg_arith` entries were removed: pointer
bounds/alignment are now validated at access time like the kernel does (mseed-5-99
analysis, #86; fix #87), so those programs agree on both sides.

Reason categories come from the exact kernel `verbose()` formats (`src/klog.rs`); the
`--strict` mode (unprivileged-equivalent) surfaces `!root` rules such as pointer-comparison
prohibitions and the loop-convergence difference as `kernel-stricter` entries — Phase 6
analysis material.

GitHub Actions: hosted runners have passwordless `sudo` and run directly in a VM, so
`sudo -E cargo run --bin diff` works in CI (do not use a `container:` job — Docker's
default seccomp profile blocks the `bpf()` syscall).

### Fuzzer (Phase 4, v0.7)

Automatically generate and mutate eBPF programs, verify them through rand-verifier
(mini + concrete), consult the kernel when privileged, and classify every program
into exactly one actionable bucket:

```sh
cargo run --bin fuzz -- --seed 42 --iters 1000                 # generation (mini + concrete)
cargo run --bin fuzz -- --seed 5 --iters 1000 --mode mutation  # seed-based mutation (corpus + campaign pool)
cargo run --bin fuzz -- --seed 7 --iters 100 --kernel          # + kernel (needs root / CAP_BPF)
cargo run --bin fuzz -- --seed 7 --iters 100 --kernel --strict # unprivileged-equivalent kernel rules
```

Generation is framed (r0 init → body → EXIT) so every program passes the nano
checks by construction; 30% of programs use verifier-stress idiom templates
(overflow chains, ALU32 roundtrips, signed/unsigned dual refinement, bounded
loops, ...). Mutation mode reuses the corpus fixtures and the campaign pool as
seeds (field replacement, insertion, deletion, splice) and tracks verdict flips.

The classification matrix (concrete is the truth axis):

| mini | concrete | kernel | classification |
|------|----------|--------|----------------|
| any | SAFE | REJECT (non-whitelisted) | 🎯 **precision candidate** — v0.7 target |
| any | UNSAFE | ACCEPT | 🚨 **soundness candidate** — v1.0 target |
| REJECT | SAFE | ACCEPT | rand-verifier precision gap |
| ACCEPT | UNSAFE | any | rand-verifier soundness bug — model bug, always surfaced |
| else | | | agree → discard |

Output layout (`--out-dir`, default `fuzz-out/`):

- `findings/` — one directory per finding (`prog.bin` replayable via `kernel_run`,
  decoded dump, mini/concrete reports, kernel log, `meta.json`); mutation-mode
  verdict flips are saved as `verdict-flip-*`.
- `groups/` — triage dedup: one representative per root cause, ordered by
  priority (model bug > soundness > precision > rv gap).
- `summary.json` — verdict counts, opcode coverage, mutation validity/flips,
  findings and groups.

Deterministic for a fixed seed on the rand-verifier side (kernel outcomes are
host-dependent and recorded separately). Triage groups are the Phase 6 analysis
entry points — they flow into the failure reducer (v0.8) and the kernel patch
work (v1.0).

### Failure reducer (Phase 5, v0.8)

Automatically minimize fuzzer findings down to a human-analyzable minimal
reproducer (500 instructions → 50 → 10 → minimal; design: issue #75). The
reduction invariant is the v0.7 oracle itself: a candidate must re-classify
to the same finding (`oracle::classify`, including the kernel reason category
for kernel-reject-based findings; verdict flips must keep the recorded flip
direction), and the final re-check is mandatory — a reduced program that no
longer reproduces the finding is a reducer bug and fails the run loudly.

```sh
cargo run --bin reduce -- <finding-dir|group-dir> [--kernel] [--strict] [--budget N]
```

Kernel-dependent findings (precision/soundness candidates, rv gaps) need the
privileged kernel column (`--kernel`; the tool refuses without it);
rv-soundness bugs and verdict flips reduce unprivileged with mini + concrete.
Passes run in the order slice → ddmin → operand minimization to a fixpoint,
with a shared hash cache and an oracle-check budget. Reduced artifacts land in
`--out-dir/reduced/<finding>/` (`prog.bin` + `prog.dump` + `reduce.json` with
the per-pass size timeline) and are the v0.9 analysis entry points.

First empirical run (v0.8, 2026-08 — the v0.7 mutation campaign findings,
unprivileged):

| findings | original total | reduced total | final sizes | oracle checks |
|----------|---------------|---------------|-------------|---------------|
| 30 verdict flips | 178 insns | 33 insns | 27 × 1 insn, 3 × 2 insns | 133 (43 cache hits) |

All 30 flips reduced with the classification preserved; every pass family
fired (CFG 23×, ddmin 31×, operand 8×). Examples: `mseed-5-3` (8 insns) →
`[exit]` — a minimal r0-uninit reject; `mseed-5-107` (8 insns) →
`[call 7; exit]` — the helper-call shape that cannot shrink further under
the flip invariant; `mseed-5-186` (7 insns) → `[r0 = 0; exit]`. A reduced
verdict flip is the minimal program with the *flipped* verdict — the
flip-boundary analysis itself is v0.9 material. The kernel-dependent
`rv-precision-gap` group (mseed-5-99) was reduced by the privileged CI job
(#83) and root-caused in v0.8.1 (#86): mini validated pointer bounds at
arithmetic time while the kernel validates at access time. The fix (#87)
moved the checks to access time; the reduced program now lives in the
accept corpus as `computed_pointer_no_access`.

Whitelist policy: on top of the v0.6 name-based diff whitelist, the first
kernel-backed campaigns added one **category-based** entry — a mini reject with
a `stack slot ... is uninitialized` reason plus kernel ACCEPT is the privileged
`allow_uninit_stack` design difference (`bpf_ns_capable` treats CAP_SYS_ADMIN as
a superset of every BPF cap, verified against kernel/bpf/token.c in v0.6) and
is whitelisted by category so fuzzer-generated programs are covered too.
Uninit *register* reads stay soundness candidates — the kernel rejects those,
so an accept would be a real bug.

First campaign numbers (v0.7, 2026-08):

| campaign | verdicts | findings | notes |
|----------|----------|----------|-------|
| generation (seed 42, 2000 iters, unprivileged) | agree 1404, skipped 596 | 0 | kernel columns skipped; no model bugs surfaced |
| mutation (seed 5, 2000 iters, unprivileged) | agree 1752, inconclusive 1, skipped 28 | 0 | validity rate 86.3% (1377/1596); 38 verdict flips (34 accept→reject, 4 reject→accept) |
| mutation + kernel (seed 5, 200 iters, privileged) | agree 159, whitelisted 1, inconclusive 1, rv-precision-gap 1, soundness-candidate 1 | 2 → both analysed | the soundness candidate is the privileged uninit-stack design difference (mseed-5-19, now whitelisted by category); the rv gap (mseed-5-99) was root-caused (#86) and fixed in v0.8.1 (#87) |
| generation + kernel (seed 42, 500 iters, privileged) | agree 500 | 0 | the kernel agrees with rand-verifier on every generated program |
| mutation + kernel --strict (seed 5, 200 iters) | agree 157, whitelisted 4, inconclusive 1, skipped 1 | 0 | strict `!root` rules absorbed by the strict whitelist |

First v0.8.1 kernel-backed mutation campaign (2026-08, seed 5, 2000 iters, privileged):

| campaign | verdicts | findings | resolution |
|----------|----------|----------|------------|
| mutation + kernel (seed 5, 2000 iters) | agree 1747, whitelisted 9, inconclusive 31, precision-candidate 5, soundness-candidate 2, rv-precision-gap 4 | 11 | all analysed against the kernel source: 2x ctx arithmetic (kernel PTR_TO_CTX allows ADD/SUB — mini+concrete now mirror it), 3x infinite loop (kernel states.c identical-state rule — mini now detects it), 2x unbounded/huge addend (kernel check_reg_sane_offset_* — mini now enforces BPF_MAX_VAR_OFF at arithmetic time), 4x complexity (whitelisted by category) |
| re-run (same seed) | agree 1760, whitelisted 13, inconclusive 37, precision-candidate 1 | 1 | the remaining candidate was a klog category gap (kernel's "math between ..." message fell to Other) — fixed; both sides reject with the same category |

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
| `0x79` | `LD_STACK` | `rX = [rY + off]` (8-byte; base `Y` must be a stack pointer, #87) |
| `0x7b` | `ST_STACK` | `[rY + off] = rX` (8-byte; base `Y` must be a stack pointer, #87) |
| `0x1d`…`0xdd` | compares | `if rX op rY goto +off` and `if rX op imm goto +off` — `JEQ`/`JNE`/`JGT`/`JGE`/`JLT`/`JLE` (unsigned) and `JSGT`/`JSGE`/`JSLT`/`JSLE` (signed), register (`BPF_J*_X`) and immediate (`BPF_J*_K`) forms |
| `0x05` | `JMP` | `goto +off` (`BPF_JA`) |
| `0x85` | `CALL` | helper call — `imm` is the helper id (kernel convention) |
| `0x18` | `LD_IMM64` | `rX = imm64` (two slots); `PSEUDO_MAP_FD` → `CONST_PTR_TO_MAP`, `PSEUDO_MAP_VALUE` → map value pointer (#89) |
| `0x95` | `EXIT` | terminate path |

Unknown opcodes, invalid registers and non-zero reserved fields are
rejected with structured decode errors; valid kernel opcodes outside this
subset (ldimm64, `BPF_JMP32`, store-immediate, `BPF_JSET`, 32-bit MOV,
BPF-to-BPF/kfunc calls, …) are rejected as unsupported.

## Test corpus

Raw bytecode fixtures live in `tests/programs/`:

- `tests/programs/accept/` — 40 programs that must pass
- `tests/programs/reject/` — 38 programs that must fail

Each fixture exercises one specific verification rule (uninitialized reads, stack bounds/alignment, write-before-read, invalid jumps, unbounded loops, helper argument mismatches, complexity limits, access-time pointer checks, map fd/key-value validation, …). See [`tests/programs/README.md`](tests/programs/README.md) for the full list. Map fixtures carry a sibling `<name>.maps` sidecar registering the referenced map fds (ARRAY key 4B / value 8B / 1 entry).

Run the test suite (472 tests — unit, corpus, and the reducer integration suite):

```sh
cargo test
```

## CI

GitHub Actions runs `cargo check`, `cargo test`, `cargo fmt --check`, and `cargo clippy -D warnings` on every push/PR to `main`, plus:

- a **fuzzer smoke job** (unprivileged) — the fixed-seed regression suite (#72), a short generation campaign, and the unprivileged reducer smoke (#83);
- a **kernel differential job** (privileged runner) — the corpus diff, a short kernel-backed fuzz campaign (#73), and the kernel-backed reduction of the rv-precision-gap fixture (#83), all failing on non-whitelisted findings.

## Roadmap

The project is a research framework in progress. The next phases:

1. **Meso verifier** — signed/unsigned ranges, ALU32/ALU64, tnum in `RegState`, overflow/wraparound, alignment, bounded loops.
2. **Concrete execution engine** — an interpreter that checks the abstract state always covers the concrete results.
3. **Linux differential verifier** — run the same program through rand-verifier, the concrete interpreter, and the real Linux verifier.
4. **Verifier fuzzer** — generate eBPF programs to search for `Linux verifier: REJECT` vs `Concrete execution: SAFE` discrepancies.
5. **Failure reducer** — automatically minimize discovered testcases down to a minimal reproducer (v0.8 ✅, see the section above).
6. **Linux verifier analysis** — trace comparisons and precision-loss analysis on the reduced reproducers (v0.9). The first analysis round is done (mseed-5-99, #86) with the fix in v0.8.1 (#87); the first kernel-backed mutation campaign then surfaced 11 findings that were all resolved against the kernel source (mini model gaps fixed, category whitelist rules added) — the next candidate feeds in from the fuzzer.
7. **Kernel patch** — a soundness-preserving fix for `kernel/bpf/verifier.c` plus a BPF selftest.
8. **Upstream** — submit `[PATCH bpf-next] bpf: verifier: ...` and land it.

## License

Apache-2.0 — see [`LICENSE`](LICENSE).
