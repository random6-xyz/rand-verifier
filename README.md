# rand-verifier

`rand-verifier` is a Rust framework for differential testing and independent safety analysis of the Linux eBPF verifier.

The project combines four verdict axes:

1. **mini** — a path-sensitive abstract interpreter that models scalar ranges, tnum, pointers, stack bytes, calls, references, dynptrs, and kfunc contracts;
2. **concrete** — a bounded interpreter used as a witness axis. A concrete failure is a real unsafe witness; a clean run means only that no witness was found within the explored seeds and budgets;
3. **Linux** — the real verifier through the raw `bpf()` syscall, either on the host or through a bpf-next QEMU guest;
4. **spec** — an independent safety specification with its own value, state, helper, and convergence models.

SMT tooling separately checks the abstract tnum/range operators and synthesizes concrete precision witnesses. The fuzzer, reducer, triage logic, drift monitor, and QEMU backend share the same verdict artifacts.

## Architecture

```text
eBPF bytecode
     │
     ├─► mini verifier       abstract interpretation: ranges, tnum, pointers, stack, calls
     ├─► concrete runner     bounded execution and unsafe-witness search
     ├─► safety spec         independent SP1/SP2/SP3 safety checks
     └─► Linux verifier      raw bpf() syscall or bpf-next QEMU guest
              │
              ▼
       oracle matrix ──► triage ──► reducer ──► reproducible artifacts

abstract operators ──► SMT soundness checks ──► precision-witness synthesis
```

The spec is intentionally not a second mini verifier: it uses one wrapping `u64` interval per scalar, a separate dynamic type system and helper table, byte-granular stack state, and a visited-set convergence policy. Unsupported helpers or instruction surfaces return `Inconclusive`, not a false safety verdict.

## Current state

The current `main` branch contains the following completed capabilities:

- **Model fidelity**: scalar signed/unsigned ranges, ALU32/ALU64, tnum, branch refinement, pointer provenance and nullable aliases, byte-level stack state, spill/fill metadata, BPF-to-BPF calls, verifier frames, references, dynptr slots, BTF pointers, and kfunc argument validation.
- **Independent spec oracle**: scalar, stack, pointer, helper, reference, dynptr, NULL-alias, and subprogram checks are wired into the fuzzer as a fourth axis. The corpus has 52 accept and 47 reject bytecode fixtures, and the spec reproduces both fixture classes.
- **SMT operator verification**: tnum add/sub/bitwise/shift/mul and scalar add/sub/mul encodings are checked exhaustively at small widths and with symbolic or randomized wider checks. `smt_verify` emits a reproducible violation catalog and currently reports zero violations.
- **Precision synthesis**: `witness_synth` ranks interval-versus-tnum gaps and can emit concrete eBPF programs and dumps under an output directory. The generated witnesses are checked by the mini verifier.
- **Campaign infrastructure**: generation and mutation fuzzing, deterministic replay, ddmin-style reduction, triage groups, direct kernel loading, and a shared QEMU batch backend. The guest agent has a 30-second per-program guard; timeout and infrastructure failures are skipped rather than classified as verifier verdicts.
- **Regression monitoring**: `drift` records mini verdicts and checkpoint counts, and compares them with the committed bpf-next baseline. CI runs compilation, tests, formatting, clippy, kernel differential smoke, fuzz smoke, reducer regression, and drift checks.

The local validation run for this snapshot is **596 tests passed**. Counts can change as the corpus and regression tests evolve; run `cargo test` for the authoritative result.

## Commands

| Task | Command |
|------|---------|
| Verify one fixture with mini + concrete | `cargo run -- tests/programs/accept/minimal_exit` |
| Load one program into the host kernel | `cargo run --bin kernel_run -- <file>` |
| Strict host-kernel load | `cargo run --bin kernel_run -- --strict --log <file>` |
| Corpus mini/kernel comparison | `cargo run --bin diff -- [--strict] [--json <path>]` |
| Generate programs | `cargo run --bin fuzz -- --seed N --iters M` |
| Mutate a corpus or supplied pool | `cargo run --bin fuzz -- --seed N --iters M --mode mutation --corpus-dir tests/programs/accept` |
| Add the host kernel column | append `--kernel` (requires root or `CAP_BPF`) |
| Use a bpf-next QEMU guest | append `--qemu-dir <share-dir>` |
| Reduce one finding | `cargo run --bin reduce -- <finding-dir>` |
| Reduce a QEMU-backed finding | `cargo run --bin reduce -- <finding-dir> --qemu-dir <share-dir> --strict --kernel` |
| Record mini drift | `cargo run --bin drift -- --record --mini-only <snapshot.json>` |
| Compare drift snapshots | `cargo run --bin drift -- --compare <base.json> --new <snapshot.json>` |
| Verify abstract operators | `cargo run --bin smt_verify -- [--catalog <path>]` |
| Synthesize precision witnesses | `cargo run --bin witness_synth -- [--out-dir <dir>]` |

Build all binaries with:

```sh
cargo build --release
```

The SMT binaries require the Z3 development library. On Debian/Ubuntu, install `libz3-dev` before building.

## Verdict semantics

The fuzzer keeps the following distinctions explicit:

- `ConcreteSide::Unsafe` is a witness, not a statistical signal.
- `ConcreteSide::Safe` is bounded evidence and never a proof by itself.
- `SpecSide::Inconclusive` means that the independent spec does not model the program surface; it is not a finding.
- `KernelUnsoundCandidate` requires kernel accept, spec reject, and no concrete unsafe witness.
- `KernelOverstrictCandidate` requires kernel reject, spec accept, and no concrete unsafe witness.
- Mini-only disagreements are reported as model gaps or rand-verifier bugs according to the concrete and kernel sides.
- Known privilege and design differences are handled by the shared whitelist rather than by silently changing the verdict.

Finding metadata preserves the mini, concrete, kernel, and spec sides so that reduction can preserve the original classification. Older finding directories without a spec field are loaded as `Inconclusive` on the spec axis.

## Test corpus

`tests/programs/` contains raw `struct bpf_insn` fixtures. The accept and reject directories cover ALU32/64, tnum refinement, stack access, pointers, maps, calls, references, dynptrs, kfuncs, control flow, and convergence limits. Map-backed programs use a sibling `.maps` sidecar to describe the map registry used during loading.

Run the complete local suite with:

```sh
cargo test
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
```

## Roadmap

The first model-fidelity milestone is complete. The current focus is the independent-oracle and operator-verification path:

1. keep the spec, SMT, fuzzer, reducer, and drift contracts stable;
2. extend the kernel surface with `const_fold` and static stack-liveness experiments;
3. use the generated precision witnesses to drive focused model and upstream-quality tests;
4. later expand the runtime/JIT differential axis and syzkaller integration.

The detailed project plan is in [`docs/ROADMAP.md`](docs/ROADMAP.md). Operational notes and the upstream contribution workflow are kept under `docs/`.

## License

Apache-2.0 — see [`LICENSE`](LICENSE).
