# rand-verifier

A differential-testing and bug-discovery framework for the **Linux eBPF verifier**, written in Rust.

It runs the same eBPF program through three oracles — an abstract-interpretation verifier (mini), a concrete interpreter (the truth axis), and the real kernel verifier via the raw `bpf()` syscall — and classifies every disagreement as a precision or soundness candidate. A program fuzzer and a ddmin-based reducer feed the pipeline, and qemu campaigns run it against bpf-next.

## How it works

```text
eBPF program
     │
     ├─► mini verifier        abstract interpretation: scalar ranges, tnum, pointers, stack
     ├─► concrete interpreter truth axis: real values; coverage check catches model unsoundness
     └─► Linux verifier       raw bpf() syscall (host kernel or qemu bpf-next guest)
              │
              ▼
        verdict matrix ──► precision / soundness candidates
```

| Tool | Command |
|------|---------|
| verify | `cargo run -- <file>` |
| kernel load | `cargo run --bin kernel_run -- [--strict] [--log2] <file>` |
| differential | `cargo run --bin diff [--strict]` — corpus-wide verdict matrix, fails on non-whitelisted findings |
| fuzz | `cargo run --bin fuzz -- --seed N --iters M [--mode mutation] [--kernel]` |
| reduce | `cargo run --bin reduce -- <finding-dir> [--kernel]` — ddmin to a minimal reproducer |

Programs use the kernel `struct bpf_insn` encoding (8 bytes/instruction). Build: `cargo build --release`.

## Current state

- **Campaigns**: 24 kernel-backed runs (22 mutation + 2 generation), 340K+ programs, verified inside a qemu bpf-next guest.
- **Corpus**: 60 accept / 54 reject fixtures in `tests/programs/` (see `tests/programs/README.md`), 544 tests green, with a drift-monitoring baseline against bpf-next 7.2.0-rc6 (`tools/drift-baseline/`, `src/bin/drift.rs --record/--compare`).
- **CI drift wiring**: the drift step is *not* wired into `.github/workflows/ci.yml` — the GitHub token in use lacks the `workflow` scope, so the workflow file cannot be pushed (the drift tool and the committed baseline are merged; the CI step is the remaining piece).
- **Model**: mini covers scalar ranges (signed/unsigned + tnum), ALU32/64, byte-level stack accesses (1/2/4/8-byte loads/stores, sign-extension, spill/fill metadata, STACK_ZERO/MISC/SPILL byte types), map/ctx/stack pointers with access-time bounds, helper calls, bounded loops, BPF-to-BPF calls with multiple verifier frames, kernel-style state pruning (liveness masks, prune points, parent/checkpoint states, `regsafe()`/`stacksafe()`/`states_equal()`), scalar precision tracking with backtracking, register ids with linked-refinement and nullable-alias refinement, reference tracking for acquire/release helpers (ringbuf reserve/submit/discard, `refsafe()`, exit-time `check_reference_leak`), stack dynptr slots (bpf_dynptr_from_mem/read/write/data with STACK_DYNPTR byte types), parent_id-derived pointer invalidation, and a kfunc layer (vmlinux-BTF-keyed table with argument validation, PTR_TO_BTF_ID acquire/release). The mini mirrors the kernel's socket-filter behavior: kfunc calls are rejected ("not allowed") and the dynptr helpers require map-value data.

## Kernel findings

- **Speculative dead-branch exploration rejects concretely-safe programs (strict loads)** — with `bypass_spec_v1` off (no `CAP_PERFMON`, e.g. the lab's `--strict` campaigns), the kernel explores statically-decided-dead branches speculatively (`sanitize_speculative_path`, kernel/bpf/verifier.c). A fixed-point loop inside such a dead branch — e.g. `r1 = -4; r2 = 100; if r1 < r2 goto -1; exit` (the unsigned compare is never taken) — then trips the infinite-loop detector on the speculative path and rejects the program, although the fall-through is concretely safe and the privileged load accepts it (bypass_spec_v1 on with `CAP_PERFMON`). mini follows the privileged behavior (accept); the strict-mode divergence is a kernel-side false reject (campaign class `precision-candidate`, first seen in the v0.8.4 campaigns, re-confirmed on bpf-next 7.2.0-rc6).

## Roadmap

### Stage 1 — Model fidelity

Deepen the abstract state model toward the kernel verifier's. Priority order, and after every step the differential fuzzer runs to compare verdicts and state counts (false reject / false accept / state-count drift):

1. **State pruning** — parent states, register/stack liveness, `regsafe()` / `states_equal()` structure, dead-state pruning. ✅
2. **Precision tracking** — `precise` bit, instruction dependency tracking, precision backtracking. ✅
3. **Register/pointer realism** — `id` / `parent_id` / provenance, fixed/variable offsets, nullable pointer aliasing, `tnum` + `cnum32/cnum64`. ✅ (issue #99: ids, linked refinement, nullable aliasing, parent_id-derived invalidation; the 32/64-bit subreg id counters are a documented sound over-approximation — ALU32 clears the id)
4. **Stack / call frames** — byte-level stack state (per-byte slot types, partial-width spill/fill, sign-extending loads), spill/fill metadata, BPF-to-BPF calls, multiple verifier frames. ✅ (issue #100)
5. **Modern verifier features** — BTF pointers, kfunc, ref acquire/release, dynptr / kptr / iterator. ✅ (issue #101: ref tracking for the ringbuf acquire/release family, STACK_DYNPTR slots with the dynptr helper family, a vmlinux-BTF-keyed kfunc table with argument validation and PTR_TO_BTF_ID acquire/release; kptr map-value slots and the iterator family remain outside the modeled program surface)

Beyond finding bugs, this model doubles as a **drift-monitoring oracle**: re-verify the corpus and fuzz pool against every bpf-next rc in qemu, and report verdict / state-count / processed-insn regressions to maintainers early.

### Stage 2 — Oracle replacement and surface expansion

The mini-vs-kernel-vs-concrete triangle saturates: mini is a small subset of the kernel, so most discrepancies are model gaps, and real kernel bugs only surface in the kernel's own machinery (speculation, const_fold). The next moves change the oracle, not just the model:

1. **Spec-based oracle fuzzing (Veritas-style)** — replace the differential oracle with an independent safety spec in Z3/Dafny and fuzz the kernel against it. The fuzzer/reducer/triage infrastructure carries over as-is. ([Veritas](https://rs3lab.github.io/assets/papers/2025/lyu%3Averitas.pdf), [SEV](https://www.usenix.org/system/files/osdi24-sun-hao.pdf))
2. **Per-operator SMT verification + precision synthesis (Agni-style)** — verify the tnum/range operators with SMT and synthesize concrete precision witnesses; the more-precise `bpf_mul` upstream merge is the precedent for this contribution route. ([Agni](https://people.cs.rutgers.edu/~sn624/papers/agni-cav23.pdf), [Differential Synthesis](https://www.researchwithrutgers.org/en/publications/comparing-theprecision-ofabstract-operators-intheebpf-verifier-us/))
3. **New kernel surface: const_fold / static stack liveness** — newly merged rewriting passes are a classic bug source; port const_fold into mini for fold/no-fold verdict diffs and run on/off qemu campaigns. ([LWN](https://lwn.net/Articles/1065872/))
4. **Runtime / JIT fuzzing** — extend past the verifier: use the concrete interpreter as a JIT-vs-interpreter differential oracle, and syzkaller with KCOV for `bpf()` syscall fuzzing. ([BRF](https://ics.uci.edu/~ardalan/papers/Hung_FSE24.pdf), [Jitterbug](https://www.usenix.org/conference/osdi20/presentation/nelson))

## License

Apache-2.0 — see [`LICENSE`](LICENSE).
