# Selftest corpus replay (#139)

`replay` compares the kernel's own verifier selftests against the three
rand-verifier axes. It is the cheapest source of signal we have: the 478
labelled programs extracted by `tools/selftest_corpus.py` expose model gaps
in about a minute, where a kernel-backed fuzz campaign needs hours to find
its first new program shape.

## Corpus

```
python3 tools/selftest_corpus.py --tree <bpf-next> --out /tmp/selftest-corpus --check-lock
```

The extractor is pinned by `tools/selftest-corpus.lock` (kernel commit,
fragment/program counts, catalog hash). CI refreshes the lock only when the
kernel selftests are intentionally re-pinned.

## Running a replay

```sh
cargo run --release --bin replay -- \
    --manifest /tmp/selftest-corpus/manifest.jsonl \
    --programs /tmp/selftest-corpus/programs \
    --json /tmp/replay.json
```

Columns:

| column | meaning |
|---|---|
| `expected` | the selftest's `.result` / `.result_unpriv` expectation |
| `kernel` | the expectation, or a recorded kernel column (`--kernel-column`) |
| `mini` | rand-verifier's abstract verifier |
| `spec` | the independent safety spec (`ACCEPT` / `REJECT` / `INCONCLUSIVE`) |
| `finding` | the campaign classification (`oracle::classify_env`) |

Raw agreement is reported separately from the classification: `agree-*`,
`rv-overstrict` (mini rejects, kernel accepts) and `rv-unsound` (mini
accepts, kernel rejects). Classification counts follow the oracle
precedence, so a case can be `inconclusive` (concrete budget) while still
counting as `agree-reject` on the raw axis.

## Kernel column

CI has no bpf-next image, so the hosted gate uses the selftest expectations
and a committed baseline. To record the real kernel column on the pinned
image:

```sh
QEMU_ASSETS=$PWD/fuzz-out/kernel-<sha> tools/qemu-share.sh --fresh
tools/qemu-boot.sh
python3 tools/guest_replay.py --share <share> \
    --manifest /tmp/selftest-corpus/manifest.jsonl \
    --programs /tmp/selftest-corpus/programs \
    --out /tmp/kernel-column.jsonl
tools/qemu-boot.sh --stop
cargo run --release --bin replay -- ... --kernel-column /tmp/kernel-column.jsonl
```

Commit the column with the image hash in the report (`--json`) so a later
review can tell which kernel produced it.

## Baseline gate

`tools/replay-baseline.json` lists the findings that are already known and
triaged. CI runs:

```sh
cargo run --release --bin replay -- ... --baseline tools/replay-baseline.json --gate
```

The gate fails when a finding id is **not** in the baseline. Shrinking the
list (a model learns a surface) is always allowed: regenerate the baseline

```sh
cargo run --release --bin replay -- ... --baseline tools/replay-baseline.json --write-baseline
```

and commit the smaller list. Never add an id without a triage note in the
issue that owns the gap.

## Current baseline (bpf-next `a30c772627b2`)

**Baseline: 9 documented deviations, 315 surface gaps (#135).**
The context model (`ProgType` + `src/ctx.rs`) moved 84 cases out of the
`unmodeled-prog-type` bucket (238 → 80): sched_cls/sched_act/cgroup_skb
and socket_filter `__sk_buff` fields, `xdp_md` scalars and the
tracepoint window are modelled; `data`/`data_end`/`data_meta`/`sk` stay
gaps (no packet-pointer register type yet).

The 9 allowed findings are known model gaps this exposed, not new
kernel behaviour:

| cases | disagreement | follow-up |
|---|---|---|
| `calls__057/058/061/062/068/070` | spec rejects (stack read / R0 at exit) on programs the kernel accepts after BPF-to-BPF calls | spec call-frame model |
| `precise__000/001` | `ptr -= ptr` on map values: kernel accepts, mini/spec reject | pointer-difference arithmetic |
| `ctx_skb__004` | the same insn sees two pointer types across loop iterations; the kernel rejects ("same insn cannot be used with different pointers"), mini accepts | state-pruning pointer identity |
| `jset__006/007` | the spec has no tnum/bit refinement for JSET, so it explores a branch the kernel prunes | spec bit-level refinement |
| `atomic_fetch__000` | an atomic fetch on a spilled map pointer: the concrete coverage check sees the pointer in the fetch result while the abstract side keeps a widened value | concrete atomic coverage |

Recent closures:

- `dead_code__005` — `check_cfg` accepts a trailing `JMP` like the kernel.
- Atomics (`STX|ATOMIC` W/DW: add/or/and/xor/xchg/cmpxchg, fetch
  forms) are decoded and modelled: the old value goes to src_reg for
  fetch and R0 for cmpxchg (kernel `bpf_atomic_load_reg`), stack targets
  go through the read path (initialization, spill size), the operand
  must be a scalar, and the memory becomes unknown.
- MOV32, JMP32, JSET and the legacy packet loads (`LD_ABS`/`LD_IND`,
  #136) are decoded and modelled: constant-only branches are decided
  statically, `jset imm` clears the tested bits on the fall-through, and
  the packet loads mirror `check_ld_abs` (R6 must be the context, R1-R5
  are caller-saved).
- `jump__000..004` — privileged pointer comparisons (`allow_ptr_leaks`):
  mini keeps both branches, the concrete side compares model addresses,
  the spec pushes both successors, and a spill of an uninitialized
  register marks the slot uninitialized instead of aborting the run. The
  unprivileged half of the rule (`"R%d pointer comparison prohibited"`)
  is the second axis in `tools/MODES.md`.

240 of 478 cases have a modelled prog type; the other 238 are
`unmodeled-prog-type` surface gaps until #135 lands SCHED_CLS/XDP support.
Surface gaps (398 total after #131: 238 prog types + 160 decode/load
surfaces) are counted separately and never gate the replay.
