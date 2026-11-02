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

| id | gap | owner |
|---|---|---|
| `jump__00{0..7}` | mini rejects a pointer/imm comparison the kernel accepts | #136 (JMP32/LD), #135 (ctx) |
| `dead_code__005` | subprogram boundary handling | #137 |

240 of 478 cases have a modelled prog type; the other 238 are
`unmodeled-prog-type` surface gaps until #135 lands SCHED_CLS/XDP support.
Surface gaps (398 total after #131: 238 prog types + 160 decode/load
surfaces) are counted separately and never gate the replay.
