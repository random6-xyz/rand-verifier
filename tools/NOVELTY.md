# Novelty scheduling (#140)

The 2026-10 campaign produced 391 finding labels that collapsed to 53
unique programs (7.4x duplication): uniform seed selection kept picking
the same shapes. This module adds a novelty signal to the mutation loop.

## Design

- **KPI signature** (`novelty::signature`) — exact shape, used for the
  `kpi` cluster key: finding class + normalized mini/kernel messages +
  FNV-1a over the opcode-family sequence.
- **Scheduling feature** (`novelty::feature_signature`) — coarse shape,
  used for seed selection: finding class + normalized messages + sorted
  opcode-family set + branch bucket + length bucket. The exact sequence is
  too specific (every mutant inserts/deletes something, so everything
  looks novel).
- **Energy**: `1 / (1 + uses)` per feature, so a feature that keeps
  reappearing loses weight while unseen ones keep full weight.
- **Promotion**: a program whose feature is new is written to
  `--novel-corpus <dir>` (default `fuzz-out/corpus`, capped at 512 files);
  the next campaign loads that directory as extra seeds.
- `--novelty` enables the weighted selection; it is **opt-in** until the
  A/B shows a win (`--no-novelty` is therefore the default).

`summary.json` reports:

```json
"novelty": {
  "enabled": true,
  "unique_features": 606,
  "novel_events": 606,
  "feature_duplicate_ratio": 3.300,
  "promoted": 512
}
```

## A/B (pilot)

```sh
tools/novelty-ab.sh --seed 7 --iters 2000
```

| arm | unique features | duplicate ratio | promoted | findings |
|---|---|---|---|---|
| baseline (uniform) | 606 | 3.30 | 512 | 0 |
| novelty | 606 | 3.30 | 512 | 0 |

Measurement, bpf-next `a30c772627b2`, mutation mode, 2 000 programs:

- **No measurable difference at this size.** The feature space is large
  relative to the pool (~600 features over 2 000 programs), so the energy
  weights stay nearly flat and the selection is effectively uniform.
- Findings are too rare at 2 000 programs (0 in both arms) to compare the
  finding-level duplicate ratio, which is the metric the issue targets.

## Acceptance status

The issue's acceptance (duplicate ratio <= 2x, novel yield >= 3x) is **not
met** by this pilot. The scheduler, promotion and A/B harness are in place
so the experiment can be run at campaign scale (20k+ programs, multiple
seeds) before the default flips. Until then `--novelty` stays opt-in and
#140 stays open.

Next measurements worth trying:

1. 20k programs, 3 seeds, mutation mode, with and without `--novelty`.
2. Seed the pool from the promoted corpus only (no fixture corpus) so the
   feature distribution is dominated by observed verifier responses.
3. Tune the energy exponent (`1/(1+uses)^k`) and the feature buckets —
   both are one-line changes in `src/fuzz/novelty.rs`.

## Result (20k x 3 seeds, #140)

Model-only mutation campaigns, same seeds and corpus, `--mode mutation`:

| seed | arm | unique features | duplicate ratio |
|---|---|---|---|
| 7 | baseline | 7273 | 2.75 |
| 7 | novelty | **10612** | **1.89** |
| 31 | baseline | 7494 | 2.67 |
| 31 | novelty | **10692** | **1.87** |
| 97 | baseline | 7338 | 2.73 |
| 97 | novelty | **10642** | **1.88** |

Novelty selection is **on by default** since this result (`--no-novelty`
opts out). The mechanism needed one fix to bite: the energy decayed on
*promotion* only, and promotion saturates after the first new signature,
so every weight stayed 1.0 and the two arms were bit-identical. Counting
picks (`NoveltyMap::note_pick`) makes the energy meaningful.
