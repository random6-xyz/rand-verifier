#!/usr/bin/env bash
# tools/novelty-ab.sh — compare uniform (baseline) vs novelty-weighted
# seed selection over the same seed and corpus (#140).
#
# Usage:
#   tools/novelty-ab.sh [--seed <n>] [--iters <n>] [--mode mutation|generation]
#
# Prints one row per arm: unique signatures, signature duplicate ratio
# (programs / unique signatures), promoted corpus size, and the KPI block.
set -euo pipefail
cd "$(dirname "$0")/.."

SEED="${SEED:-7}"
ITERS="${ITERS:-2000}"
MODE="${MODE:-mutation}"
while [ $# -gt 0 ]; do
    case "$1" in
        --seed) SEED="$2"; shift 2 ;;
        --iters) ITERS="$2"; shift 2 ;;
        --mode) MODE="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

cargo build --release --quiet --bin fuzz

printf '%-10s %10s %12s %10s %10s\n' arm features dup-ratio promoted findings
for arm in baseline novelty; do
    out="$(mktemp -d)"
    corpus="$out/corpus"
    extra=()
    [ "$arm" = novelty ] && extra+=(--novelty)
    ./target/release/fuzz --seed "$SEED" --iters "$ITERS" --mode "$MODE" \
        "${extra[@]}" --novel-corpus "$corpus" --out-dir "$out/campaign" >/dev/null 2>&1 || true
    python3 - "$out/campaign/summary.json" "$arm" <<'PY'
import json, sys
path, arm = sys.argv[1], sys.argv[2]
try:
    data = json.load(open(path))
except Exception:
    print(f"{arm:<10} {'-':>10} {'-':>10} {'-':>10} {'-':>10}")
    sys.exit(0)
nov = data.get("novelty", {})
kpi = data.get("kpi", {})
print(
    f"{arm:<10} {nov.get('unique_features', 0):>10} "
    f"{nov.get('feature_duplicate_ratio', 0):>12.2f} "
    f"{nov.get('promoted', 0):>10} {kpi.get('findings_total', 0):>10}"
)
PY
    rm -rf "$out"
done

echo
echo "acceptance (pilot, 2k programs): novelty dup-ratio <= 2.0 and"
echo "unique signatures >= 3x baseline; the 10x target is tracked in #141."
