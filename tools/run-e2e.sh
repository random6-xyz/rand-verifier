#!/usr/bin/env bash
# tools/run-e2e.sh — end-to-end pipeline: validate → fuzz → report →
# reduce → drift. The local kernel column is QEMU by default; host
# kernel direct testing is CI-only (and printed as a user step here).
#
#   [1/5] validate  cargo build/test/fmt/clippy + smt_verify
#   [2/5] fuzz      qemu campaign (default) or unprivileged smoke (--no-kernel)
#   [3/5] report    tools/finding-report.sh  (preserves assets to fuzz-out/reports/)
#   [4/5] reduce    reduce --all-groups --kernel --strict --qemu-dir (QEMU mode)
#   [5/5] drift     drift --compare baseline
#
# AGENTS.md: this pipeline NEVER touches lab/ and NEVER runs sudo. A
# host-kernel step is only printed for the user to run themselves.
#
# Usage:
#   tools/run-e2e.sh --seed 12345 [--iters 20000] [--mode mutation]
#                     [--no-kernel] [--with-host-kernel] [--skip-validate]
#                     [--skip-drift] [--report-dir <dir>]
#   DRY_RUN=1 tools/run-e2e.sh --seed 12345
#
# env overrides: SEED, ITERS, MODE (same semantics as qemu-campaign.sh)

set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=tools/lib.sh
. ./tools/lib.sh

SEED="${SEED:-}"
ITERS="${ITERS:-20000}"
MODE="${MODE:-mutation}"
USE_KERNEL=1            # 1 = qemu kernel column (default), 0 = unprivileged smoke
WITH_HOST=0
SKIP_VALIDATE=0
SKIP_DRIFT=0
REPORT_ROOT="$CAMPAIGN_ROOT/reports"

usage() {
    cat <<EOF
usage: $0 --seed <seed> [--iters <n>] [--mode mutation|generation] \\
          [--no-kernel] [--with-host-kernel] [--skip-validate] [--skip-drift]
EOF
    exit 1
}

while [ $# -gt 0 ]; do
    case "$1" in
        --seed) SEED="$2"; shift 2 ;;
        --iters) ITERS="$2"; shift 2 ;;
        --mode) MODE="$2"; shift 2 ;;
        --no-kernel) USE_KERNEL=0; shift ;;
        --with-host-kernel) WITH_HOST=1; shift ;;
        --skip-validate) SKIP_VALIDATE=1; shift ;;
        --skip-drift) SKIP_DRIFT=1; shift ;;
        *) usage ;;
    esac
done

[ -n "$SEED" ] || die "--seed is required"
[ "$USE_KERNEL" = "1" ] && [ "$WITH_HOST" = "1" ] && die "--no-kernel and --with-host-kernel are mutually exclusive"

say "e2e: seed=$SEED iters=$ITERS mode=$MODE kernel_column=$([ "$USE_KERNEL" = "1" ] && echo qemu || echo none)"

STEP=0
TOTAL=5

# ── [1/5] validate ───────────────────────────────────────────────────────────
STEP=$((STEP+1))
if [ "$SKIP_VALIDATE" = "1" ]; then
    echo "### [$STEP/$TOTAL] validate (skipped)"
else
    say_step "$STEP" "$TOTAL" "validate (build + test + fmt + clippy)"
    run "$CARGO" build --all-targets
    run "$CARGO" test
    run "$CARGO" fmt --all --check
    run "$CARGO" clippy --all-targets -- -D warnings
    echo "    SMT operator check:"
    if [ "${DRY_RUN:-0}" = "1" ]; then
        echo "    [dry-run] $CARGO run --release --bin smt_verify --"
    else
        (cd "$PROJECT_ROOT" && "$CARGO" run --release --bin smt_verify --) || echo "    (smt_verify: non-zero — review the catalog)"
    fi
fi

# ── [2/5] fuzz ───────────────────────────────────────────────────────────────
STEP=$((STEP+1))
# the campaign out dir is computed ONCE and shared by fuzz / report / reduce
CAMPAIGN_OUT=""
if [ "$USE_KERNEL" = "1" ]; then
    CAMPAIGN_OUT="$CAMPAIGN_ROOT/qemu-${SEED}-$(date +%Y%m%d-%H%M%S)"
else
    CAMPAIGN_OUT="$CAMPAIGN_ROOT/nokernel-${SEED}-$(date +%Y%m%d-%H%M%S)"
fi
export CAMPAIGN_OUT

if [ "$USE_KERNEL" = "1" ]; then
    say_step "$STEP" "$TOTAL" "fuzz (qemu kernel column)"
    # the guest stays up so the reduce step can reuse it
    tools/qemu-campaign.sh --seed "$SEED" --iters "$ITERS" --mode "$MODE" --strict --keep-guest --out-dir "$CAMPAIGN_OUT"
else
    say_step "$STEP" "$TOTAL" "fuzz (unprivileged smoke, no kernel)"
    ensure_dir "$CAMPAIGN_OUT"
    FUZZ_ARGS=(--seed "$SEED" --iters "$ITERS" --mode "$MODE" --out-dir "$CAMPAIGN_OUT")
    if [ "${DRY_RUN:-0}" = "1" ]; then
        echo "    [dry-run] $CARGO run --release --bin fuzz -- ${FUZZ_ARGS[*]}"
    else
        (cd "$PROJECT_ROOT" && "$CARGO" run --release --bin fuzz -- "${FUZZ_ARGS[@]}")
    fi
fi

# host kernel is CI-only: never executed here, only printed for the user
if [ "$WITH_HOST" = "1" ]; then
    user_step "host-kernel campaign (CI-only, requires root)" \
        "tools/fuzz-kernel.sh $SEED   # ITERS=$ITERS MODE=$MODE"
fi

# ── [3/5] report ─────────────────────────────────────────────────────────────
STEP=$((STEP+1))
say_step "$STEP" "$TOTAL" "finding report"
if [ -n "$CAMPAIGN_OUT" ] && [ -d "$CAMPAIGN_OUT" ]; then
    tools/finding-report.sh "$CAMPAIGN_OUT"
else
    echo "    (no campaign out dir — report skipped)"
fi

# ── [4/5] reduce ─────────────────────────────────────────────────────────────
STEP=$((STEP+1))
say_step "$STEP" "$TOTAL" "reduce findings"
if [ "$USE_KERNEL" = "1" ]; then
    REDUCE_ARGS=(--all-groups "$CAMPAIGN_OUT" --kernel --strict --qemu-dir "$QEMU_SHARE" --out-dir "$CAMPAIGN_OUT/reduced")
    if [ "${DRY_RUN:-0}" = "1" ]; then
        echo "    [dry-run] $CARGO run --release --bin reduce -- ${REDUCE_ARGS[*]}"
    else
        (cd "$PROJECT_ROOT" && "$CARGO" run --release --bin reduce -- "${REDUCE_ARGS[@]}") || true
    fi
else
    # unprivileged: only rv-soundness bugs / verdict flips reduce without a kernel
    REDUCE_ARGS=(--all-groups "$CAMPAIGN_OUT" --out-dir "$CAMPAIGN_OUT/reduced")
    if [ "${DRY_RUN:-0}" = "1" ]; then
        echo "    [dry-run] $CARGO run --release --bin reduce -- ${REDUCE_ARGS[*]}"
    else
        (cd "$PROJECT_ROOT" && "$CARGO" run --release --bin reduce -- "${REDUCE_ARGS[@]}") \
            || echo "    (some groups need a kernel — skipped in smoke mode)"
    fi
fi

# stop the guest now that reduce is done (QEMU mode)
if [ "$USE_KERNEL" = "1" ] && [ "${DRY_RUN:-0}" != "1" ]; then
    tools/qemu-boot.sh --stop || true
fi

# ── [5/5] drift ──────────────────────────────────────────────────────────────
STEP=$((STEP+1))
if [ "$SKIP_DRIFT" = "1" ]; then
    echo "### [$STEP/$TOTAL] drift (skipped)"
else
    say_step "$STEP" "$TOTAL" "drift (mini baseline compare)"
    DRAFT="$CAMPAIGN_ROOT/drift-$(date +%Y%m%d-%H%M%S).json"
    if [ "${DRY_RUN:-0}" = "1" ]; then
        echo "    [dry-run] $DRIFT_BIN --record --mini-only $DRAFT"
        echo "    [dry-run] $DRIFT_BIN --compare $DRIFT_BASELINE --new $DRAFT"
    else
        "$DRIFT_BIN" --record --mini-only "$DRAFT"
        "$DRIFT_BIN" --compare "$DRIFT_BASELINE" --new "$DRAFT" || true
    fi
fi

echo
echo "==> e2e complete (seed=$SEED)"
echo "    campaign: $CAMPAIGN_OUT"
echo "    report:   $REPORT_ROOT/<stamp>/"
