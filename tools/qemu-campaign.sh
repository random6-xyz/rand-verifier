#!/usr/bin/env bash
# tools/qemu-campaign.sh — run a fuzz campaign with the qemu bpf-next
# guest as the kernel column. This is the DEFAULT local kernel backend
# (host-kernel direct testing is CI-only / user-run).
#
# Flow:
#   1. asset checks   (kernel image + rootfs in fuzz-out/qemu-assets/)
#   2. share prep     tools/qemu-share.sh [--fresh] + strict marker
#   3. guest boot     tools/qemu-boot.sh (background, no sudo)
#   4. campaign       fuzz --kernel --strict --qemu-dir <share> --out-dir <out>
#   5. teardown       tools/qemu-boot.sh --stop
#   6. result         campaign summary + finding count
#
# Usage:
#   tools/qemu-campaign.sh --seed 12345 [--iters 20000] [--mode mutation|generation]
#                          [--strict|--no-strict] [--no-share-reset] [--keep-guest]
#   DRY_RUN=1 tools/qemu-campaign.sh --seed 12345        # preview only
#
# env overrides: QEMU_IMG, QEMU_ROOTFS, QEMU_MEM, QEMU_SMP (see tools/lib.sh)

set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=tools/lib.sh
. ./tools/lib.sh

SEED=""
ITERS="${ITERS:-20000}"
MODE="${MODE:-mutation}"
STRICT=1
RESET_SHARE=1
KEEP_GUEST=0
OUT_DIR=""

usage() {
    cat <<EOF
usage: $0 --seed <seed> [--iters <n>] [--mode mutation|generation] \\
          [--strict|--no-strict] [--no-share-reset] [--keep-guest] \\
          [--out-dir <dir>]
EOF
    exit 1
}

while [ $# -gt 0 ]; do
    case "$1" in
        --seed) SEED="$2"; shift 2 ;;
        --iters) ITERS="$2"; shift 2 ;;
        --mode) MODE="$2"; shift 2 ;;
        --strict) STRICT=1; shift ;;
        --no-strict) STRICT=0; shift ;;
        --no-share-reset) RESET_SHARE=0; shift ;;
        --keep-guest) KEEP_GUEST=1; shift ;;
        --out-dir) OUT_DIR="$2"; shift 2 ;;
        *) usage ;;
    esac
done

[ -n "$SEED" ] || die "--seed is required"
case "$MODE" in mutation|generation) ;; *) die "--mode must be mutation or generation" ;; esac

if [ -z "$OUT_DIR" ]; then
    STAMP="$(stamp)"
    OUT_DIR="$CAMPAIGN_ROOT/qemu-${SEED}-${STAMP}"
fi
export CAMPAIGN_OUT="$OUT_DIR"

say "qemu campaign: seed=$SEED iters=$ITERS mode=$MODE strict=$STRICT"
echo "    campaign out: $OUT_DIR"

# 1. assets
[ -f "$QEMU_KERNEL_IMG" ] || die "kernel image missing: $QEMU_KERNEL_IMG — run tools/qemu-assets.sh -k <bzImage>"
if [ ! -f "$QEMU_ROOTFS" ]; then
    echo "rootfs missing: $QEMU_ROOTFS"
    echo "  → build the sample initramfs (recommended): tools/qemu-assets.sh --sample-initramfs"
    echo "  → or copy a user rootfs:                   tools/qemu-assets.sh -r <rootfs.cpio.gz>"
    exit 1
fi

# 2. share prep
say_step 1 5 "9p share"
if [ "$RESET_SHARE" = "1" ]; then
    tools/qemu-share.sh --fresh
else
    tools/qemu-share.sh
fi
if [ "$STRICT" = "1" ]; then
    run touch "$QEMU_SHARE/strict"
    echo "    strict marker set"
fi

# 3. boot guest
say_step 2 5 "qemu guest boot"
# a stale qemu.pid from an aborted run would make qemu-boot.sh refuse
# to start; clear it before booting (qemu-boot.sh --stop is also
# harmless if nothing is running)
tools/qemu-boot.sh --stop >/dev/null 2>&1 || true
rm -f "$QEMU_ASSETS/qemu.pid"
tools/qemu-boot.sh
trap 'tools/qemu-boot.sh --stop >/dev/null 2>&1 || true' EXIT

# 4. campaign
say_step 3 5 "fuzz campaign (qemu kernel column)"
ensure_dir "$OUT_DIR"
FUZZ_ARGS=(--seed "$SEED" --iters "$ITERS" --mode "$MODE" --kernel --strict \
    --qemu-dir "$QEMU_SHARE" --out-dir "$OUT_DIR")
if [ "${DRY_RUN:-0}" = "1" ]; then
    echo "    [dry-run] cargo run --release --bin fuzz -- ${FUZZ_ARGS[*]}"
else
    (cd "$PROJECT_ROOT" && "$CARGO" run --release --bin fuzz -- "${FUZZ_ARGS[@]}")
fi

# 5. teardown (unless --keep-guest)
say_step 4 5 "teardown"
if [ "$KEEP_GUEST" = "1" ]; then
    echo "    keeping guest running (stop later: tools/qemu-boot.sh --stop)"
    trap - EXIT
else
    tools/qemu-boot.sh --stop
    trap - EXIT
fi

# 6. result summary
say_step 5 5 "results"
echo "    out: $OUT_DIR"
if [ -f "$OUT_DIR/summary.json" ]; then
    python3 - "$OUT_DIR/summary.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
print("    counts:", json.dumps(d.get("counts", {})))
print("    findings:", json.dumps(d.get("findings", [])))
PY
else
    echo "    (no summary.json — campaign may have failed; see run.log)"
fi
echo "    findings dir: $OUT_DIR/findings/"
