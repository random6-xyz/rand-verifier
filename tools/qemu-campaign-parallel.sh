#!/usr/bin/env bash
# tools/qemu-campaign-parallel.sh — parallel qemu bpf-next campaigns (host-less)
#
# Runs N independent qemu guests, each with its own 9p share (job/out) and
# kernel verifier column (mini+concrete+spec+kernel = 4 axes per campaign).
# No host BPF_PROG_LOAD, no sudo. Each guest is isolated via
# QEMU_ASSETS/QEMU_SHARE/QEMU_KERNEL_IMG/QEMU_ROOTFS env overrides
# (tools/lib.sh contract) so src/fuzz/qemu.rs never races.
#
# Flow per job:
#   1. per-guest asset prep  (bzImage/rootfs copy + share --fresh + strict marker)
#   2. per-guest boot        (qemu-boot.sh, guest-ready poll)
#   3. parallel fuzz         (cargo run --bin fuzz -- --kernel --strict --qemu-dir $share)
#   4. teardown              (qemu-boot.sh --stop per guest)
#   5. aggregate summary     (per-job summary.json + overall)
#
# Usage:
#   tools/qemu-campaign-parallel.sh [--seed <seed>] [--jobs <N>] [--iters <n>]
#                                   [--mode mutation|generation] [--strict|--no-strict]
#                                   [--kernel-image <bzImage>] [--mem <MB>] [--smp <N>]
#                                   [--out-root <dir>] [--keep-guests] [--no-share-reset]
#   DRY_RUN=1 tools/qemu-campaign-parallel.sh --seed 20260101-2344 --jobs 4
#
# Defaults:
#   --seed  YYYYMMDD-XXXX  (e.g. 20260101-2344, date + 4-digit random; numeric part is passed to fuzz)
#   --jobs  4 (capped at nproc)
#   --iters 20000
#   --mode  mutation
#   --strict (on)
#   --kernel-image  single bzImage (replicated to every guest; if omitted, uses fuzz-out/qemu-assets/bzImage)
#   --mem   auto-downscale: per-guest = max(512, 2048 / jobs) unless --mem given
#
# Env overrides: QEMU_KERNEL_IMG, QEMU_ROOTFS, QEMU_MEM, QEMU_SMP, QEMU_BIN, CAMPAIGN_ROOT (see tools/lib.sh)

set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=tools/lib.sh
. ./tools/lib.sh

# ---- defaults -------------------------------------------------------------
# seed: YYYYMMDD-XXXX (date + 4-digit random). Stored with hyphen for
# display; numeric part (hyphen stripped) is passed to `fuzz --seed`.
DEFAULT_SEED_RAW=""
DEFAULT_JOBS=4
ITERS="${ITERS:-20000}"
MODE="${MODE:-mutation}"
STRICT=1
RESET_SHARE=1
KEEP_GUESTS=0
OUT_ROOT=""
KERNEL_IMAGE=""
MEM_ARG=""
SMP_ARG=""

# jobs default is 4 but must not exceed nproc
NPROC="$(nproc 2>/dev/null || echo 4)"
if [ "$DEFAULT_JOBS" -gt "$NPROC" ]; then
    DEFAULT_JOBS="$NPROC"
fi
JOBS="$DEFAULT_JOBS"
SEED_RAW=""

usage() {
    cat <<EOF
usage: $0 [--seed <seed>] [--jobs <N>] [--iters <n>] [--mode mutation|generation]
          [--strict|--no-strict] [--kernel-image <bzImage>] [--mem <MB>] [--smp <N>]
          [--out-root <dir>] [--keep-guests] [--no-share-reset]

  --seed <seed>        base seed (YYYYMMDD-XXXX or numeric). Default: \$(date +%Y%m%d)-XXXX
  --jobs <N>           parallel campaigns (default 4, max nproc=$NPROC)
  --iters <n>          iters per campaign (default 20000, env ITERS)
  --mode <mode>        mutation or generation (default mutation, env MODE)
  --strict/--no-strict strict marker per guest (default --strict)
  --kernel-image <img> single bzImage replicated to every guest (if omitted, uses \$QEMU_ASSETS/bzImage)
  --mem <MB>           per-guest memory MB (default auto: max(512, 2048/jobs))
  --smp <N>            per-guest vCPUs (default 2, env QEMU_SMP)
  --out-root <dir>     root for campaign outs (default \$CAMPAIGN_ROOT)
  --keep-guests        keep guests running after campaigns
  --no-share-reset     do not --fresh the share
EOF
    exit 1
}

# ---- arg parse ------------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        --seed) SEED_RAW="$2"; shift 2 ;;
        --jobs) JOBS="$2"; shift 2 ;;
        --iters) ITERS="$2"; shift 2 ;;
        --mode) MODE="$2"; shift 2 ;;
        --strict) STRICT=1; shift ;;
        --no-strict) STRICT=0; shift ;;
        --kernel-image) KERNEL_IMAGE="$2"; shift 2 ;;
        --mem) MEM_ARG="$2"; shift 2 ;;
        --smp) SMP_ARG="$2"; shift 2 ;;
        --out-root) OUT_ROOT="$2"; shift 2 ;;
        --keep-guests) KEEP_GUESTS=1; shift ;;
        --no-share-reset) RESET_SHARE=0; shift ;;
        --help|-h) usage ;;
        *) echo "unknown arg: $1" >&2; usage ;;
    esac
done

# ---- seed default: YYYYMMDD-XXXX -----------------------------------------
if [ -z "$SEED_RAW" ]; then
    RAND4="$(printf "%04d" "$(shuf -i 0-9999 -n 1)")"
    SEED_RAW="$(date +%Y%m%d)-${RAND4}"
fi
# numeric part for fuzz (strip hyphen and non-digits)
SEED_NUM="$(echo "$SEED_RAW" | tr -cd '0-9')"
if [ -z "$SEED_NUM" ]; then
    die "invalid --seed $SEED_RAW (must contain digits)"
fi
# fuzz expects u64; 12-digit YYYYMMDDXXXX is < 2^64 ( ~1e12 ), safe
# Validate it fits u64 by checking length and that python can parse it
python3 -c "int('$SEED_NUM')" 2>/dev/null || die "seed not numeric: $SEED_RAW -> $SEED_NUM"

# ---- jobs validation (nproc cap) -----------------------------------------
if ! [[ "$JOBS" =~ ^[0-9]+$ ]] || [ "$JOBS" -lt 1 ]; then
    die "--jobs must be >=1 (got $JOBS)"
fi
if [ "$JOBS" -gt "$NPROC" ]; then
    echo "warning: --jobs $JOBS > nproc $NPROC, capping to $NPROC" >&2
    JOBS="$NPROC"
fi

case "$MODE" in mutation|generation) ;; *) die "--mode must be mutation or generation" ;; esac

# ---- mem auto-downscale --------------------------------------------------
# base 2048 MB single-guest default; per-guest = max(512, 2048 / jobs) unless overridden
BASE_MEM=2048
if [ -n "$MEM_ARG" ]; then
    if ! [[ "$MEM_ARG" =~ ^[0-9]+$ ]] || [ "$MEM_ARG" -lt 128 ]; then
        die "--mem must be >=128 (got $MEM_ARG)"
    fi
    PER_GUEST_MEM="$MEM_ARG"
else
    # auto: divide base by jobs, floor 512
    PER_GUEST_MEM=$(( BASE_MEM / JOBS ))
    if [ "$PER_GUEST_MEM" -lt 512 ]; then
        PER_GUEST_MEM=512
    fi
    # if user exported QEMU_MEM, treat it as explicit per-guest and respect it
    if [ -n "${QEMU_MEM:-}" ] && [ "${QEMU_MEM}" != "2048" ]; then
        # env override is present (non-default) -> use it as per-guest
        PER_GUEST_MEM="$QEMU_MEM"
    fi
fi

if [ -n "$SMP_ARG" ]; then
    if ! [[ "$SMP_ARG" =~ ^[0-9]+$ ]] || [ "$SMP_ARG" -lt 1 ]; then
        die "--smp must be >=1 (got $SMP_ARG)"
    fi
    PER_GUEST_SMP="$SMP_ARG"
else
    PER_GUEST_SMP="${QEMU_SMP:-2}"
fi

if [ -n "$OUT_ROOT" ]; then
    CAMPAIGN_ROOT="$OUT_ROOT"
fi

STAMP="$(stamp)"
say "parallel qemu campaign: base-seed=$SEED_RAW ($SEED_NUM) jobs=$JOBS iters=$ITERS mode=$MODE strict=$STRICT"
echo "    per-guest mem=${PER_GUEST_MEM}MB smp=${PER_GUEST_SMP} keep-guests=${KEEP_GUESTS}"
echo "    stamp: $STAMP"
echo "    out root: $CAMPAIGN_ROOT"

# ---- build fuzz binary once ----------------------------------------------
say_step 1 5 "build fuzz binary"
if [ "${DRY_RUN:-0}" = "1" ]; then
    echo "    [dry-run] cargo build --release --bin fuzz"
else
    (cd "$PROJECT_ROOT" && "$CARGO" build --release --bin fuzz)
fi

# ---- resolve kernel image source -----------------------------------------
# single image replicated to every guest
KERNEL_SRC=""
if [ -n "$KERNEL_IMAGE" ]; then
    KERNEL_SRC="$KERNEL_IMAGE"
    [ -f "$KERNEL_SRC" ] || die "kernel image not found: $KERNEL_SRC"
    assert_not_lab "$KERNEL_SRC"
else
    # default: current QEMU_KERNEL_IMG (fuzz-out/qemu-assets/bzImage)
    if [ -f "$QEMU_KERNEL_IMG" ]; then
        KERNEL_SRC="$QEMU_KERNEL_IMG"
    else
        die "kernel image missing: $QEMU_KERNEL_IMG — pass --kernel-image <bzImage> or run tools/qemu-assets.sh -k <bzImage>"
    fi
fi

# rootfs source: current QEMU_ROOTFS
ROOTFS_SRC="$QEMU_ROOTFS"
if [ ! -f "$ROOTFS_SRC" ]; then
    echo "rootfs missing: $ROOTFS_SRC"
    echo "  → build the sample initramfs (recommended): tools/qemu-assets.sh --sample-initramfs"
    echo "  → or copy a user rootfs:                   tools/qemu-assets.sh -r <rootfs.cpio.gz>"
    exit 1
fi

# ---- per-guest asset prep ------------------------------------------------
say_step 2 5 "per-guest assets (share isolation)"
GUEST_ASSETS=()
GUEST_SHARES=()
for j in $(seq 0 $((JOBS - 1))); do
    GA="$CAMPAIGN_ROOT/qemu-assets-p${j}"
    GS="$GA/share"
    GUEST_ASSETS+=("$GA")
    GUEST_SHARES+=("$GS")
    echo "    [p$j] assets=$GA share=$GS"

    if [ "${DRY_RUN:-0}" = "1" ]; then
        echo "    [dry-run] mkdir -p $GA && cp $KERNEL_SRC $GA/bzImage && cp $ROOTFS_SRC $GA/rootfs.cpio.gz"
        echo "    [dry-run] QEMU_ASSETS=$GA QEMU_SHARE=$GS tools/qemu-share.sh --fresh"
        continue
    fi

    ensure_dir "$GA"
    # copy kernel image per guest (replicated)
    if [ ! -f "$GA/bzImage" ]; then
        cp "$KERNEL_SRC" "$GA/bzImage"
        chmod 644 "$GA/bzImage"
    else
        # if user gave --kernel-image and guest already has a bzImage, ensure it matches
        if [ -n "$KERNEL_IMAGE" ]; then
            # overwrite only if different (by size/mtime); keep explicit replication
            if ! cmp -s "$KERNEL_SRC" "$GA/bzImage"; then
                cp -f "$KERNEL_SRC" "$GA/bzImage"
                chmod 644 "$GA/bzImage"
            fi
        fi
    fi
    if [ ! -f "$GA/rootfs.cpio.gz" ]; then
        cp "$ROOTFS_SRC" "$GA/rootfs.cpio.gz"
        chmod 644 "$GA/rootfs.cpio.gz"
    fi

    # share prep with isolation
    if [ "$RESET_SHARE" = "1" ]; then
        QEMU_ASSETS="$GA" QEMU_SHARE="$GS" tools/qemu-share.sh --fresh
    else
        QEMU_ASSETS="$GA" QEMU_SHARE="$GS" tools/qemu-share.sh
    fi
    if [ "$STRICT" = "1" ]; then
        # strict marker is consumed by guest init loop; set per share
        if [ "${DRY_RUN:-0}" = "1" ]; then
            echo "    [dry-run] touch $GS/strict"
        else
            touch "$GS/strict"
        fi
    else
        rm -f "$GS/strict"
    fi
done

if [ "${DRY_RUN:-0}" = "1" ]; then
    echo "    [dry-run] per-guest assets done"
fi

# ---- per-guest boot (sequential to avoid KVM thundering herd) ------------
say_step 3 5 "boot $JOBS guests (sequential, mem=${PER_GUEST_MEM}MB)"
BOOT_PIDS=()
for j in $(seq 0 $((JOBS - 1))); do
    GA="${GUEST_ASSETS[$j]}"
    GS="${GUEST_SHARES[$j]}"
    echo "    [p$j] booting: QEMU_ASSETS=$GA QEMU_SHARE=$GS QEMU_MEM=$PER_GUEST_MEM QEMU_SMP=$PER_GUEST_SMP"

    if [ "${DRY_RUN:-0}" = "1" ]; then
        echo "    [dry-run] QEMU_ASSETS=$GA QEMU_SHARE=$GS QEMU_MEM=$PER_GUEST_MEM QEMU_SMP=$PER_GUEST_SMP tools/qemu-boot.sh"
        continue
    fi

    # clear stale pid before boot
    QEMU_ASSETS="$GA" QEMU_SHARE="$GS" tools/qemu-boot.sh --stop >/dev/null 2>&1 || true
    rm -f "$GA/qemu.pid"
    if ! QEMU_ASSETS="$GA" QEMU_SHARE="$GS" QEMU_MEM="$PER_GUEST_MEM" QEMU_SMP="$PER_GUEST_SMP" tools/qemu-boot.sh; then
        echo "error: guest p$j failed to boot — tearing down already booted guests" >&2
        for k in $(seq 0 $((j - 1))); do
            GAK="${GUEST_ASSETS[$k]}"
            GSK="${GUEST_SHARES[$k]}"
            QEMU_ASSETS="$GAK" QEMU_SHARE="$GSK" tools/qemu-boot.sh --stop >/dev/null 2>&1 || true
        done
        exit 1
    fi
done

# trap: stop all guests on exit unless --keep-guests
cleanup_guests() {
    if [ "$KEEP_GUESTS" = "1" ]; then
        echo "    keeping $JOBS guests running (--keep-guests)"
        for j in $(seq 0 $((JOBS - 1))); do
            echo "      p$j: QEMU_ASSETS=${GUEST_ASSETS[$j]} (stop later: QEMU_ASSETS=${GUEST_ASSETS[$j]} tools/qemu-boot.sh --stop)"
        done
        return 0
    fi
    echo "    stopping $JOBS guests"
    for j in $(seq 0 $((JOBS - 1))); do
        GA="${GUEST_ASSETS[$j]}"
        GS="${GUEST_SHARES[$j]}"
        QEMU_ASSETS="$GA" QEMU_SHARE="$GS" tools/qemu-boot.sh --stop >/dev/null 2>&1 || true
    done
}

if [ "$KEEP_GUESTS" != "1" ]; then
    trap cleanup_guests EXIT INT TERM
else
    trap 'echo "keep-guests: not stopping on EXIT"' EXIT
fi

if [ "${DRY_RUN:-0}" = "1" ]; then
    echo "    [dry-run] guests would be booted"
fi

# ---- parallel fuzz campaigns ---------------------------------------------
say_step 4 5 "parallel fuzz campaigns (each 4 axes: mini+concrete+spec+kernel)"
OUT_DIRS=()
SEEDS=()
for j in $(seq 0 $((JOBS - 1))); do
    SEED_J=$((SEED_NUM + j))
    SEEDS+=("$SEED_J")
    OUT_J="$CAMPAIGN_ROOT/qemu-parallel-${STAMP}-seed-${SEED_J}-p${j}"
    OUT_DIRS+=("$OUT_J")
    if [ "${DRY_RUN:-0}" != "1" ]; then
        ensure_dir "$OUT_J"
    fi
done
echo "    seeds: ${SEEDS[*]}"
echo "    outs : ${OUT_DIRS[*]}"

PIDS=()
for j in $(seq 0 $((JOBS - 1))); do
    SEED_J="${SEEDS[$j]}"
    GS="${GUEST_SHARES[$j]}"
    OUT_J="${OUT_DIRS[$j]}"
    echo "    [p$j] seed=$SEED_J qemu-dir=$GS out=$OUT_J"

    if [ "${DRY_RUN:-0}" = "1" ]; then
        STRICT_FLAG=""
        [ "$STRICT" = "1" ] && STRICT_FLAG=" --strict"
        echo "    [dry-run] cargo run --release --bin fuzz -- --seed $SEED_J --iters $ITERS --mode $MODE --kernel${STRICT_FLAG} --qemu-dir $GS --out-dir $OUT_J"
        continue
    fi

    # strict is already via share/strict, but also pass --strict flag when STRICT=1 (qemu.rs checks env, fuzz checks flag too)
    FUZZ_ARGS=(--seed "$SEED_J" --iters "$ITERS" --mode "$MODE" --kernel --qemu-dir "$GS" --out-dir "$OUT_J")
    if [ "$STRICT" = "1" ]; then
        FUZZ_ARGS+=(--strict)
    fi
    # run in background, log to run.log
    (
        cd "$PROJECT_ROOT" && "$CARGO" run --release --bin fuzz -- "${FUZZ_ARGS[@]}" > "$OUT_J/run.log" 2>&1
        echo "$?" > "$OUT_J/exit.code"
    ) &
    PIDS+=("$!")
done

if [ "${DRY_RUN:-0}" = "1" ]; then
    echo "    [dry-run] would launch $JOBS parallel fuzz campaigns"
    echo "    [dry-run] seeds ${SEEDS[*]}"
    # dry-run teardown preview
    if [ "$KEEP_GUESTS" != "1" ]; then
        echo "    [dry-run] would stop $JOBS guests"
        for j in $(seq 0 $((JOBS - 1))); do
            echo "    [dry-run] QEMU_ASSETS=${GUEST_ASSETS[$j]} tools/qemu-boot.sh --stop"
        done
    fi
    trap - EXIT INT TERM
    exit 0
fi

echo "    waiting for $JOBS campaigns..."
OVERALL=0
for idx in "${!PIDS[@]}"; do
    pid="${PIDS[$idx]}"
    SEED_J="${SEEDS[$idx]}"
    OUT_J="${OUT_DIRS[$idx]}"
    if wait "$pid"; then
        st=0
    else
        st=$?
    fi
    # also check fuzz exit.code if exists (fuzz exits 1 on findings, which is expected)
    if [ -f "$OUT_J/exit.code" ]; then
        st="$(cat "$OUT_J/exit.code")"
    fi
    # findings count from summary.json (precision/soundness etc)
    n="?"
    if [ -f "$OUT_J/summary.json" ]; then
        n=$(python3 -c "import json; d=json.load(open('$OUT_J/summary.json')); print(sum(d.get('counts',{}).get(k,0) for k in ('precision-candidate','soundness-candidate','kernel-unsound-candidate','kernel-overstrict-candidate','rv-precision-gap','rv-soundness-bug','rv-panic')))" 2>/dev/null || echo "?")
    fi
    echo "    [p$idx] seed $SEED_J: exit $st, $n finding(s) → $OUT_J"
    # fuzz exit 1 is not an infra failure; only infra (e.g. missing summary) counts as overall failure
    # but we preserve overall=1 if any campaign had findings and user wants to gate on it
    if [ "$st" -ne 0 ] && [ "$st" -ne 1 ]; then
        OVERALL=1
    fi
    # if findings exist, mark overall 1 for CI (unless TOLERATE logic desired later)
    if [ "$n" != "?" ] && [ "$n" != "0" ]; then
        OVERALL=1
    fi
done

# ---- teardown ------------------------------------------------------------
say_step 5 5 "teardown"
if [ "$KEEP_GUESTS" = "1" ]; then
    echo "    keeping guests running"
    trap - EXIT INT TERM
else
    cleanup_guests
    trap - EXIT INT TERM
fi

# ---- aggregate -----------------------------------------------------------
say "results: $CAMPAIGN_ROOT (parallel $JOBS)"
for idx in "${!OUT_DIRS[@]}"; do
    OUT_J="${OUT_DIRS[$idx]}"
    SEED_J="${SEEDS[$idx]}"
    echo "    [p$idx] seed $SEED_J → $OUT_J"
    if [ -f "$OUT_J/summary.json" ]; then
        python3 - "$OUT_J/summary.json" <<'PY'
import json, sys
d=json.load(open(sys.argv[1]))
print("      counts:", json.dumps(d.get("counts", {})))
print("      findings:", len(d.get("findings", [])))
PY
    else
        echo "      (no summary.json — see $OUT_J/run.log)"
    fi
done

# overall summary file
OVERALL_SUM="$CAMPAIGN_ROOT/qemu-parallel-${STAMP}-overall.json"
if [ "${DRY_RUN:-0}" != "1" ]; then
    python3 <<PY
import json, pathlib
stamp = "$STAMP"
jobs = int("$JOBS")
base_raw = "$SEED_RAW"
base_num = int("$SEED_NUM")
seeds = [int(s) for s in "${SEEDS[*]}".split() if s.strip()]
outs = [s for s in "${OUT_DIRS[*]}".split() if s]
per_guest_mem = int("$PER_GUEST_MEM")
per_guest_smp = int("$PER_GUEST_SMP")
mode = "$MODE"
strict = bool(int("$STRICT"))
agg = {
    "stamp": stamp,
    "jobs": jobs,
    "base_seed_raw": base_raw,
    "base_seed_num": base_num,
    "seeds": seeds,
    "outs": outs,
    "per_guest_mem": per_guest_mem,
    "per_guest_smp": per_guest_smp,
    "mode": mode,
    "strict": strict,
}
try:
    for o in outs:
        p = pathlib.Path(o) / "summary.json"
        if p.exists():
            d = json.load(open(p))
            agg.setdefault("per_job", []).append({"out": o, "counts": d.get("counts", {}), "findings": d.get("findings", [])})
except Exception as e:
    agg["aggregate_error"] = str(e)
open("$OVERALL_SUM", "w").write(json.dumps(agg, indent=2))
print(f"wrote $OVERALL_SUM")
PY
    echo "    overall: $OVERALL_SUM"
fi

exit "$OVERALL"
