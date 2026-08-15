#!/usr/bin/env bash
# tools/fuzz-kernel.sh — build the fuzz binary and run kernel-backed
# campaigns with a random seed (20000 iters by default), storing the
# results inside the project under fuzz-out/ (gitignored).
#
# Usage:
#   tools/fuzz-kernel.sh                # random seed, 20000 iters, strict
#   tools/fuzz-kernel.sh 12345          # fixed seed (reproducible)
#   SEED=12345 ITERS=5000 tools/fuzz-kernel.sh
#   JOBS=4 tools/fuzz-kernel.sh 12345   # 4 parallel campaigns, seeds 12345..12348
#   STRICT=0 tools/fuzz-kernel.sh       # privileged kernel rules (default: strict)
#   TOLERATE=1 tools/fuzz-kernel.sh     # exit 0 even when findings exist
#   MODE=generation tools/fuzz-kernel.sh
#   DRY_RUN=1 tools/fuzz-kernel.sh      # print the commands without running them
#
# Parallel mode (JOBS > 1): one campaign per job with seeds
# SEED .. SEED+JOBS-1, each writing to its own
# fuzz-out/kernel-<stamp>-seed-<seed>/ (run log in run.log). Requires
# passwordless sudo or a cached credential — `sudo -v` is run before
# launching the jobs, so the background sudo invocations do not prompt.
#
# Requires sudo: --kernel loads the program into the real kernel
# (BPF_PROG_LOAD); --strict drops CAP_SYS_ADMIN/CAP_PERFMON for
# unprivileged-equivalent rules (recommended — privileged loads get
# allow_ptr_leaks leniency and hide unprivileged design rules).
#
# Exit code: 1 when any campaign found findings (unless TOLERATE=1),
# 0 otherwise.

set -euo pipefail
cd "$(dirname "$0")/.."

SEED="${1:-${SEED:-$(shuf -i 0-99999 -n 1)}}"
ITERS="${ITERS:-20000}"
MODE="${MODE:-mutation}"
STRICT="${STRICT:-1}"
TOLERATE="${TOLERATE:-0}"
JOBS="${JOBS:-1}"

echo "==> cargo build --release --bin fuzz"
cargo build --release --bin fuzz

STAMP="$(date +%Y%m%d-%H%M%S)"

# One campaign: seed → its own out-dir. The fuzz binary must run as
# root (BPF_PROG_LOAD), so the whole job (including the log redirect)
# runs inside a single sudo shell; the results are chowned back to the
# user afterwards.
run_one() {
    local seed="$1"
    local out="fuzz-out/kernel-${STAMP}-seed-${seed}"
    local extra=""
    [ "$STRICT" = "1" ] && extra="$extra --strict"
    [ "$TOLERATE" = "1" ] && extra="$extra --tolerate-findings"
    local cmd="mkdir -p '$out' && cd '$PWD' && ./target/release/fuzz \
--seed $seed --iters $ITERS --mode $MODE --kernel --out-dir '$out'$extra \
> '$out/run.log' 2>&1"
    if [ "${DRY_RUN:-0}" = "1" ]; then
        echo "    sudo bash -c \"$cmd\""
        return 0
    fi
    sudo bash -c "$cmd"
}

if [ "${DRY_RUN:-0}" = "1" ]; then
    if [ "$JOBS" -le 1 ]; then
        echo "==> would run (single):"
    else
        echo "==> would launch $JOBS parallel campaigns (seeds $SEED..$((SEED + JOBS - 1)))"
    fi
    run_one "$SEED"
    for i in $(seq 1 $((JOBS - 1))); do
        run_one "$((SEED + i))"
    done
    exit 0
fi

if [ "$JOBS" -le 1 ]; then
    echo "==> sudo ./target/release/fuzz --seed $SEED --iters $ITERS --mode $MODE --kernel --strict --out-dir fuzz-out/kernel-${STAMP}-seed-${SEED} (strict=$STRICT)"
    status=0
    run_one "$SEED" || status=$?
    sudo chown -R "$(id -un)" "fuzz-out/kernel-${STAMP}-seed-${SEED}"
    echo
    echo "==> results: fuzz-out/kernel-${STAMP}-seed-${SEED}"
    echo "    summary : fuzz-out/kernel-${STAMP}-seed-${SEED}/summary.json"
    echo "    findings: fuzz-out/kernel-${STAMP}-seed-${SEED}/findings/"
    exit "$status"
fi

# ── parallel: JOBS campaigns, seeds SEED .. SEED+JOBS-1 ──────────────
sudo -v # cache the credential so the background sudo jobs do not prompt
seeds=()
for i in $(seq 0 $((JOBS - 1))); do
    seeds+=("$((SEED + i))")
done
echo "==> launching $JOBS parallel campaigns (seeds ${seeds[*]}), iters $ITERS, strict=$STRICT"

pids=()
for seed in "${seeds[@]}"; do
    run_one "$seed" &
    pids+=("$!")
done

overall=0
for i in "${!pids[@]}"; do
    seed="${seeds[$i]}"
    out="fuzz-out/kernel-${STAMP}-seed-${seed}"
    if wait "${pids[$i]}"; then st=0; else st=$?; fi
    sudo chown -R "$(id -un)" "$out"
    n=$(python3 -c "import json,sys; d=json.load(open('$out/summary.json')); print(sum(d['counts'].get(k, 0) for k in ('precision-candidate','soundness-candidate','rv-precision-gap','rv-soundness-bug')))" 2>/dev/null || echo "?")
    echo "    seed $seed: exit $st, $n finding(s) → $out"
    [ "$st" -ne 0 ] && overall=1
done

echo
echo "==> results: fuzz-out/ (kernel-${STAMP}-seed-*)"
echo "    summary per job: fuzz-out/kernel-${STAMP}-seed-*/summary.json"
exit "$overall"
