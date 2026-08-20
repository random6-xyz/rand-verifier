#!/usr/bin/env bash
# tools/lib.sh — shared path constants and helpers for the rand-verifier
# automation pipeline. Sourced by every tools/*.sh script.
#
# PATH CONTRACT (single source of truth):
#
#   CAMPAIGN_ROOT     fuzz-out/                      all campaign artifacts (gitignored)
#   QEMU_ASSETS       fuzz-out/qemu-assets/          qemu images/rootfs/9p share root (gitignored)
#   QEMU_SHARE        fuzz-out/qemu-assets/share/    live 9p share root (job/ + out/)
#   CAMPAIGN_OUT      fuzz-out/qemu-<seed>-<stamp>/  one campaign's result dir
#   RUNBOOK           docs/RUNBOOK.md                the authoritative path doc
#
# AGENTS.md constraints enforced here:
#   * lab/ is the user's manual workspace — the pipeline MUST NOT read or
#     write anything under lab/. No tools/*.sh script references lab/.
#   * `sudo` is never invoked by these scripts. Any host-privileged step
#     (e.g. host kernel) is printed as a dry-run command for the user to
#     run themselves.
#   * git is never committed/pushed by these scripts.

set -euo pipefail

# ---- project layout --------------------------------------------------------
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PROJECT_ROOT

# Campaign artifacts root (gitignored).
CAMPAIGN_ROOT="${CAMPAIGN_ROOT:-$PROJECT_ROOT/fuzz-out}"
export CAMPAIGN_ROOT

# qemu assets: images, rootfs, and the live 9p share root (gitignored).
QEMU_ASSETS="${QEMU_ASSETS:-$CAMPAIGN_ROOT/qemu-assets}"
export QEMU_ASSETS

# Live 9p share root consumed by src/fuzz/qemu.rs (job/ + out/).
QEMU_SHARE="${QEMU_SHARE:-$QEMU_ASSETS/share}"
export QEMU_SHARE

# A single campaign's result directory:
#   fuzz-out/qemu-<seed>-<stamp>/  (or fuzz-out/<mode>-<seed>-<stamp>/ when !kernel)
CAMPAIGN_OUT=""
export CAMPAIGN_OUT

# ---- binaries --------------------------------------------------------------
CARGO="${CARGO:-cargo}"
QEMU_BIN="${QEMU_BIN:-qemu-system-x86_64}"
export CARGO QEMU_BIN

# ---- release binaries (built into target/release) --------------------------
FUZZ_BIN="$PROJECT_ROOT/target/release/fuzz"
REDUCE_BIN="$PROJECT_ROOT/target/release/reduce"
DRIFT_BIN="$PROJECT_ROOT/target/release/drift"
DIFF_BIN="$PROJECT_ROOT/target/release/diff"
KERNEL_RUN_BIN="$PROJECT_ROOT/target/release/kernel_run"
SMT_VERIFY_BIN="$PROJECT_ROOT/target/release/smt_verify"
export FUZZ_BIN REDUCE_BIN DRIFT_BIN DIFF_BIN KERNEL_RUN_BIN SMT_VERIFY_BIN

# ---- qemu asset defaults ---------------------------------------------------
QEMU_KERNEL_IMG="${QEMU_KERNEL_IMG:-$QEMU_ASSETS/bzImage}"
QEMU_ROOTFS="${QEMU_ROOTFS:-$QEMU_ASSETS/rootfs.cpio.gz}"
QEMU_MEM="${QEMU_MEM:-2048}"
QEMU_SMP="${QEMU_SMP:-2}"
QEMU_BOOT_TIMEOUT="${QEMU_BOOT_TIMEOUT:-90}"
export QEMU_KERNEL_IMG QEMU_ROOTFS QEMU_MEM QEMU_SMP QEMU_BOOT_TIMEOUT

# ---- drift baseline --------------------------------------------------------
DRIFT_BASELINE="${DRIFT_BASELINE:-$PROJECT_ROOT/tools/drift-baseline/v0.9-bpfnext-7.2.0-rc6.json}"
export DRIFT_BASELINE

# ---- corpus ----------------------------------------------------------------
CORPUS_ACCEPT="$PROJECT_ROOT/tests/programs/accept"
CORPUS_REJECT="$PROJECT_ROOT/tests/programs/reject"
export CORPUS_ACCEPT CORPUS_REJECT

# ---- generic helpers -------------------------------------------------------
die() {
    echo "error: $*" >&2
    exit 1
}

say() {
    echo "==> $*"
}

say_step() {
    echo
    echo "### [$1/$2] $3"
}

# DRY_RUN=1: print the command without executing it.
run() {
    if [ "${DRY_RUN:-0}" = "1" ]; then
        echo "    [dry-run] $*"
    else
        echo "    $*"
        "$@"
    fi
}

# A step that would need privileges: never run it, only print the command
# for the user to execute themselves (AGENTS.md: sudo is user-run).
#   user_step <description> <command...>
user_step() {
    local desc="$1"
    shift
    echo
    echo "### $desc (requires privileges — run this yourself, the pipeline never executes it)"
    echo "    $*"
}

# Guard: lab/ must never be referenced by the pipeline.
assert_not_lab() {
    case "$1" in
        *"/lab/"* | */lab | lab/*)
            die "refusing to touch lab/ ($1): lab is the user's manual workspace"
            ;;
    esac
}

# Determine a default seed: timestamp seconds + a 4-digit random suffix.
default_seed() {
    echo "$(date +%s)$(shuf -i 0-9999 -n 1)"
}

# Stamp for campaign dirs: YYYYMMDD-HHMMSS.
stamp() {
    date +%Y%m%d-%H%M%S
}

# Root of a directory, creating it if needed. Refuses lab/.
ensure_dir() {
    assert_not_lab "$1"
    mkdir -p "$1"
}

# Build a single release binary with cargo.
build_release_bin() {
    local bin="$1"
    say "cargo build --release --bin $bin"
    if [ "${DRY_RUN:-0}" != "1" ]; then
        (cd "$PROJECT_ROOT" && "$CARGO" build --release --bin "$bin")
    else
        echo "    [dry-run] (cd $PROJECT_ROOT && $CARGO build --release --bin $bin)"
    fi
}

# ---- qemu guest agent (src/bin/agent.rs, static musl, no z3) -----------------
AGENT_BIN="$PROJECT_ROOT/target/x86_64-unknown-linux-musl/release/agent"
export AGENT_BIN

# Build the guest agent as a static musl binary without z3/SMT. This is
# what the initramfs build injects at /sbin/agent.
build_agent() {
    if [ -f "$AGENT_BIN" ] && file "$AGENT_BIN" | grep -qiE "static"; then
        echo "    agent: $AGENT_BIN (cached, static)"
        return 0
    fi
    say "building agent (agent-musl, no z3)"
    if [ "${DRY_RUN:-0}" != "1" ]; then
        (cd "$PROJECT_ROOT" && "$CARGO" build --release \
            --no-default-features --features agent-musl \
            --target x86_64-unknown-linux-musl --bin agent)
    else
        echo "    [dry-run] (cd $PROJECT_ROOT && $CARGO build --release --no-default-features --features agent-musl --target x86_64-unknown-linux-musl --bin agent)"
    fi
    [ -f "$AGENT_BIN" ] || die "agent binary missing after build: $AGENT_BIN"
    echo "    agent: $AGENT_BIN"
}

# ---- sample initramfs (tools/qemu/initramfs/) ---------------------------------
SAMPLE_INITRAMFS_BUILD="$PROJECT_ROOT/tools/qemu/initramfs/build.sh"
export SAMPLE_INITRAMFS_BUILD

# Build the sample initramfs (busybox + /init loop + /sbin/agent) into
# QEMU_ROOTFS. This is the default guest rootfs for qemu campaigns.
build_sample_initramfs() {
    local out="$QEMU_ROOTFS"
    say "building sample initramfs → $out"
    [ -f "$SAMPLE_INITRAMFS_BUILD" ] || die "sample initramfs build missing: $SAMPLE_INITRAMFS_BUILD"
    if [ "${DRY_RUN:-0}" = "1" ]; then
        echo "    [dry-run] $SAMPLE_INITRAMFS_BUILD --out $out"
    else
        "$SAMPLE_INITRAMFS_BUILD" --out "$out"
    fi
}
