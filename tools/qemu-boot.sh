#!/usr/bin/env bash
# tools/qemu-boot.sh — boot the bpf-next qemu guest that serves as the
# kernel column for fuzz/reduce campaigns.
#
# The guest is booted WITHOUT sudo: the pipeline never elevates. qemu
# needs /dev/kvm access (user in the kvm group) or falls back to TCG.
# The guest mounts the 9p share (QEMU_SHARE) and processes job files
# with its own initramfs-provided loader — the protocol implemented by
# src/fuzz/qemu.rs. The guest-side loader is USER-SUPPLIED: it lives in
# the initramfs the user injects, never in this repository.
#
# Usage:
#   tools/qemu-boot.sh               # boot in background, wait until ready, print PID
#   tools/qemu-boot.sh --foreground  # boot in foreground (Ctrl-A X to exit)
#   tools/qemu-boot.sh --stop        # stop a running guest (QEMU_PID env or QEMU_ASSETS/qemu.pid)
#   DRY_RUN=1 tools/qemu-boot.sh     # preview the exact qemu command
#
# The guest runs a READY LOOP: it is not expected to self-poweroff. The
# campaign scripts stop it explicitly when done. The 9p share must exist
# before boot (tools/qemu-share.sh).

set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=tools/lib.sh
. ./tools/lib.sh

usage() {
    cat <<EOF
usage: $0 [--foreground | --stop]
EOF
    exit 1
}

MODE="bg"
for arg in "$@"; do
    case "$arg" in
        --foreground) MODE="fg" ;;
        --stop) MODE="stop" ;;
        *) usage ;;
    esac
done

# ---- asset checks (fail with a clear message instead of silently booting) ---
require_asset() {
    local p="$1" label="$2" hint="$3"
    [ -f "$p" ] || die "$label missing: $p — $hint"
}
require_asset "$QEMU_KERNEL_IMG" "kernel image" \
    "run 'tools/qemu-assets.sh -k <bzImage>' to populate fuzz-out/qemu-assets/"
require_asset "$QEMU_ROOTFS" "rootfs" \
    "run 'tools/qemu-assets.sh -r <rootfs.cpio.gz>' to populate fuzz-out/qemu-assets/"
[ -d "$QEMU_SHARE" ] || die "9p share missing: $QEMU_SHARE — run 'tools/qemu-share.sh' first"

# ---- guest mount protocol ---------------------------------------------------
# The guest mounts the 9p share at /mnt/host and runs a ready loop. Two
# conventions are supported, both race-free:
#   * a shared "guest-ready" marker file the host polls for
#   * nothing else — the guest is simply considered ready once the VM is up.
# The host waits for the marker (or the boot timeout), then proceeds.

# ---- stop mode ---------------------------------------------------------------
if [ "$MODE" = "stop" ]; then
    PID_FILE="${QEMU_PID_FILE:-$QEMU_ASSETS/qemu.pid}"
    if [ -f "$PID_FILE" ]; then
        pid="$(cat "$PID_FILE")"
        say "stopping qemu guest pid $pid"
        if [ "${DRY_RUN:-0}" = "1" ]; then
            echo "    [dry-run] kill $pid"
        else
            kill "$pid" 2>/dev/null || true
            rm -f "$PID_FILE"
        fi
    else
        die "no qemu.pid at $PID_FILE — is a guest running?"
    fi
    exit 0
fi

# ---- boot ---------------------------------------------------------------------
say "booting bpf-next guest (no sudo, kvm group or TCG)"
ensure_dir "$QEMU_ASSETS"

PID_FILE="${QEMU_PID_FILE:-$QEMU_ASSETS/qemu.pid}"
[ ! -f "$PID_FILE" ] || die "guest already running (pid $(cat "$PID_FILE")) — stop it first: tools/qemu-boot.sh --stop"

CMD_LINE="console=ttyS0 loglevel=4 panic=-1 nokaslr"
# KVM acceleration when the user can open /dev/kvm; otherwise TCG.
ACCEL="-accel tcg"
[ -r /dev/kvm ] && ACCEL="-enable-kvm"

QEMU_CMD=(
    "$QEMU_BIN"
    -kernel "$QEMU_KERNEL_IMG"
    -initrd "$QEMU_ROOTFS"
    -append "$CMD_LINE"
    -m "$QEMU_MEM" -smp "$QEMU_SMP"
    $ACCEL
    -display none
    -serial mon:stdio
    -no-reboot
    -virtfs "local,path=$QEMU_SHARE,mount_tag=host,security_model=none,id=host"
)

echo "    guest ready marker: $QEMU_SHARE/guest-ready (created by the guest /init)"
if [ "${DRY_RUN:-0}" = "1" ]; then
    echo "    [dry-run] ${QEMU_CMD[*]}"
    exit 0
fi

if [ "$MODE" = "fg" ]; then
    exec "${QEMU_CMD[@]}"
fi

# background boot: stdio -> log file, pid file for --stop
LOG="$QEMU_ASSETS/qemu-boot.log"
nohup "${QEMU_CMD[@]}" >"$LOG" 2>&1 &
QPID=$!
echo "$QPID" > "$PID_FILE"
say "guest pid $QPID (log: $LOG, pid file: $PID_FILE)"

# wait for the guest-ready marker or timeout
deadline=$(( $(date +%s) + QEMU_BOOT_TIMEOUT ))
while [ "$(date +%s)" -lt "$deadline" ]; do
    if [ -f "$QEMU_SHARE/guest-ready" ]; then
        say "guest ready ($QEMU_SHARE/guest-ready present)"
        exit 0
    fi
    if ! kill -0 "$QPID" 2>/dev/null; then
        die "qemu exited during boot — see $LOG"
    fi
    sleep 1
done
echo "warning: guest-ready not seen within ${QEMU_BOOT_TIMEOUT}s; check $LOG" >&2
exit 1
