#!/usr/bin/env bash
# tools/qemu/initramfs/build.sh — build the sample rand-verifier
# initramfs (a cpio.gz) that boots the bpf-next guest kernel column.
#
# Contents:
#   /init            the PID-1 loop (9p mount + run.sh consumer)
#   /bin/busybox     static busybox (copied from the host, never committed)
#   /sbin/agent      the guest kernel loader (built with agent-musl)
#   /bin/sh etc.     symlinks to /bin/busybox
#
# Usage:
#   tools/qemu/initramfs/build.sh [--out <initramfs.cpio.gz>]
#   DRY_RUN=1 tools/qemu/initramfs/build.sh
#
# The output defaults to fuzz-out/qemu-assets/initramfs.cpio.gz. The
# host busybox must be a static binary (checked). The agent binary is
# built on demand with the agent-musl feature (no z3).
#
# git policy: the init script and this build script are committed; the
# busybox and agent binaries are generated, never committed.

set -euo pipefail
cd "$(dirname "$0")/../../.."   # → project root
# shellcheck source=tools/lib.sh
. ./tools/lib.sh

OUT=""
if [ "$#" -ge 2 ] && [ "$1" = "--out" ]; then
    OUT="$2"
elif [ "$#" -ge 1 ] && [ -n "$1" ]; then
    OUT="$1"
fi
if [ -z "$OUT" ]; then
    OUT="$QEMU_ASSETS/initramfs.cpio.gz"
fi
assert_not_lab "$OUT"
ensure_dir "$(dirname "$OUT")"

# ── inputs ───────────────────────────────────────────────────────────────────
INIT_SRC="$PROJECT_ROOT/tools/qemu/initramfs/init"
BUSYBOX_SRC="${BUSYBOX_SRC:-/bin/busybox}"

say "initramfs build → $OUT"
echo "    init:    $INIT_SRC"
echo "    busybox: $BUSYBOX_SRC"

[ -f "$INIT_SRC" ] || die "init script missing: $INIT_SRC"
[ -f "$BUSYBOX_SRC" ] || die "busybox missing: $BUSYBOX_SRC"
if file "$BUSYBOX_SRC" | grep -qiE "static"; then
    echo "    busybox: static OK"
else
    die "busybox is not static: $BUSYBOX_SRC (need a static busybox for the initramfs)"
fi

# ── agent binary (build on demand) ───────────────────────────────────────────
AGENT_BIN="${AGENT_BIN:-$PROJECT_ROOT/target/x86_64-unknown-linux-musl/release/agent}"
if [ ! -f "$AGENT_BIN" ]; then
    say "building agent (agent-musl, no z3)"
    (cd "$PROJECT_ROOT" && "$CARGO" build --release \
        --no-default-features --features agent-musl \
        --target x86_64-unknown-linux-musl --bin agent)
fi
echo "    agent:   $AGENT_BIN"
[ -f "$AGENT_BIN" ] || die "agent binary missing after build: $AGENT_BIN"
if file "$AGENT_BIN" | grep -qiE "static"; then
    echo "    agent: static OK"
else
    die "agent is not static: $AGENT_BIN"
fi

# ── assemble the initramfs tree ──────────────────────────────────────────────
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
BIN="$WORK/bin"
SBIN="$WORK/sbin"
ETC="$WORK/etc"
mkdir -p "$BIN" "$SBIN" "$ETC"

# busybox + applet symlinks (the applets run.sh/init need)
cp "$BUSYBOX_SRC" "$BIN/busybox"
chmod 755 "$BIN/busybox"
for applet in sh mount sleep touch ls rm cat echo mkdir mknod cpio gzip basename \
              timeout poweroff chmod ps kill head tail; do
    ln -s /bin/busybox "$BIN/$applet"
done

# the guest kernel loader
cp "$AGENT_BIN" "$SBIN/agent"
chmod 755 "$SBIN/agent"

# the PID-1 init loop
cp "$INIT_SRC" "$WORK/init"
chmod 755 "$WORK/init"

# ── pack ─────────────────────────────────────────────────────────────────────
say "packing initramfs"
TMP_OUT="$WORK/initramfs.cpio.gz"
if [ "${DRY_RUN:-0}" = "1" ]; then
    echo "    [dry-run] (cd $WORK && find . | cpio -o -H newc | gzip -9 > $TMP_OUT)"
    echo "    [dry-run] mv $TMP_OUT $OUT"
else
    (cd "$WORK" && find . | cpio -o -H newc 2>/dev/null | gzip -9 > "$TMP_OUT")
    mv "$TMP_OUT" "$OUT"
fi

echo
echo "==> initramfs: $OUT ($(du -h "$OUT" 2>/dev/null | cut -f1))"
echo "    contents: /init /bin/busybox /sbin/agent (+ symlinks)"
