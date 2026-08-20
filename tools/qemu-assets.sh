#!/usr/bin/env bash
# tools/qemu-assets.sh — prepare the qemu assets under fuzz-out/qemu-assets/
# by copying a user-built bzImage or building the sample initramfs.
#
# The pipeline NEVER builds the kernel and NEVER reads lab/. The user
# builds a bpf-next bzImage (e.g. via kernel-lab) and copies it here;
# the guest rootfs can be either a user rootfs copied with -r, or the
# SAMPLE initramfs built with --sample-initramfs (busybox + /init loop
# + /sbin/agent) which is the recommended default.
#
# Usage:
#   tools/qemu-assets.sh                    # show current status of qemu-assets
#   tools/qemu-assets.sh -k <bzImage>       # copy a kernel image
#   tools/qemu-assets.sh -r <rootfs.cpio.gz># copy a user rootfs
#   tools/qemu-assets.sh --sample-initramfs # build the sample initramfs
#   DRY_RUN=1 tools/qemu-assets.sh ...      # preview only
#
# env overrides: QEMU_KERNEL_IMG, QEMU_ROOTFS (destination paths)

set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=tools/lib.sh
. ./tools/lib.sh

usage() {
    cat <<EOF
usage: $0 [-k <bzImage>] [-r <rootfs.cpio.gz>] [--sample-initramfs] [-q]

  -k <img>     copy a kernel bzImage into qemu-assets/
  -r <rootfs>  copy a user rootfs (cpio.gz) into qemu-assets/
  --sample-initramfs  build the sample initramfs (busybox + /init + /sbin/agent)
  -q           quiet status
EOF
    exit 1
}

SRC_IMG=""
SRC_ROOTFS=""
QUIET=0
SAMPLE=0
while [ $# -gt 0 ]; do
    case "$1" in
        -k) SRC_IMG="$2"; shift 2 ;;
        -r) SRC_ROOTFS="$2"; shift 2 ;;
        --sample-initramfs) SAMPLE=1; shift ;;
        -q) QUIET=1; shift ;;
        *) usage ;;
    esac
done

ensure_dir "$QEMU_ASSETS"

status_line() {
    local p="$1" label="$2"
    if [ -f "$p" ]; then
        echo "    $label: $p ($(du -h "$p" 2>/dev/null | cut -f1))"
    else
        echo "    $label: $p (missing)"
    fi
}

if [ -z "$SRC_IMG" ] && [ -z "$SRC_ROOTFS" ] && [ "$SAMPLE" = "0" ]; then
    echo "==> qemu-assets status ($QEMU_ASSETS)"
    status_line "$QEMU_KERNEL_IMG" "kernel"
    status_line "$QEMU_ROOTFS" "rootfs"
    echo "    use -k <bzImage> / -r <rootfs.cpio.gz> / --sample-initramfs to populate"
    exit 0
fi

copy_asset() {
    local src="$1" dst="$2" label="$3"
    assert_not_lab "$src"
    [ -f "$src" ] || die "$label source does not exist: $src"
    [ -f "$dst" ] && die "$dst already exists — remove it first (qemu-assets is pipeline-owned, overwrites are explicit)"
    say "copy $label"
    run cp "$src" "$dst"
    run chmod 644 "$dst"
    echo "    $label ready: $dst"
}

if [ -n "$SRC_IMG" ]; then
    copy_asset "$SRC_IMG" "$QEMU_KERNEL_IMG" "kernel image"
fi
if [ -n "$SRC_ROOTFS" ]; then
    copy_asset "$SRC_ROOTFS" "$QEMU_ROOTFS" "rootfs"
fi
if [ "$SAMPLE" = "1" ]; then
    if [ -f "$QEMU_ROOTFS" ]; then
        die "$QEMU_ROOTFS already exists — remove it first or use -r instead"
    fi
    build_sample_initramfs
fi

echo
echo "==> qemu-assets ready:"
status_line "$QEMU_KERNEL_IMG" "kernel"
status_line "$QEMU_ROOTFS" "rootfs"
