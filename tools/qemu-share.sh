#!/usr/bin/env bash
# tools/qemu-share.sh — create the 9p share directory layout the qemu
# guest consumes (src/fuzz/qemu.rs protocol: job/ + out/). The guest-side
# loader is provided by the user's initramfs, not by this repository.
#
# The share is pipeline-owned under fuzz-out/qemu-assets/share/. A
# single share is reused across campaigns; the campaign scripts clear
# job/ and out/ before/after each run (the markerless protocol is
# race-free only when the guest has consumed the previous batch).
#
# Usage:
#   tools/qemu-share.sh [--fresh]   # create (or clear when --fresh) the share
#   DRY_RUN=1 tools/qemu-share.sh

set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=tools/lib.sh
. ./tools/lib.sh

FRESH=0
for arg in "$@"; do
    case "$arg" in
        --fresh) FRESH=1 ;;
        *) die "unknown arg: $arg (use --fresh)" ;;
    esac
done

ensure_dir "$QEMU_ASSETS"

if [ "$FRESH" = "1" ] && [ -d "$QEMU_SHARE" ]; then
    say "clearing previous share: $QEMU_SHARE"
    run rm -rf "$QEMU_SHARE"
fi

ensure_dir "$QEMU_SHARE/job"
ensure_dir "$QEMU_SHARE/out"

# job/ and out/ must be world-writable: the 9p share uses
# security_model=none (the guest sees root-owned files but the host
# drops CAP_DAC_OVERRIDE in strict mode, so writes into a root-owned
# dir would fail). 0777 mirrors the world-writable requirement from the
# historical campaign notes (docs/ROADMAP.md).
run chmod 0777 "$QEMU_SHARE" "$QEMU_SHARE/job" "$QEMU_SHARE/out"

# strict marker: when present, the guest-side loader runs with --strict
# (CAP_PERFMON dropped). The campaign script sets it per campaign.
rm -f "$QEMU_SHARE/strict"

echo
echo "==> 9p share ready: $QEMU_SHARE"
echo "    job/  : host drops <name>.bin program batches"
echo "    out/  : guest writes <name>.out verdict files"
echo "    strict: optional marker enabling --strict on the guest"
