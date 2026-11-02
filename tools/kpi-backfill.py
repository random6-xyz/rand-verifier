#!/usr/bin/env python3
"""Backfill the campaign KPI block for pre-#141 campaign directories.

`fuzz` writes a `kpi` block into `summary.json` since #141. Older campaign
directories only have the label counts, which is exactly the number that
hides saturation. This tool derives the KPI from the artifacts that are
already on disk:

- a cluster is `finding + normalized mini reason + program hash` (the
  runtime key also uses the structural opcode hash and the kernel message;
  the backfill's program hash is the conservative stand-in),
- `time_to_first_new_cluster_ms` is not recoverable without timestamps, so
  it is reported as null.

Usage:

    python3 tools/kpi-backfill.py fuzz-out/kernel-20261029-092421
    python3 tools/kpi-backfill.py --root fuzz-out --dry-run
    python3 tools/kpi-backfill.py --root fuzz-out --force
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path


_NUM = re.compile(r"(?<![A-Za-z0-9_])[-+]?(?:0[xX][0-9a-fA-F]+|\d+)")


def normalize_message(message: str) -> str:
    """Same normalization as `fuzz::normalize_message`: embedded hex and
    decimal literals become `#`, register names (`R6`) stay."""
    text = _NUM.sub("#", " ".join(message.split()))
    return text[:120]


def cluster_key(meta: dict, mini_reason: str, program: bytes) -> str:
    digest = hashlib.sha256(program).hexdigest()[:16]
    return "|".join(
        [
            str(meta.get("finding", "unknown")),
            normalize_message(mini_reason),
            digest,
        ]
    )


def compute_kpi(findings: list[dict], iters: int, surface_total: int) -> dict:
    clusters = {cluster_key(f["meta"], f["mini_reason"], f["program"]) for f in findings}
    unique = len(clusters)
    total = len(findings)
    per_10k = (unique * 10_000.0 / iters) if iters else 0.0
    surface_rate = (surface_total / iters) if iters else 0.0
    return {
        "findings_total": total,
        "unique_clusters": unique,
        "duplicate_ratio": (total / unique) if unique else 0.0,
        "unique_clusters_per_10k": round(per_10k, 3),
        "surface_gap_rate": round(surface_rate, 3),
        "time_to_first_new_cluster_ms": None,
        "backfilled": True,
    }


def read_findings(campaign: Path) -> list[dict]:
    out = []
    findings_dir = campaign / "findings"
    if not findings_dir.is_dir():
        return out
    for entry in sorted(findings_dir.iterdir()):
        if not entry.is_dir():
            continue
        meta = {}
        meta_path = entry / "meta.json"
        if meta_path.is_file():
            try:
                meta = json.loads(meta_path.read_text())
            except json.JSONDecodeError:
                meta = {}
        reason = ""
        mini_path = entry / "mini.txt"
        if mini_path.is_file():
            for line in mini_path.read_text().splitlines():
                if line.startswith("reason: "):
                    reason = line[len("reason: "):]
                    break
        program = (entry / "prog.bin").read_bytes() if (entry / "prog.bin").is_file() else b""
        out.append({"name": entry.name, "meta": meta, "mini_reason": reason, "program": program})
    return out


def campaign_dirs(root: Path) -> list[Path]:
    return sorted(
        p
        for p in root.iterdir()
        if p.is_dir() and (p / "summary.json").is_file()
    )


def backfill(campaign: Path, dry_run: bool, force: bool) -> dict | None:
    summary_path = campaign / "summary.json"
    summary = json.loads(summary_path.read_text())
    if "kpi" in summary and not force:
        return None
    findings = read_findings(campaign)
    iters = int(summary.get("iters") or 0)
    surface_total = sum((summary.get("surface_gaps") or {}).values())
    kpi = compute_kpi(findings, iters, surface_total)
    summary["kpi"] = kpi
    if not dry_run:
        summary_path.write_text(json.dumps(summary, indent=2) + "\n")
    return kpi


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("campaign", nargs="*", type=Path)
    ap.add_argument("--root", type=Path, help="scan every campaign under this directory")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--force", action="store_true", help="recompute an existing kpi block")
    args = ap.parse_args()

    targets = list(args.campaign)
    if args.root:
        targets.extend(campaign_dirs(args.root))
    if not targets:
        ap.error("pass campaign directories or --root <dir>")

    print(f"{'campaign':<44}{'unique':>8}{'total':>8}{'dup':>7}{'per10k':>9}")
    for campaign in targets:
        if not (campaign / "summary.json").is_file():
            print(f"{campaign}: no summary.json", file=sys.stderr)
            continue
        kpi = backfill(campaign, args.dry_run, args.force)
        if kpi is None:
            print(f"{str(campaign):<44}{'(already has kpi)':>32}")
            continue
        print(
            f"{str(campaign):<44}"
            f"{kpi['unique_clusters']:>8}{kpi['findings_total']:>8}"
            f"{kpi['duplicate_ratio']:>7.2f}{kpi['unique_clusters_per_10k']:>9.2f}"
        )
    if args.dry_run:
        print("dry run: no files written")
    return 0


if __name__ == "__main__":
    sys.exit(main())
