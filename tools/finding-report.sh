#!/usr/bin/env bash
# tools/finding-report.sh — turn a campaign output dir into a
# prioritized finding report (JSON + Markdown) and PRESERVE the report
# assets (summary, findings, groups, run log) under
# fuzz-out/reports/<stamp>/.
#
# Assets preserved verbatim (no transformation, no loss):
#   summary.json, findings/ (meta.json + prog.bin + prog.dump + mini.txt
#   + concrete.txt + kernel.log), groups/, run.log, and a generated
#   report.json + report.md.
#
# Priority order follows the oracle semantics (docs/ROADMAP.md):
#   concrete unsafe / rv-soundness-bug (rand-verifier model bug)
#   > kernel-unsound-candidate (kernel accepted, spec rejected)
#   > kernel-overstrict-candidate (kernel rejected, spec accepted)
#   > precision-candidate / soundness-candidate
#   > rv-precision-gap / rv-panic
#   > whitelisted / agree / inconclusive / skipped
#
# Usage:
#   tools/finding-report.sh [<campaign-dir>] [--out <report-root>]
#   tools/finding-report.sh            # latest fuzz-out/qemu-*/ or fuzz-out/kernel-*
#   tools/finding-report.sh fuzz-out/kernel-20260814-170322-seed-52555
#   DRY_RUN=1 tools/finding-report.sh <dir>

set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=tools/lib.sh
. ./tools/lib.sh

CAMPAIGN="${1:-}"
REPORT_ROOT="${2:-$CAMPAIGN_ROOT/reports}"

if [ -z "$CAMPAIGN" ]; then
    # pick the most recent campaign dir
    CAMPAIGN="$(ls -dt "$CAMPAIGN_ROOT"/qemu-* "$CAMPAIGN_ROOT"/kernel-* 2>/dev/null | head -1 || true)"
    [ -n "$CAMPAIGN" ] || die "no campaign dir found under $CAMPAIGN_ROOT; pass one explicitly"
fi
assert_not_lab "$CAMPAIGN"
[ -d "$CAMPAIGN" ] || die "campaign dir does not exist: $CAMPAIGN"

STAMP="$(stamp)"
REPORT_DIR="$REPORT_ROOT/$STAMP"

say "finding report for: $CAMPAIGN"
echo "    report dir: $REPORT_DIR"

ensure_dir "$REPORT_DIR"

# ── 1. preserve assets verbatim ─────────────────────────────────────────────
preserve() {
    local src="$1"
    [ -e "$src" ] || return 0
    assert_not_lab "$src"
    run cp -a "$src" "$REPORT_DIR/"
}
for a in summary.json findings groups run.log; do
    preserve "$CAMPAIGN/$a"
done

# ── 2. collect findings with metadata ───────────────────────────────────────
python3 - "$CAMPAIGN" "$REPORT_DIR" <<'PY'
import json, os, sys, shutil

campaign, report_dir = sys.argv[1], sys.argv[2]

PRIORITY = {
    "rv-soundness-bug": 0,
    "kernel-unsound-candidate": 1,
    "kernel-overstrict-candidate": 2,
    "soundness-candidate": 3,
    "precision-candidate": 4,
    "rv-precision-gap": 5,
    "rv-panic": 6,
    "whitelisted": 7,
    "agree": 8,
    "inconclusive": 9,
    "skipped": 10,
}

findings = []
findings_dir = os.path.join(campaign, "findings")
if os.path.isdir(findings_dir):
    for name in sorted(os.listdir(findings_dir)):
        d = os.path.join(findings_dir, name)
        if not os.path.isdir(d):
            continue
        meta = {}
        mp = os.path.join(d, "meta.json")
        if os.path.isfile(mp):
            try:
                meta = json.load(open(mp))
            except Exception as e:
                meta = {"_parse_error": str(e)}
        finding = meta.get("finding", "unknown")
        findings.append({
            "name": name,
            "dir": d,
            "meta": meta,
            "priority": PRIORITY.get(finding, 11),
            "label": meta.get("label", ""),
            "mini": meta.get("mini", ""),
            "kernel": meta.get("kernel", ""),
            "spec": meta.get("spec", ""),
        })

findings.sort(key=lambda f: (f["priority"], f["name"]))

# summary from summary.json when present
summary = {}
sp = os.path.join(campaign, "summary.json")
if os.path.isfile(sp):
    try:
        summary = json.load(open(sp))
    except Exception:
        summary = {}

report = {
    "campaign": campaign,
    "generated_at": os.path.basename(report_dir),
    "summary": summary,
    "findings": findings,
}
with open(os.path.join(report_dir, "report.json"), "w") as f:
    json.dump(report, f, indent=2)

# ── 3. markdown summary ─────────────────────────────────────────────────────
def side(s):
    s = str(s)
    return s if s else "-"

lines = []
lines.append("# rand-verifier finding report")
lines.append("")
lines.append(f"- campaign: `{campaign}`")
lines.append(f"- generated: `{os.path.basename(report_dir)}`")
lines.append("")
if summary:
    lines.append("## summary.json counts")
    lines.append("")
    lines.append("```json")
    lines.append(json.dumps(summary.get("counts", {}), indent=2))
    lines.append("```")
    lines.append("")
    if summary.get("findings"):
        lines.append("## campaign-reported findings")
        lines.append("")
        for fin in summary["findings"]:
            lines.append(f"- {fin.get('name', '?')} -> `{fin.get('dir', '?')}`")
        lines.append("")

lines.append("## findings (by priority)")
lines.append("")
if findings:
    lines.append("| priority | finding | mini | kernel | spec |")
    lines.append("|----------|---------|------|--------|------|")
    for f in findings:
        lines.append(f"| {f['priority']} | `{f['name']}` | {side(f['mini'])} | {side(f['kernel'])} | {side(f['spec'])} |")
else:
    lines.append("_no findings_")
lines.append("")

with open(os.path.join(report_dir, "report.md"), "w") as f:
    f.write("\n".join(lines))

# print a console summary
print(f"findings: {len(findings)}")
for f in findings:
    print(f"  [{f['priority']}] {f['name']}  mini={f['mini'] or '-'} kernel={f['kernel'] or '-'} spec={f['spec'] or '-'}")
PY

echo
echo "==> report written:"
echo "    $REPORT_DIR/report.json"
echo "    $REPORT_DIR/report.md"
echo "    assets preserved under $REPORT_DIR/{summary.json,findings,groups,run.log}"
