#!/usr/bin/env python3
"""Extract the legacy verifier selftests into a replayable corpus (#138).

The kernel tree ships ~1k labelled bytecode tests under
``tools/testing/selftests/bpf/verifier/*.c``.  They are C fragments
(``{ "name", .insns = {...}, .result = ACCEPT, ... },``) that rely on the
``BPF_*_INSN`` helper macros from ``tools/include/linux/filter.h``.

This tool preprocesses each fragment with clang (no compilation, only
``-E``), resolves every ``struct bpf_insn`` field expression (including
``__builtin_offsetof(...)`` forms) to an integer, and writes:

  <out>/programs/<file>__<n>.bin   raw bytecode (replayable)
  <out>/manifest.jsonl             id, name, expected verdict, errstr,
                                   prog_type, insn count, fixups

Expected verdicts are the kernel selftest expectations (``REJECT``,
``ACCEPT``, ``VERBOSE_ACCEPT``); they are ground truth for the *kernel*,
not necessarily for rand-verifier's models - that is exactly what makes
the corpus useful as a differential oracle.

The corpus is pinned by ``tools/selftest-corpus.lock``: the bpf-next
commit, the fragment/program counts and a catalog hash over
``id<TAB>name<TAB>expected``.  ``--check-lock`` verifies the extraction
against the lock so CI notices when the kernel selftests change shape.

Usage:

    python3 tools/selftest_corpus.py --tree <kernel> --out <dir>
    python3 tools/selftest_corpus.py --tree <kernel> --out <dir> --check-lock
    python3 tools/selftest_corpus.py --write-lock tools/selftest-corpus.lock \
        --tree <kernel> --out <dir> --commit <sha>
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

LOCK_PATH = Path(__file__).resolve().parent / "selftest-corpus.lock"

INSN_RE = re.compile(
    r"\(\s*\(\s*struct\s+bpf_insn\s*\)\s*\{([^}]*)\}\s*\)", re.S
)
FIELD_RE = re.compile(r"\.(\w+)\s*=\s*(.*?)(?=,\s*\.|,\s*$|\Z)", re.S)


def preprocess(fragment: Path, tree: Path, bpf_dir: Path, cc: str) -> str:
    wrapper = bpf_dir / ".rv_extract_wrap.c"
    rel = fragment.relative_to(bpf_dir)
    wrapper.write_text(
        "#include <linux/bpf.h>\n"
        "#include <linux/filter.h>\n"
        "#include <linux/if_ether.h>\n"
        "#include <linux/ip.h>\n"
        "#include <linux/ipv6.h>\n"
        "#include <linux/tcp.h>\n"
        "#include <linux/udp.h>\n"
        "#include <linux/if_packet.h>\n"
        "#include <stddef.h>\n"
        "#include <stdint.h>\n"
        "#include <stdbool.h>\n"
        "#include <limits.h>\n"
        "#ifndef INSN_OFF_MASK\n"
        "#define INSN_OFF_MASK ((__s16)0xFFFF)\n"
        "#define INSN_IMM_MASK ((__s32)0xFFFFFFFF)\n"
        "#endif\n"
        "#ifndef offsetofend\n"
        "#define sizeof_field(TYPE, MEMBER) sizeof((((TYPE *)0)->MEMBER))\n"
        "#define offsetofend(TYPE, MEMBER) "
        "(offsetof(TYPE, MEMBER) + sizeof_field(TYPE, MEMBER))\n"
        "#endif\n"
        f'#include "{rel}"\n'
    )
    cmd = [
        cc,
        "-E",
        f"-I{tree / 'tools/include'}",
        f"-I{tree / 'tools/lib'}",
        f"-I{bpf_dir}",
    ]
    try:
        out = subprocess.run(
            cmd + [str(wrapper)], capture_output=True, text=True, check=True
        ).stdout
    finally:
        wrapper.unlink(missing_ok=True)
    marker = re.compile(
        r'^#\s*1\s+"(?:[^"]*/)?' + re.escape(str(rel)) + r'"\s+1\s*$',
        re.M,
    )
    m = marker.search(out)
    body = out[m.end():] if m else out
    end = body.rfind("# ")
    if end > 0:
        body = body[:end]
    return body


def split_tests(body: str) -> list[str]:
    """Split the fragment into top-level `{ ... },` test blocks."""
    blocks: list[str] = []
    depth = 0
    start = None
    in_str = False
    esc = False
    for i, ch in enumerate(body):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start is not None:
                blocks.append(body[start : i + 1])
                start = None
    return blocks


def strip_comments(text: str) -> str:
    return re.sub(r"/\*.*?\*/", " ", text, flags=re.S)


def insn_section(block: str) -> str:
    m = re.search(r"\.insns\s*=\s*\{", block)
    if not m:
        return ""
    depth = 0
    start = m.end() - 1
    for i in range(start, len(block)):
        if block[i] == "{":
            depth += 1
        elif block[i] == "}":
            depth -= 1
            if depth == 0:
                return block[start : i + 1]
    return ""


def field_exprs(section: str) -> list[dict[str, str]]:
    out = []
    for fields in INSN_RE.findall(section):
        out.append({name: expr.strip() for name, expr in FIELD_RE.findall(fields)})
    return out


def resolve_constants(tree: Path, exprs: set[str], cc: str) -> dict[str, int]:
    """Resolve every expression by compiling one C printer.

    Pure BPF_* / INSN_* / limits expressions could be evaluated in
    Python, but `__builtin_offsetof(struct __sk_buff, cb)` and similar
    forms need a real C compiler - so everything goes through clang.
    """
    bpf_dir = tree / "tools/testing/selftests/bpf"
    cfile = bpf_dir / ".rv_consts.c"
    exe = bpf_dir / ".rv_consts.bin"
    lines = [
        "#include <linux/bpf.h>",
        "#include <linux/filter.h>",
        "#include <linux/if_ether.h>",
        "#include <linux/ip.h>",
        "#include <linux/ipv6.h>",
        "#include <linux/tcp.h>",
        "#include <linux/udp.h>",
        "#include <stddef.h>",
        "#include <stdint.h>",
        "#include <limits.h>",
        "#define INSN_OFF_MASK ((__s16)0xFFFF)",
        "#define INSN_IMM_MASK ((__s32)0xFFFFFFFF)",
        "#define sizeof_field(TYPE, MEMBER) sizeof((((TYPE *)0)->MEMBER))",
        "#define offsetofend(TYPE, MEMBER) "
        "(offsetof(TYPE, MEMBER) + sizeof_field(TYPE, MEMBER))",
        "#include <stdio.h>",
        "int main(void){",
    ]
    ordered = sorted(exprs)
    for i, expr in enumerate(ordered):
        lines.append(f'printf("{i} %lld\\n", (long long)({expr}));')
    lines.append("return 0;}")
    active = set(range(len(ordered)))
    try:
        for _ in range(20):
            body = [
                ln
                for ln in lines
                if not ln.startswith('printf("')
                or int(ln.split('"')[1].split()[0]) in active
            ]
            cfile.write_text("\n".join(body))
            proc = subprocess.run(
                [
                    cc,
                    f"-I{tree / 'tools/include'}",
                    f"-I{tree / 'tools/lib'}",
                    str(cfile),
                    "-o",
                    str(exe),
                ],
                capture_output=True,
                text=True,
            )
            if proc.returncode == 0:
                break
            # drop the expressions clang could not resolve and retry
            bad = {
                int(m.group(1))
                for m in re.finditer(r'printf\("(\d+) ', proc.stderr)
            }
            bad &= active
            if not bad:
                raise RuntimeError(proc.stderr[:4000])
            active -= bad
        else:
            raise RuntimeError("constant resolution did not converge")
        values: dict[str, int] = {}
        for line in subprocess.run(
            [str(exe)], capture_output=True, text=True, check=True
        ).stdout.splitlines():
            idx, value = line.split()
            values[ordered[int(idx)]] = int(value)
        return values
    finally:
        cfile.unlink(missing_ok=True)
        exe.unlink(missing_ok=True)


def scalar_field(block: str, name: str) -> str | None:
    m = re.search(rf"\.{name}\s*=\s*([^,\n}}]+)", block)
    return m.group(1).strip() if m else None


def string_field(block: str, name: str) -> str | None:
    m = re.search(rf'\.{name}\s*=\s*"((?:[^"\\]|\\.)*)"', block)
    return m.group(1) if m else None


def encode(code: int, dst: int, src: int, off: int, imm: int) -> bytes:
    b = bytearray(8)
    b[0] = code & 0xFF
    b[1] = (dst & 0xF) | ((src & 0xF) << 4)
    b[2:4] = off.to_bytes(2, "little", signed=True)
    b[4:8] = (imm & 0xFFFFFFFF).to_bytes(4, "little")
    return bytes(b)


def extract(tree: Path, out: Path, cc: str) -> dict[str, object]:
    """Extract the corpus and return the catalog facts for the lock file."""
    bpf_dir = tree / "tools/testing/selftests/bpf"
    verifier_dir = bpf_dir / "verifier"
    programs = out / "programs"
    programs.mkdir(parents=True, exist_ok=True)

    fragments = sorted(verifier_dir.glob("*.c"))
    if not fragments:
        raise SystemExit(f"no fragments under {verifier_dir}")

    blocks_by_frag: dict[Path, list[str]] = {}
    all_exprs: set[str] = set()
    for frag in fragments:
        body = strip_comments(preprocess(frag, tree, bpf_dir, cc))
        blocks = split_tests(body)
        blocks_by_frag[frag] = blocks
        for block in blocks:
            for fields in field_exprs(insn_section(block)):
                all_exprs.update(fields.values())
    values = resolve_constants(tree, all_exprs, cc)

    manifest = out / "manifest.jsonl"
    total = 0
    skipped = 0
    catalog: list[str] = []
    with manifest.open("w") as mf:
        for frag in fragments:
            for n, block in enumerate(blocks_by_frag[frag]):
                # a macro left unexpanded (e.g. BPF_DIRECT_PKT_R2, defined
                # in test_verifier.c rather than a header) would silently
                # drop instructions - skip the whole case instead
                section = insn_section(block)
                residual = INSN_RE.sub("", section)
                unresolved = re.search(r"\bBPF_[A-Z0-9_]+\b", residual)
                fields_list = field_exprs(section)
                result = scalar_field(block, "result") or ""
                if unresolved or not fields_list or result not in (
                    "ACCEPT",
                    "REJECT",
                    "VERBOSE_ACCEPT",
                ):
                    skipped += 1
                    continue
                name = string_field(block, "name") or f"{frag.stem}-{n}"
                data = b"".join(
                    encode(
                        values.get(f.get("code", "0"), 0),
                        values.get(f.get("dst_reg", "0"), 0),
                        values.get(f.get("src_reg", "0"), 0),
                        values.get(f.get("off", "0"), 0),
                        values.get(f.get("imm", "0"), 0),
                    )
                    for f in fields_list
                )
                stem = f"{frag.stem}__{n:03d}"
                (programs / f"{stem}.bin").write_bytes(data)
                expected = (
                    "ACCEPT" if result in ("ACCEPT", "VERBOSE_ACCEPT") else "REJECT"
                )
                mf.write(
                    json.dumps(
                        {
                            "id": stem,
                            "name": name,
                            "file": frag.name,
                            "expected": expected,
                            "errstr": string_field(block, "errstr"),
                            "errstr_unpriv": string_field(block, "errstr_unpriv"),
                            "result_unpriv": scalar_field(block, "result_unpriv"),
                            "prog_type": scalar_field(block, "prog_type"),
                            "insn_cnt": len(fields_list),
                            "fixups": sorted(
                                set(
                                    re.findall(
                                        r"\.(fixup_map_\w+|kfunc_call|btf_ctx_access)",
                                        block,
                                    )
                                )
                            ),
                        }
                    )
                    + "\n"
                )
                catalog.append(f"{stem}\t{name}\t{expected}")
                total += 1

    catalog_sha = hashlib.sha256(
        "\n".join(sorted(catalog)).encode() + b"\n"
    ).hexdigest()
    return {
        "fragments": len(fragments),
        "programs": total,
        "skipped": skipped,
        "catalog_sha256": catalog_sha,
    }


def read_lock(path: Path) -> dict[str, object]:
    return json.loads(path.read_text())


def write_lock(path: Path, facts: dict[str, object], commit: str) -> None:
    lock = {
        "kernel_commit": commit,
        "fragments": facts["fragments"],
        "programs": facts["programs"],
        "skipped": facts["skipped"],
        "catalog_sha256": facts["catalog_sha256"],
    }
    path.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n")


def check_lock(path: Path, facts: dict[str, object]) -> list[str]:
    lock = read_lock(path)
    problems = []
    for key in ("fragments", "programs", "skipped", "catalog_sha256"):
        if lock.get(key) != facts[key]:
            problems.append(f"{key}: lock={lock.get(key)!r} extracted={facts[key]!r}")
    return problems


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--tree", required=True, help="kernel tree")
    ap.add_argument("--out", required=True, help="output directory")
    ap.add_argument("--cc", default=os.environ.get("CC", "clang"))
    ap.add_argument("--lock", type=Path, default=LOCK_PATH)
    ap.add_argument(
        "--check-lock",
        action="store_true",
        help="compare the extraction against the lock file and exit 1 on drift",
    )
    ap.add_argument(
        "--write-lock",
        action="store_true",
        help="rewrite the lock file from this extraction (needs --commit)",
    )
    ap.add_argument("--commit", default="", help="kernel commit for --write-lock")
    args = ap.parse_args()

    tree = Path(args.tree).resolve()
    out = Path(args.out).resolve()
    facts = extract(tree, out, args.cc)
    print(
        f"extracted {facts['programs']} programs from {facts['fragments']} "
        f"fragments ({facts['skipped']} skipped) -> {out}"
    )

    if args.write_lock:
        if not args.commit:
            ap.error("--write-lock requires --commit <sha>")
        write_lock(args.lock, facts, args.commit)
        print(f"wrote lock {args.lock} (commit {args.commit})")
        return 0

    if args.check_lock:
        if not args.lock.exists():
            print(f"lock file missing: {args.lock}", file=sys.stderr)
            return 1
        problems = check_lock(args.lock, facts)
        if problems:
            print("corpus lock drift:", file=sys.stderr)
            for problem in problems:
                print(f"  {problem}", file=sys.stderr)
            return 1
        print(f"corpus lock ok ({args.lock})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
