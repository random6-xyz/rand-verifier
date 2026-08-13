#!/usr/bin/env python3
"""Migrate the test corpus from the custom opcode encoding to the real
eBPF (kernel UAPI) encoding.

One-off tool for issues #56/#58: the custom encoding
`[op, (src << 4 | dst), off_le16, imm_le32]` has the same field layout
as `struct bpf_insn`, so migration is an opcode substitution plus two
special cases:

  - LD_STACK / ST_STACK move the frame pointer into the base-register
    field (src_reg = 10 for BPF_LDX, dst_reg = 10 for BPF_STX)
  - CALL flips the immediate sign (custom negative helper ids become
    the positive kernel helper ids)

Every instruction is validated twice: the custom form is decoded with
the custom table and the real form with the (inverted) real table, and
the normalized semantics (op, dst, src, off, imm) must match exactly.

Usage: python3 tools/migrate_corpus.py
"""

import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "tests" / "programs"

# custom opcode -> kernel opcode. Compares are the register-register
# (BPF_J*_X) forms — the corpus never uses immediate compares.
OP_MAP = {
    0x01: 0xB7,  # MOV_IMM -> BPF_ALU64|BPF_MOV|BPF_K
    0x02: 0xBF,  # MOV_REG -> BPF_ALU64|BPF_MOV|BPF_X
    0x03: 0x07,  # ADD_IMM
    0x04: 0x0F,  # ADD_REG
    0x05: 0x79,  # LD_STACK -> BPF_LDX|BPF_MEM|BPF_DW
    0x06: 0x7B,  # ST_STACK -> BPF_STX|BPF_MEM|BPF_DW
    0x07: 0x1D,  # JEQ
    0x08: 0x2D,  # JGT (unsigned)
    0x09: 0x05,  # JMP -> BPF_JA
    0x0A: 0x85,  # CALL
    0x0B: 0x95,  # EXIT
    0x0C: 0x17,  # SUB_IMM
    0x0D: 0x1F,  # SUB_REG
    0x0E: 0x57,  # AND_IMM
    0x0F: 0x5F,  # AND_REG
    0x10: 0x47,  # OR_IMM
    0x11: 0x4F,  # OR_REG
    0x12: 0xA7,  # XOR_IMM
    0x13: 0xAF,  # XOR_REG
    0x14: 0x67,  # LSH_IMM
    0x15: 0x6F,  # LSH_REG
    0x16: 0x77,  # RSH_IMM
    0x17: 0x7F,  # RSH_REG
    0x18: 0xC7,  # ARSH_IMM
    0x19: 0xCF,  # ARSH_REG
    0x1A: 0x5D,  # JNE
    0x1B: 0x3D,  # JGE (unsigned)
    0x1C: 0xAD,  # JLT (unsigned)
    0x1D: 0xBD,  # JLE (unsigned)
    0x1E: 0x6D,  # JSGT (signed)
    0x1F: 0x7D,  # JSGE (signed)
    0x20: 0xCD,  # JSLT (signed)
    0x21: 0xDD,  # JSLE (signed)
    # ALU32 forms (custom base op | 0x40 flag)
    0x43: 0x04,  # ADD32_IMM
    0x44: 0x0C,  # ADD32_REG
    0x4C: 0x14,  # SUB32_IMM
    0x4D: 0x1C,  # SUB32_REG
    0x4E: 0x54,  # AND32_IMM
    0x4F: 0x5C,  # AND32_REG
    0x50: 0x44,  # OR32_IMM
    0x51: 0x4C,  # OR32_REG
    0x52: 0xA4,  # XOR32_IMM
    0x53: 0xAC,  # XOR32_REG
    0x54: 0x64,  # LSH32_IMM
    0x55: 0x6C,  # LSH32_REG
    0x56: 0x74,  # RSH32_IMM
    0x57: 0x7C,  # RSH32_REG
    0x58: 0xC4,  # ARSH32_IMM
    0x59: 0xCC,  # ARSH32_REG
}
REAL_TO_OP = {real: custom for custom, real in OP_MAP.items()}

LD_STACK = 0x05
ST_STACK = 0x06
CALL = 0x0A


def decode(raw: bytes, real: bool):
    """Extract (op_semantic, dst, src, off, imm) from one 8-byte insn.

    `op_semantic` is the custom opcode value for both encodings; `src`
    is normalized to the frame pointer (10) for stack accesses and the
    CALL immediate is normalized to the positive helper id.
    """
    op, regs, off, imm = (
        raw[0],
        raw[1],
        struct.unpack("<h", raw[2:4])[0],
        struct.unpack("<i", raw[4:8])[0],
    )
    dst = regs & 0x0F
    src = (regs >> 4) & 0x0F
    if real:
        op = REAL_TO_OP[op]
        if op == LD_STACK:
            dst, src = dst, 10
        elif op == ST_STACK:
            dst, src = 10, src
        elif op == CALL:
            imm = imm  # already the positive helper id
    else:
        if op == LD_STACK:
            src = 10
        elif op == ST_STACK:
            dst = 10
        elif op == CALL:
            imm = -imm  # negative custom id -> positive helper id
    return op, dst, src, off, imm


def migrate_insn(raw: bytes) -> bytes:
    op, regs, off, imm = (
        raw[0],
        raw[1],
        struct.unpack("<h", raw[2:4])[0],
        struct.unpack("<i", raw[4:8])[0],
    )
    dst = regs & 0x0F
    src = (regs >> 4) & 0x0F
    new_op = OP_MAP.get(op)
    if new_op is None:
        raise SystemExit(f"{raw.hex()}: unknown custom opcode {op:#04x}")
    if op == LD_STACK:
        regs = dst | (10 << 4)  # src_reg = R10 (frame pointer)
    elif op == ST_STACK:
        regs = 10 | (src << 4)  # dst_reg = R10 (frame pointer)
    elif op == CALL:
        imm = -imm  # negative helper id -> positive kernel helper id
    return bytes([new_op, regs]) + struct.pack("<h", off) + struct.pack("<i", imm)


def main() -> None:
    total = 0
    for sub in ("accept", "reject"):
        for path in sorted((ROOT / sub).iterdir()):
            if not path.is_file() or path.suffix:
                continue
            data = path.read_bytes()
            assert len(data) % 8 == 0, f"{path}: not a multiple of 8 bytes"
            out = b"".join(migrate_insn(data[i : i + 8]) for i in range(0, len(data), 8))
            # self-check: custom and real encodings must decode to the
            # same normalized semantics
            for i in range(0, len(data), 8):
                custom = decode(data[i : i + 8], real=False)
                real = decode(out[i : i + 8], real=True)
                assert custom == real, f"{path} insn {i // 8}: {custom} != {real}"
            path.write_bytes(out)
            total += 1
    print(f"migrated {total} programs")


if __name__ == "__main__":
    main()
