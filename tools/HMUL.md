# HMUL / SHMUL differential matrix (#146)

bpf-next commit `c9ec5e4256c1` ("bpf: Add verifier support for UHMUL and
SHMUL") added two ALU64 multiply forms selected by the instruction's `off`
field:

| `off` | form | result |
|---|---|---|
| 0 | MUL | low 64 bits of the product |
| 1 | `BPF_UHMUL` | unsigned high 64 bits |
| 2 | `BPF_SHMUL` | signed high 64 bits |

The verifier rules implemented in rand-verifier (`src/insn.rs`,
`src/exec.rs`): ALU64 only, `off` reserved for ALU32 and every other ALU
op, constant operands fold exactly, variable operands become an unknown
scalar (no HMUL range analysis yet), and a `PTR_TO_ARENA` operand is
rejected.

## Recorded matrix (bpf-next `a30c772627b2`, privileged guest)

Fixtures live in `tests/programs/{accept,reject}/hmul_*.bin` and
`mul_div_mod_neg.bin`; the kernel column was recorded with
`tools/guest_replay.py` against the pinned image.

| fixture | encoding | kernel | mini | classification |
|---|---|---|---|---|
| `hmul_uhigh_const` | `r0 = -1; r0 = uhmul(r0, -1)` | ACCEPT | ACCEPT | agree |
| `hmul_shigh_const` | `r0 = -1; r0 = shmul(r0, -1)` | ACCEPT | ACCEPT | agree |
| `hmul_reg_const` | `r1 = -1; r0 = uhmul(r0, r1)` | ACCEPT | ACCEPT | agree |
| `hmul_var_operand` | `call 7; r0 = uhmul(r0, 3)` | ACCEPT | ACCEPT | agree |
| `mul_div_mod_neg` | `r0 = 6; *= 7; /= 2; %= 5; -r0` | ACCEPT | ACCEPT | agree |
| `hmul_alu32_reserved` | `w0 *= 2` with `off = 1` | REJECT (`BPF_ALU uses reserved fields`) | REJECT | agree (decode) |

Constant folding is exact on both sides: `(-1) uhmul (-1) = 2^64 - 2`,
`(-1) shmul (-1) = 0`.

## Rules without a local fixture

- **JIT / hardware offload**: a JIT that cannot encode HMUL makes the load
  fail with `-EOPNOTSUPP` after verification; the interpreter supports it.
  This is a post-verifier path, so the matrix records it as accepted by the
  verifier and documented here.
- **`PTR_TO_ARENA` operand**: the verifier rejects HMUL/SHMUL on arena
  pointers (`check_alu_op`). Building that fixture needs an arena map and
  `BPF_PSEUDO_MAP_FD`, which the map sidecar wiring (#134) will enable;
  until then the rule is documented, not tested.

## Reproducing the kernel column

```sh
python3 tools/guest_replay.py \
  --share fuzz-out/kernel-<sha>/share \
  --manifest /tmp/hmul-corpus/manifest.jsonl \
  --programs /tmp/hmul-corpus/programs \
  --out /tmp/hmul-priv.jsonl --skip-fixups --only-prog-type none

cargo run --release --bin replay -- \
  --manifest /tmp/hmul-corpus/manifest2.jsonl \
  --programs /tmp/hmul-corpus/programs \
  --kernel-column /tmp/hmul-column.jsonl
```

(`guest_replay.py` writes `kernel`; `replay` expects `verdict`/`message`
rows, so map the column as shown above.)
