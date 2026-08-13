# Verifier Test Corpus

Raw eBPF bytecode fixtures for the unified verifier pipeline.
Each program is a small binary file exercising one specific verification rule.

Encoding: kernel `struct bpf_insn` (8 bytes per instruction):
`[code, (src_reg << 4 | dst_reg), off_le16, imm_le32]` — the same encoding
clang and the kernel selftests emit (issue #56).

All programs are verified with the full pipeline (nano structural checks +
mini path exploration — the most advanced pass). Since v0.5 the pipeline
additionally runs every program through the concrete interpreter and checks
that the abstract states cover the concrete reachable states (issues #49–#54).
Helper calls are `BPF_JMP|BPF_CALL` with the helper id in the immediate
(kernel convention); BPF-to-BPF calls (`BPF_PSEUDO_CALL`) are not supported.

## Opcode map (real eBPF ISA)

| op | mnemonic | meaning |
|----|----------|---------|
| `0xb7` | `rX = imm` | MOV64 immediate (`BPF_ALU64|BPF_MOV|BPF_K`) |
| `0xbf` | `rX = rY` | MOV64 register (`BPF_ALU64|BPF_MOV|BPF_X`) |
| `0x07`/`0x0f` | `rX += imm` / `rX += rY` | ADD64 |
| `0x17`/`0x1f` | `rX -= imm` / `rX -= rY` | SUB64 |
| `0x57`/`0x5f` | `rX &= imm` / `rX &= rY` | AND64 |
| `0x47`/`0x4f` | `rX |= imm` / `rX |= rY` | OR64 |
| `0xa7`/`0xaf` | `rX ^= imm` / `rX ^= rY` | XOR64 |
| `0x67`/`0x6f` | `rX <<= imm` / `rX <<= rY` | shift left |
| `0x77`/`0x7f` | `rX >>= imm` / `rX >>= rY` | shift right (logical) |
| `0xc7`/`0xcf` | `rX s>>= imm` / `rX s>>= rY` | shift right (arithmetic) |
| `0x79` | `rX = [r10+off]` | load stack slot (`BPF_LDX|BPF_MEM|BPF_DW`, src_reg = 10) |
| `0x7b` | `[r10+off] = rX` | store stack slot (`BPF_STX|BPF_MEM|BPF_DW`, dst_reg = 10) |
| `0x1d` | `if rX == rY goto +off` | jump equal (`BPF_JMP|BPF_JEQ|BPF_X`) |
| `0x5d` | `if rX != rY goto +off` | jump not equal |
| `0x2d` | `if rX > rY goto +off` | jump greater (unsigned) |
| `0x3d` | `if rX >= rY goto +off` | jump greater-or-equal (unsigned) |
| `0xad` | `if rX < rY goto +off` | jump less (unsigned) |
| `0xbd` | `if rX <= rY goto +off` | jump less-or-equal (unsigned) |
| `0x6d` | `if rX s> rY goto +off` | jump greater (signed) |
| `0x7d` | `if rX s>= rY goto +off` | jump greater-or-equal (signed) |
| `0xcd` | `if rX s< rY goto +off` | jump less (signed) |
| `0xdd` | `if rX s<= rY goto +off` | jump less-or-equal (signed) |
| `0x05` | `goto +off` | unconditional jump (`BPF_JA`) |
| `0x85` | `call imm` | helper call (imm = helper id) |
| `0x95` | `exit` | exit |

ALU32 is the separate `BPF_ALU` class: `0x04`/`0x0c` = `wX += imm` / `wX += rY`,
`0x14`/`0x1c` = `wX -= imm` / `wX -= rY`, … `0xcc` = `wX s>>= rY` (ARSH32).
A 32-bit operation truncates its operands to 32 bits and zero-extends the
result into the 64-bit register; `w` notation is used for the destination.
Compares are the register-register (BPF_X) forms only — the immediate
(BPF_K) forms are not supported yet (issue #57).

## Concrete execution (v0.5)

The same programs are also executed with real values and the results are
checked against the abstract verifier state (Phase 2). Execution model:

- fixed virtual addresses: `R10 = STACK_BASE` (`0x1000`), `R1 = CTX_BASE`
  (`0x2000`); the 512-byte frame spans `0x0E00..0x1000`
- entry state mirrors the abstract one: only R1 and R10 are initialized,
  all other registers and the stack are uninitialized
- branches are **deterministic**: a conditional branch takes exactly one
  successor per concrete state (like a real CPU); path forking happens only
  at helper calls
- helper calls mirror the abstract side: arguments are validated against the
  prototype, R1..R5 are clobbered, and `R0` is set to each return seed —
  constant returns get the constant, unknown scalars (e.g. `get_prandom_u32`)
  get `[0, 1, u64::MAX]`, pointer returns are unsupported (unreachable for
  this corpus)
- exploration budgets mirror the mini pass; a loop that never converges
  marks the run **inconclusive** (a warning, not a REJECT)
- accepted programs must have **zero coverage violations** (the abstract
  state must contain every concrete reachable state — enforced by the
  corpus); rejected programs get an informational concrete cross-check note
  ("also fails" / "executes concretely — precision candidate" /
  "inconclusive")

## accept/ — must pass verification (and concrete coverage)

| program                  | bytecode                                                      | rule exercised                  |
|--------------------------|---------------------------------------------------------------|---------------------------------|
| minimal_exit             | `r0 = 0; exit`                                                | minimal valid program           |
| scalar_constants         | `r0 = 42; exit`                                               | scalar constant                 |
| scalar_propagation       | `r2 = 10; r2 += 5; r0 = r2; exit`                             | constant propagation            |
| scalar_add_reg           | `r1 = 3; r2 = 7; r1 += r2; r0 = r1; exit`                     | register ALU                    |
| initialized_on_all_paths | `jeq r10, r10, +2; r0 = 1; jmp +1; r0 = 1; exit`              | R0 set on every path            |
| two_branches             | `jeq r10, r10, +2; r0 = 1; jmp +1; r0 = 2; exit`              | distinct branch values          |
| stack_roundtrip          | `r2 = 10; [r10-8] = r2; r0 = [r10-8]; exit`                   | spill/fill with range preserved |
| stack_two_slots          | `r2 = 1; [r10-8] = r2; [r10-16] = r2; r0 = [r10-8]; exit`     | multi-slot stack                |
| pointer_spill            | `[r10-8] = r1; r0 = 0; exit`                                  | pointer spill                   |
| pointer_spill_fill       | `[r10-8] = r1; r5 = [r10-8]; r0 = 0; exit`                    | pointer spill/fill roundtrip    |
| pointer_arithmetic       | `r5 = r10; r5 += -16; r0 = 0; exit`                           | stack pointer arithmetic        |
| helper_return_used       | `call 7; exit`                                               | helper return value (unknown)   |
| range_checked_access     | `call 7; r1 = 0; jeq r0, r1, +1; r0 = 1; exit`               | branch range refinement         |
| alu_sub                  | `r2 = 10; r2 -= 3; r0 = r2; exit`                             | SUB propagation                 |
| alu_and_or_xor           | `r2 = 12; r2 &= 10; r2 |= 3; r2 ^= 12; r0 = r2; exit`         | AND/OR/XOR propagation          |
| alu_shift                | `r2 = 1; r2 <<= 4; r2 >>= 2; r2 s>>= 1; r0 = r2; exit`        | shift propagation               |
| alu32                    | `r2 = 2147483647; r2 += 2147483647; r2 += 3; w2 += 0; r0 = r2; exit` | ALU32 truncation + zero-extension |
| alu32_roundtrip          | `r2 = -1; w2 += 0; w2 += 1; r0 = r2; exit`                       | ALU32 overflow wraps to 0        |
| alu32_zero_extend        | `r2 = -2147483648; w2 += 0; r2 += 1; r0 = r2; exit`               | ALU32 zero-extension of sign bit |
| tnum_precise_branch       | `call 7; r0 &= 1; r1 = 0; jeq r0, r1, +1; exit; exit`          | tnum-precise equality refinement  |
| overflow_full_range        | `call 7; r0 += 1000000000; r1 = 0; jeq r0, r1, +1; exit; exit` | sound overflow over-approximation |
| unsigned_then_signed_refine | `call 7; r1 = 100; jle r0, r1, +1; exit; r2 = -1; jsgt r0, r2, +1; exit; exit` | unsigned refine then signed prune    |
| jeq_fall_exclusion          | `call 7; r3 = 42; jle r0, r3, +1; exit; r4 = 42; jeq r0, r4, +1; exit; exit` | equality fall-through exclusion     |
| computed_offset_access      | `r6 = r10; r6 += -512; call 7; r2 = r0; r3 = 255; jsle r2, r3, +1; exit; r4 = 0; jsge r2, r4, +1; exit; r2 &= 248; r6 += r2; r0 = 1; exit` | computed offset in-frame + aligned   |
| bounded_loop                | `r0 = 0; r2 = 100; r1 = 0; r1 += 1; jlt r1, r2, -2; exit`            | bounded counter loop (100 iterations) |
| jne_branch               | `r1 = 5; r2 = 7; jne r1, r2, +2; r0 = 0; exit; r0 = 1; exit`  | JNE always-taken pruning        |
| unsigned_compare         | `r1 = -1; r2 = 0; jgt r1, r2, +2; r0 = 0; exit; r0 = 1; exit` | unsigned comparison (u64 view)  |
| signed_compare           | `r1 = -1; r2 = 0; jsgt r1, r2, +2; r0 = 0; exit; r0 = 1; exit` | signed comparison (i64 view)   |

## reject/ — must fail verification (concrete cross-check)

| program                       | bytecode                                            | rule exercised                      |
|-------------------------------|-----------------------------------------------------|-------------------------------------|
| loop_unreachable_exit          | `jmp -1; exit`                                      | self-loop with an unreachable exit  |
| invalid_jump                  | `jmp +100; exit`                                    | jump target out of range            |
| no_exit                       | `r0 = 1`                                            | missing exit                        |
| unreachable                   | `jmp +1; r0 = 1; exit`                              | unreachable instruction             |
| uninit_read                   | `r0 = r2; exit`                                     | uninitialized register read         |
| uninit_alu                    | `r2 += 5; exit`                                     | ALU on uninitialized register       |
| uninit_store                  | `[r10-8] = r0; exit`                                | store of uninitialized register     |
| stack_write_before_read       | `r0 = [r10-8]; exit`                                | stack read before write             |
| stack_wrong_direction         | `r0 = [r10+8]; exit`                                | positive stack offset               |
| stack_out_of_frame            | `r2 = 1; [r10-520] = r2; exit`                      | offset beyond the frame             |
| stack_misaligned              | `r2 = 1; [r10-4] = r2; exit`                        | misaligned offset                   |
| pointer_out_of_frame          | `r10 += 8; exit`                                    | stack pointer out of frame          |
| ctx_arith                     | `r1 += 8; exit`                                     | arithmetic on context pointer       |
| pointer_reg_arith             | `r0 = 1; r0 += r10; exit`                           | register-offset pointer arithmetic  |
| initialized_on_one_path_only  | `jeq r10, r10, +1; r0 = 1; exit`                    | R0 unset on one path                |
| uninit_register_on_path       | `jeq r10, r10, +1; r2 = 5; r0 = r2; exit`           | uninitialized register on a path    |
| invalid_helper_argument       | `call 1; exit`                                     | helper argument type mismatch       |
| invalid_pointer_arithmetic    | `r1 += 8; exit`                                     | context pointer arithmetic          |
| complexity_limit              | 11 stacked diamonds (2^11 states)                   | exploration complexity limit        |
| sub_on_pointer                | `r10 -= 8; exit`                                    | SUB on a stack pointer              |
| invalid_shift                 | `r2 = 1; r2 <<= 64; exit`                           | shift amount out of 0..64           |
| alu32_pointer_arith           | `w1 += 1; exit`                                     | 32-bit arithmetic on context pointer |
| jsgt_must_be_signed            | `r1 = -1; r2 = 0; jsgt r1, r2, +1; exit; r0 = 1; exit`          | signed compare must prune the taken path |
| computed_offset_misaligned     | `r6 = r10; r6 += -512; call 7; r2 = r0; r3 = 255; jsle r2, r3, +1; exit; r4 = 0; jsge r2, r4, +1; exit; r2 &= 254; r6 += r2; r0 = 1; exit` | computed offset alignment not provable    |
| computed_offset_out_of_frame   | `r6 = r10; r6 += -32; call 7; r2 = r0; r3 = 255; jsle r2, r3, +1; exit; r4 = 0; jsge r2, r4, +1; exit; r2 &= 248; r6 += r2; r0 = 1; exit` | computed offset can leave the frame       |
| non_converging_loop            | `r0 = 0; r1 = 0; r1 += 1; jeq r1, r1, -2; exit`                    | non-converging loop (loop budget)         |
| alu32_uninit                   | `w2 += 5; exit`                                     | ALU32 read of an uninitialized register   |
| loop_no_exit                   | `jmp -1`                                           | loop whose subprogram does not end with exit |
| overflowed_range_out_of_frame   | `r6 = r10; r6 += -32; call 7; r2 = r0; r2 += 1000000000; r6 += r2; r0 = 1; exit` | overflowed range cannot be in-frame       |
