# Verifier Test Corpus

Raw eBPF bytecode fixtures for the unified verifier pipeline.
Each program is a small binary file exercising one specific verification rule.

Encoding: 8 bytes per instruction — `[op, (src << 4 | dst), off_le16, imm_le32]`.

All programs are verified with the full pipeline (nano structural checks +
mini path exploration) — the most advanced pass. Helper calls use negative
immediates (kernel convention); positive immediates are BPF-to-BPF calls.

## Opcode map (custom encoding, Meso #39)

| op | mnemonic | meaning |
|----|----------|---------|
| `0x01` | `rX = imm` | MOV immediate |
| `0x02` | `rX = rY` | MOV register |
| `0x03` | `rX += imm` | ADD immediate |
| `0x04` | `rX += rY` | ADD register |
| `0x05` | `rX = [r10+off]` | load stack slot |
| `0x06` | `[r10+off] = rX` | store stack slot |
| `0x07` | `if rX == rY goto +off` | jump equal |
| `0x08` | `if rX > rY goto +off` | jump greater (unsigned) |
| `0x09` | `goto +off` | unconditional jump |
| `0x0A` | `call imm` | helper call (imm < 0) / BPF-to-BPF call (imm >= 0) |
| `0x0B` | `exit` | exit |
| `0x0C`/`0x0D` | `rX -= imm` / `rX -= rY` | SUB |
| `0x0E`/`0x0F` | `rX &= imm` / `rX &= rY` | AND |
| `0x10`/`0x11` | `rX |= imm` / `rX |= rY` | OR |
| `0x12`/`0x13` | `rX ^= imm` / `rX ^= rY` | XOR |
| `0x14`/`0x15` | `rX <<= imm` / `rX <<= rY` | shift left |
| `0x16`/`0x17` | `rX >>= imm` / `rX >>= rY` | shift right (logical) |
| `0x18`/`0x19` | `rX s>>= imm` / `rX s>>= rY` | shift right (arithmetic) |
| `0x1A` | `if rX != rY goto +off` | jump not equal |
| `0x1B` | `if rX >= rY goto +off` | jump greater-or-equal (unsigned) |
| `0x1C` | `if rX < rY goto +off` | jump less (unsigned) |
| `0x1D` | `if rX <= rY goto +off` | jump less-or-equal (unsigned) |
| `0x1E` | `if rX s> rY goto +off` | jump greater (signed) |
| `0x1F` | `if rX s>= rY goto +off` | jump greater-or-equal (signed) |
| `0x20` | `if rX s< rY goto +off` | jump less (signed) |
| `0x21` | `if rX s<= rY goto +off` | jump less-or-equal (signed) |

ALU32 forms are the ALU64 opcode with the `0x40` flag bit set (like the
kernel's BPF_ALU vs BPF_ALU64 class split), e.g. `0x43`/`0x44` = `wX += imm` /
`wX += rY`, `0x4C`/`0x4D` = `wX -= imm` / `wX -= rY`, … `0x59` = `wX s>>= rY`.
A 32-bit operation truncates its operands to 32 bits and zero-extends the
result into the 64-bit register; `w` notation is used for the destination.

## accept/ — must pass verification

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
| helper_return_used       | `call -7; exit`                                               | helper return value (unknown)   |
| range_checked_access     | `call -7; r1 = 0; jeq r0, r1, +1; r0 = 1; exit`               | branch range refinement         |
| alu_sub                  | `r2 = 10; r2 -= 3; r0 = r2; exit`                             | SUB propagation                 |
| alu_and_or_xor           | `r2 = 12; r2 &= 10; r2 |= 3; r2 ^= 12; r0 = r2; exit`         | AND/OR/XOR propagation          |
| alu_shift                | `r2 = 1; r2 <<= 4; r2 >>= 2; r2 s>>= 1; r0 = r2; exit`        | shift propagation               |
| alu32                    | `r2 = 2147483647; r2 += 2147483647; r2 += 3; w2 += 0; r0 = r2; exit` | ALU32 truncation + zero-extension |
| alu32_roundtrip          | `r2 = -1; w2 += 0; w2 += 1; r0 = r2; exit`                       | ALU32 overflow wraps to 0        |
| alu32_zero_extend        | `r2 = -2147483648; w2 += 0; r2 += 1; r0 = r2; exit`               | ALU32 zero-extension of sign bit |
| tnum_precise_branch       | `call -7; r0 &= 1; r1 = 0; jeq r0, r1, +1; exit; exit`          | tnum-precise equality refinement  |
| overflow_full_range        | `call -7; r0 += 1000000000; r1 = 0; jeq r0, r1, +1; exit; exit` | sound overflow over-approximation |
| unsigned_then_signed_refine | `call -7; r1 = 100; jle r0, r1, +1; exit; r2 = -1; jsgt r0, r2, +1; exit; exit` | unsigned refine then signed prune    |
| jeq_fall_exclusion          | `call -7; r3 = 42; jle r0, r3, +1; exit; r4 = 42; jeq r0, r4, +1; exit; exit` | equality fall-through exclusion     |
| jne_branch               | `r1 = 5; r2 = 7; jne r1, r2, +2; r0 = 0; exit; r0 = 1; exit`  | JNE always-taken pruning        |
| unsigned_compare         | `r1 = -1; r2 = 0; jgt r1, r2, +2; r0 = 0; exit; r0 = 1; exit` | unsigned comparison (u64 view)  |
| signed_compare           | `r1 = -1; r2 = 0; jsgt r1, r2, +2; r0 = 0; exit; r0 = 1; exit` | signed comparison (i64 view)   |

## reject/ — must fail verification

| program                       | bytecode                                            | rule exercised                      |
|-------------------------------|-----------------------------------------------------|-------------------------------------|
| backward_jump                 | `jmp -1; exit`                                      | backward jump (loop)                |
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
| invalid_helper_argument       | `call -1; exit`                                     | helper argument type mismatch       |
| invalid_pointer_arithmetic    | `r1 += 8; exit`                                     | context pointer arithmetic          |
| complexity_limit              | 11 stacked diamonds (2^11 states)                   | exploration complexity limit        |
| sub_on_pointer                | `r10 -= 8; exit`                                    | SUB on a stack pointer              |
| invalid_shift                 | `r2 = 1; r2 <<= 64; exit`                           | shift amount out of 0..64           |
| alu32_pointer_arith           | `w1 += 1; exit`                                     | 32-bit arithmetic on context pointer |
| jsgt_must_be_signed            | `r1 = -1; r2 = 0; jsgt r1, r2, +1; exit; r0 = 1; exit`          | signed compare must prune the taken path |
