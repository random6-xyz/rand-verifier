# Verifier Test Corpus

Raw eBPF bytecode fixtures for the unified verifier pipeline.
Each program is a small binary file exercising one specific verification rule.

Encoding: 8 bytes per instruction — `[op, (src << 4 | dst), off_le16, imm_le32]`.

All programs are verified with the full pipeline (nano structural checks +
mini path exploration) — the most advanced pass. Helper calls use negative
immediates (kernel convention); positive immediates are BPF-to-BPF calls.

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
