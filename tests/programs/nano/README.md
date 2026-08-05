# Nano Verifier Test Corpus

Raw eBPF bytecode fixtures for the Nano (structural) verifier milestone.
Each program is a small binary file exercising one specific verification rule.

Encoding: 8 bytes per instruction — `[op, (src << 4 | dst), off_le16, imm_le32]`.

## accept/ — must pass verification

| program      | bytecode                                            | rule exercised                 |
|--------------|-----------------------------------------------------|--------------------------------|
| simple_exit  | `r0 = 0; exit`                                      | minimal valid program          |
| conditional  | `if r1 == r2 goto +2; r0 = 1; exit; r0 = 2; exit`   | both branch paths reach EXIT   |
| two_branches | `if r1 == r2 goto +1; jmp +1; r0 = 1; exit`         | branch join, no loop           |

## reject/ — must fail verification

| program       | bytecode               | rule exercised               |
|---------------|------------------------|------------------------------|
| invalid_jump  | `jmp +5; exit`         | jump target out of range     |
| unreachable   | `jmp +1; r0 = 1; exit` | dead instruction (insn 1)    |
| backward_jump | `jmp +0; jmp -2`       | backward edge = unbounded loop |
| no_exit       | `r0 = 1; r0 = 2`       | falls through, no EXIT       |

## Usage

The corpus is consumed by the `corpus_accept_all` / `corpus_reject_all` tests in
`src/tests.rs`. Any new file dropped into `accept/` must pass verification,
any new file dropped into `reject/` must fail it.
