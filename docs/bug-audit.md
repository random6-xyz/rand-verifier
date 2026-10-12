# Repository Bug Audit

## Scope and method

This was one bounded, repository-wide audit of `rand-verifier`, targeting `main` at `eb7637a` plus the existing working-tree change in `src/insn.rs`. Exactly ten read-only reviewer subagents ran in parallel on non-overlapping scopes. The parent merged duplicates, checked source evidence, and added regression tests for confirmed findings. The audit is broad but does not prove the repository bug-free.

The ten scopes were:

1. Instruction encoding/decoding and raw program loading (`src/insn.rs`, `src/env.rs`).
2. CFG, jumps, subprogram structure, recursion, and stack depth (`src/cfg.rs`).
3. Scalar abstract state and tracked numbers (`src/state.rs`, `src/tnum.rs`).
4. ALU32/ALU64 transfer functions and shifts (`src/exec.rs`).
5. Branch refinement, state equality, liveness, and pruning (`src/exec.rs`, `src/state_eq.rs`, `src/liveness.rs`).
6. Stack/memory, pointers, helpers, maps, references, dynptrs, and kfuncs (`src/exec.rs`, `src/state.rs`, `src/helper.rs`).
7. Mini-verifier worklist, precision backtracking, loops, and limits (`src/mini.rs`).
8. Concrete execution and abstract-state coverage (`src/concrete.rs`).
9. Independent spec oracle (`src/spec/**`).
10. Differential/fuzz/reducer/triage/drift/QEMU/kernel/CLI/CI tooling (`src/diff.rs`, `src/fuzz/**`, `src/krun.rs`, `src/klog.rs`, `src/bin/**`, `tools/**`, `.github/**`).

## Confirmed findings fixed

The reports produced 20 confirmed findings. The fixes and regression coverage are summarized below.

| Area | Finding and fix | Regression coverage |
|---|---|---|
| CFG | Static call-graph traversal now rejects recursive subprogram calls, including calls on runtime-infeasible branches. | `recursive_subprogram_call_is_rejected_even_on_dead_branch` |
| CFG/stack | Stack depth reached through R10-derived aliases is included using the mini verifier's per-PC frame states, so combined caller/callee use cannot bypass the frame limit. | `combined_stack_depth_counts_r10_alias_accesses` |
| ALU64 | Variable left shifts now widen the signed range across both halves of the i64 domain; this retains possible results such as `1 << 63`. | `variable_alu64_lsh_preserves_sign_bit_result` |
| ALU32 | A zero-bit left shift returns the original range without evaluating a shift by 32. | `alu32_lsh_zero_amount_does_not_panic` |
| Liveness | Only full-width stack stores kill a whole liveness slot; narrow writes preserve liveness for untouched bytes. | `partial_stack_write_keeps_unwritten_slot_bytes_live` |
| Mini verifier | Precision backtracking through a BPF-to-BPF call now falls back conservatively when R0 or an argument is required. | `backtracking_through_subprog_return_falls_back` |
| Concrete map model | Map pointers carry map fd, array index, and value-relative offset separately; map memory is keyed by that identity rather than fixed, overlapping address windows. | `large_map_elements_keep_their_map_identity`, `map_ptr_family_covered`, existing map lookup/store tests |
| Concrete map model | Invalid negative value offsets return a concrete failure instead of unsigned-subtraction panic. | `map_pointer_below_value_base_returns_error_without_panicking`, `concrete_map_value_out_of_bounds` |
| References | New reference IDs are selected so they cannot collide with any currently active reference after a release. | `acquired_reference_ids_do_not_reuse_an_active_id` |
| References | Releasing a reference invalidates matching aliases and spills in all active frames, including saved caller frames, for helper and kfunc releases. | `callee_reference_release_invalidates_saved_caller_aliases` |
| Dynptr | `dynptr_from_mem` checks the full 16-byte slot is inside the current frame before indexing it. | `dynptr_from_mem_out_of_frame_returns_error_without_panicking` |
| Dynptr | `dynptr_read` validates the complete output-buffer range and marks the covered bytes only after bounds checks. | `dynptr_read_out_of_frame_returns_error_without_panicking` |
| Memory stores | Stores through map-value and referenced-memory pointers now read and validate their source register and reject non-scalar pointer leaks. | `map_store_rejects_uninitialized_source_register` |
| Spec subprograms | Callee frames receive the call-site return PC; returns restore that PC and transfer the callee's actual R0. | `subprog_return_value_reaches_the_callsite`; existing `spec_subprog_returns_r0` |
| Spec stack | A narrow write invalidates stale scalar-spill metadata while retaining the correct byte-level contents. | `narrow_stack_write_invalidates_stale_scalar_spill`; existing `spec_spill_bytes_visible_to_narrow_loads` |
| QEMU verdicts | `not-privileged` is treated as infrastructure failure and becomes Skipped, not a kernel rejection/finding. | `parse_infra_failures_are_none` |
| Strict classifier | Strict-mode whitelisting now requires the explicit `for !root` message rather than suppressing every PointerArith/Complexity rejection. Reducer replay also carries the kernel reason so it applies the same rule. | `strict_pointer_category_does_not_hide_regular_rejections`, `strict_whitelist_for_root_message`, `invariant_strict_mode_whitelists` |
| QEMU triage | The guest emits `insn_idx`; the host parser and QEMU batch path preserve it for triage grouping. | `parse_verdicts`, `rejection_output_preserves_instruction_index` |
| Kernel log categories | Generic `R0 ` prefixes no longer make pointer-memory errors classify as ExitR0. | `r0_prefixed_pointer_errors_keep_pointer_category` |
| Strict capability handling | The guest agent skips strict runs if capability dropping fails; the host `diff` command exits rather than continuing with privileged capabilities. | `strict_capability_drop_failure_is_propagated`, `strict_capability_drop_failure_is_not_silently_accepted`, `non_strict_mode_does_not_attempt_capability_drop` |

The `src/insn.rs` working-tree change was already present when the audit began. It fixes decoder-boundary bugs by rejecting trailing partial instruction bytes and returning length errors rather than panicking on malformed slot lengths. The instruction-decoder auditor confirmed the fix; coverage includes `decode_program_rejects_trailing_partial_instruction` and `parse_functions_reject_invalid_instruction_lengths`.

## Rejected concern

A spec-oracle review raised a concern that a narrow store might cross an 8-byte slot boundary and miss a pointer spill in the next slot. This was not treated as a bug: the referenced bpf-next verifier marks `PTR_TO_STACK` accesses as strictly aligned, so valid 2/4/8-byte accesses cannot straddle the 8-byte slot boundary (and a 1-byte access cannot cross it). No code change was made for this concern.

The scalar/tnum review found no concrete issue in its assigned scope. The decoder review found no remaining issue in the current decoder change.

## Final verification

- `cargo test --all-targets -- --quiet`: passed; the library suite reported 623 passed, with all other test targets also passing.
- `cargo test --no-default-features --lib -- --quiet`: 603 passed.
- `cargo check --no-default-features --features agent-musl --bin agent`: passed.
- `cargo fmt --all --check`: passed.
- `cargo clippy --all-targets -- -D warnings`: passed.
- `git diff --check`: passed.
- `cargo run --quiet --bin smt_verify --`: violation count 0.
- Deterministic generation fuzz (seed 777, 500 iterations): 0 findings (342 agree, 158 skipped; no kernel column).
- Corpus mutation fuzz (seed 1601, 200 iterations): 0 findings; 167 mutations, 125 valid and 42 invalid (no kernel column).
- Targeted regression tests, including `cargo test --bin agent`, `cargo test --bin diff`, QEMU parser tests, and reducer strict-mode invariants, passed. Pre-fix failures were observed for the focused ALU, liveness, CFG/stack, resource/dynptr, spec, mini, QEMU privilege, strict-classifier, and log-category repros.

A follow-up actual QEMU kernel smoke campaign was run after the audit: `tools/qemu-campaign.sh --seed 20261013 --iters 20 --mode generation --out-dir fuzz-out/qemu-audit-smoke`. The guest booted on the prebuilt bpf-next `7.2.0-rc6-gf79066c78402` bzImage in strict mode; all 20 kernel queries returned (19 agree, 0 skipped) and one `kernel-overstrict-candidate` was recorded. The finding is `seed-20261013-2`: the mini/spec accept a 29-iteration bounded loop, while the kernel rejects it with `BPF program is too large. Processed 1000001 insn`. This is a candidate requiring reduction/follow-up, not a confirmed kernel bug. Its artifacts are under `fuzz-out/qemu-audit-smoke/findings/kernel-overstrict-candidate-seed-20261013-2/`. The campaign exited 1 as designed when it recorded a finding and stopped the guest cleanly. No privileged host operations or source changes were needed for this run.

The earlier static concern about a spec write crossing a spill-slot boundary was rejected after read-only inspection of bpf-next `check_ptr_alignment`, which enforces strict alignment for `PTR_TO_STACK`. No separate live kernel differential smoke or QEMU-backed reducer run was performed.

## Residual limits

This was a single audit round; absence of findings in a scope is not proof that it is bug-free. The reducer's strict-mode behavior is covered at the invariant level, while end-to-end QEMU protocol execution and kernel verdict-index propagation were not exercised against a live guest. No commits, pushes, or privileged commands were used.
