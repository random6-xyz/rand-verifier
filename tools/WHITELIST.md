# Whitelist fingerprints (#144)

The differential oracle discards a pair when it is a **known design
difference**, not a bug. Each entry is a named fingerprint in
`src/diff.rs::FINGERPRINTS` with the evidence that justifies it, and every
suppression is counted in `summary.json`:

```json
"suppressed": { "mini-complexity-budget": 12, "privileged-uninit-stack": 3 }
```

A fingerprint must name the exact mechanism. Broad rules ("any loop", "any
`!root` message") are not allowed: they hide live false rejects like K-1b
(`r0=0; r0+=1; if r0!=4 goto -2; exit` is accepted with full capabilities
and rejected under CAP_BPF on bpf-next `a30c772627b2`).

## Entries

| id | condition | evidence | review |
|---|---|---|---|
| `mini-complexity-budget` | mini rejects with `Complexity`, kernel accepts | mini's exploration budget (`max_states 1024` / `max_steps`) vs the kernel's much larger limits — an intentional, documented limit (`docs/DIFFERENTIAL_PLAN.md` §6) | re-check when the mini budget grows |
| `privileged-uninit-stack` | mini `UninitRead` with a stack message, kernel accepts | uninit stack reads (`allow_uninit_stack`) and indirect reads over spilled pointers (`allow_ptr_leaks`) are gated on `bpf_token_capable`/CAP_SYS_ADMIN superset (`kernel/bpf/token.c`) | strict/unpriv mode must reject these — the axis split is #143 |
| `privileged-r0-pointer-exit` | mini `ExitR0` with an "at exit" message, kernel accepts | `allow_ptr_leaks` gates the exit-time "R0 leaks addr" check for privileged loaders | same as above |
| `corpus-uninit-stack-fixture` | corpus fixtures `stack_write_before_read` / `narrow_read_uninit`, kernel accepts | same privileged leniency, kept name-stable for the accept/reject corpus | drop when the corpus fixtures move to the unpriv axis |

## Adding an entry

1. Reproduce the pair and identify the kernel mechanism (source line or
   selftest).
2. Add a `Fingerprint` with a stable `id`, the evidence, and the narrowest
   predicate that still covers the pair.
3. Add a regression test next to `fingerprints_are_named_and_evidence_backed`.
4. Verify `suppressed` counts in a short campaign and note the change in
   the issue that owns the gap.

`suppressed` is a **budget**, not a dumping ground: a growing entry with no
review is a signal that the model is wrong, not that the kernel is.
