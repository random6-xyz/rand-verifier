# Capability modes (#143)

A BPF load's verifier rules depend on which capabilities the loader holds.
`--strict` only modelled "CAP_BPF without CAP_PERFMON", which is neither the
privileged nor the unprivileged kernel. This is the explicit axis.

## Modes

| `--caps` | capabilities kept | verifier rules |
|---|---|---|
| `priv` (default for `agent`) | unchanged | privileged: `allow_uninit_stack`, `allow_ptr_leaks`, speculative bypass |
| `cap-bpf` (`--strict` alias) | CAP_BPF + CAP_NET_ADMIN | no CAP_PERFMON: privileged leniencies off, loads still allowed |
| `cap-bpf-perfmon` | + CAP_PERFMON | CAP_PERFMON-gated rules on, CAP_SYS_ADMIN gone |
| `unpriv` | none | unprivileged rules; needs `unprivileged_bpf_disabled=0` |

`CAP_PERFMON` (38) is the gate for `allow_uninit_stack`, `allow_ptr_leaks`
and the speculative bypass (`include/linux/bpf.h`); `bpf_ns_capable` treats
CAP_SYS_ADMIN as a superset of every BPF capability (`kernel/bpf/token.c`),
so a mode that keeps CAP_SYS_ADMIN is effectively privileged.

## Usage

```sh
# guest agent (inside the qemu image)
/sbin/agent --caps cap-bpf job.bin
/sbin/agent --caps unpriv job.bin        # requires the unpriv kernel

# host-side library
krun::drop_caps(CapMode::CapBpfPerfmon)
```

`drop_privileged_caps()` remains as `CapMode::CapBpf` for compatibility.

## Unprivileged kernel

The hosted/qemu guest kernels default to `kernel.unprivileged_bpf_disabled=2`,
which rejects capability-less loads before the verifier runs. Build a guest
with `tools/kernel/unpriv.config`:

```sh
cd <bpf-next>
./scripts/kconfig/merge_config.sh -m .config tools/kernel/unpriv.config
make -j"$(nproc)" bzImage
```

The config fragment sets `CONFIG_BPF_UNPRIV_DEFAULT_OFF=n`, so the guest boots
with unprivileged loads enabled.

## Replay mapping (next step)

The corpus manifest already carries `.result_unpriv` and `errstr_unpriv`
(e.g. `verifier/jump.c`: `.result = ACCEPT`, `.result_unpriv = REJECT`,
`"R1 pointer comparison"`). Once the unpriv image exists:

```sh
python3 tools/guest_replay.py --share <share> --manifest <corpus>/manifest.jsonl \
    --programs <corpus>/programs --out /tmp/unpriv.jsonl --skip-fixups \
    --only-prog-type none --use-unpriv
cargo run --release --bin replay -- --manifest <corpus>/manifest.jsonl \
    --programs <corpus>/programs --kernel-column /tmp/unpriv-column.jsonl --gate
```

The model already follows the privileged rules (pointer comparisons,
uninit stack reads); the unpriv kernel column is the remaining evidence
for the second axis.

## Measured evidence (2026-11-02, bpf-next `a30c772627b2`)

A guest kernel built with `tools/kernel/unpriv.config`
(`CONFIG_BPF_UNPRIV_DEFAULT_OFF` unset, `CONFIG_BPF_SYSCALL=y`) and the
`agent-musl` binary running with `--caps unpriv` loads socket-filter
programs with **no capabilities at all**. Corpus programs through the
guest:

| case | privileged expectation | unpriv result |
|---|---|---|
| `jump__000..004` | ACCEPT | `REJECT R1 pointer comparison prohibited` |
| `ctx_skb__004` | REJECT (ptr comparison) | `REJECT R1 pointer comparison prohibited` |
| `basic_instr__000/001`, `ctx_skb__000`, `atomic_fetch_add__000` | ACCEPT | `ACCEPT` |

This matches the corpus `.result_unpriv` column (REJECT for the five
`jump__*` cases, whose `.errstr_unpriv` is "R1 pointer comparison"), and
shows the unprivileged axis is not a blanket rejection: ordinary
socket-filter programs still load.

Reproduce:

```sh
# one-time: build the guest kernel with the fragment merged, then
#   tools/qemu-assets.sh --sample-initramfs
# (the agent must be rebuilt first: cargo build --release
#  --no-default-features --features agent-musl \
#  --target x86_64-unknown-linux-musl --bin agent)
QEMU_ASSETS=$PWD/fuzz-out/kernel-a30c772627b2-unpriv \
  tools/qemu-share.sh --fresh && QEMU_ASSETS=$PWD/fuzz-out/kernel-a30c772627b2-unpriv \
  tools/qemu-boot.sh
# submit job/<case>.bin with a run.sh that calls
#   /sbin/agent --caps unpriv job/<case>.bin
```

The unprivileged half of the pointer-comparison rule is therefore
confirmed on the same kernel the model is measured against.
