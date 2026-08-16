// ── qemu guest kernel column (9p share batch protocol) ──────────────────────

//! Kernel-verdict queries via a qemu guest running the bpf-next kernel
//! (AGENTS.md: campaigns run against a self-built kernel in qemu, no
//! host privileges needed). The host drops program batches into a 9p
//! share; the guest's init loop runs `/sbin/agent` per file and writes
//! the verdict back. Shared by the fuzz campaign runner (bin/fuzz.rs)
//! and the reducer (bin/reduce.rs, issue #114).
//!
//! Completion protocol (markerless, race-free over the 9p share): the
//! host waits until `job/` is empty (the guest consumed the previous
//! batch), clears stale results, writes the new batch, and polls until
//! every job has its `out/<name>.out` and `job/` is empty again. No
//! batch-done marker exists, so host and guest never churn the same
//! file. (A shared batch-done marker races badly over the 9p share:
//! the guest's stale dentry cache can make its touch fail with ENOENT
//! or hide the host's deletions, stalling the host for its full
//! 60s/300s wait.)

use std::fs;
use std::path::{Path, PathBuf};

use crate::diff::SideVerdict;
use crate::klog::categorize_reason;

/// qemu batch size: programs sent to the guest per round-trip.
pub const QEMU_BATCH: usize = 100;

/// The script the guest runs for one batch: verify every job file,
/// write `out/<name>.out`.
pub const QEMU_RUN_SCRIPT: &str = r###"#!/bin/sh
STRICT=""
[ -f /mnt/host/strict ] && STRICT="--strict"
for f in /mnt/host/job/*.bin; do
    [ -e "$f" ] || continue
    b=$(basename "$f" .bin)
    /sbin/agent "$f" $STRICT > "/mnt/host/out/$b.out" 2>&1
    rm -f "$f"
done
"###;

/// Batch kernel-verdict queries to the qemu guest via the 9p share:
/// the guest's init loop picks up `job/<name>.bin`, runs the agent,
/// and writes the verdict to `out/<name>.out`. The host polls until
/// every result is back (or times out), then classifies.
pub struct QemuBatch {
    tx: std::sync::mpsc::Sender<QemuJob>,
    handle: Option<std::thread::JoinHandle<()>>,
}

/// One kernel query: program bytes + a channel the worker replies on.
pub type QemuJob = (
    String,
    Vec<u8>,
    std::sync::mpsc::Sender<Result<(SideVerdict, Option<String>), String>>,
);

impl QemuBatch {
    pub fn new(dir: PathBuf, strict: bool) -> Self {
        let (tx, rx) = std::sync::mpsc::channel();
        let worker_dir = dir.clone();
        let handle = std::thread::spawn(move || qemu_worker(worker_dir, strict, rx));
        Self {
            tx,
            handle: Some(handle),
        }
    }

    /// Queue one program and block until the guest kernel verdict is
    /// back. The worker batches queries and flushes them to the guest
    /// every [`QEMU_BATCH`] jobs or ~30ms, whichever comes first.
    pub fn ask(
        &mut self,
        name: &str,
        bytes: &[u8],
    ) -> anyhow::Result<(SideVerdict, Option<String>, Option<u32>)> {
        let (rtx, rrx) = std::sync::mpsc::channel();
        self.tx.send((name.to_string(), bytes.to_vec(), rtx))?;
        match rrx.recv()? {
            Ok((v, m)) => Ok((v, m, None)),
            Err(e) => Ok((SideVerdict::Skipped, Some(e), None)),
        }
    }

    /// Flush any remaining tail batch (campaign end).
    pub fn flush(&mut self) -> anyhow::Result<()> {
        let (rtx, rrx) = std::sync::mpsc::channel();
        self.tx.send(("__flush__".into(), Vec::new(), rtx))?;
        rrx.recv()?.map_err(anyhow::Error::msg)?;
        Ok(())
    }
}

impl Drop for QemuBatch {
    fn drop(&mut self) {
        // disconnect the channel so the worker drains and exits: send the
        // flush signal, then drop our sender so the worker's recv_timeout
        // loop sees the disconnect and terminates (without dropping the
        // sender first, join() hangs forever — the channel stays open).
        let _ = self
            .tx
            .send(("__flush__".into(), Vec::new(), std::sync::mpsc::channel().0));
        drop(std::mem::replace(
            &mut self.tx,
            std::sync::mpsc::channel().0,
        ));
        let _ = self.handle.take().map(|h| h.join());
    }
}

/// Worker thread: collect queries, flush them to the guest in batches,
/// and deliver every verdict to its query channel.
fn qemu_worker(dir: PathBuf, strict: bool, rx: std::sync::mpsc::Receiver<QemuJob>) {
    let mut pending: Vec<QemuJob> = Vec::new();
    loop {
        match rx.recv_timeout(std::time::Duration::from_millis(30)) {
            Ok((name, bytes, resp)) => {
                if name == "__flush__" {
                    flush_batch(&dir, strict, &mut pending);
                    let _ = resp.send(Ok((SideVerdict::Accept, None)));
                } else {
                    pending.push((name, bytes, resp));
                    if pending.len() >= QEMU_BATCH {
                        flush_batch(&dir, strict, &mut pending);
                    }
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if !pending.is_empty() {
                    flush_batch(&dir, strict, &mut pending);
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                flush_batch(&dir, strict, &mut pending);
                break;
            }
        }
    }
}

/// Send one batch to the guest and deliver the parsed verdicts.
fn flush_batch(dir: &Path, strict: bool, pending: &mut Vec<QemuJob>) {
    if pending.is_empty() {
        return;
    }
    let job = dir.join("job");
    let out = dir.join("out");
    if fs::create_dir_all(&job).is_err() || fs::create_dir_all(&out).is_err() {
        fail_all(pending, "qemu: cannot create share dirs");
        return;
    }
    // strict mode is signalled to the guest via a marker file
    let strict_marker = dir.join("strict");
    if strict {
        let _ = fs::write(&strict_marker, b"1");
    } else {
        let _ = fs::remove_file(&strict_marker);
    }

    // wait until the guest consumed the previous batch (job/ empty),
    // then clear stale results
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while job_has_files(&job) {
        if std::time::Instant::now() > deadline {
            eprintln!("qemu: previous batch never consumed; clearing job dir");
            clear_dir(&job);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    clear_dir(&out);

    // write the batch + the run script
    let mut ok = true;
    for (name, bytes, _) in pending.iter() {
        if fs::write(job.join(format!("{name}.bin")), bytes).is_err() {
            ok = false;
            break;
        }
    }
    if ok {
        ok = fs::write(dir.join("run.sh"), QEMU_RUN_SCRIPT).is_ok();
    }
    if !ok {
        fail_all(pending, "qemu: cannot write batch");
        return;
    }
    // poll until every job has its result and the guest consumed the
    // whole batch: the job file disappears only after the agent
    // finished writing its out file, so both conditions together mean
    // the result is complete
    let want = pending.len();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(300);
    while pending.iter().any(|(name, _, _)| {
        job.join(format!("{name}.bin")).exists() || !out.join(format!("{name}.out")).is_file()
    }) {
        if std::time::Instant::now() > deadline {
            eprintln!("qemu: timeout waiting for {want} results; marking rest skipped");
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    // parse the results and reply
    for (name, _, resp) in pending.drain(..) {
        let p = out.join(format!("{name}.out"));
        // the guest may still be writing the last file: retry a few
        // times before giving up
        let mut parsed = None;
        for _ in 0..10 {
            let text = fs::read_to_string(&p).unwrap_or_default();
            if text.trim().is_empty() {
                std::thread::sleep(std::time::Duration::from_millis(50));
                continue;
            }
            parsed = parse_agent_verdict(&text);
            break;
        }
        let first_line = fs::read_to_string(&p)
            .ok()
            .and_then(|s| s.lines().next().map(|l| l.to_string()))
            .unwrap_or_else(|| "<no file>".into());
        let _ = fs::remove_file(&p);
        match parsed {
            Some((v, m)) => {
                let _ = resp.send(Ok((v, m)));
            }
            None => {
                eprintln!("qemu: parse failure for {name}: {first_line:?}");
                let _ = resp.send(Err("qemu: parse/read failure".into()));
            }
        }
    }
}

fn job_has_files(job: &Path) -> bool {
    fs::read_dir(job)
        .map(|it| it.flatten().next().is_some())
        .unwrap_or(false)
}

fn clear_dir(dir: &Path) {
    if let Ok(entries) = fs::read_dir(dir) {
        for e in entries.flatten() {
            let _ = fs::remove_file(e.path());
        }
    }
}

fn fail_all(pending: &mut Vec<QemuJob>, why: &str) {
    for (name, _, resp) in pending.drain(..) {
        eprintln!("qemu: {why} for {name}");
        let _ = resp.send(Err(why.into()));
    }
}

/// Parse one agent output file: `ACCEPT` or `REJECT <reason> errno=<n>`.
pub fn parse_agent_verdict(text: &str) -> Option<(SideVerdict, Option<String>)> {
    let first = text.lines().find(|l| !l.trim().is_empty())?;
    if first.trim() == "ACCEPT" {
        return Some((SideVerdict::Accept, None));
    }
    let rest = first.trim();
    if let Some(reason) = rest.strip_prefix("REJECT ") {
        // strip the trailing "errno=<n>"
        let reason = reason
            .rsplit_once(" errno=")
            .map(|(r, _)| r)
            .unwrap_or(reason);
        let category = categorize_reason(reason);
        return Some((SideVerdict::Reject { category }, Some(reason.to_string())));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_verdicts() {
        assert_eq!(
            parse_agent_verdict("ACCEPT\n"),
            Some((SideVerdict::Accept, None))
        );
        let (v, m) =
            parse_agent_verdict("REJECT invalid stack off=-520 size=8 errno=13\n").unwrap();
        assert!(matches!(v, SideVerdict::Reject { .. }));
        assert!(m.unwrap().contains("invalid stack off"));
        assert!(parse_agent_verdict("").is_none());
        assert!(parse_agent_verdict("TIMEOUT\n").is_none());
    }
}
