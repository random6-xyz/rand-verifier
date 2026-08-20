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
///
/// `timeout 30` guards the guest kernel verifier: a pathological
/// program can keep BPF_PROG_LOAD busy for minutes (speculative
/// paths, complexity explosions), which would stall the host's 300s
/// batch deadline and skip the whole batch tail. When the timeout
/// kills the agent, write an explicit marker so the host's result
/// polling terminates quickly instead of waiting out its 300s
/// deadline.
pub const QEMU_RUN_SCRIPT: &str = r###"#!/bin/sh
STRICT=""
[ -f /mnt/host/strict ] && STRICT="--strict"
# Force a fresh 9p readdir of the job dir BEFORE reading the manifest:
# the 9p client can serve a stale directory listing, so a job file
# written just now may not appear in a glob yet. An explicit ls
# refreshes the readdir cache so the manifest-driven opens below see
# every file (stale listings surfaced as REJECT cannot-read job file
# errno=2).
ls -la /mnt/host/job/ > /mnt/host/out/.diag-jobls 2>&1
ls /mnt/host/job/ >/dev/null 2>&1
id > /mnt/host/out/.diag-id 2>&1
ls -la /sbin/agent >> /mnt/host/out/.diag-id 2>&1
id /sbin/agent >> /mnt/host/out/.diag-id 2>&1 || true
# security_model=none can map host files to non-root guest ownership
# even though we run as root, so make the batch world-readable/writable
# before opening it (EACCES used to surface as cannot-read errno=13).
chmod 777 /mnt/host/job /mnt/host/out 2>/dev/null
for f in /mnt/host/job/*.bin; do chmod 666 "$f" 2>/dev/null; done
# Process exactly the job files listed in /mnt/host/manifest (one name
# per line). The manifest is a plain file the host writes AFTER all
# job/*.bin are on disk, so we never depend on 9p directory readdir
# visibility — the guest opens the manifest by path, which is reliable
# even when readdir lags.
if [ -f /mnt/host/manifest ]; then
    while IFS= read -r name; do
        [ -n "$name" ] || continue
        f="/mnt/host/job/$name.bin"
        [ -e "$f" ] || continue
        timeout 30 /sbin/agent "$f" $STRICT > "/mnt/host/out/$name.out" 2>&1
        rc=$?
        if [ $rc -eq 124 ]; then
            echo "AGENT-TIMEOUT" > "/mnt/host/out/$name.out"
        fi
        rm -f "$f"
    done < /mnt/host/manifest
fi
# tell the host this batch is fully consumed. The host waits for every
# out file, not for this marker, so a slow file cannot strand a job.
touch /mnt/host/batch-done
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

    // wait until the guest consumed the previous batch: job/ empty AND
    // the guest's run.sh has finished (batch-done marker). The marker
    // closes the race where a slow guest is still processing the
    // previous batch while we clear job/ and out/ below — that used to
    // surface as REJECT cannot-read job file errno=2 for the tail of
    // the next batch.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while job_has_files(&job) || dir.join("batch-done").exists() {
        if std::time::Instant::now() > deadline {
            eprintln!("qemu: previous batch never consumed; clearing job dir");
            clear_dir(&job);
            let _ = fs::remove_file(dir.join("batch-done"));
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    // stale markers from a previous batch would make the guest re-run
    // the old run.sh, so clear them before writing anything
    let _ = fs::remove_file(dir.join("batch-ready"));
    let _ = fs::remove_file(dir.join("run.sh"));
    let _ = fs::remove_file(dir.join("manifest"));
    clear_dir(&out);

    // write the batch: job files, then a manifest listing them, then
    // the run script + batch-ready marker. The guest reads the
    // manifest by path (reliable) instead of globbing job/ (9p
    // readdir can lag and miss fresh files).
    let mut ok = true;
    let mut manifest = String::new();
    for (name, bytes, _) in pending.iter() {
        let p = job.join(format!("{name}.bin"));
        if fs::write(&p, bytes).is_err() {
            ok = false;
            break;
        }
        // security_model=none can surface host files to the guest with
        // ownership the guest cannot read even as root (EACCES); force
        // world-read/write so the guest agent can always open them.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&p, fs::Permissions::from_mode(0o666));
        }
        manifest.push_str(name);
        manifest.push('\n');
    }
    if ok {
        ok = fs::write(dir.join("manifest"), manifest.as_bytes()).is_ok();
    }
    if ok {
        ok = fs::write(dir.join("run.sh"), QEMU_RUN_SCRIPT).is_ok();
    }
    // batch-ready tells the guest that every job/*.bin and the
    // manifest are on disk. The guest only runs run.sh when
    // batch-ready exists, so it never sees a half-written batch.
    if ok {
        // give the 9p server a moment to settle the freshly written
        // files (metadata/ownership) before the guest opens them;
        // opening too early surfaced as EACCES (errno=13) even for
        // world-readable files.
        std::thread::sleep(std::time::Duration::from_millis(100));
        ok = fs::write(dir.join("batch-ready"), b"1").is_ok();
    }
    if !ok {
        fail_all(pending, "qemu: cannot write batch");
        return;
    }
    // poll until every job has its result AND the guest consumed the
    // whole batch (job files gone). We do NOT stop on batch-done alone:
    // the guest touches it after its glob loop, which can finish with
    // job files still present if 9p showed a stale empty directory —
    // stopping then would strand those jobs. Waiting for every out
    // file instead gives the guest's retry globs time to pick up
    // stragglers.
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
    // signal the guest we parsed everything: remove the batch-done
    // marker so the next flush_batch's wait loop passes immediately,
    // and remove run.sh/batch-ready/manifest so the guest does not
    // re-run the same batch (it must not delete them itself — by-name
    // removal would also delete the NEXT batch's files, stranding its
    // jobs).
    let _ = fs::remove_file(dir.join("batch-done"));
    let _ = fs::remove_file(dir.join("run.sh"));
    let _ = fs::remove_file(dir.join("batch-ready"));
    let _ = fs::remove_file(dir.join("manifest"));
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
/// Infrastructure failures (the agent could not read the job file, the
/// guest verifier hit the per-program timeout, or the load failed
/// without a verifier-log line) return `None` — they are not kernel
/// verdicts and must surface as `Skipped`, never as findings (a
/// cannot-read race with the batch deadline clearing the job dir used
/// to classify as REJECT(Other) → precision-candidate).
pub fn parse_agent_verdict(text: &str) -> Option<(SideVerdict, Option<String>)> {
    let first = text.lines().find(|l| !l.trim().is_empty())?;
    if first.trim() == "ACCEPT" {
        return Some((SideVerdict::Accept, None));
    }
    let rest = first.trim();
    if rest.trim() == "AGENT-TIMEOUT" {
        // the guest kernel verifier exceeded the per-program budget
        // (pathological program) — not a verdict
        return None;
    }
    if let Some(reason) = rest.strip_prefix("REJECT ") {
        // infrastructure failures: not kernel verdicts
        if reason.starts_with("cannot-read")
            || reason.starts_with("invalid-program")
            || reason.starts_with("no-error-line")
        {
            return None;
        }
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

    #[test]
    fn parse_infra_failures_are_none() {
        // infrastructure failures are not kernel verdicts: they must
        // surface as Skipped, never as findings
        assert!(parse_agent_verdict("AGENT-TIMEOUT\n").is_none());
        assert!(parse_agent_verdict("REJECT cannot-read job file errno=2\n").is_none());
        assert!(parse_agent_verdict("REJECT invalid-program bytes errno=22\n").is_none());
        assert!(parse_agent_verdict("REJECT no-error-line errno=28\n").is_none());
    }
}
