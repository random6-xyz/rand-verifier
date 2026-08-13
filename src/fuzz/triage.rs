// ── Candidate triage and dedup for fuzz findings (v0.7, #70) ────────────────

//! A campaign produces many findings that share one root cause. Triage
//! groups them by a deterministic key — (finding, mini reason category,
//! kernel reason category, first divergent instruction index, concrete
//! divergence point) — and keeps one representative per group plus the
//! variant count, so manual analysis (Phase 6) starts from one minimal
//! reproducer per cause instead of thousands of variants.
//!
//! Grouping is fully deterministic: candidates are sorted by name first
//! (stable representative), then grouped through a `BTreeMap` keyed by
//! the ordered [`GroupKey`].

use std::collections::BTreeMap;

use crate::diff::SideVerdict;
use crate::fuzz::oracle::Finding;
use crate::klog::ReasonCategory;

/// The divergence signature of one finding — the dedup key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Divergence {
    /// The mini failure instruction index (None for accepted programs).
    pub mini_insn: Option<u32>,
    /// The kernel reject instruction index (None unless the kernel
    /// rejected).
    pub kernel_insn: Option<u32>,
    /// The first concrete coverage-violation pc (None when the
    /// concrete side is safe).
    pub concrete_pc: Option<u32>,
}

/// One finding plus its classification context, as fed to the triage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub name: String,
    pub finding: Finding,
    pub mini: SideVerdict,
    pub kernel: SideVerdict,
    pub divergence: Divergence,
}

/// The group key: (finding, mini category, kernel category, first
/// divergent instruction index, concrete divergence point).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct GroupKey {
    pub finding: Finding,
    pub mini_category: Option<ReasonCategory>,
    pub kernel_category: Option<ReasonCategory>,
    /// The first divergent instruction: mini's failure index when mini
    /// rejected, otherwise the kernel's reject index.
    pub div_insn: Option<u32>,
    pub concrete_pc: Option<u32>,
}

/// One deduplicated group of findings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    pub key: GroupKey,
    /// How many findings share this key.
    pub count: usize,
    /// The name of the representative finding (the name-sorted first).
    pub representative: String,
    /// Analysis priority: model bug (3) > soundness (2) > precision
    /// (1) > rand-verifier gap (0).
    pub priority: u8,
}

/// Group candidates by their dedup key, returning groups ordered by
/// priority (highest first), then by key. Deterministic for the same
/// candidate set regardless of input order.
pub fn group(candidates: Vec<Candidate>) -> Vec<Group> {
    let mut candidates = candidates;
    // name-sorted first: the representative is stable across runs and
    // independent of the campaign's iteration order
    candidates.sort_by(|a, b| a.name.cmp(&b.name));

    let mut counts: BTreeMap<GroupKey, (usize, String)> = BTreeMap::new();
    for c in candidates {
        let key = GroupKey {
            finding: c.finding,
            mini_category: category_of(&c.mini),
            kernel_category: category_of(&c.kernel),
            div_insn: c.divergence.mini_insn.or(c.divergence.kernel_insn),
            concrete_pc: c.divergence.concrete_pc,
        };
        let entry = counts.entry(key).or_insert((0, c.name.clone()));
        entry.0 += 1;
    }

    let mut groups: Vec<Group> = counts
        .into_iter()
        .map(|(key, (count, representative))| Group {
            priority: priority_of(&key.finding),
            key,
            count,
            representative,
        })
        .collect();
    groups.sort_by(|a, b| b.priority.cmp(&a.priority).then_with(|| a.key.cmp(&b.key)));
    groups
}

fn category_of(side: &SideVerdict) -> Option<ReasonCategory> {
    match side {
        SideVerdict::Reject { category } => Some(*category),
        _ => None,
    }
}

fn priority_of(finding: &Finding) -> u8 {
    match finding {
        // a model bug is the most urgent: rand-verifier is unsound
        Finding::RvSoundnessBug => 3,
        // the kernel accepts a concretely unsafe program
        Finding::SoundnessCandidate => 2,
        // the kernel rejects a concretely safe program — the v0.7 target
        Finding::PrecisionCandidate => 1,
        Finding::RvPrecisionGap => 0,
        // non-findings are never grouped (is_finding gate upstream)
        _ => 0,
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::klog::ReasonCategory;

    fn cand(
        name: &str,
        finding: Finding,
        mini_cat: Option<ReasonCategory>,
        kernel_cat: Option<ReasonCategory>,
        mini_insn: Option<u32>,
        kernel_insn: Option<u32>,
        concrete_pc: Option<u32>,
    ) -> Candidate {
        Candidate {
            name: name.to_string(),
            finding,
            mini: match mini_cat {
                Some(c) => SideVerdict::Reject { category: c },
                None => SideVerdict::Accept,
            },
            kernel: match kernel_cat {
                Some(c) => SideVerdict::Reject { category: c },
                None => SideVerdict::Accept,
            },
            divergence: Divergence {
                mini_insn,
                kernel_insn,
                concrete_pc,
            },
        }
    }

    /// 1000 same-cause candidates → exactly one group with count 1000
    /// and the name-sorted first candidate as the representative.
    #[test]
    fn triage_1000_same_cause() {
        let mut candidates = Vec::new();
        for i in 0..1000 {
            candidates.push(cand(
                &format!("seed-0-{i}"),
                Finding::PrecisionCandidate,
                Some(ReasonCategory::UninitRead),
                Some(ReasonCategory::StackBounds),
                Some(7),
                Some(9),
                None,
            ));
        }
        let groups = group(candidates);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].count, 1000);
        assert_eq!(groups[0].representative, "seed-0-0");
        assert_eq!(groups[0].key.div_insn, Some(7));
        assert_eq!(groups[0].priority, 1);
    }

    /// Every key component separates groups: finding, mini category,
    /// kernel category, divergent instruction, concrete divergence.
    #[test]
    fn triage_different_causes_separate() {
        let u = ReasonCategory::UninitRead;
        let s = ReasonCategory::StackBounds;
        let candidates = vec![
            // the baseline cause
            cand(
                "a",
                Finding::PrecisionCandidate,
                Some(u),
                Some(s),
                Some(7),
                Some(9),
                None,
            ),
            // different mini failure instruction
            cand(
                "b",
                Finding::PrecisionCandidate,
                Some(u),
                Some(s),
                Some(8),
                Some(9),
                None,
            ),
            // different mini category
            cand(
                "c",
                Finding::PrecisionCandidate,
                Some(ReasonCategory::StackAlign),
                Some(s),
                Some(7),
                Some(9),
                None,
            ),
            // different finding
            cand(
                "d",
                Finding::SoundnessCandidate,
                Some(u),
                None,
                Some(7),
                None,
                None,
            ),
            // different concrete divergence
            cand(
                "e",
                Finding::PrecisionCandidate,
                Some(u),
                Some(s),
                Some(7),
                Some(9),
                Some(3),
            ),
            // same key as "a" — joins it
            cand(
                "f",
                Finding::PrecisionCandidate,
                Some(u),
                Some(s),
                Some(7),
                Some(9),
                None,
            ),
        ];
        let groups = group(candidates);
        assert_eq!(groups.len(), 5, "{groups:#?}");
        let baseline = groups.iter().find(|g| g.representative == "a").unwrap();
        assert_eq!(baseline.count, 2);
    }

    /// Grouping is independent of the input order.
    #[test]
    fn triage_deterministic() {
        let mk = || {
            vec![
                cand(
                    "z",
                    Finding::PrecisionCandidate,
                    Some(ReasonCategory::UninitRead),
                    Some(ReasonCategory::StackBounds),
                    Some(7),
                    Some(9),
                    None,
                ),
                cand(
                    "a",
                    Finding::PrecisionCandidate,
                    Some(ReasonCategory::UninitRead),
                    Some(ReasonCategory::StackBounds),
                    Some(7),
                    Some(9),
                    None,
                ),
                cand(
                    "m",
                    Finding::PrecisionCandidate,
                    Some(ReasonCategory::UninitRead),
                    Some(ReasonCategory::StackBounds),
                    Some(7),
                    Some(9),
                    None,
                ),
                cand(
                    "k",
                    Finding::SoundnessCandidate,
                    Some(ReasonCategory::UninitRead),
                    None,
                    Some(7),
                    None,
                    Some(2),
                ),
            ]
        };
        let mut reversed = mk();
        reversed.reverse();
        assert_eq!(group(mk()), group(mk()));
        assert_eq!(group(mk()), group(reversed));
    }

    /// Groups surface in analysis priority order: model bug > soundness
    /// > precision > rand-verifier gap.
    #[test]
    fn triage_priority_order() {
        let u = ReasonCategory::UninitRead;
        let groups = group(vec![
            cand(
                "p",
                Finding::PrecisionCandidate,
                Some(u),
                Some(ReasonCategory::StackBounds),
                Some(7),
                Some(9),
                None,
            ),
            cand(
                "s",
                Finding::SoundnessCandidate,
                Some(u),
                None,
                Some(7),
                None,
                None,
            ),
            cand(
                "g",
                Finding::RvPrecisionGap,
                Some(u),
                None,
                Some(7),
                None,
                None,
            ),
            cand(
                "b",
                Finding::RvSoundnessBug,
                Some(u),
                None,
                None,
                None,
                Some(2),
            ),
        ]);
        let order: Vec<Finding> = groups.iter().map(|g| g.key.finding).collect();
        assert_eq!(
            order,
            vec![
                Finding::RvSoundnessBug,
                Finding::SoundnessCandidate,
                Finding::PrecisionCandidate,
                Finding::RvPrecisionGap
            ]
        );
        assert_eq!(groups[0].priority, 3);
        assert_eq!(groups[1].priority, 2);
        assert_eq!(groups[2].priority, 1);
        assert_eq!(groups[3].priority, 0);
    }
}
