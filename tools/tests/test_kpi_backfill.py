"""Unit tests for tools/kpi-backfill.py (#141)."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "kpi-backfill.py"
spec = importlib.util.spec_from_file_location("kpi_backfill", MODULE_PATH)
kpi = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(kpi)


class NormalizeTests(unittest.TestCase):
    def test_hex_and_decimals_become_placeholder(self) -> None:
        self.assertEqual(
            kpi.normalize_message("invalid stack off=-8 size=8"),
            "invalid stack off=# size=#",
        )
        self.assertEqual(
            kpi.normalize_message("R6 invalid mem access 'scalar' 0xffff"),
            "R6 invalid mem access 'scalar' #",
        )

    def test_truncates(self) -> None:
        self.assertLessEqual(len(kpi.normalize_message("x " * 200)), 120)


class ClusterTests(unittest.TestCase):
    def _f(self, mini_reason: str, program: bytes, finding: str = "precision-candidate"):
        return {
            "meta": {"finding": finding},
            "mini_reason": mini_reason,
            "program": program,
        }

    def test_same_rule_different_program_hashes_differ(self) -> None:
        # the runtime key includes the structural hash, so two programs
        # with the same message stay separate clusters
        a = kpi.cluster_key({"finding": "precision-candidate"}, "x off=-8", b"a")
        b = kpi.cluster_key({"finding": "precision-candidate"}, "x off=-8", b"b")
        self.assertNotEqual(a, b)

    def test_duplicate_programs_collapse(self) -> None:
        a = kpi.cluster_key({"finding": "precision-candidate"}, "x off=-8", b"a")
        b = kpi.cluster_key({"finding": "precision-candidate"}, "x off=-16", b"a")
        self.assertEqual(a, b)

    def test_compute_kpi_counts_and_ratios(self) -> None:
        findings = [
            self._f("same", b"a"),
            self._f("other", b"b"),
        ]
        out = kpi.compute_kpi(findings, iters=1000, surface_total=50)
        self.assertEqual(out["findings_total"], 2)
        # "same" != "other": two clusters
        self.assertEqual(out["unique_clusters"], 2)
        self.assertEqual(out["duplicate_ratio"], 1.0)
        self.assertEqual(out["unique_clusters_per_10k"], 20.0)
        self.assertEqual(out["surface_gap_rate"], 0.05)
        self.assertIsNone(out["time_to_first_new_cluster_ms"])
        self.assertTrue(out["backfilled"])

    def test_zero_iters_is_safe(self) -> None:
        out = kpi.compute_kpi([], iters=0, surface_total=0)
        self.assertEqual(out["duplicate_ratio"], 0.0)
        self.assertEqual(out["unique_clusters_per_10k"], 0.0)


if __name__ == "__main__":
    unittest.main()
