"""Unit tests for tools/selftest_corpus.py (#138).

The extraction itself needs a kernel tree and clang, so CI runs it as a
separate job; these tests cover the parsing helpers that decide what a
test case is, which is where silent corpus drift would originate.
"""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "selftest_corpus.py"
spec = importlib.util.spec_from_file_location("selftest_corpus", MODULE_PATH)
corpus = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(corpus)


FRAGMENT = """
{
    "basic",
    .insns = {
        BPF_MOV64_IMM(BPF_REG_0, 0),
        ((struct bpf_insn) {
            .code = BPF_ALU64 | BPF_MOV | BPF_K,
            .dst_reg = BPF_REG_0,
            .imm = 42,
        }),
        BPF_EXIT_INSN(),
    },
    .result = ACCEPT,
    .result_unpriv = REJECT,
    .errstr_unpriv = "not allowed",
},
{
    "brace in string } and nested {",
    .insns = {
        ((struct bpf_insn) { .code = BPF_JMP | BPF_EXIT }),
    },
    .result = REJECT,
    .errstr = "bad { thing",
},
"""


class SplitTests(unittest.TestCase):
    def test_splits_top_level_blocks_only(self) -> None:
        blocks = corpus.split_tests(FRAGMENT)
        self.assertEqual(len(blocks), 2)
        self.assertIn('"basic"', blocks[0])
        self.assertIn("brace in string", blocks[1])

    def test_ignores_braces_in_strings(self) -> None:
        blocks = corpus.split_tests(FRAGMENT)
        self.assertTrue(blocks[0].startswith("{") and blocks[0].endswith("}"))


class InsnSectionTests(unittest.TestCase):
    def test_takes_balanced_insns_block(self) -> None:
        section = corpus.insn_section(corpus.split_tests(FRAGMENT)[0])
        self.assertTrue(section.startswith("{"))
        self.assertTrue(section.endswith("}"))
        self.assertIn("BPF_EXIT_INSN()", section)

    def test_missing_insns_is_empty(self) -> None:
        self.assertEqual(corpus.insn_section('{ "x", .result = ACCEPT }'), "")


class FieldExprTests(unittest.TestCase):
    def test_unwraps_struct_bpf_insn_fields(self) -> None:
        section = corpus.insn_section(corpus.split_tests(FRAGMENT)[0])
        fields = corpus.field_exprs(section)
        self.assertEqual(len(fields), 1)
        self.assertEqual(fields[0]["code"], "BPF_ALU64 | BPF_MOV | BPF_K")
        self.assertEqual(fields[0]["dst_reg"], "BPF_REG_0")
        self.assertEqual(fields[0]["imm"], "42")
        # the BPF_MOV64_IMM(...) macro form is not a struct literal
        self.assertEqual(len(fields[0]), 3)


class EncodeTests(unittest.TestCase):
    def test_kernel_bpf_insn_layout(self) -> None:
        raw = corpus.encode(0x07, 1, 2, -2, 0x11223344)
        self.assertEqual(raw[0], 0x07)
        self.assertEqual(raw[1], 0x21)  # src << 4 | dst
        self.assertEqual(raw[2:4], (-2).to_bytes(2, "little", signed=True))
        self.assertEqual(raw[4:8], (0x11223344).to_bytes(4, "little"))

    def test_negative_imm_is_masked(self) -> None:
        raw = corpus.encode(0xB7, 0, 0, 0, -1)
        self.assertEqual(raw[4:8], b"\xff\xff\xff\xff")


class FieldParsingTests(unittest.TestCase):
    def test_scalar_and_string_fields(self) -> None:
        block = corpus.split_tests(FRAGMENT)[0]
        self.assertEqual(corpus.scalar_field(block, "result"), "ACCEPT")
        self.assertEqual(corpus.scalar_field(block, "result_unpriv"), "REJECT")
        self.assertEqual(corpus.string_field(block, "errstr_unpriv"), "not allowed")
        self.assertIsNone(corpus.string_field(block, "missing"))

    def test_strip_comments(self) -> None:
        self.assertEqual(corpus.strip_comments("a /* { */ b"), "a   b")


class LockTests(unittest.TestCase):
    def test_check_lock_reports_every_drift(self) -> None:
        facts = {
            "fragments": 3,
            "programs": 10,
            "skipped": 1,
            "catalog_sha256": "abc",
        }
        with tempfile.TemporaryDirectory() as tmp:
            lock = Path(tmp) / "lock.json"
            lock.write_text(
                json.dumps(
                    {
                        "kernel_commit": "deadbeef",
                        "fragments": 3,
                        "programs": 9,
                        "skipped": 1,
                        "catalog_sha256": "abc",
                    }
                )
            )
            problems = corpus.check_lock(lock, facts)
            self.assertEqual(len(problems), 1)
            self.assertIn("programs", problems[0])

    def test_check_lock_clean(self) -> None:
        facts = {
            "fragments": 3,
            "programs": 10,
            "skipped": 1,
            "catalog_sha256": "abc",
        }
        with tempfile.TemporaryDirectory() as tmp:
            lock = Path(tmp) / "lock.json"
            lock.write_text(json.dumps({"kernel_commit": "x", **facts}))
            self.assertEqual(corpus.check_lock(lock, facts), [])


if __name__ == "__main__":
    unittest.main()
