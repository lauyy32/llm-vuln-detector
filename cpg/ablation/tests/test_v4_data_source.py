# -*- coding: utf-8 -*-
"""V4 数据入口测试：canonical manifest + corpus-v3；fail-closed 禁旧 corpus_pairs；
行尾中立 apply（防 write_text→CRLF 回归）；legacy 兼容。"""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from cpg.ablation import v4_patch_gen as v4g  # noqa: E402
from cpg.ablation import upstream_manifest as um  # noqa: E402

CVE = "CVE-2026-10692"


class TestV4SampleDir(unittest.TestCase):
    def test_returns_corpus_v3(self):
        d = v4g.sample_dir(CVE)
        self.assertIn("corpus-v3", d.as_posix())
        self.assertNotIn("corpus_pairs", d.as_posix())

    def test_rejects_unknown_cve(self):
        with self.assertRaises(KeyError):
            v4g.sample_dir("CVE-9999-99999")

    def test_rejects_corpus_pairs_source_path(self):
        """canonical manifest 若把 source_path 指向 corpus_pairs，必须 fail-closed。"""
        with mock.patch.object(v4g, "_canonical_by_id",
                               return_value={"CVE-X": {"source_path": "cpg/corpus_pairs/CVE-X"}}):
            with self.assertRaises(AssertionError):
                v4g.sample_dir("CVE-X")

    def test_rejects_missing_source_path(self):
        with mock.patch.object(v4g, "_canonical_by_id",
                               return_value={"CVE-X": {"source_path": None}}):
            with self.assertRaises(ValueError):
                v4g.sample_dir("CVE-X")


class TestV4LineEnding(unittest.TestCase):
    def test_write_patch_is_byte_lf(self):
        """write_patch 必须字节写入（Windows 下 write_text 会把 LF 转 CRLF）。"""
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "x.diff"
            v4g.write_patch(p, "a\nb\n")
            self.assertEqual(p.read_bytes(), b"a\nb\n")

    def test_real_diff_applies_to_lf_corpus(self):
        """real diff 必须 apply-clean 且与 fixed 树逐字节一致（LF 语料回归锚点）。"""
        diff, rep = v4g.gen_complete_real_diff(CVE)
        ok, msg = v4g.apply_and_verify(CVE, diff)
        self.assertTrue(ok, msg)

    def test_placebo_apply_clean(self):
        pd, prep = v4g.gen_placebo_diff(CVE)
        self.assertTrue(prep.get("ast_equivalent"), prep)
        self.assertTrue(prep.get("apply_clean"), prep)


class TestUpstreamV4Entry(unittest.TestCase):
    def test_read_sample_from_canonical(self):
        s = um.read_sample(CVE)
        self.assertEqual(s["sample_id"], CVE)
        self.assertIn("corpus-v3", s["source_path"])
        self.assertIn("parent_commit", s)

    def test_corpus_py_files_v3(self):
        n = len(um.corpus_py_files_v3(CVE))
        self.assertGreater(n, 0)

    def test_read_corpus_v3_file(self):
        b = um.read_corpus_v3_file(CVE, "vuln", "src/code_index_mcp/search/ag.py")
        self.assertIsNotNone(b)
        self.assertEqual(b.count(bytes([13])), 0, "corpus-v3 应为 LF")


class TestLegacyCompat(unittest.TestCase):
    def test_read_meta_legacy_still_works(self):
        """历史脚本（rebuild_pair/rerun_61539/five_state_audit）依赖 read_meta。"""
        m = um.read_meta(CVE)
        self.assertNotIn("_error", m)
        self.assertIn("repo_slug", m)

    def test_corpus_py_files_legacy_still_works(self):
        m = um.read_meta(CVE)
        s = um.corpus_py_files(m)
        self.assertGreater(len(s), 0)


if __name__ == "__main__":
    unittest.main()
