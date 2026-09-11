# -*- coding: utf-8 -*-
"""coverage gate 测试：直接调用**生产函数** evaluate_coverage_gate（不在测试内重实现）。"""
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from cpg.ablation import v4_gate_a as ga  # noqa: E402


def _ident(file="x.py", status="M", os_=10, oc=3, ns=10, nc=3, sha="a" * 64):
    return {"file": file, "file_status": status, "old_start": os_, "old_count": oc,
            "new_start": ns, "new_count": nc, "body_lf_sha256": sha}


def _cov(entries):
    """entries = [(ident, coverage)]"""
    return {"kind": "MECHANICAL_COVERAGE_AUDIT",
            "samples": {"CVE-X": {"n_hunks": len(entries), "hunks": [
                {"sample_id": "CVE-X", "hunk_identity": i, "coverage": c}
                for i, c in entries]}}}


def _frozen(entries):
    """entries = [(ident, criticality)]"""
    return {"status": "FROZEN_LABELED",
            "entries": [{"sample_id": "CVE-X", "hunk_identity": i, "criticality": c}
                        for i, c in entries]}


class TestEvaluateCoverageGate(unittest.TestCase):
    def test_registry_missing_blocks(self):
        self.assertTrue(ga.evaluate_coverage_gate(_cov([(_ident(), "FULL")]), None))

    def test_registry_not_frozen_blocks(self):
        reg = _frozen([(_ident(), "NON_CRITICAL")])
        reg["status"] = "DRAFT_UNLABELED"
        self.assertTrue(ga.evaluate_coverage_gate(_cov([(_ident(), "FULL")]), reg))

    def test_coverage_artifact_missing_blocks(self):
        self.assertTrue(ga.evaluate_coverage_gate(None, _frozen([])))

    def test_identity_set_equal_and_ok(self):
        i = _ident()
        errs = ga.evaluate_coverage_gate(_cov([(i, "FULL")]), _frozen([(i, "NON_CRITICAL")]))
        self.assertEqual(errs, [])

    def test_missing_identity_blocks(self):
        i1, i2 = _ident(sha="1" * 64), _ident(sha="2" * 64)
        errs = ga.evaluate_coverage_gate(_cov([(i1, "FULL"), (i2, "FULL")]),
                                         _frozen([(i1, "NON_CRITICAL")]))
        self.assertTrue(any("缺少" in e for e in errs))

    def test_extra_identity_blocks(self):
        i1, i2 = _ident(sha="1" * 64), _ident(sha="2" * 64)
        errs = ga.evaluate_coverage_gate(_cov([(i1, "FULL")]),
                                         _frozen([(i1, "NON_CRITICAL"), (i2, "NON_CRITICAL")]))
        self.assertTrue(any("不存在" in e for e in errs))

    def test_critical_absent_blocks(self):
        i = _ident()
        errs = ga.evaluate_coverage_gate(_cov([(i, "ABSENT")]),
                                         _frozen([(i, "SECURITY_CRITICAL")]))
        self.assertTrue(any("SECURITY_CRITICAL × ABSENT" in e for e in errs))

    def test_noncritical_absent_does_not_block(self):
        i = _ident()
        errs = ga.evaluate_coverage_gate(_cov([(i, "ABSENT")]),
                                         _frozen([(i, "NON_CRITICAL")]))
        self.assertEqual(errs, [])

    def test_unadjudicated_criticality_blocks(self):
        i = _ident()
        reg = {"status": "FROZEN_LABELED",
               "entries": [{"sample_id": "CVE-X", "hunk_identity": i,
                            "criticality": "UNCLEAR"}]}
        errs = ga.evaluate_coverage_gate(_cov([(i, "FULL")]), reg)
        self.assertTrue(any("未裁决" in e for e in errs))

    def test_gate_reads_current_coverage_not_registry_copy(self):
        """P0-1：registry 内即使带旧 coverage，也必须以**当前** coverage 为准。"""
        i = _ident()
        reg = _frozen([(i, "SECURITY_CRITICAL")])
        # 故意在 registry 条目里塞过期的 coverage=FULL
        reg["entries"][0]["mechanical_coverage"] = "FULL"
        # 当前 coverage 是 ABSENT → 必须阻断（证明没有读 registry 里的旧值）
        errs = ga.evaluate_coverage_gate(_cov([(i, "ABSENT")]), reg)
        self.assertTrue(any("ABSENT" in e for e in errs))

    def test_current_coverage_full_with_stale_registry_full_still_ok(self):
        i = _ident()
        reg = _frozen([(i, "NON_CRITICAL")])
        reg["entries"][0]["mechanical_coverage"] = "ABSENT"  # 过期值，应被忽略
        errs = ga.evaluate_coverage_gate(_cov([(i, "FULL")]), reg)
        self.assertEqual(errs, [])


class TestHunkIdentity(unittest.TestCase):
    def test_body_sha_present_and_differs_by_body(self):
        p1 = ("diff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n"
              "@@ -10,3 +10,3 @@ h\n ctx\n")
        p2 = ("diff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n"
              "@@ -10,3 +10,3 @@ h\n other\n")
        h1 = ga._parse_patch_hunks(p1)["x.py"][0]
        h2 = ga._parse_patch_hunks(p2)["x.py"][0]
        self.assertNotEqual(ga._lf_sha(h1["_body"].encode()), ga._lf_sha(h2["_body"].encode()))

    def test_added_detected_by_file_status_not_old_count(self):
        added = ("diff --git a/n.py b/n.py\nnew file mode 100644\n--- /dev/null\n"
                 "+++ b/n.py\n@@ -0,0 +1,2 @@\n+import os\n+x=1\n")
        self.assertEqual(ga._file_status(added)["n.py"], "A")

    def test_pure_insertion_in_existing_file_is_not_added(self):
        """P0-3：已有文件中的纯插入（old_count==0）不得判为 added。"""
        ins = ("diff --git a/e.py b/e.py\n--- a/e.py\n+++ b/e.py\n"
               "@@ -5,0 +6,2 @@\n+guard()\n+check()\n")
        self.assertEqual(ga._file_status(ins)["e.py"], "M")

    def test_malformed_header_fails_closed(self):
        with self.assertRaises(ValueError):
            ga._parse_patch_hunks("diff --git a/x.py b/x.py\n@@ bad @@\n")


class TestIntegration(unittest.TestCase):
    def test_real_gate_report_blocks_on_unfrozen_registry(self):
        """集成：真实 build_gate_a_report 必须因 frozen registry 缺失而 FAIL。

        需要 tokenizers（build_gate_a_report → token gate）；缺失则跳过而非 ERROR。
        """
        try:
            import tokenizers  # noqa: F401
        except ImportError:
            self.skipTest("tokenizers 未安装（集成测试需真实 tokenizer）")
        out = ga.OUT_DIR
        if not (out / "v4_hunk_coverage.json").exists():
            self.skipTest("coverage 工件未生成")
        rep = ga.build_gate_a_report(out)
        self.assertFalse(rep["gate_a_pass"])
        self.assertTrue(any("coverage" in b for b in rep["blockers"]))


if __name__ == "__main__":
    unittest.main()
