# -*- coding: utf-8 -*-
"""coverage gate 测试：直接调用**生产函数** evaluate_coverage_gate（不在测试内重实现逻辑）。"""
import hashlib
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from cpg.ablation import v4_gate_a as ga  # noqa: E402
from cpg.ablation import v4_selector as sel  # noqa: E402

IDS = {"CVE-X"}


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _ident(file="x.py", status="M", os_=10, oc=3, ns=10, nc=3, sha="a" * 64):
    return {"sample_id": "CVE-X", "file": file, "file_status": status,
            "old_start": os_, "old_count": oc, "new_start": ns, "new_count": nc,
            "body_lf_sha256": sha}


def _cov(entries):
    """entries = [(ident, coverage)] → 满足新 schema 的 mock coverage。"""
    hunks = [{"sample_id": "CVE-X", "hunk_identity": i, "coverage": c}
             for i, c in entries]
    seen = {}
    for h in hunks:
        seen[h["coverage"]] = seen.get(h["coverage"], 0) + 1
    return {
        "kind": "MECHANICAL_COVERAGE_AUDIT",
        "samples": {"CVE-X": {"n_hunks": len(hunks), "hunks": hunks,
                              "selection_bound": True}},
        "missing_selection": [],
        "selection_errors": {},
        "totals": {k: seen.get(k, 0) for k in
                   ("FULL", "PARTIAL", "ABSENT", "NOT_APPLICABLE_ADDED")},
    }


def _frozen(entries):
    return {"status": "FROZEN_LABELED",
            "entries": [{"sample_id": "CVE-X", "hunk_identity": i, "criticality": c}
                        for i, c in entries]}


def _gate(cov, froz):
    return ga.evaluate_coverage_gate(cov, froz, expected_ids=IDS)


class TestEvaluateCoverageGate(unittest.TestCase):
    def test_registry_missing_blocks(self):
        self.assertTrue(_gate(_cov([(_ident(), "FULL")]), None))

    def test_registry_not_frozen_blocks(self):
        reg = _frozen([(_ident(), "NON_CRITICAL")])
        reg["status"] = "DRAFT_UNLABELED"
        self.assertTrue(_gate(_cov([(_ident(), "FULL")]), reg))

    def test_coverage_missing_blocks(self):
        self.assertTrue(ga.evaluate_coverage_gate(None, _frozen([]), expected_ids=IDS))

    def test_ok_when_equal_and_noncritical(self):
        i = _ident()
        self.assertEqual(_gate(_cov([(i, "FULL")]), _frozen([(i, "NON_CRITICAL")])), [])

    def test_missing_identity_blocks(self):
        i1, i2 = _ident(sha="1" * 64), _ident(sha="2" * 64)
        errs = _gate(_cov([(i1, "FULL"), (i2, "FULL")]), _frozen([(i1, "NON_CRITICAL")]))
        self.assertTrue(any("缺少" in e for e in errs))

    def test_extra_identity_blocks(self):
        i1, i2 = _ident(sha="1" * 64), _ident(sha="2" * 64)
        errs = _gate(_cov([(i1, "FULL")]), _frozen([(i1, "NON_CRITICAL"), (i2, "NON_CRITICAL")]))
        self.assertTrue(any("不存在" in e for e in errs))

    def test_critical_absent_blocks(self):
        i = _ident()
        errs = _gate(_cov([(i, "ABSENT")]), _frozen([(i, "SECURITY_CRITICAL")]))
        self.assertTrue(any("非 FULL" in e for e in errs))

    def test_critical_partial_blocks(self):
        i = _ident()
        errs = _gate(_cov([(i, "PARTIAL")]), _frozen([(i, "SECURITY_CRITICAL")]))
        self.assertTrue(any("非 FULL" in e for e in errs))

    def test_critical_full_passes(self):
        i = _ident()
        self.assertEqual(_gate(_cov([(i, "FULL")]), _frozen([(i, "SECURITY_CRITICAL")])), [])

    def test_noncritical_absent_does_not_block(self):
        i = _ident()
        self.assertEqual(_gate(_cov([(i, "ABSENT")]), _frozen([(i, "NON_CRITICAL")])), [])

    def test_unadjudicated_criticality_blocks(self):
        i = _ident()
        reg = {"status": "FROZEN_LABELED",
               "entries": [{"sample_id": "CVE-X", "hunk_identity": i,
                            "criticality": "UNCLEAR"}]}
        errs = _gate(_cov([(i, "FULL")]), reg)
        self.assertTrue(any("未裁决" in e for e in errs))

    def test_gate_reads_current_coverage_not_registry_copy(self):
        i = _ident()
        reg = _frozen([(i, "SECURITY_CRITICAL")])
        reg["entries"][0]["mechanical_coverage"] = "FULL"    # 过期副本
        errs = _gate(_cov([(i, "ABSENT")]), reg)             # 当前值才是 ABSENT
        self.assertTrue(any("非 FULL" in e for e in errs))

    def test_stale_registry_copy_ignored_when_current_full(self):
        i = _ident()
        reg = _frozen([(i, "NON_CRITICAL")])
        reg["entries"][0]["mechanical_coverage"] = "ABSENT"  # 过期副本，应被忽略
        self.assertEqual(_gate(_cov([(i, "FULL")]), reg), [])

    def test_invalid_coverage_enum_blocks(self):
        i = _ident()
        errs = _gate(_cov([(i, "BOGUS")]), _frozen([(i, "NON_CRITICAL")]))
        self.assertTrue(any("非法 coverage enum" in e for e in errs))

    def test_bad_hex_sha_blocks(self):
        i = _ident(sha="z" * 64)
        errs = _gate(_cov([(i, "FULL")]), _frozen([(i, "NON_CRITICAL")]))
        self.assertTrue(any("hex" in e for e in errs))

    def test_totals_mismatch_blocks(self):
        i = _ident()
        c = _cov([(i, "FULL")])
        c["totals"]["FULL"] = 99
        errs = _gate(c, _frozen([(i, "NON_CRITICAL")]))
        self.assertTrue(any("totals" in e for e in errs))

    def test_missing_selection_blocks(self):
        i = _ident()
        c = _cov([(i, "FULL")])
        c["missing_selection"] = ["CVE-X"]
        errs = _gate(c, _frozen([(i, "NON_CRITICAL")]))
        self.assertTrue(any("g0_selection" in e for e in errs))


class TestSelector(unittest.TestCase):
    def test_body_sha_differs_by_body(self):
        p1 = ("diff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n@@ -10,3 +10,3 @@ h\n ctx\n")
        p2 = ("diff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n@@ -10,3 +10,3 @@ h\n other\n")
        h1 = sel.parse_patch_hunks(p1)["x.py"][0]
        h2 = sel.parse_patch_hunks(p2)["x.py"][0]
        self.assertNotEqual(_sha(h1["_body"]), _sha(h2["_body"]))

    def test_multifile_body_boundary(self):
        """P0-2：前文件末 hunk 不得吞入后文件内容。"""
        p = ("diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1,2 +1,2 @@\n-old_a\n"
             "+new_a\n ctx\n"
             "diff --git a/b.py b/b.py\n--- a/b.py\n+++ b/b.py\n@@ -5,2 +5,2 @@\n-old_b\n+new_b\n")
        body = sel.parse_patch_hunks(p)["a.py"][0]["_body"]
        self.assertNotIn("old_b", body)
        self.assertNotIn("diff --git", body)

    def test_added_by_file_status_not_old_count(self):
        added = ("diff --git a/n.py b/n.py\nnew file mode 100644\n--- /dev/null\n"
                 "+++ b/n.py\n@@ -0,0 +1,2 @@\n+import os\n+x=1\n")
        ins = ("diff --git a/e.py b/e.py\n--- a/e.py\n+++ b/e.py\n"
               "@@ -5,0 +6,2 @@\n+guard()\n+check()\n")
        self.assertEqual(sel.file_status(added)["n.py"], "A")
        self.assertEqual(sel.file_status(ins)["e.py"], "M")   # 纯插入不是 added

    def test_malformed_header_fails_closed(self):
        with self.assertRaises(ValueError):
            sel.parse_patch_hunks("diff --git a/x.py b/x.py\n@@ bad @@\n")


class TestAnnotationInfra(unittest.TestCase):
    def test_kappa_perfect_agreement(self):
        from cpg.ablation import v4_annotation as va
        self.assertEqual(va._cohen_kappa(["A", "B"], ["A", "B"], ["A", "B"]), 1.0)

    def test_kappa_chance_level(self):
        from cpg.ablation import v4_annotation as va
        k = va._cohen_kappa(["A", "A", "B", "B"], ["A", "B", "A", "B"], ["A", "B"])
        self.assertAlmostEqual(k, 0.0, places=6)


if __name__ == "__main__":
    unittest.main()
