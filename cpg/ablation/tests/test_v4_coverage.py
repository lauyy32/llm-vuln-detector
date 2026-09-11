# -*- coding: utf-8 -*-
"""coverage gate 测试：直接调用**生产函数** evaluate_coverage_gate（不在测试内重实现逻辑）。"""
import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from cpg.ablation import v4_gate_a as ga  # noqa: E402
from cpg.ablation import v4_selector as sel  # noqa: E402
from cpg.ablation import v4_annotation as va  # noqa: E402

IDS = {"CVE-X"}


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _ident(file="x.py", status="M", os_=10, oc=3, ns=10, nc=3, sha="a" * 64):
    ident = {"sample_id": "CVE-X", "file": file, "file_status": status,
             "old_start": os_, "old_count": oc, "new_start": ns, "new_count": nc,
             "body_lf_sha256": sha}
    from cpg.ablation import v4_selector as _sel
    ident["hunk_id"] = _sel.hunk_id(ident)
    return ident


def _cov(entries):
    """entries = [(ident, coverage)] → 满足新 schema 的 mock coverage。"""
    hunks = [{"sample_id": "CVE-X", "hunk_identity": i, "coverage": c,
              "source_context_coverage": c, "candidate_patch_coverage": c}
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


def _frozen(entries, excluded=(), all_ids=("CVE-X",)):
    import hashlib as _h, json as _j
    ROLE = {"SECURITY_CRITICAL": "DIRECT_SECURITY", "NON_CRITICAL": "NON_CRITICAL"}
    ents = [{"sample_id": "CVE-X", "hunk_identity": i, "criticality": c,
             "role": ROLE.get(c, c)} for i, c in entries]
    role_counts = {}
    for e in ents:
        role_counts[e["role"]] = role_counts.get(e["role"], 0) + 1
    uni = {"all_sample_ids": list(all_ids), "active_sample_ids": ["CVE-X"],
           "excluded_sample_ids": list(excluded), "exclusions": {}}
    return {"status": "FROZEN_LABELED" if not excluded else "FROZEN_WITH_EXCLUSIONS",
            "stale_universe_guard": uni,
            "universe_sha256": _h.sha256(
                _j.dumps(uni, sort_keys=True).encode("utf-8")).hexdigest(),
            "n_entries": len(ents), "n_excluded_samples": len(excluded),
            "role_counts": role_counts,
            "entries": ents}


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
        self.assertTrue(any("覆盖不合格" in e for e in errs))

    def test_critical_partial_blocks(self):
        i = _ident()
        errs = _gate(_cov([(i, "PARTIAL")]), _frozen([(i, "SECURITY_CRITICAL")]))
        self.assertTrue(any("覆盖不合格" in e for e in errs))

    def test_critical_full_passes(self):
        i = _ident()
        self.assertEqual(_gate(_cov([(i, "FULL")]), _frozen([(i, "SECURITY_CRITICAL")])), [])

    def test_noncritical_absent_does_not_block(self):
        i = _ident()
        self.assertEqual(_gate(_cov([(i, "ABSENT")]), _frozen([(i, "NON_CRITICAL")])), [])

    def test_unadjudicated_criticality_blocks(self):
        i = _ident()
        import hashlib as _h, json as _j
        uni = {"all_sample_ids": ["CVE-X"], "active_sample_ids": ["CVE-X"],
               "excluded_sample_ids": [], "exclusions": {}}
        reg = {"status": "FROZEN_LABELED", "stale_universe_guard": uni,
               "universe_sha256": _h.sha256(
                   _j.dumps(uni, sort_keys=True).encode("utf-8")).hexdigest(),
               "n_entries": 1, "n_excluded_samples": 0,
               "role_counts": {"UNCLEAR": 1},
               "entries": [{"sample_id": "CVE-X", "hunk_identity": i,
                            "criticality": "UNCLEAR", "role": "UNCLEAR"}]}
        errs = _gate(_cov([(i, "FULL")]), reg)
        self.assertTrue(any("未裁决" in e for e in errs))

    def test_gate_reads_current_coverage_not_registry_copy(self):
        i = _ident()
        reg = _frozen([(i, "SECURITY_CRITICAL")])
        reg["entries"][0]["mechanical_coverage"] = "FULL"    # 过期副本
        errs = _gate(_cov([(i, "ABSENT")]), reg)             # 当前值才是 ABSENT
        self.assertTrue(any("覆盖不合格" in e for e in errs))

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


class TestProductionAnnotationPackage(unittest.TestCase):
    """P0 端到端：**真正调用生产生成器**产出的空白包，填写合法值后必须通过 validator。

    这是此前 171 测试没覆盖的断点（生产生成器 vs 新 validator）。
    """

    def setUp(self):
        try:
            import tokenizers  # noqa: F401
        except ImportError:
            self.skipTest("tokenizers 未安装（生产生成器需真实 tokenizer）")
        self.out = ga.OUT_DIR
        if not (self.out / "critical_hunks.template.json").exists():
            self.skipTest("template 未生成")

    def test_blank_package_matches_template_ids(self):
        errs = ga.validate_blank_annotation_package(self.out)
        self.assertEqual(errs, [], errs)

    def test_blank_rows_have_hunk_id(self):
        p = self.out / "annotation" / "critical_hunks.reviewer1.jsonl"
        import json as _j
        first = _j.loads(p.read_text(encoding="utf-8").splitlines()[0])
        self.assertIn("hunk_id", first["hunk_identity"])

    def test_filled_package_passes_validator(self):
        """把空白包填成合法值 → validate_submission 必须通过（含依赖精确引用）。"""
        import json as _j, tempfile
        from cpg.ablation import v4_annotation as va
        tpl = self.out / "critical_hunks.template.json"
        blank = self.out / "annotation" / "critical_hunks.reviewer1.jsonl"
        rows = [_j.loads(l) for l in blank.read_text(encoding="utf-8").splitlines() if l.strip()]
        # 取同 CVE 的前两条做依赖（不跨 CVE）
        by_cve = {}
        for r in rows:
            by_cve.setdefault(r["sample_id"], []).append(r)
        cve = next(c for c, rs in by_cve.items() if len(rs) >= 2)
        dep_ids = [r["hunk_identity"]["hunk_id"] for r in by_cve[cve][:2]]
        for r in rows:
            r["criticality"] = "NON_CRITICAL"
            r["reason"] = "test"
            r["evidence"] = "code-reasoning"
            r["counterfactual"] = "否"
            # 依赖指向**同 CVE 的另一条**（不得自引用）
            me = r["hunk_identity"]["hunk_id"]
            others = [d for d in dep_ids if d != me]
            r["dependency_group"] = others[:1] if me in dep_ids else []
        with tempfile.TemporaryDirectory() as td:
            fp = Path(td) / "filled.jsonl"
            fp.write_text("\n".join(_j.dumps(r, ensure_ascii=False) for r in rows), encoding="utf-8")
            v = va.validate_submission(fp, tpl)
            self.assertTrue(v["ok"], v["errors"][:5])


class TestAddedCriticalSemantics(unittest.TestCase):
    """P0-3：新增文件的 critical hunk —— source 侧 N/A 可接受，candidate 必须 FULL。"""

    def test_added_critical_requires_candidate_full(self):
        src = ga._critical_ok
        self.assertTrue(src({"source_context_coverage": "NOT_APPLICABLE_ADDED",
                             "candidate_patch_coverage": "FULL"}))
        self.assertFalse(src({"source_context_coverage": "NOT_APPLICABLE_ADDED",
                              "candidate_patch_coverage": "ABSENT"}))
        self.assertTrue(src({"source_context_coverage": "FULL",
                             "candidate_patch_coverage": "FULL"}))
        self.assertFalse(src({"source_context_coverage": "ABSENT",
                              "candidate_patch_coverage": "FULL"}))


class TestUniverseAnchoring(unittest.TestCase):
    """P0-1：universe 必须外部锚定，不得自声明缩成子集。"""

    def _cov_two(self):
        i1, i2 = _ident(sha="1" * 64), _ident(sha="2" * 64)
        return _cov([(i1, "FULL"), (i2, "FULL")])

    def test_shrunk_universe_blocked(self):
        cov = self._cov_two()
        # 伪造 all=[CVE-X]（缩成一个样本）——cov 里其实有两个 hunk 但同一 CVE
        fz = _frozen([(_ident(sha="1" * 64), "NON_CRITICAL")], all_ids=("CVE-X",))
        errs = _gate(cov, fz)
        # entries 只有 1 条而 active 是 CVE-X → missing identity 应阻断
        self.assertTrue(errs)

    def test_all_must_equal_expected_ids(self):
        cov = self._cov_two()
        fz = _frozen([(_ident(sha="1" * 64), "NON_CRITICAL"),
                      (_ident(sha="2" * 64), "NON_CRITICAL")])
        fz["stale_universe_guard"]["all_sample_ids"] = ["CVE-X", "CVE-Y"]
        import hashlib as _h, json as _j
        fz["universe_sha256"] = _h.sha256(_j.dumps(
            fz["stale_universe_guard"], sort_keys=True).encode("utf-8")).hexdigest()
        errs = _gate(cov, fz)
        self.assertTrue(any("expected_ids" in e or "coverage.samples" in e for e in errs))

    def test_status_set_semantics(self):
        cov = _cov([(_ident(), "FULL")])
        fz = _frozen([(_ident(), "NON_CRITICAL")], excluded=("CVE-X",))
        fz["status"] = "FROZEN_LABELED"     # 有 excluded 却称 LABELED
        errs = _gate(cov, fz)
        self.assertTrue(any("FROZEN_LABELED 不允许有 excluded" in e for e in errs))


class TestArbitraryExclusionGuard(unittest.TestCase):
    """P0-2：不得把**确定一致**的样本塞进 exclusions 删掉。"""

    def test_confirmed_sample_cannot_be_excluded(self):
        from cpg.ablation.tests.test_v4_annotation import _Env
        e = _Env()
        e.all_same(va.ROLE_NONCRIT)          # 两人完全一致、无 UNCERTAIN
        dis = va.disagreement_list(e.sub1, e.sub2, e.tpl, e.d / "dis.json")
        doc = json.loads((e.d / "dis.json").read_text(encoding="utf-8"))
        doc["exclusions"] = {"CVE-A": {"reason": "r", "adjudicator": "a",
                                       "evidence": "insufficient",
                                       "source_item_ids": [e.ids["a1"]["hunk_id"]]}}
        (e.d / "adj.json").write_bytes(
            (json.dumps(doc, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
        with self.assertRaises(ValueError) as cm:
            va.compile_frozen(e.tpl, e.sub1, e.sub2, e.d / "adj.json",
                              e.d / "frozen.json", exclusions=doc["exclusions"])
        self.assertIn("非 UNCERTAIN", str(cm.exception))


class TestRealGeneratorEndToEnd(unittest.TestCase):
    """真正调用 build_annotation_package（临时目录），而非只读既有工件。"""

    def test_generate_then_validate(self):
        try:
            import tokenizers  # noqa: F401
        except ImportError:
            self.skipTest("tokenizers 未安装")
        import json as _j, tempfile, shutil
        src = ga.OUT_DIR
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            # 复制生成所需输入（patches / g0_selection / canonical manifest 引用）
            shutil.copytree(src / "patches", out / "patches")
            shutil.copytree(src / "g0_selection", out / "g0_selection")
            shutil.copy2(src / "v4_hunk_coverage.json", out / "v4_hunk_coverage.json")
            shutil.copy2(src / "critical_hunks.template.json", out / "critical_hunks.template.json")
            pkg = ga.build_annotation_package(out)
            self.assertEqual(ga.validate_blank_annotation_package(out), [])
            self.assertTrue(pkg["blank_package_check"]["ok"])
