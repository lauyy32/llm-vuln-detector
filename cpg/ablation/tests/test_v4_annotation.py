# -*- coding: utf-8 -*-
"""标注流水线测试：hunk_id 精确引用 / 科学字段分歧 / 仲裁 provenance / sample 级排除 /
端到端状态机（含 Gate 通过路径）。"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from cpg.ablation import v4_annotation as va  # noqa: E402
from cpg.ablation import v4_selector as sel  # noqa: E402


def _ident(cve="CVE-X", file="x.py", os_=1, oc=1, sha="a" * 64):
    ident = {"sample_id": cve, "file": file, "file_status": "M", "old_start": os_,
             "old_count": oc, "new_start": os_, "new_count": oc, "body_lf_sha256": sha}
    ident["hunk_id"] = sel.hunk_id(ident)
    return ident


def _row(ident, role=va.ROLE_DIRECT, who="reviewer1", deps=None, cf="否",
         ev="code-reasoning", reason="r"):
    return {"sample_id": ident["sample_id"], "hunk_identity": ident, "question": "q",
            "criticality": role, "dependency_group": deps or [], "counterfactual": cf,
            "evidence": ev, "reason": reason, "reviewer": who}


class _Env:
    """构造一个双 CVE、多 hunk 的最小环境。"""

    def __init__(self, n_a=2):
        self.td = tempfile.TemporaryDirectory()
        d = Path(self.td.name)
        self.d = d
        self.ids = {"a1": _ident("CVE-A", "a.py", 1, 1, "a" * 64),
                    "a2": _ident("CVE-A", "b.py", 5, 2, "b" * 64),
                    "x1": _ident("CVE-X", "x.py", 1, 1, "c" * 64)}
        self.tpl = d / "tpl.json"
        self.tpl.write_text(json.dumps({"entries": [
            {"sample_id": v["sample_id"], "hunk_identity": v} for v in self.ids.values()]}),
            encoding="utf-8")

    def subs(self, r1_roles, r2_roles, r1_deps=None, r2_deps=None,
             r1_cf=None, r2_cf=None):
        r1_deps = r1_deps or {}
        r2_deps = r2_deps or {}
        r1_cf = r1_cf or {}
        r2_cf = r2_cf or {}
        s1, s2 = [], []
        for k, ident in self.ids.items():
            e1 = "insufficient" if r1_roles[k] == va.ROLE_UNCERTAIN else "code-reasoning"
            e2 = "insufficient" if r2_roles[k] == va.ROLE_UNCERTAIN else "code-reasoning"
            s1.append(_row(ident, r1_roles[k], "reviewer1", r1_deps.get(k), r1_cf.get(k, "否"), e1))
            s2.append(_row(ident, r2_roles[k], "reviewer2", r2_deps.get(k), r2_cf.get(k, "否"), e2))
        self.sub1 = self.d / "r1.jsonl"
        self.sub2 = self.d / "r2.jsonl"
        self.sub1.write_text("\n".join(json.dumps(x) for x in s1), encoding="utf-8")
        self.sub2.write_text("\n".join(json.dumps(x) for x in s2), encoding="utf-8")

    def all_same(self, role=va.ROLE_NONCRIT):
        same = {k: role for k in self.ids}
        self.subs(same, same)

    def freeze(self, exclusions=None):
        dis = va.disagreement_list(self.sub1, self.sub2, self.tpl, self.d / "dis.json")
        doc = json.loads((self.d / "dis.json").read_text(encoding="utf-8"))
        (self.d / "adj.json").write_bytes(
            (json.dumps(doc, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
        return va.compile_frozen(self.tpl, self.sub1, self.sub2, self.d / "adj.json",
                                 self.d / "frozen.json", exclusions=exclusions)


class TestHunkIdPrecision(unittest.TestCase):
    """P0-4：依赖只接受完整 hunk_id，禁前缀。"""

    def test_prefix_dependency_rejected(self):
        e = _Env()
        e.subs({k: va.ROLE_NONCRIT for k in e.ids}, {k: va.ROLE_NONCRIT for k in e.ids},
               r1_deps={"a1": ["a2"[:8]]})   # 前缀
        v = va.validate_submission(e.sub1, e.tpl)
        self.assertFalse(v["ok"])
        self.assertTrue(any("禁前缀" in x for x in v["errors"]))

    def test_full_id_dependency_accepted(self):
        e = _Env()
        e.subs({k: va.ROLE_NONCRIT for k in e.ids}, {k: va.ROLE_NONCRIT for k in e.ids},
               r1_deps={"a1": [e.ids["a2"]["hunk_id"]]})
        v = va.validate_submission(e.sub1, e.tpl)
        self.assertTrue(v["ok"], v["errors"])

    def test_self_and_cross_cve_rejected(self):
        e = _Env()
        e.subs({k: va.ROLE_NONCRIT for k in e.ids}, {k: va.ROLE_NONCRIT for k in e.ids},
               r1_deps={"a1": [e.ids["a1"]["hunk_id"], e.ids["x1"]["hunk_id"]]})
        errs = va.validate_submission(e.sub1, e.tpl)["errors"]
        self.assertTrue(any("自引用" in x for x in errs))
        self.assertTrue(any("跨 CVE" in x for x in errs))


class TestScienceFieldDisagreement(unittest.TestCase):
    """P0-3：role 一致但科学字段不同，必须进入仲裁。"""

    def test_dependency_disagreement_enters_arbitration(self):
        e = _Env()
        same = {k: va.ROLE_NONCRIT for k in e.ids}
        e.subs(same, same, r1_deps={"a1": []}, r2_deps={"a1": [e.ids["a2"]["hunk_id"]]})
        dis = va.disagreement_list(e.sub1, e.sub2, e.tpl, e.d / "dis.json")
        self.assertEqual(dis["n_items"], 1)
        self.assertTrue(dis["items"][0]["fields_in_dispute"]["dependency"])
        self.assertFalse(dis["items"][0]["fields_in_dispute"]["role"])

    def test_counterfactual_disagreement_enters_arbitration(self):
        e = _Env()
        same = {k: va.ROLE_NONCRIT for k in e.ids}
        e.subs(same, same, r1_cf={"x1": "是"}, r2_cf={"x1": "否"})
        dis = va.disagreement_list(e.sub1, e.sub2, e.tpl, e.d / "dis.json")
        self.assertTrue(dis["items"][0]["fields_in_dispute"]["counterfactual"])

    def test_agreement_report_reports_each_field(self):
        e = _Env()
        same = {k: va.ROLE_NONCRIT for k in e.ids}
        e.subs(same, same, r1_cf={"x1": "是"}, r2_cf={"x1": "否"})
        rep = va.agreement_report(e.sub1, e.sub2, e.tpl)
        self.assertEqual(rep["raw_agreement_role"], 1.0)
        self.assertLess(rep["raw_agreement_counterfactual"], 1.0)


class TestAdjudicationProvenance(unittest.TestCase):
    """P0-2：仲裁件必须绑定两份 submission SHA。"""

    def test_stale_adjudication_with_replaced_submission_fails(self):
        e = _Env()
        e.all_same(va.ROLE_NONCRIT)
        e.freeze()
        # 替换提交内容（SHA 变）
        e.subs({k: va.ROLE_DIRECT for k in e.ids}, {k: va.ROLE_NONCRIT for k in e.ids})
        with self.assertRaises(ValueError) as cm:
            va.compile_frozen(e.tpl, e.sub1, e.sub2, e.d / "adj.json", e.d / "frozen2.json")
        self.assertIn("submission SHA", str(cm.exception))

    def test_tampered_item_set_fails(self):
        e = _Env()
        e.all_same(va.ROLE_NONCRIT)
        e.freeze()
        doc = json.loads((e.d / "adj.json").read_text(encoding="utf-8"))
        doc["items"].append({"kind": "DISAGREEMENT", "hunk_id": "f" * 64,
                             "hunk_identity": _ident("CVE-Z"), "sample_id": "CVE-Z"})
        (e.d / "adj2.json").write_bytes((json.dumps(doc) + "\n").encode("utf-8"))
        with self.assertRaises(ValueError):
            va.adjudicate(e.d / "adj2.json", e.d / "out.json", e.tpl, e.sub1, e.sub2)


class TestSampleLevelExclusion(unittest.TestCase):
    """P0-1：排除必须是整例（CVE），不得部分排除。"""

    def test_uncertain_excludes_whole_cve(self):
        e = _Env()
        e.subs({"a1": va.ROLE_UNCERTAIN, "a2": va.ROLE_UNCERTAIN, "x1": va.ROLE_NONCRIT},
               {"a1": va.ROLE_UNCERTAIN, "a2": va.ROLE_UNCERTAIN, "x1": va.ROLE_NONCRIT})
        unc = [e.ids[k]["hunk_id"] for k in ("a1", "a2")]
        froz = e.freeze(exclusions={"CVE-A": {"reason": "两标注者均证据不足", "adjudicator": "adjudicator1", "evidence": "insufficient", "source_item_ids": unc}})
        self.assertEqual(froz["status"], "FROZEN_WITH_EXCLUSIONS")
        # 不得残留任何 CVE-A entry
        self.assertFalse(any(x["sample_id"] == "CVE-A" for x in froz["entries"]))
        self.assertEqual(froz["stale_universe_guard"]["active_sample_ids"], ["CVE-X"])
        self.assertEqual(froz["stale_universe_guard"]["excluded_sample_ids"], ["CVE-A"])

    def test_partial_cve_not_allowed(self):
        """一个 hunk 未处置 → 整例须排除；只排除一个 hunk 无效（仍抛异常）。"""
        e = _Env()
        e.subs({"a1": va.ROLE_UNCERTAIN, "a2": va.ROLE_NONCRIT, "x1": va.ROLE_NONCRIT},
               {"a1": va.ROLE_UNCERTAIN, "a2": va.ROLE_NONCRIT, "x1": va.ROLE_NONCRIT})
        # 未给 exclusions → 抛
        with self.assertRaises(ValueError):
            e.freeze(exclusions=None)


class TestEndToEndGate(unittest.TestCase):
    """端到端：frozen × coverage → Gate。"""

    def _cov_for(self, ids, status="FULL"):
        samples = {}
        for ident in ids:
            samples.setdefault(ident["sample_id"], {"n_hunks": 0, "hunks": []})
            samples[ident["sample_id"]]["hunks"].append(
                {"sample_id": ident["sample_id"], "hunk_identity": ident, "coverage": status,
                 "source_context_coverage": status, "candidate_patch_coverage": status})
            samples[ident["sample_id"]]["n_hunks"] += 1
        for s in samples.values():
            s["selection_bound"] = True
        seen = {}
        for s in samples.values():
            for h in s["hunks"]:
                seen[h["coverage"]] = seen.get(h["coverage"], 0) + 1
        return {"kind": "MECHANICAL_COVERAGE_AUDIT", "samples": samples,
                "missing_selection": [], "selection_errors": {},
                "totals": {k: seen.get(k, 0) for k in
                           ("FULL", "PARTIAL", "ABSENT", "NOT_APPLICABLE_ADDED")}}

    def _gate(self, cov, froz):
        from cpg.ablation import v4_gate_a as ga
        return ga.evaluate_coverage_gate(cov, froz,
                                         expected_ids={s["sample_id"] for s in cov["samples"].values()} or None)

    def test_all_agree_frozen_passes(self):
        from cpg.ablation import v4_gate_a as ga
        e = _Env()
        e.all_same(va.ROLE_NONCRIT)
        froz = e.freeze()
        cov = self._cov_for(list(e.ids.values()))
        errs = ga.evaluate_coverage_gate(cov, froz,
                                         expected_ids=set(cov["samples"]))
        self.assertEqual(errs, [])

    def test_exclusion_shrinks_universe_and_passes(self):
        """整例排除后，在缩减 active universe 上 Gate 应 PASS。"""
        from cpg.ablation import v4_gate_a as ga
        e = _Env()
        e.subs({"a1": va.ROLE_UNCERTAIN, "a2": va.ROLE_UNCERTAIN, "x1": va.ROLE_NONCRIT},
               {"a1": va.ROLE_UNCERTAIN, "a2": va.ROLE_UNCERTAIN, "x1": va.ROLE_NONCRIT})
        unc = [e.ids[k]["hunk_id"] for k in ("a1", "a2")]
        froz = e.freeze(exclusions={"CVE-A": {"reason": "两标注者均证据不足", "adjudicator": "adjudicator1", "evidence": "insufficient", "source_item_ids": unc}})
        cov = self._cov_for(list(e.ids.values()))     # coverage 仍含 CVE-A
        errs = ga.evaluate_coverage_gate(cov, froz, expected_ids={"CVE-A", "CVE-X"})
        self.assertEqual(errs, [], errs)

    def test_critical_not_full_blocks(self):
        from cpg.ablation import v4_gate_a as ga
        e = _Env()
        e.all_same(va.ROLE_DIRECT)
        froz = e.freeze()
        cov = self._cov_for(list(e.ids.values()), status="ABSENT")
        errs = ga.evaluate_coverage_gate(cov, froz, expected_ids=set(cov["samples"]))
        self.assertTrue(any("覆盖不合格" in x for x in errs))

    def test_unfrozen_blocks(self):
        from cpg.ablation import v4_gate_a as ga
        e = _Env()
        e.all_same(va.ROLE_NONCRIT)
        cov = self._cov_for(list(e.ids.values()))
        errs = ga.evaluate_coverage_gate(cov, {"status": "DRAFT"}, expected_ids=set(cov["samples"]))
        self.assertTrue(errs)


if __name__ == "__main__":
    unittest.main()
