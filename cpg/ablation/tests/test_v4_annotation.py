# -*- coding: utf-8 -*-
"""标注基础设施测试：格式统一 / 强制校验 / 依赖校验 / UNCERTAIN 状态机。"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from cpg.ablation import v4_annotation as va  # noqa: E402


def _ident(sha="a" * 64, cve="CVE-X", file="x.py"):
    return {"sample_id": cve, "file": file, "file_status": "M", "old_start": 1,
            "old_count": 1, "new_start": 1, "new_count": 1, "body_lf_sha256": sha}


def _row(sha="a" * 64, cve="CVE-X", role=va.ROLE_DIRECT, who="reviewer1", deps=None,
         ev="code-reasoning", cf="否"):
    return {"sample_id": cve, "hunk_identity": _ident(sha, cve),
            "question": "q", "criticality": role, "dependency_group": deps or [],
            "counterfactual": cf, "evidence": ev, "reason": "r", "reviewer": who}


class TestRoundTrip(unittest.TestCase):
    """P0-1：disagreement → adjudicate → compile_frozen 必须同格式、可串起来。"""

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        d = Path(self.td.name)
        self.tpl = d / "tpl.json"
        self.tpl.write_text(json.dumps({"entries": [
            {"sample_id": "CVE-X", "hunk_identity": _ident("a" * 64)},
            {"sample_id": "CVE-X", "hunk_identity": _ident("b" * 64)}]}), encoding="utf-8")
        self.s1 = d / "r1.jsonl"
        self.s2 = d / "r2.jsonl"
        self.s1.write_text("\n".join([
            json.dumps(_row("a" * 64, role=va.ROLE_DIRECT, who="reviewer1")),
            json.dumps(_row("b" * 64, role=va.ROLE_NONCRIT, who="reviewer1")),
        ]), encoding="utf-8")
        self.s2.write_text("\n".join([
            json.dumps(_row("a" * 64, role=va.ROLE_SUPPORTING, who="reviewer2")),
            json.dumps(_row("b" * 64, role=va.ROLE_NONCRIT, who="reviewer2")),
        ]), encoding="utf-8")
        self.d = d

    def test_full_roundtrip(self):
        dis = va.disagreement_list(self.s1, self.s2, self.tpl, self.d / "dis.json")
        self.assertEqual(dis["n_items"], 1)          # 仅 a 有分歧
        self.assertEqual(dis["items"][0]["kind"], "DISAGREEMENT")
        # 同格式仲裁
        doc = json.loads((self.d / "dis.json").read_text(encoding="utf-8"))
        doc["items"][0].update({"final": va.ROLE_DIRECT, "adjudicator": "adjudicator1"})
        (self.d / "adj.json").write_bytes(
            (json.dumps(doc, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
        va.adjudicate(self.d / "dis.json", self.d / "adj2.json", self.tpl, self.s1, self.s2)
        froz = va.compile_frozen(self.tpl, self.s1, self.s2, self.d / "adj.json",
                                 self.d / "frozen.json")
        self.assertEqual(froz["status"], "FROZEN_LABELED")
        self.assertEqual(froz["n_entries"], 2)
        self.assertEqual(froz["role_counts"][va.ROLE_DIRECT], 1)
        self.assertEqual(froz["role_counts"][va.ROLE_NONCRIT], 1)

    def test_disagreement_is_json_object(self):
        """P0-1：分歧件必须是 JSON 对象（可被 compiler 消费），不是裸 JSONL。"""
        va.disagreement_list(self.s1, self.s2, self.tpl, self.d / "dis.json")
        doc = json.loads((self.d / "dis.json").read_text(encoding="utf-8"))
        self.assertIn("items", doc)
        self.assertEqual(doc["schema"], "v4-adjudication/1")


class TestForcedValidation(unittest.TestCase):
    """P1-1：所有入口必须强制校验（重复 identity 不得被静默覆盖）。"""

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        d = Path(self.td.name)
        self.tpl = d / "tpl.json"
        self.tpl.write_text(json.dumps({"entries": [
            {"sample_id": "CVE-X", "hunk_identity": _ident("a" * 64)}]}), encoding="utf-8")
        self.s1 = d / "r1.jsonl"
        self.s2 = d / "r2.jsonl"
        dup = json.dumps(_row("a" * 64, who="reviewer1"))
        self.s1.write_text(dup + "\n" + dup + "\n", encoding="utf-8")   # 重复
        self.s2.write_text(json.dumps(_row("a" * 64, who="reviewer2")) + "\n", encoding="utf-8")
        self.d = d

    def test_duplicate_identity_detected(self):
        v = va.validate_submission(self.s1, self.tpl)
        self.assertFalse(v["ok"])
        self.assertTrue(any("重复" in e for e in v["errors"]))

    def test_agreement_refuses_invalid(self):
        with self.assertRaises(ValueError):
            va.agreement_report(self.s1, self.s2, self.tpl)

    def test_wrong_reviewer_identity_rejected(self):
        self.s1.write_text(json.dumps(_row("a" * 64, who="reviewer2")) + "\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            va.agreement_report(self.s1, self.s2, self.tpl)


class TestDependencyValidation(unittest.TestCase):
    """P0-2：依赖必须存在、同 CVE、不得自引用。"""

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        d = Path(self.td.name)
        self.tpl = d / "tpl.json"
        self.tpl.write_text(json.dumps({"entries": [
            {"sample_id": "CVE-X", "hunk_identity": _ident("a" * 64)},
            {"sample_id": "CVE-X", "hunk_identity": _ident("b" * 64)},
            {"sample_id": "CVE-Y", "hunk_identity": _ident("c" * 64, cve="CVE-Y")}]}),
            encoding="utf-8")
        self.sub = d / "r1.jsonl"
        self.d = d

    def _write(self, rows):
        self.sub.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
        return va.validate_submission(self.sub, self.tpl)

    def test_valid_dependency(self):
        v = self._write([_row("a" * 64, deps=["b" * 64]), _row("b" * 64),
                         _row("c" * 64, cve="CVE-Y")])
        self.assertTrue(v["ok"], v["errors"])

    def test_nonexistent_dependency(self):
        v = self._write([_row("a" * 64, deps=["f" * 64]), _row("b" * 64),
                         _row("c" * 64, cve="CVE-Y")])
        self.assertTrue(any("依赖不存在" in e for e in v["errors"]))

    def test_self_dependency(self):
        v = self._write([_row("a" * 64, deps=["a" * 64]), _row("b" * 64),
                         _row("c" * 64, cve="CVE-Y")])
        self.assertTrue(any("自引用" in e for e in v["errors"]))

    def test_cross_cve_dependency(self):
        v = self._write([_row("a" * 64, deps=["c" * 64]), _row("b" * 64),
                         _row("c" * 64, cve="CVE-Y")])
        self.assertTrue(any("跨 CVE" in e for e in v["errors"]))


class TestUncertainLifecycle(unittest.TestCase):
    """P0-3：UNCERTAIN 必须有明确处置，不得名义冻结却永远过不了 Gate。"""

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        d = Path(self.td.name)
        self.tpl = d / "tpl.json"
        self.tpl.write_text(json.dumps({"entries": [
            {"sample_id": "CVE-X", "hunk_identity": _ident("a" * 64)}]}), encoding="utf-8")
        self.s1 = d / "r1.jsonl"
        self.s2 = d / "r2.jsonl"
        self.d = d

    def _subs(self, r1role, r2role):
        self.s1.write_text(json.dumps(_row("a" * 64, role=r1role, who="reviewer1",
                                          ev="insufficient" if r1role == va.ROLE_UNCERTAIN else "code-reasoning")), encoding="utf-8")
        self.s2.write_text(json.dumps(_row("a" * 64, role=r2role, who="reviewer2",
                                          ev="insufficient" if r2role == va.ROLE_UNCERTAIN else "code-reasoning")), encoding="utf-8")

    def test_unanimous_uncertain_enters_review_list(self):
        self._subs(va.ROLE_UNCERTAIN, va.ROLE_UNCERTAIN)
        dis = va.disagreement_list(self.s1, self.s2, self.tpl, self.d / "dis.json")
        self.assertEqual(dis["items"][0]["kind"], "UNANIMOUS_UNCERTAIN")

    def test_unhandled_uncertain_blocks_freeze(self):
        self._subs(va.ROLE_UNCERTAIN, va.ROLE_UNCERTAIN)
        va.disagreement_list(self.s1, self.s2, self.tpl, self.d / "dis.json")
        doc = json.loads((self.d / "dis.json").read_text(encoding="utf-8"))
        (self.d / "adj.json").write_bytes(
            (json.dumps(doc, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
        with self.assertRaises(ValueError) as cm:
            va.compile_frozen(self.tpl, self.s1, self.s2, self.d / "adj.json",
                              self.d / "frozen.json")
        self.assertIn("UNCERTAIN", str(cm.exception))

    def test_uncertain_via_exclusion_allows_freeze_with_exclusions(self):
        self._subs(va.ROLE_UNCERTAIN, va.ROLE_UNCERTAIN)
        va.disagreement_list(self.s1, self.s2, self.tpl, self.d / "dis.json")
        doc = json.loads((self.d / "dis.json").read_text(encoding="utf-8"))
        doc["exclusions"] = {"CVE-X": "两标注者均证据不足（无 PoC/无回归测试）"}
        (self.d / "adj.json").write_bytes(
            (json.dumps(doc, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
        froz = va.compile_frozen(self.tpl, self.s1, self.s2, self.d / "adj.json",
                                 self.d / "frozen.json")
        self.assertEqual(froz["status"], "FROZEN_WITH_EXCLUSIONS")
        self.assertEqual(froz["n_excluded"], 1)
        self.assertEqual(froz["n_entries"], 0)

    def test_uncertain_resolved_by_adjudicator(self):
        self._subs(va.ROLE_UNCERTAIN, va.ROLE_NONCRIT)
        va.disagreement_list(self.s1, self.s2, self.tpl, self.d / "dis.json")
        doc = json.loads((self.d / "dis.json").read_text(encoding="utf-8"))
        doc["items"][0].update({"final": va.ROLE_NONCRIT, "adjudicator": "adjudicator1"})
        (self.d / "adj.json").write_bytes(
            (json.dumps(doc, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
        froz = va.compile_frozen(self.tpl, self.s1, self.s2, self.d / "adj.json",
                                 self.d / "frozen.json")
        self.assertEqual(froz["entries"][0]["criticality"], "NON_CRITICAL")
        self.assertEqual(froz["entries"][0]["source"], "adjudicated_uncertain")


class TestFrozenPreservesScience(unittest.TestCase):
    """P0-2：frozen 必须保留 dependency/counterfactual/evidence/角色原值。"""

    def test_fields_preserved(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            tpl = d / "tpl.json"
            tpl.write_text(json.dumps({"entries": [
                {"sample_id": "CVE-X", "hunk_identity": _ident("a" * 64)},
                {"sample_id": "CVE-X", "hunk_identity": _ident("b" * 64)}]}), encoding="utf-8")
            s1 = d / "r1.jsonl"
            s2 = d / "r2.jsonl"
            s1.write_text("\n".join([
                json.dumps(_row("a" * 64, role=va.ROLE_SUPPORTING, who="reviewer1",
                                deps=["b" * 64], cf="是")),
                json.dumps(_row("b" * 64, role=va.ROLE_DIRECT, who="reviewer1"))]),
                encoding="utf-8")
            s2.write_text(s1.read_text(encoding="utf-8").replace("reviewer1", "reviewer2"),
                          encoding="utf-8")
            va.disagreement_list(s1, s2, tpl, d / "dis.json")
            doc = json.loads((d / "dis.json").read_text(encoding="utf-8"))
            (d / "adj.json").write_bytes(
                (json.dumps(doc, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
            froz = va.compile_frozen(tpl, s1, s2, d / "adj.json", d / "frozen.json")
            a = [e for e in froz["entries"] if e["hunk_identity"]["body_lf_sha256"] == "a" * 64][0]
            self.assertEqual(a["role"], va.ROLE_SUPPORTING)            # 角色原值
            self.assertEqual(a["criticality"], "SECURITY_CRITICAL")   # 映射
            self.assertEqual(a["dependency_group"], ["b" * 64])
            self.assertEqual(a["counterfactual"], "是")
            self.assertIsNotNone(a["evidence"])


class TestKappa(unittest.TestCase):
    def test_perfect(self):
        self.assertEqual(va._cohen_kappa(["A", "B"], ["A", "B"], ["A", "B"]), 1.0)

    def test_chance(self):
        self.assertAlmostEqual(
            va._cohen_kappa(["A", "A", "B", "B"], ["A", "B", "A", "B"], ["A", "B"]),
            0.0, places=6)


if __name__ == "__main__":
    unittest.main()
