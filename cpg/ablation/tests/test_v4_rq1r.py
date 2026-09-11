# -*- coding: utf-8 -*-
"""A-5 验收：数字对账 / 列联表 / CPG 分层 / 匿名化 fail-closed。

全部基于**真实权威数据**（strict_recompute_out.json + claims.json + seeds CSV），
不做合成替身；统计实现另用公开已知值校验。
"""
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from cpg.ablation import v4_rq1r as rq  # noqa: E402


class TestAuthoritativeReconciliation(unittest.TestCase):
    """报告引用的每个数字都必须能对账到 claims.json（fail-closed）。"""

    def test_claims_reconcile(self):
        auth = rq.load_authoritative()
        self.assertEqual(rq.verify_against_claims(auth), [])

    def test_missing_authoritative_fails(self):
        orig = rq.AUTH_OUT
        try:
            rq.AUTH_OUT = Path("no/such/out.json")
            with self.assertRaises(FileNotFoundError):
                rq.load_authoritative()
        finally:
            rq.AUTH_OUT = orig

    def test_tampered_claim_detected(self):
        """把复算值改坏 → 对账必须失败（证明对账不是走过场）。"""
        auth = rq.load_authoritative()
        auth["recompute"]["disc_strict"]["DS r1"]["strict_count"] = 999
        errs = rq.verify_against_claims(auth)
        self.assertTrue(any("frontier_strict_disc_r1" in e for e in errs), errs)


class TestPairingIntegrity(unittest.TestCase):
    def test_reference_seed_pairing_is_strict_clean(self):
        """参考配置（工具族横评）必须配对完整。"""
        rows = rq.load_rows(seeds=[rq.REFERENCE_TOOL_FAMILY_SEED])
        self.assertGreater(len(rows), 0)
        self.assertEqual(
            rq.strict_pairing_errors(rows, [rq.REFERENCE_TOOL_FAMILY_SEED]), [])

    def test_full_scan_reports_non_reference_warnings_only(self):
        """全量扫描：非参考配置的单侧样本只作 warning，不混入参考判定。"""
        all_errs = rq.pairing_integrity(rq.load_rows())
        hard = [e for e in all_errs if not e.startswith("[non-reference]")]
        self.assertEqual(hard, [], "不得有非参考外的硬错误")
        self.assertTrue(any(e.startswith("[non-reference]") for e in all_errs),
                        "真实数据中确有单侧样本配置")

    def test_integrity_detects_missing_fixed(self):
        rows = [{"sample_id": "CVE-X", "version": "vuln", "mode": "code",
                 "scorer": "CPGEvidenceScorer", "predicted": "vulnerable",
                 "truth": "vulnerable", "group": "taint", "_seed": "S"}]
        errs = rq.strict_pairing_errors(rows, ["S"])
        self.assertTrue(any("CVE-X" in e for e in errs))


class TestContingencyAndStratification(unittest.TestCase):
    def setUp(self):
        # 分层分析必须锚定单一配置（跨配置叠加会重复计数，模块会 fail-closed）
        self.rows = rq.load_rows(seeds=[rq.REFERENCE_TOOL_FAMILY_SEED])
        self.seeds = [rq.REFERENCE_TOOL_FAMILY_SEED]

    def test_contingency_shape(self):
        tbl = rq.contingency(self.rows)
        self.assertTrue(tbl)
        for key, bytruth in tbl.items():
            self.assertIn("|", key)
            for truth, preds in bytruth.items():
                self.assertTrue(all(isinstance(v, int) and v > 0 for v in preds.values()))

    def test_tool_family_stratification_labels(self):
        st = rq.strict_discrimination_by_group(self.rows, "scorer", seeds=self.seeds)
        self.assertTrue(st)
        allowed = set(rq.CPG_TOOL_FAMILIES.values())
        self.assertTrue(set(st) <= allowed, set(st) - allowed)
        for v in st.values():
            self.assertLessEqual(v["strict_disc"], v["n"])
            self.assertEqual(len(v["ci95_exact"]), 2)

    def test_vuln_group_stratification(self):
        st = rq.strict_discrimination_by_group(self.rows, "group", seeds=self.seeds)
        self.assertTrue(st)
        for v in st.values():
            self.assertLessEqual(v["strict_disc"], v["n"])

    def test_multi_seed_rows_without_explicit_seeds_fails_closed(self):
        """跨配置未指定 seeds 时必须拒绝（防 41× 重复计数）。"""
        with self.assertRaises(ValueError) as cm:
            rq.strict_discrimination_by_group(rq.load_rows(), "scorer")
        self.assertIn("必须显式指定 seeds", str(cm.exception))

    def test_bad_key_rejected(self):
        with self.assertRaises(ValueError):
            rq.strict_discrimination_by_group(self.rows, "sample_id", seeds=self.seeds)


class TestStatisticsKnownValues(unittest.TestCase):
    def test_cp_table_value(self):
        lo, hi = rq.clopper_pearson(7, 82)
        self.assertAlmostEqual(lo, 0.0351, places=3)
        self.assertAlmostEqual(hi, 0.1679, places=3)

    def test_cp_boundaries(self):
        self.assertEqual(rq.clopper_pearson(0, 74)[0], 0.0)
        self.assertEqual(rq.clopper_pearson(74, 74)[1], 1.0)

    def test_mcnemar_one_sided_matches_claims(self):
        """b=6,c=1 → 单侧精确 p = (C(7,0)+C(7,1))/2^7 = 8/128 = 0.0625。"""
        self.assertAlmostEqual(rq.mcnemar_one_sided(6, 1), 0.0625, places=6)

    def test_mcnemar_zero(self):
        self.assertEqual(rq.mcnemar_one_sided(0, 0), 1.0)


class TestAnonymization(unittest.TestCase):
    def test_replaces_pii_patterns(self):
        doc = {"p": "C:/Users/someone/project", "u": "lauyy32",
               "r": "https://github.com/lauyy32/llm-vuln-detector"}
        out = rq.anonymize(doc)
        s = json.dumps(out, ensure_ascii=False)
        self.assertNotIn("someone", s)
        self.assertNotIn("lauyy32", s.lower())
        self.assertIn("<REPO_URL>", s)          # 整个仓库 URL 被整体替换（含其用户名）
        self.assertEqual(rq.anonymize_check(out), [])

    def test_check_flags_residual_pii(self):
        bad = {"x": "C:/Users/someone/f"}
        self.assertTrue(rq.anonymize_check(bad))
        self.assertEqual(rq.anonymize_check({"x": "<USER_HOME>/f"}), [])

    def test_nested_structures_anonymized(self):
        doc = {"a": [{"b": "lauyy32"}], "c": {"d": "/c/Users/other/x"}}
        s = json.dumps(rq.anonymize(doc), ensure_ascii=False)
        self.assertNotIn("lauyy32", s.lower())
        self.assertNotIn("other", s)


class TestReport(unittest.TestCase):
    def test_report_built_and_reconciled(self):
        doc = rq.build_report(publish=False)
        self.assertTrue(doc["claims_reconciled"])
        self.assertTrue(doc["pairing_integrity_ok"])
        self.assertEqual(len(doc["claims_ledger"]), 7)
        # headline 数字必须与 claims 一致（抽样硬比对）
        c = {x["id"]: x["expect"] for x in doc["claims_ledger"]}
        self.assertEqual(doc["headline"]["frontier_r1_strict"]["strict_count"],
                         c["frontier_strict_disc_r1"])
        self.assertEqual(doc["headline"]["local_7b_strict"]["strict_count"],
                         c["local7b_strict_disc_d1"])
        self.assertEqual(doc["headline"]["abstain_genuine"], c["frontier_abstain_genuine_rate"])

    def test_public_report_is_anonymized(self):
        pub = rq.build_report(publish=True)
        self.assertTrue(pub["anonymized"])
        self.assertEqual(rq.anonymize_check(pub), [])
        s = json.dumps(pub, ensure_ascii=False)
        self.assertNotIn("lauyy32", s.lower())
        self.assertNotIn("C:/Users", s)
        self.assertNotIn("/c/Users", s)

    def test_report_includes_required_sections(self):
        doc = rq.build_report(publish=False)
        for k in ("protocol", "sources", "headline", "exact_ci",
                  "stratified_by_tool_family", "stratified_by_vuln_group",
                  "contingency_by_scorer_mode", "claims_ledger"):
            self.assertIn(k, doc, k)
        self.assertIn("显式 vulnerable", doc["protocol"]["strict_rule"])
        self.assertIn("abstain", doc["protocol"]["lenient_note"])

    def test_write_reports_creates_both(self):
        import tempfile
        orig = rq.OUT
        with tempfile.TemporaryDirectory() as td:
            try:
                rq.OUT = Path(td)
                r = rq.write_reports()
                self.assertTrue((Path(td) / "rq1r_report.json").exists())
                self.assertTrue((Path(td) / "rq1r_report_public.json").exists())
                self.assertTrue(r["public"]["anonymized"])
            finally:
                rq.OUT = orig


if __name__ == "__main__":
    unittest.main()
