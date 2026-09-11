# -*- coding: utf-8 -*-
"""canonical RQ1-R 报告验收（严格标准）。

核心纪律：
  - 报告数字必须与运行目录的 `summary.json` **对账通过**；
  - 锁链验证必须能**检出篡改**（不是走过场）；
  - CPG 行数分层不可得时必须**显式声明**，不得用其它字段替代推断。
"""
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from cpg.ablation import v4_rq1r_canonical as rc  # noqa: E402

# 只复制锁链所需的浅层工件（运行目录含深层 staging/，全量 copytree 会超长路径失败）
_RUN_FILES = ("protocol.json", "lock_request.json", "review_approval.json",
              "summary.json", "state.json", "run_schedule.json", "results.jsonl",
              "prompt_manifest.jsonl", "cpg_bundle.json")


def _make_run_copy(td: str) -> Path:
    tmp = Path(td) / "run"
    tmp.mkdir(parents=True, exist_ok=True)
    for n in _RUN_FILES:
        shutil.copy2(rc.RUN_DIR / n, tmp / n)
    # lock_request.files 中 base=repo 的项由验证函数从仓库取，无需复制
    return tmp


class TestLockChain(unittest.TestCase):
    def test_real_run_chain_ok(self):
        c = rc.verify_lock_chain()
        self.assertTrue(c["ok"])
        self.assertEqual(c["reviewer"], "Codex-independent-review-2026-09-10")
        self.assertEqual(c["n_results"], 164)
        for f in c["file_checks"]:
            self.assertTrue(f["ok"], f)
            self.assertTrue(f["normalized_lf"])

    def test_detects_tampered_protocol(self):
        """篡改 protocol.json → 文件 SHA 不符 → 必须失败。"""
        with tempfile.TemporaryDirectory() as td:
            tmp = _make_run_copy(td)
            p = tmp / "protocol.json"
            doc = json.loads(p.read_text(encoding="utf-8"))
            doc["model"] = "TAMPERED"
            p.write_bytes((json.dumps(doc, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
            with self.assertRaises(ValueError) as cm:
                rc.verify_lock_chain(tmp)
            self.assertIn("protocol", str(cm.exception))

    def test_detects_tampered_review_decision(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = _make_run_copy(td)
            p = tmp / "review_approval.json"
            doc = json.loads(p.read_text(encoding="utf-8"))
            doc["decision"] = "REJECTED"
            p.write_bytes((json.dumps(doc, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
            with self.assertRaises(ValueError) as cm:
                rc.verify_lock_chain(tmp)
            self.assertIn("APPROVED", str(cm.exception))

    def test_detects_state_not_verified(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = _make_run_copy(td)
            p = tmp / "state.json"
            doc = json.loads(p.read_text(encoding="utf-8"))
            doc["state"] = "PARTIAL"
            p.write_bytes((json.dumps(doc, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
            with self.assertRaises(ValueError) as cm:
                rc.verify_lock_chain(tmp)
            self.assertIn("VERIFIED", str(cm.exception))


class TestMainResult(unittest.TestCase):
    def setUp(self):
        self.results = rc._read_jsonl(rc.RUN_DIR / "results.jsonl")
        self.pairs = rc.build_pairs(self.results)
        self.main = rc.classify_pairs(self.pairs)

    def test_strict_count_matches_summary(self):
        summary = rc._read_json(rc.RUN_DIR / "summary.json")
        self.assertEqual(rc.reconcile_with_summary(self.main, summary), [])
        self.assertEqual(self.main["n_pairs"], 82)
        self.assertEqual(self.main["strict_success"], 1)
        self.assertEqual(self.main["strict_ids"], ["CVE-2026-67435"])

    def test_reconcile_detects_tampered_summary(self):
        errs = rc.reconcile_with_summary(self.main, {"n_pairs": 999, "strict_success": 1,
                                                     "rate": 0.0122})
        self.assertTrue(any("n_pairs" in e for e in errs))

    def test_contingency_totals_match_pairs(self):
        tbl = rc.contingency_3x3(self.pairs)
        total = sum(sum(row.values()) for row in tbl.values())
        self.assertEqual(total, self.main["n_pairs"])
        # 行/列键必须是三个 verdict
        self.assertEqual(set(tbl), set(rc.VERDICT_ORDER))
        for row in tbl.values():
            self.assertEqual(set(row), set(rc.VERDICT_ORDER))

    def test_strict_cell_is_one(self):
        """strict 成功 = vuln=vulnerable 且 fixed=benign 的格子，必须等于 strict_success。"""
        tbl = rc.contingency_3x3(self.pairs)
        self.assertEqual(tbl["vulnerable"]["benign"], self.main["strict_success"])

    def test_abstain_decomposition_frozen_semantics(self):
        """P0-2：必须拆成 any / double / directional 三类，且 any == double + directional。"""
        m = self.main
        self.assertEqual(m["same_verdict"], 76)
        self.assertEqual(m["any_abstain_pairs"], 13)
        self.assertEqual(m["double_abstain_pairs"], 8)
        self.assertEqual(m["directionally_abstain_assisted"], 5)   # 1 + 4
        self.assertEqual(m["abstain_assisted_breakdown"],
                         {"vulnerable_then_abstain": 1, "abstain_then_benign": 4})
        self.assertEqual(m["any_abstain_pairs"],
                         m["double_abstain_pairs"] + m["directionally_abstain_assisted"])
        self.assertNotIn("abstain_assisted", m)   # 旧字段不得再存在
        for k in ("same_verdict_rate",):
            self.assertTrue(0.0 <= m[k] <= 1.0)

    def test_marginals_correct(self):
        """P0-1：边际必须正确（vuln 侧 17 / fixed 侧 15 / 对角线 76）。"""
        doc = rc.build_report(publish=False)
        mg = doc["contingency_marginals"]
        self.assertEqual(mg["vuln_side_vulnerable"], 17)
        self.assertEqual(mg["fixed_side_vulnerable"], 15)
        self.assertEqual(mg["diagonal_pairs"], 76)
        self.assertEqual(mg["n_total"], 82)
        self.assertIn("边际差异小", mg["interpretation"])

    def test_pairs_have_both_sides(self):
        bad = [sid for sid, v in self.pairs.items() if set(v) != {"vuln", "fixed"}]
        self.assertEqual(bad, [], f"存在非配对样本: {bad[:3]}")


class TestScheduleIntegrity(unittest.TestCase):
    def test_schedule_matches_results(self):
        sched = rc._read_json(rc.RUN_DIR / "run_schedule.json")
        results = rc._read_jsonl(rc.RUN_DIR / "results.jsonl")
        self.assertEqual(len(sched), len(results))
        self.assertEqual({(s["sample_id"], s["side"], s["arm"]) for s in sched},
                         {(r["sample_id"], r["side"], r["arm"]) for r in results})


class TestCpgStratification(unittest.TestCase):
    def test_declares_line_count_unavailable(self):
        """CPG 行数在 results 中不可得 → 必须显式声明，不得编造。"""
        results = rc._read_jsonl(rc.RUN_DIR / "results.jsonl")
        st = rc.cpg_stratification(results, rc.build_pairs(results))
        self.assertEqual(st["line_count_stratification"], "NOT_AVAILABLE_IN_RESULTS")
        self.assertIn("不得", st["note"])
        for dim in ("canonical_cpg_rows_sha256", "cpg_eval_sha256", "cpg_cache_key"):
            self.assertIn(dim, st["available_dimensions"])


class TestCanonicalReport(unittest.TestCase):
    def test_report_structure_and_reconciliation(self):
        doc = rc.build_report(publish=False)
        self.assertEqual(doc["schema"], rc.SCHEMA)
        self.assertEqual(doc["artifact_kind"], "canonical_rq1r_main_result")
        self.assertTrue(doc["summary_reconciled"])
        self.assertEqual(doc["n_results"], doc["n_schedule"])
        for k in ("protocol", "lock_chain", "sources", "main_result", "exact_ci95",
                  "contingency_vuln_x_fixed", "cpg_stratification"):
            self.assertIn(k, doc, k)
        self.assertEqual(len(doc["sources"]), 7)

    def test_exact_ci_matches_counts(self):
        from cpg.ablation.v4_scaffold import clopper_pearson
        doc = rc.build_report(publish=False)
        m = doc["main_result"]
        self.assertEqual(doc["exact_ci95"],
                         list(clopper_pearson(m["strict_success"], m["n_pairs"])))

    def test_public_report_anonymized(self):
        from cpg.ablation.v4_rq1r import anonymize_check
        pub = rc.build_report(publish=True)
        self.assertEqual(pub["schema"], rc.SCHEMA_PUBLIC)
        self.assertTrue(pub["anonymized"])
        self.assertEqual(anonymize_check(pub), [])
        s = json.dumps(pub, ensure_ascii=False)
        self.assertNotIn("lauyy32", s.lower())
        self.assertNotIn("C:/Users", s)

    def test_report_explicitly_distinguishes_from_historical(self):
        doc = rc.build_report(publish=False)
        self.assertIn("1/82", doc["note"])
        self.assertIn("historical", doc["note"].lower())

    def test_write_reports_creates_both(self):
        orig = rc.OUT
        with tempfile.TemporaryDirectory() as td:
            try:
                rc.OUT = Path(td)
                r = rc.write_reports()
                self.assertTrue((Path(td) / "rq1r_canonical_report.json").exists())
                self.assertTrue((Path(td) / "rq1r_canonical_report_public.json").exists())
                self.assertTrue(r["public"]["anonymized"])
            finally:
                rc.OUT = orig


class TestPublishableLedger(unittest.TestCase):
    """P1-2：干净克隆必须能从仓库独立复算主结果。"""

    def test_ledger_exists_and_has_all_samples(self):
        p = rc.OUT / "rq1r_canonical_ledger.jsonl"
        self.assertTrue(p.exists(), "账本必须入库")
        rows = [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]
        self.assertEqual(len(rows), 164)
        for f in rc.LEDGER_FIELDS:
            self.assertIn(f, rows[0], f)

    def test_ledger_has_no_raw_response_text(self):
        """账本**不得**含原始响应体（体积与发布风险）。"""
        p = rc.OUT / "rq1r_canonical_ledger.jsonl"
        s = p.read_text(encoding="utf-8")
        self.assertNotIn("raw_response_text", s)

    def test_manifest_records_run_artifact_shas(self):
        mf = rc.OUT / "rq1r_canonical_manifest.json"
        self.assertTrue(mf.exists())
        doc = json.loads(mf.read_text(encoding="utf-8"))
        self.assertEqual(len(doc["run_artifacts"]), 9)
        for name, f in doc["run_artifacts"].items():
            self.assertEqual(len(f["sha256"]), 64, name)
        self.assertIn("reproduce", doc)
        self.assertIn("lock_chain", doc)

    def test_ledger_independently_reproduces_main_result(self):
        v = rc.verify_ledger_reproduces()
        self.assertTrue(v["ok"])
        self.assertEqual(v["reproduced"]["n_pairs"], 82)
        self.assertEqual(v["reproduced"]["strict_success"], 1)
        self.assertEqual(v["reproduced"]["strict_ids"], ["CVE-2026-67435"])

    def test_reproduce_detects_tampered_ledger(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "led.jsonl"
            rows = [json.loads(l) for l in
                    (rc.OUT / "rq1r_canonical_ledger.jsonl").read_text(encoding="utf-8").splitlines()
                    if l.strip()]
            for r in rows:                       # 把所有判定改成 abstain → 复算必变
                r["verdict"] = "abstain"
            p.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n",
                         encoding="utf-8")
            got = rc.reproduce_from_ledger(p)
            self.assertNotEqual(got["strict_success"], 1)


if __name__ == "__main__":
    unittest.main()
