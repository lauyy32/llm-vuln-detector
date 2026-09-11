# -*- coding: utf-8 -*-
"""A-4 脚手架验收（严格标准）。

要点：
  - 统计部分用**公开已知值**校验（Clopper–Pearson 表值 / McNemar 手算值），不靠自洽；
  - 所有产物必须带 SCAFFOLD_ONLY；
  - 校验 fail-closed 路径（gate 未过、字段缺失、非法枚举、重复、缺条）。
"""
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from cpg.ablation import v4_scaffold as sc  # noqa: E402

TOKENIZER = ROOT / "cpg/ablation/artifacts/v4/tokenizer/tokenizer.json"


# ---------------------------------------------------------------------------
# 1) envelope
# ---------------------------------------------------------------------------
class TestEnvelope(unittest.TestCase):
    def test_build_and_validate(self):
        env = sc.build_envelope("qwen2.5-coder:7b", "PROMPT")
        self.assertEqual(sc.validate_envelope(env), [])
        self.assertIs(env[sc.SCAFFOLD_TAG], True)
        self.assertEqual(env["stream"], False)

    def test_validate_rejects_stream_true(self):
        env = sc.build_envelope("m", "p")
        env["stream"] = True
        self.assertTrue(any("stream" in e for e in sc.validate_envelope(env)))

    def test_validate_rejects_nonzero_temperature(self):
        env = sc.build_envelope("m", "p", temperature=0.7)
        self.assertTrue(any("temperature" in e for e in sc.validate_envelope(env)))

    def test_validate_rejects_empty_prompt(self):
        env = sc.build_envelope("m", "")
        self.assertTrue(any("prompt" in e for e in sc.validate_envelope(env)))

    def test_envelope_sha_stable_and_content_sensitive(self):
        a1 = sc.build_envelope("m", "p")
        a2 = sc.build_envelope("m", "p")
        b = sc.build_envelope("m", "p2")
        self.assertEqual(sc.envelope_sha256(a1), sc.envelope_sha256(a2))
        self.assertNotEqual(sc.envelope_sha256(a1), sc.envelope_sha256(b))

    def test_system_field_optional(self):
        self.assertNotIn("system", sc.build_envelope("m", "p"))
        self.assertIn("system", sc.build_envelope("m", "p", system="sys"))


# ---------------------------------------------------------------------------
# 2) tokenizer / context fit
# ---------------------------------------------------------------------------
class TestTokenizer(unittest.TestCase):
    def test_identity(self):
        ident = sc.tokenizer_identity(TOKENIZER)
        self.assertEqual(len(ident["sha256"]), 64)
        self.assertTrue(ident["bytes"] > 0)

    def test_missing_tokenizer_raises(self):
        with self.assertRaises(FileNotFoundError):
            sc.tokenizer_identity(Path("no/such/tokenizer.json"))

    def test_count_tokens_monotonic(self):
        n1 = sc.count_prompt_tokens("hello", TOKENIZER)
        n2 = sc.count_prompt_tokens("hello world this is longer", TOKENIZER)
        self.assertTrue(n1 > 0 and n2 > n1)

    def test_context_fit_boundary(self):
        self.assertTrue(sc.context_fit(31744, 32768, 1024)["fits"])    # == num_ctx
        self.assertFalse(sc.context_fit(31745, 32768, 1024)["fits"])   # > num_ctx


# ---------------------------------------------------------------------------
# 3) 调度器 / resume
# ---------------------------------------------------------------------------
class TestScheduler(unittest.TestCase):
    def test_plan_marks_missing_prompt(self):
        plan = sc.plan_runs(["real", "partial"], ["CVE-A", "CVE-B"], "m",
                            prompt_lookup={("real", "CVE-A"): "P"})
        self.assertIs(plan[sc.SCAFFOLD_TAG], True)
        self.assertEqual(plan["n_items"], 4)
        self.assertEqual(plan["n_ready"], 1)
        self.assertEqual(plan["n_missing_prompt"], 3)
        st = {(i["sample_id"], i["arm"]): i["status"] for i in plan["items"]}
        self.assertEqual(st[("CVE-A", "real")], "READY")
        self.assertEqual(st[("CVE-B", "real")], "MISSING_PROMPT")

    def test_resume_reads_done_ids_and_tolerates_partial_line(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "r.jsonl"
            p.write_text(
                json.dumps({"sample_id": "A", "arm": "real"}) + "\n"
                + '{"sample_id": "B", "arm": "part' + "\n"      # 半行
                + json.dumps({"sample_id": "C", "arm": "partial"}) + "\n",
                encoding="utf-8")
            done = sc.load_done_ids(p)
            self.assertEqual(done, {("A", "real"), ("C", "partial")})

    def test_append_result_is_atomic_and_appendable(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "out.jsonl"
            sc.append_result(p, {"sample_id": "A", "arm": "real"})
            sc.append_result(p, {"sample_id": "B", "arm": "real"})
            lines = [l for l in p.read_text(encoding="utf-8").splitlines() if l]
            self.assertEqual(len(lines), 2)
            self.assertFalse(p.with_suffix(p.suffix + ".tmp").exists())

    def test_missing_results_file_returns_empty(self):
        self.assertEqual(sc.load_done_ids(Path("no/such.jsonl")), set())


# ---------------------------------------------------------------------------
# 4) 结果 verifier
# ---------------------------------------------------------------------------
def _rec(**kw):
    base = {"sample_id": "A", "arm": "real", "model": "m", "verdict": "benign",
            "raw_response_sha256": "a" * 64, "envelope_sha256": "b" * 64}
    base.update(kw)
    return base


class TestVerifier(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(sc.verify_result(_rec()), [])

    def test_missing_field(self):
        r = _rec()
        r.pop("raw_response_sha256")
        self.assertTrue(any("raw_response_sha256" in e for e in sc.verify_result(r)))

    def test_bad_verdict(self):
        self.assertTrue(any("verdict" in e for e in sc.verify_result(_rec(verdict="maybe"))))

    def test_bad_hex(self):
        self.assertTrue(any("hex" in e for e in sc.verify_result(_rec(envelope_sha256="zz"))))

    def test_abstain_requires_reason(self):
        errs = sc.verify_result(_rec(verdict="abstain"))
        self.assertTrue(any("abstain_reason" in e for e in errs))
        self.assertEqual(sc.verify_result(_rec(verdict="abstain", abstain_reason="x")), [])

    def test_file_verify_detects_dup_and_missing(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "r.jsonl"
            p.write_text("\n".join(json.dumps(_rec(sample_id="A", arm=a))
                                   for a in ("real", "real")) + "\n", encoding="utf-8")
            r = sc.verify_results_file(p, expected_pairs={("A", "real"), ("A", "partial")})
            self.assertFalse(r["ok"])
            self.assertTrue(any("重复" in e for e in r["errors"]))
            self.assertTrue(any("缺" in e for e in r["errors"]))

    def test_file_verify_ok(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "r.jsonl"
            p.write_text("\n".join(json.dumps(_rec(sample_id="A", arm=a))
                                   for a in ("real", "partial")) + "\n", encoding="utf-8")
            r = sc.verify_results_file(p, expected_pairs={("A", "real"), ("A", "partial")})
            self.assertTrue(r["ok"], r["errors"])


# ---------------------------------------------------------------------------
# 5) RUN_LOCK 请求模板
# ---------------------------------------------------------------------------
class TestLockRequest(unittest.TestCase):
    def test_gate_not_passed_refuses(self):
        with self.assertRaises(ValueError):
            sc.build_lock_request({}, "e" * 64, gate_a_pass=False,
                                  run_plan_sha="p" * 64, tokenizer_sha="t" * 64, model="m")

    def test_request_has_no_signature(self):
        req = sc.build_lock_request({"real": "a" * 64}, "e" * 64, gate_a_pass=True,
                                    run_plan_sha="d" * 64, tokenizer_sha="f" * 64, model="m")
        # 请求模板必须**无签名**且**不含签名者身份字段**
        self.assertEqual(req["signatures"], [])
        self.assertIs(req[sc.SCAFFOLD_TAG], True)
        for forbidden in ("reviewer_id", "signature", "signed_at", "approver"):
            self.assertNotIn(forbidden, req)


# ---------------------------------------------------------------------------
# 6) 统计（**已知值**校验）
# ---------------------------------------------------------------------------
class TestStatisticsKnownValues(unittest.TestCase):
    def test_clopper_pearson_table_value(self):
        """k=5,n=10,α=0.05 → (0.1871, 0.8129)（标准 CP 表值）。"""
        lo, hi = sc.clopper_pearson(5, 10)
        self.assertAlmostEqual(lo, 0.1871, places=3)
        self.assertAlmostEqual(hi, 0.8129, places=3)

    def test_clopper_pearson_boundaries(self):
        self.assertEqual(sc.clopper_pearson(0, 10)[0], 0.0)
        self.assertEqual(sc.clopper_pearson(10, 10)[1], 1.0)
        lo, hi = sc.clopper_pearson(0, 10)
        self.assertAlmostEqual(hi, 0.3085, places=3)   # 1-0.95^(1/10)

    def test_clopper_pearson_monotone(self):
        lo1, hi1 = sc.clopper_pearson(2, 10)
        lo2, hi2 = sc.clopper_pearson(8, 10)
        self.assertLess(lo1, lo2)
        self.assertLess(hi1, hi2)

    def test_mcnemar_exact_hand_computed(self):
        """b=10,c=2,n=12 → 2*(1+12+66)/4096 = 0.03857。"""
        r = sc.mcnemar_exact(10, 2)
        self.assertEqual(r["n_discordant"], 12)
        self.assertAlmostEqual(r["p_two_sided"], 0.03857, places=4)

    def test_mcnemar_zero_discordant(self):
        self.assertEqual(sc.mcnemar_exact(0, 0)["p_two_sided"], 1.0)

    def test_pairwise_all_discriminated(self):
        r = sc.pairwise_sufficiency_discrimination(
            {"A": "benign", "B": "benign"}, {"A": "vulnerable", "B": "vulnerable"})
        self.assertEqual(r["n_discriminated"], 2)
        self.assertEqual(r["rate"], 1.0)
        self.assertEqual(r["ci95_exact"][1], 1.0)

    def test_pairwise_none_discriminated(self):
        r = sc.pairwise_sufficiency_discrimination(
            {"A": "vulnerable"}, {"A": "benign"})
        self.assertEqual(r["n_discriminated"], 0)
        self.assertEqual(r["rate"], 0.0)

    def test_pairwise_abstain_counted_separately(self):
        r = sc.pairwise_sufficiency_discrimination(
            {"A": "benign", "B": "abstain"}, {"A": "vulnerable", "B": "vulnerable"})
        self.assertEqual(r["abstain"], 1)
        self.assertEqual(r["n_discriminated"], 1)
        self.assertEqual(r["n_pairs"], 2)

    def test_pairwise_reports_baseline_and_power_notes(self):
        r = sc.pairwise_sufficiency_discrimination({}, {})
        self.assertIn("不可直接比较", r["trivial_baseline_note"])
        self.assertIn("m=12", r["power_note"])

    def test_arm_level_metrics_known_confusion(self):
        """tp=8,fp=2,fn=2,tn=8 → P=0.8,R=0.8,F1=0.8,BA=0.8。"""
        y = [1] * 10 + [0] * 10
        p = [1] * 8 + [0] * 2 + [1] * 2 + [0] * 8
        m = sc.arm_level_metrics(y, p)
        self.assertEqual((m["tp"], m["fp"], m["fn"], m["tn"]), (8, 2, 2, 8))
        self.assertAlmostEqual(m["f1"], 0.8, places=6)
        self.assertAlmostEqual(m["ba"], 0.8, places=6)
        self.assertEqual(m["trivial_all_vulnerable_f1"], 0.667)

    def test_arm_level_mcc_perfect(self):
        m = sc.arm_level_metrics([1, 0], [1, 0])
        self.assertAlmostEqual(m["mcc"], 1.0, places=6)


class TestScaffoldBoundaries(unittest.TestCase):
    """边界：脚手架不得读取 DRAFT_PREREG，且所有产物须带 SCAFFOLD_ONLY。"""

    def test_module_does_not_read_prereg(self):
        """用 AST 检查**代码**（而非 docstring 文本）是否有读取 DRAFT_PREREG 的行为。"""
        import ast
        src = (ROOT / "cpg/ablation/v4_scaffold.py").read_text(encoding="utf-8")
        tree = ast.parse(src)
        # docstring 常量不参与：只看字符串字面量是否被用于 open/read/Path 等调用
        offenders = []
        for n in ast.walk(tree):
            if isinstance(n, ast.Constant) and isinstance(n.value, str):
                if "v4_prereg.json" in n.value:
                    offenders.append(n.lineno)
        # 允许 docstring（模块首条表达式语句）中的说明，但不得出现在其它字符串里
        doc_lines = set()
        if tree.body and isinstance(tree.body[0], ast.Expr) and \
                isinstance(tree.body[0].value, ast.Constant):
            doc_lines = set(range(tree.body[0].lineno,
                                  getattr(tree.body[0], "end_lineno", tree.body[0].lineno) + 1))
        bad = [ln for ln in offenders if ln not in doc_lines]
        self.assertEqual(bad, [], f"v4_prereg.json 出现在非 docstring 字符串（行 {bad}）")

    def test_products_tagged(self):
        self.assertIs(sc.plan_runs(["real"], ["A"], "m")[sc.SCAFFOLD_TAG], True)
        self.assertIs(sc.pairwise_sufficiency_discrimination({}, {})[sc.SCAFFOLD_TAG], True)
        self.assertIs(sc.build_envelope("m", "p")[sc.SCAFFOLD_TAG], True)


class TestLockRequestSchemaFrozen(unittest.TestCase):
    """A-4 剩余：RUN_LOCK 正式字段集冻结。"""

    def _req(self, **kw):
        # 注意：必须是**合法 64 位 hex**（'t'/'p' 等超范围字符会被 fail-closed 拒绝）
        base = dict(arm_artifact_shas={"real": "a" * 64, "partial": "b" * 64},
                    envelope_sha="e" * 64, gate_a_pass=True,
                    run_plan_sha="d" * 64, tokenizer_sha="f" * 64, model="m")
        base.update(kw)
        return sc.build_lock_request(**base)

    def test_valid_passes_validation(self):
        self.assertEqual(sc.validate_lock_request(self._req()), [])

    def test_missing_required_field(self):
        req = self._req()
        req.pop("envelope_sha256")
        self.assertTrue(any("envelope_sha256" in e for e in sc.validate_lock_request(req)))

    def test_bad_hex_rejected(self):
        req = self._req()
        req["run_plan_sha256"] = "zz"
        self.assertTrue(any("hex" in e for e in sc.validate_lock_request(req)))

    def test_nonempty_signatures_rejected(self):
        req = self._req()
        req["signatures"] = [{"by": "x"}]
        self.assertTrue(any("signatures" in e for e in sc.validate_lock_request(req)))

    def test_signer_fields_forbidden(self):
        req = self._req()
        req["reviewer_id"] = "someone"
        self.assertTrue(any("reviewer_id" in e for e in sc.validate_lock_request(req)))

    def test_gate_not_passed_refuses(self):
        with self.assertRaises(ValueError):
            sc.build_lock_request({}, "e" * 64, gate_a_pass=False,
                                  run_plan_sha="p" * 64, tokenizer_sha="t" * 64, model="m")


class TestPlanPersistence(unittest.TestCase):
    """A-4 剩余：调度计划持久化 + 指纹对账。"""

    def test_write_then_load_roundtrip(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "plan.json"
            plan = sc.plan_runs(["real"], ["A"], "m", prompt_lookup={("real", "A"): "P"})
            meta = sc.write_plan(p, plan)
            self.assertTrue(p.exists())
            self.assertEqual(len(meta["sha256"]), 64)
            back = sc.load_plan(p, expect_sha=meta["sha256"])
            self.assertEqual(back["n_items"], plan["n_items"])
            self.assertFalse(p.with_suffix(p.suffix + ".tmp").exists())

    def test_sha_mismatch_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "plan.json"
            sc.write_plan(p, sc.plan_runs(["real"], ["A"], "m"))
            with self.assertRaises(ValueError):
                sc.load_plan(p, expect_sha="0" * 64)

    def test_missing_plan_raises(self):
        with self.assertRaises(FileNotFoundError):
            sc.load_plan(Path("no/such/plan.json"))


class TestUnifiedClopperPearson(unittest.TestCase):
    """全项目 CP 只有一份实现，且与权威口径逐位一致。"""

    def test_matches_authoritative_values(self):
        self.assertAlmostEqual(sc.clopper_pearson(7, 82)[0], 0.035013, places=5)
        self.assertAlmostEqual(sc.clopper_pearson(7, 82)[1], 0.168008, places=5)
        self.assertAlmostEqual(sc.clopper_pearson(2, 74)[0], 0.003290, places=5)

    def test_rq1r_delegates_to_scaffold(self):
        from cpg.ablation import v4_rq1r as rq
        for k, n in ((0, 10), (5, 10), (7, 82), (74, 74), (2, 74)):
            self.assertEqual(rq.clopper_pearson(k, n), sc.clopper_pearson(k, n))


if __name__ == "__main__":
    unittest.main()
