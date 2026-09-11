# -*- coding: utf-8 -*-
"""A-3 步 2/3/4/5（第六次返工）验收：评审 5 的 P0-1..P0-5。

被反向固定的历史错误：
  · placebo/shuffled 曾仅凭一个 `apply_clean` 布尔即可纳入 → 现断言缺臂工件即拒；
  · 「受控 runner 记录」曾由调用者手填 → 现断言记录只能来自真实执行，且 stdout/
    stderr/post-apply 树/stdout 工件可重算；
  · 候选 prompt 的 SHA/token 曾自报 → 现断言须 prompt 文件重哈希 + 冻结 tokenizer
    重计数 + envelope 重渲染，且 ratio 由**重计数**结果计算；
  · T3 曾提前返回绕过 provenance → 现断言 T3 同样执行；
  · 结果契约曾缺 abstain → 现断言三者齐备且 run_error 单列。
"""
import ast
import inspect
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from cpg.ablation import v4_apply_runner as ar  # noqa: E402
from cpg.ablation import v4_arms as va  # noqa: E402
from cpg.ablation import v4_power as vp  # noqa: E402

_HEX = "a" * 64
TARGET_TOKENS = 1000
PATCH = (b"--- a/src/m.py\n+++ b/src/m.py\n@@ -1,2 +1,2 @@\n"
         b" def f():\n-    return 1\n+    return 2\n")


def _w(p: Path, data: bytes):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)


def _words(n):
    return " ".join(["tok"] * n)


class Fixture:
    """真实工件目录：目标树 + 可 apply 的补丁 + 假 tokenizer + 冻结运行时。"""

    def __init__(self, tmp):
        b = Path(tmp)
        self.base = b
        _w(b / "tree" / "src" / "m.py", b"def f():\n    return 1\n")
        _w(b / "tree" / "src" / "other.py", b"x = 1\n")
        _w(b / "fix.diff", PATCH)
        _w(b / "fake_tokenizer.json", b'{"fake": true}\n')
        _w(b / "poc.py", b"print('poc')\n")
        _w(b / "checker.py", b"assert True\n")
        _w(b / "residual.md", b"residual exploitation path\n")
        _w(b / "r1.json", b'{"reviewer": "R1"}\n')
        _w(b / "r2.json", b'{"reviewer": "R2"}\n')
        _w(b / "adj.json", b'{"adjudicator": "R3"}\n')
        self.tree_sha = va.normalized_tree_sha256(b / "tree")
        self.sha = lambda n: va.file_content_sha256(b / n)[1]
        self.counter = lambda text: len(text.split())
        self.runtime = va.FrozenRuntime(
            tokenizer_path=b / "fake_tokenizer.json",
            tokenizer_sha256=self.sha("fake_tokenizer.json"),
            apply_runner_sha256=ar.apply_runner_sha256(),
            model="qwen2.5-coder:7b", system_text="You are a security reviewer.")
        arms = {a: {"poc_sha256": self.sha("poc.py"), "patch_sha256": self.sha("fix.diff"),
                    "checker_sha256": self.sha("checker.py"),
                    "residual_path_sha256": self.sha("residual.md")}
                for a in va.ARM_ORACLE}
        self.ctx = va.FrozenContext(
            manifest_sha256=_HEX, template_sha256=_HEX,
            samples={"TARGET": {"target_tree_sha256": self.tree_sha, "arms": arms}},
            runtime=self.runtime)
        self.target = {"sample_id": "TARGET", "language": "python",
                       "cwe_family": "injection", "n_files": 1, "is_composite": False}
        self.donor = {"sample_id": "D", "language": "python",
                      "cwe_family": "injection", "n_files": 1, "is_composite": False}

    # ---- oracle 证据 ----
    def t1(self, arm="annotated-security-complete", verdict="fixed", code=0, **kw):
        kw.setdefault("raw", f"collected 1 item\nVERDICT: {verdict}\n")
        kw.setdefault("poc_path", "poc.py")
        kw.setdefault("patch_path", "fix.diff")
        kw.setdefault("target_tree_dir", "tree")
        kw.setdefault("command", "pytest -q tests/security/test_x.py")
        return va.make_evidence("pytest-security-regression", arm, "TARGET",
                               kw.pop("raw"), code, base_dir=self.base,
                               context=self.ctx, **kw)

    def t2(self, arm="placebo", verdict="still_vulnerable", code=0, **kw):
        kw.setdefault("raw", f"checked\nVERDICT: {verdict}\n")
        kw.setdefault("patch_path", "fix.diff")
        kw.setdefault("target_tree_dir", "tree")
        kw.setdefault("checker_path", "checker.py")
        kw.setdefault("command", "python checker.py --target tree")
        return va.make_evidence("semantic-assertion", arm, "TARGET",
                               kw.pop("raw"), code, base_dir=self.base,
                               context=self.ctx, **kw)

    def t3(self, verdict="still_vulnerable", **kw):
        kw.setdefault("raw", f"review notes\nVERDICT: {verdict}\n")
        kw.setdefault("command", "manual review")
        kw.setdefault("residual_path", "residual.md")
        kw.setdefault("reviewer1_id", "R1")
        kw.setdefault("reviewer2_id", "R2")
        kw.setdefault("reviewer1_submission", "r1.json")
        kw.setdefault("reviewer2_submission", "r2.json")
        kw.setdefault("reviewer1_verdict", verdict)
        kw.setdefault("reviewer2_verdict", verdict)
        return va.make_evidence("reviewer-residual-path", "placebo", "TARGET",
                               kw.pop("raw"), 0, base_dir=self.base,
                               context=self.ctx, **kw)

    # ---- shuffled 工件 ----
    def baseline(self, tokens=TARGET_TOKENS):
        txt = _words(tokens)
        art = va.write_prompt_artifact(self.base, "prompts/base.txt", txt)
        _e, env = va.build_arm_envelope(self.runtime, txt)
        return va.TargetBaseline(sample_id="TARGET", target_tree_sha256=self.tree_sha,
                                 base_prompt_path=art["path"],
                                 base_prompt_sha256=art["sha256"],
                                 base_final_prompt_tokens=tokens,
                                 base_envelope_sha256=env)

    def donor_patch(self, sid="D"):
        return va.DonorPatch(sample_id=sid, patch_path="fix.diff",
                             real_patch_sha256=va.patch_sha256(self.base / "fix.diff"))

    def pair(self, tokens=950, sid="D"):
        return va.build_pair_candidate(
            base_dir=self.base, target_id="TARGET", donor_id=sid,
            target_tree_dir="tree", donor_patch_path="fix.diff", runtime=self.runtime,
            renderer=lambda tree_abs, did: _words(tokens),
            token_counter=self.counter)

    def pair_evidence(self, **kw):
        return {"target": self.target, "donor": self.donor,
                "baseline": kw.get("baseline") or self.baseline(),
                "donor_patch": kw.get("donor_patch") or self.donor_patch(),
                "pair_candidate": kw.get("pair_candidate") or self.pair(
                    tokens=kw.get("tokens", 950))}

    def placebo(self, operator="dead_branch", **kw):
        return va.build_placebo_artifact(
            base_dir=self.base, sample_id="TARGET", source_rel="src/m.py",
            tree_rel="tree", operator_name=operator, out_tree_rel="placebo_tree",
            runtime=self.runtime,
            renderer=lambda t, s: _words(kw.get("tokens", TARGET_TOKENS)),
            token_counter=self.counter)


# ===========================================================================
# 步 2：token 搜索
# ===========================================================================
def _cand(key, tokens):
    return va.Candidate(key=key, tokens=tokens, tokenizer_sha256=_HEX,
                        envelope_sha256=_HEX, prompt_sha256=_HEX)


class TestTokenSearchInBoundsFirst(unittest.TestCase):
    def test_named_regression_79_125_100(self):
        r = va.token_match_search([_cand("A", 79), _cand("B", 125)], 100)
        self.assertEqual(r["status"], "OK")
        self.assertEqual(r["selected"].key, "B")

    def test_nearer_but_out_of_bounds_never_wins(self):
        for target, items, want in [(100, [("oob", 70), ("ib", 81)], "ib"),
                                    (100, [("oob", 130), ("ib", 124)], "ib"),
                                    (1000, [("oob", 700), ("ib", 800)], "ib"),
                                    (1000, [("oob", 1300), ("ib", 1250)], "ib")]:
            with self.subTest(items=items):
                self.assertEqual(va.token_match_search(
                    [_cand(k, t) for k, t in items], target)["selected"].key, want)

    def test_only_out_of_bounds_and_audit(self):
        r = va.token_match_search([_cand("A", 79), _cand("B", 70)], 100)
        self.assertEqual(r["status"], "NO_IN_BOUNDS_CANDIDATE")
        r2 = va.token_match_search([_cand("A", 79), _cand("B", 125)], 100)
        self.assertEqual({e["key"] for e in r2["excluded_out_of_bounds"]}, {"A"})
        self.assertEqual([t["key"] for t in r2["trace"]], ["B"])

    def test_invalid_and_bad_args(self):
        for cands in ([], [_cand("x", 100.0)], [_cand("x", True)],
                      [_cand("d", 100), _cand("d", 110)], [va.Candidate(key="n", tokens=100)]):
            self.assertEqual(va.token_match_search(cands, 100)["status"], "INVALID_CANDIDATES")
        for bad in [(1.0, 0.5), (0, 1), "x", (True, 2)]:
            with self.assertRaises(ValueError):
                va.token_match_search([_cand("a", 100)], 100, bounds=bad)


# ===========================================================================
# P0-1：构造门禁按臂强制消费构造工件（布尔 apply_clean 单独不足）
# ===========================================================================
class TestConstructionGateRequiresArmEvidence(unittest.TestCase):
    def test_signature_has_no_model_output(self):
        names = set(inspect.signature(va.construction_gate).parameters)
        for n in names:
            self.assertFalse(any(t in n.lower() for t in
                                 ("model", "verdict", "is_vulnerable", "response",
                                  "prediction", "benign")), f"疑似模型输出参数: {n}")

    def test_old_result_aware_api_removed(self):
        self.assertFalse(hasattr(va, "evaluate_arm"))

    def test_arm_evidence_kind_declared(self):
        self.assertEqual(va.ARM_EVIDENCE_KIND["placebo"], "placebo")
        self.assertEqual(va.ARM_EVIDENCE_KIND["shuffled"], "pair_candidate")
        self.assertEqual(va.ARM_EVIDENCE_KIND["annotated-security-complete"], "oracle")

    def test_bare_apply_clean_is_insufficient_for_every_arm(self):
        for arm in va.ARM_ORACLE:
            with self.subTest(arm=arm):
                r = va.construction_gate(arm, apply_clean=True)
                self.assertFalse(r["eligible"], r)
                self.assertIn("缺", r["reason"])

    def test_placebo_gate_consumes_placebo_artifact(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            r = va.construction_gate("placebo", apply_clean=True, sample_id="TARGET",
                                     placebo_artifact=fx.placebo(),
                                     runtime=fx.runtime, base_dir=fx.base,
                                     token_counter=fx.counter)
            self.assertTrue(r["eligible"], r)
            self.assertEqual(r["placebo_operator"], "dead_branch")

    def test_shuffled_gate_consumes_pair_evidence(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            r = va.construction_gate("shuffled", apply_clean=True, sample_id="TARGET",
                                     pair_evidence=fx.pair_evidence(),
                                     runtime=fx.runtime, base_dir=fx.base,
                                     token_counter=fx.counter)
            self.assertTrue(r["eligible"], r)
            self.assertIn("apply_record", r)

    def test_oracle_arms_consume_oracle_evidence(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            self.assertTrue(va.construction_gate(
                "annotated-security-complete", apply_clean=True, sample_id="TARGET",
                oracle_evidence=fx.t1(), base_dir=fx.base, ctx=fx.ctx)["eligible"])
            self.assertFalse(va.construction_gate(
                "annotated-security-complete", apply_clean=True, sample_id="TARGET",
                oracle_evidence=fx.t1(verdict="still_vulnerable"),
                base_dir=fx.base, ctx=fx.ctx)["eligible"])

    def test_inclusion_invariant_under_model_verdicts(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            before = va.construction_gate(
                "placebo", apply_clean=True, sample_id="TARGET",
                placebo_artifact=fx.placebo(), runtime=fx.runtime,
                base_dir=fx.base, token_counter=fx.counter)["eligible"]
            for mv in va.MODEL_VERDICTS:
                va.outcome_evaluation("placebo", model_verdict=mv,
                                      abstain_reason="r" if mv == "abstain" else "")
            after = va.construction_gate(
                "placebo", apply_clean=True, sample_id="TARGET",
                placebo_artifact=fx.placebo(), runtime=fx.runtime,
                base_dir=fx.base, token_counter=fx.counter)["eligible"]
            self.assertTrue(before)
            self.assertEqual(before, after)

    def test_optional_oracle_error_is_inconclusive_not_consistent(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            ev = fx.t1(arm="placebo", raw="no marker\n")
            r = va.construction_gate("placebo", apply_clean=True, sample_id="TARGET",
                                     placebo_artifact=fx.placebo(),
                                     oracle_evidence=ev, runtime=fx.runtime,
                                     base_dir=fx.base, ctx=fx.ctx,
                                     token_counter=fx.counter)
            self.assertTrue(r["eligible"], r)
            self.assertEqual(r["optional_oracle"], "inconclusive")
            self.assertIn("不得", r["reason"])

    def test_optional_oracle_fixed_blocks_placebo(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            r = va.construction_gate("placebo", apply_clean=True, sample_id="TARGET",
                                     placebo_artifact=fx.placebo(),
                                     oracle_evidence=fx.t1(arm="placebo", verdict="fixed"),
                                     runtime=fx.runtime, base_dir=fx.base, ctx=fx.ctx,
                                     token_counter=fx.counter)
            self.assertFalse(r["eligible"])
            self.assertIn("非行为中性", r["reason"])

    def test_registry_declares_inclusion_rule(self):
        reg = va.arms_registry()
        self.assertIn("construction_gate", reg["inclusion_rule"])
        self.assertIn("changes_inclusion", reg["inclusion_rule"])
        self.assertEqual(set(reg["arm_evidence_kind"]), set(va.ARM_ORACLE))


# ===========================================================================
# P0-5：结果契约（abstain 合法；run_error 单列）
# ===========================================================================
class TestOutcomeContract(unittest.TestCase):
    def test_verdict_contract_sourced_from_scaffold(self):
        from cpg.ablation import v4_scaffold as sc
        self.assertEqual(set(va.MODEL_VERDICTS), set(sc.VALID_VERDICTS))
        self.assertEqual(set(va.RUN_ERROR_STATES), set(sc.RUN_ERROR_STATES))
        self.assertIn("abstain", va.MODEL_VERDICTS)

    def test_abstain_is_a_legal_outcome(self):
        r = va.outcome_evaluation("placebo", model_verdict="abstain",
                                  abstain_reason="模型拒答")
        self.assertEqual(r["manipulation_check"], "inconclusive-abstained")
        self.assertIsNone(r["is_vulnerable"])
        self.assertIs(r["changes_inclusion"], False)
        with self.assertRaises(ValueError):
            va.outcome_evaluation("placebo", model_verdict="abstain")

    def test_run_error_is_separate_from_verdict(self):
        r = va.outcome_evaluation("placebo", run_error="INVOKE_ERROR")
        self.assertEqual(r["manipulation_check"], "infra-error")
        self.assertIsNone(r["model_verdict"])
        with self.assertRaises(ValueError):
            va.outcome_evaluation("placebo", run_error="NOPE")
        with self.assertRaises(ValueError):
            va.outcome_evaluation("placebo", model_verdict="benign", run_error="INVOKE_ERROR")

    def test_all_outcomes_keep_inclusion_fixed(self):
        for mv in va.MODEL_VERDICTS:
            r = va.outcome_evaluation("placebo", model_verdict=mv,
                                      abstain_reason="r" if mv == "abstain" else "")
            self.assertIs(r["changes_inclusion"], False)


# ===========================================================================
# P0-2：真实执行绑定（stdout/stderr/post 树/runner 实现 SHA）
# ===========================================================================
class TestRealApplyBinding(unittest.TestCase):
    def _select(self, fx, pair=None, baseline=None, runtime=None, patches=None):
        return va.select_donor(
            fx.target, [fx.donor], target_baseline=baseline or fx.baseline(),
            donor_patches=patches if patches is not None else {"D": fx.donor_patch()},
            pair_candidates={"D": pair or fx.pair()},
            runtime=runtime or fx.runtime, base_dir=fx.base,
            token_counter=fx.counter)

    def test_valid_selection(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            r = self._select(fx)
            self.assertEqual(r["status"], "OK", r)
            self.assertAlmostEqual(r["token_window"]["ratio"], 0.95, places=6)
            self.assertIn("真实执行记录", r["binding"])

    def test_post_tree_tamper_after_execution_is_detected(self):
        """复用同一工件：post 目录内容被改 → 必须拒绝。"""
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            pc = fx.pair()
            self.assertEqual(self._select(fx, pair=pc)["status"], "OK")
            post = fx.base / pc.post_apply_tree_dir
            (post / "src" / "m.py").write_bytes(b"def f():\n    return 999\n")
            r2 = self._select(fx, pair=pc)
            self.assertEqual(r2["status"], "NO_DONOR")
            self.assertIn("post-apply 树 SHA 与实际目录不符",
                          " ".join(r2["hard_reject_reasons"][0]["reasons"]))

    def test_forged_post_sha_is_detected(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            pc = fx.pair()
            pc.post_apply_tree_sha256 = "9" * 64
            pc.apply_record.post_apply_tree_sha256 = "9" * 64
            self.assertEqual(self._select(fx, pair=pc)["status"], "NO_DONOR")

    def test_runner_implementation_sha_is_bound(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            pc = fx.pair()
            pc.apply_record.runner_sha256 = "7" * 64
            r = self._select(fx, pair=pc)
            self.assertEqual(r["status"], "NO_DONOR")
            self.assertIn("runner_sha256", " ".join(r["hard_reject_reasons"][0]["reasons"]))

    def test_stdout_and_stderr_artifacts_are_rehashed(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            pc = fx.pair()
            (fx.base / pc.apply_record.stdout_path).write_bytes(b"tampered stdout\n")
            r = self._select(fx, pair=pc)
            self.assertEqual(r["status"], "NO_DONOR")
            self.assertIn("stdout", " ".join(r["hard_reject_reasons"][0]["reasons"]))

    def test_artifacts_must_live_in_the_run_workdir(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            pc = fx.pair()
            pc.apply_record.workdir_id = "deadbeefdeadbeef"
            r = self._select(fx, pair=pc)
            self.assertEqual(r["status"], "NO_DONOR")
            self.assertIn("工作目录内", " ".join(r["hard_reject_reasons"][0]["reasons"]))

    def test_runtime_runner_sha_must_match_live_runner(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            rt = va.FrozenRuntime(tokenizer_path=fx.runtime.tokenizer_path,
                                  tokenizer_sha256=fx.runtime.tokenizer_sha256,
                                  apply_runner_sha256="b" * 64,
                                  model=fx.runtime.model,
                                  system_text=fx.runtime.system_text)
            r = self._select(fx, runtime=rt)
            self.assertEqual(r["status"], "NO_AUTHORITY")
            self.assertIn("apply_runner_sha256", r["reason"])

    def test_donor_patch_uses_raw_byte_hash(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            dp = fx.donor_patch()
            self.assertEqual(dp.real_patch_sha256, va.patch_sha256(fx.base / "fix.diff"))
            self.assertEqual(va.PATCH_HASH_MODE, "raw-bytes")

    def test_authority_missing_fail_closed(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            r = va.select_donor(fx.target, [fx.donor], target_baseline=None,
                                donor_patches={"D": fx.donor_patch()},
                                pair_candidates={"D": fx.pair()},
                                runtime=fx.runtime, base_dir=fx.base)
            self.assertEqual(r["status"], "NO_AUTHORITY")
            r2 = va.select_donor(fx.target, [fx.donor], target_baseline=fx.baseline(),
                                 donor_patches={"D": fx.donor_patch()},
                                 pair_candidates={"D": fx.pair()},
                                 runtime=None, base_dir=fx.base)
            self.assertEqual(r2["status"], "NO_AUTHORITY")

    def test_soft_relaxation_still_works(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            donor = dict(fx.donor, language="java")
            r = va.select_donor(fx.target, [donor], target_baseline=fx.baseline(),
                                donor_patches={"D": fx.donor_patch()},
                                pair_candidates={"D": fx.pair()},
                                runtime=fx.runtime, base_dir=fx.base,
                                token_counter=fx.counter)
            self.assertEqual(r["status"], "OK", r)
            self.assertEqual(r["relaxations"][0], "not_composite")

    def test_registry_documents_pair_and_apply_fields(self):
        sh = va.arms_registry()["shuffle"]
        self.assertEqual(set(sh["pair_candidate_fields"]), set(va.PAIR_CANDIDATE_FIELDS))
        self.assertEqual(set(sh["apply_record_fields"]), set(va.APPLY_RECORD_FIELDS))
        self.assertIn("真实执行", sh["binding"])


# ===========================================================================
# P0-3：prompt 工件（重哈希 + 冻结 tokenizer 重计数 + envelope 重渲染）
# ===========================================================================
class TestPromptArtifactBinding(unittest.TestCase):
    def _sel(self, fx, pair=None, baseline=None):
        return va.select_donor(fx.target, [fx.donor],
                               target_baseline=baseline or fx.baseline(),
                               donor_patches={"D": fx.donor_patch()},
                               pair_candidates={"D": pair or fx.pair()},
                               runtime=fx.runtime, base_dir=fx.base,
                               token_counter=fx.counter)

    def test_ratio_boundaries(self):
        for tok, want in ((790, "NO_DONOR"), (800, "OK"), (1250, "OK"), (1260, "NO_DONOR")):
            with self.subTest(tok=tok):
                with tempfile.TemporaryDirectory() as t:
                    fx = Fixture(t)
                    self.assertEqual(self._sel(fx, pair=fx.pair(tokens=tok))["status"], want)

    def test_candidate_prompt_content_tamper_detected(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            pc = fx.pair()
            (fx.base / pc.candidate_prompt_path).write_bytes(_words(950).encode() + b" X")
            r = self._sel(fx, pair=pc)
            self.assertEqual(r["status"], "NO_DONOR")
            self.assertIn("候选 prompt 内容 SHA", " ".join(r["hard_reject_reasons"][0]["reasons"]))

    def test_token_recount_overrides_self_reported_value(self):
        """自报 token 数落在界内，但**重计数**不符 → 必拒。"""
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            pc = fx.pair(tokens=950)
            pc.candidate_final_prompt_tokens = 1000      # 手改成看似更佳的值
            r = self._sel(fx, pair=pc)
            self.assertEqual(r["status"], "NO_DONOR")
            self.assertIn("重计数", " ".join(r["hard_reject_reasons"][0]["reasons"]))

    def test_envelope_mismatch_detected(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            pc = fx.pair()
            pc.candidate_envelope_sha256 = "c" * 64
            r = self._sel(fx, pair=pc)
            self.assertEqual(r["status"], "NO_DONOR")
            self.assertIn("envelope", " ".join(r["hard_reject_reasons"][0]["reasons"]))

    def test_baseline_prompt_is_rehashed(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            bl = fx.baseline()
            (fx.base / bl.base_prompt_path).write_bytes(_words(900).encode())
            r = self._sel(fx, baseline=bl)
            self.assertEqual(r["status"], "NO_DONOR")
            self.assertIn("基准臂 prompt 内容 SHA",
                          " ".join(r["hard_reject_reasons"][0]["reasons"]))

    def test_tokenizer_missing_library_is_fail_closed(self):
        """不注入计数器且缺 `tokenizers` → 必须报错，不得静默退化。"""
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            pc = fx.pair()
            r = va.select_donor(fx.target, [fx.donor], target_baseline=fx.baseline(),
                                donor_patches={"D": fx.donor_patch()},
                                pair_candidates={"D": pc}, runtime=fx.runtime,
                                base_dir=fx.base, token_counter=None)
            reasons = " ".join(r.get("hard_reject_reasons", [{}])[0].get("reasons", []))
            self.assertEqual(r["status"], "NO_DONOR")
            self.assertTrue("tokenizers" in reasons or "重计数" in reasons, reasons)

    def test_runtime_tokenizer_file_is_bound(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            rt = va.FrozenRuntime(tokenizer_path=fx.runtime.tokenizer_path,
                                  tokenizer_sha256="e" * 64,
                                  apply_runner_sha256=fx.runtime.apply_runner_sha256,
                                  model=fx.runtime.model,
                                  system_text=fx.runtime.system_text)
            errs = rt.errors()
            self.assertTrue(any("tokenizer_sha256" in e for e in errs), errs)


# ===========================================================================
# P0-1：placebo 构造工件（注册算子重跑）
# ===========================================================================
class TestPlaceboArtifact(unittest.TestCase):
    def _gate(self, fx, art, **kw):
        kw.setdefault("token_counter", fx.counter)
        return va.construction_gate("placebo", apply_clean=True, sample_id="TARGET",
                                    placebo_artifact=art, runtime=fx.runtime,
                                    base_dir=fx.base, **kw)

    def test_valid_placebo_passes_and_operator_rerun_matches(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            art = fx.placebo()
            self.assertEqual(va.verify_placebo_artifact(fx.base, art, fx.runtime,
                                                        fx.counter), [])
            self.assertTrue(self._gate(fx, art)["eligible"])

    def test_source_tamper_detected(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            art = fx.placebo()
            (fx.base / art.source_path).write_bytes(b"def f():\n    return 42\n")
            errs = va.verify_placebo_artifact(fx.base, art, fx.runtime, fx.counter)
            self.assertTrue(any("源文件" in e for e in errs), errs)
            self.assertFalse(self._gate(fx, art)["eligible"])

    def test_transformed_source_must_match_operator_rerun(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            art = fx.placebo()
            p = fx.base / art.transformed_path
            art.transformed_sha256 = va.file_content_sha256(p)[1]  # 先对齐 SHA
            p.write_bytes(b"def f():\n    return 1\n")
            art.transformed_sha256 = va.file_content_sha256(p)[1]
            errs = va.verify_placebo_artifact(fx.base, art, fx.runtime, fx.counter)
            self.assertTrue(any("重跑算子结果不逐字节相同" in e for e in errs), errs)

    def test_operator_fingerprint_and_registration_bound(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            art = fx.placebo()
            art.operator_fingerprint = "f" * 64
            errs = va.verify_placebo_artifact(fx.base, art, fx.runtime, fx.counter)
            self.assertTrue(any("指纹" in e for e in errs), errs)
            art2 = fx.placebo()
            art2.operator_name = "no_such_operator"
            self.assertTrue(any("未登记" in e for e in
                                va.verify_placebo_artifact(fx.base, art2, fx.runtime,
                                                           fx.counter)))

    def test_transformed_source_must_live_in_its_tree(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            art = fx.placebo()
            art.transformed_tree_dir = "tree"
            errs = va.verify_placebo_artifact(fx.base, art, fx.runtime, fx.counter)
            self.assertTrue(any("变换后树 SHA" in e or "不在其变换后树内" in e
                                for e in errs), errs)

    def test_placebo_prompt_is_checked(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            art = fx.placebo()
            art.prompt_final_tokens = 7
            errs = va.verify_placebo_artifact(fx.base, art, fx.runtime, fx.counter)
            self.assertTrue(any("重计数" in e for e in errs), errs)


# ===========================================================================
# oracle 分层契约（沿用上一轮，已闭环部分不回归）
# ===========================================================================
class TestOracleTierContracts(unittest.TestCase):
    def test_no_exit_code_to_verdict_mapping(self):
        self.assertFalse(hasattr(va, "EXIT_CODE_CONVENTION"))
        self.assertEqual(va.parse_oracle_verdict(
            "pytest-security-regression", "1 failed", 1), va.ORACLE_ERROR)
        self.assertEqual(va.parse_oracle_verdict(
            "pytest-security-regression", "VERDICT: fixed", 1), "fixed")
        self.assertEqual(va.parse_oracle_verdict(
            "poc-exploit-script", "exploit done", 0), va.ORACLE_ERROR)

    def test_infra_and_unknown_exit_codes(self):
        for name, c in va.ORACLE_CONTRACTS.items():
            if not c.machine_decidable:
                continue
            for code in c.infra_exit_codes:
                self.assertEqual(va.parse_oracle_verdict(name, "VERDICT: fixed", code),
                                 va.ORACLE_ERROR)
        self.assertEqual(va.parse_oracle_verdict(
            "pytest-security-regression", "VERDICT: fixed", 99), va.ORACLE_ERROR)

    def test_marker_rules(self):
        for raw, want in [("no marker", va.ORACLE_ERROR),
                          ("VERDICT: maybe", va.ORACLE_ERROR),
                          ("VERDICT: fixed\nVERDICT: still_vulnerable", va.ORACLE_ERROR),
                          ("  VERDICT: FIXED  ", "fixed"),
                          ("not a marker: VERDICT: fixed", va.ORACLE_ERROR)]:
            self.assertEqual(va.parse_oracle_verdict(
                "pytest-security-regression", raw, 0), want)

    def test_t3_not_machine_decidable_and_derive(self):
        with self.assertRaises(ValueError):
            va.parse_oracle_verdict("reviewer-residual-path", "VERDICT: fixed", 0)
        self.assertEqual(va.derive_t3_verdict("fixed", "fixed", ""), "fixed")
        self.assertEqual(va.derive_t3_verdict("fixed", "still_vulnerable", "fixed"), "fixed")
        self.assertEqual(va.derive_t3_verdict("fixed", "still_vulnerable", ""),
                         va.ORACLE_ERROR)


class TestOracleStrictProvenance(unittest.TestCase):
    def test_t1_tree_swap_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            ev = fx.t1()
            self.assertEqual(ev.verify(fx.base, fx.ctx), [])
            _w(fx.base / "tree" / "src" / "m.py", b"def f():\n    return 999\n")
            self.assertTrue(any("target 树 SHA" in e for e in ev.verify(fx.base, fx.ctx)))
            _w(fx.base / "tree" / "src" / "m.py", b"def f():\n    return 1\n")
            self.assertEqual(ev.verify(fx.base, fx.ctx), [])

    def test_t1_requires_all_artifacts(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            for drop in ("poc_path", "patch_path", "target_tree_dir"):
                ev = fx.t1(**{drop: None})
                self.assertTrue(any("强制要求工件引用" in e for e in
                                    ev.verify(fx.base, fx.ctx)), drop)

    def test_t2_checker_rehash_and_frozen_binding(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            ev = fx.t2()
            self.assertEqual(ev.verify(fx.base, fx.ctx), [])
            _w(fx.base / "checker.py", b"assert False\n")
            self.assertTrue(any("checker 内容 SHA" in e for e in ev.verify(fx.base, fx.ctx)))
            _w(fx.base / "checker.py", b"assert True\n")
            bad_arms = {a: dict(fx.ctx.samples["TARGET"]["arms"][a]) for a in va.ARM_ORACLE}
            bad_arms["placebo"]["checker_sha256"] = "c" * 64
            ctx2 = va.FrozenContext(manifest_sha256=_HEX, template_sha256=_HEX,
                                    samples={"TARGET": {"target_tree_sha256": fx.tree_sha,
                                                        "arms": bad_arms}},
                                    runtime=fx.runtime)
            self.assertTrue(any("checker_sha256 与冻结 arm 规格不符" in e
                                for e in ev.verify(fx.base, ctx2)))

    def test_t3_dual_reviewer_artifacts(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            self.assertEqual(fx.t3().verify(fx.base, fx.ctx), [])
            self.assertTrue(any("不得为同一人" in e for e in
                                fx.t3(reviewer2_id="R1").verify(fx.base, fx.ctx)))
            self.assertTrue(any("不得为同一文件" in e for e in
                                fx.t3(reviewer2_submission="r1.json").verify(fx.base, fx.ctx)))
            self.assertTrue(any("必须提供仲裁工件" in e for e in
                                fx.t3(reviewer2_verdict="fixed").verify(fx.base, fx.ctx)))
            adj = fx.t3(reviewer2_verdict="fixed", adjudication_path="adj.json",
                        adjudicated_verdict="still_vulnerable")
            self.assertEqual(adj.verify(fx.base, fx.ctx), [])

    def test_t3_has_no_early_return_bypass(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            for mut, needle in ((lambda e: setattr(e, "raw_result_sha256", "b" * 64),
                                 "raw_result_sha256"),
                                (lambda e: setattr(e, "oracle_parser_sha256", "c" * 64),
                                 "冻结 parser"),
                                (lambda e: setattr(e, "manifest_sha256", "d" * 64),
                                 "manifest_sha256 与冻结上下文不符"),
                                (lambda e: setattr(e, "template_sha256", "e" * 64),
                                 "template_sha256 与冻结上下文不符")):
                ev = fx.t3()
                mut(ev)
                self.assertTrue(any(needle in e for e in ev.verify(fx.base, fx.ctx)), needle)

    def test_t3_rehashes_written_materials(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            ev = fx.t3()
            _w(fx.base / "residual.md", b"changed\n")
            self.assertTrue(any("残余路径书面材料 内容 SHA" in e
                                for e in ev.verify(fx.base, fx.ctx)))
            ev2 = fx.t3()
            _w(fx.base / "r2.json", b'{"reviewer": "changed"}\n')
            self.assertTrue(any("reviewer2 submission 内容 SHA" in e
                                for e in ev2.verify(fx.base, fx.ctx)))

    def test_forged_oracle_evidence_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            forged = va.OracleEvidence(
                contract="pytest-security-regression", tier=va.ORACLE_TIER_T1,
                arm="support-only-insufficient", sample_id="TARGET",
                manifest_sha256=_HEX, template_sha256=_HEX, poc_sha256="d" * 64,
                target_tree_sha256="e" * 64, patch_sha256="f" * 64,
                command="pytest -q x", exit_code=0, raw_result="VERDICT: still_vulnerable",
                raw_result_sha256=va._sha_text("VERDICT: still_vulnerable"),
                parsed_verdict="still_vulnerable",
                oracle_parser_sha256=va.oracle_parser_sha256(),
                poc_path="poc.py", patch_path="fix.diff", target_tree_dir="tree")
            self.assertTrue(forged.verify(fx.base, fx.ctx))


# ===========================================================================
# P1：功效
# ===========================================================================
class TestPowerFirstCrossing(unittest.TestCase):
    def test_old_names_removed_and_first_crossing(self):
        for name in ("required_discordant_pairs", "required_N_for_target"):
            self.assertFalse(hasattr(vp, name))
        self.assertEqual(vp.first_crossing_m(), vp.PREREG_M_FOR_TARGET)

    def test_non_monotone_power(self):
        self.assertLess(vp.conditional_power(11, 0.90), vp.conditional_power(10, 0.90))

    def test_sustained_crossing(self):
        s = vp.sustained_crossing_m()
        self.assertTrue(s["no_drop_through_upto"])
        for q in (0.3, 0.5, 0.7):
            sN = vp.sustained_crossing_N(0.90, q)
            self.assertGreater(sN["first_crossing"], vp.PLANNED_MAX_N)
            self.assertFalse(sN["no_drop_through_upto"])

    def test_wording_and_underpowered_cells(self):
        rep = vp.power_report()
        self.assertIn("具体参数组合", rep["wording_rule"])
        self.assertIn("不等于", rep["first_crossing_naming_warning"])
        for c in vp.underpowered_cells():
            self.assertLess(c["unconditional_power"], vp.DEFAULT_TARGET_POWER)
        for bad in (0, -1, 1.5, True, "10"):
            with self.assertRaises(ValueError):
                vp.power_report(bad)

    def test_basic_statistics(self):
        self.assertEqual(vp.POWER_SCHEMA, "v4-power/4")
        self.assertNotIn("p", inspect.signature(vp.exact_two_sided_p).parameters)
        self.assertAlmostEqual(vp.exact_two_sided_p(2, 12), 0.03857, places=4)
        self.assertAlmostEqual(vp.conditional_power(8, 0.90), 0.4305, places=3)


class TestSourceHygiene(unittest.TestCase):
    def test_arms_module_hygiene(self):
        src = (ROOT / "cpg/ablation/v4_arms.py").read_text(encoding="utf-8")
        ast.parse(src)
        self.assertNotIn("ast.unparse", src)
        self.assertIn("from __future__ import annotations", src)
        self.assertEqual(va.ARMS_SCHEMA, "v4-arms/5")

    def test_apply_runner_is_real_execution(self):
        src = (ROOT / "cpg/ablation/v4_apply_runner.py").read_text(encoding="utf-8")
        self.assertIn("subprocess.run", src)
        self.assertIn("shell=False", src)
        self.assertEqual(len(ar.apply_runner_sha256()), 64)


if __name__ == "__main__":
    unittest.main()
