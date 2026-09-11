# -*- coding: utf-8 -*-
"""A-3 步 2/3/4/5（第五次返工）验收：评审 5 的 P0-1/P0-2/P0-3/P1。

本文件把**曾经被错误契约固化成 PASS 的情形**改成反向断言：
  · 模型判定曾被当作 placebo/shuffled 的接纳条件 → 现断言构造门禁**签名中不存在**
    模型输出参数，且纳入集不随模型判定变化（结果感知分母为 0）；
  · donor 自身 prompt 曾被当作 shuffled 候选 prompt → 现断言候选 prompt 来自
    target×donor 工件，token 窗口比较「基准臂 token vs 候选 token」；
  · apply-clean 曾采信自报字段 → 现断言假 post-apply 树必被拒绝；
  · T3 曾有提前返回绕过 → 现断言 T3 同样执行 raw/parser/manifest/template/工件重算；
  · 「双人确认」曾只是两个字符串 → 现断言同人 / 同文件 / 缺仲裁均被拒绝。
"""
import ast
import inspect
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from cpg.ablation import v4_arms as va  # noqa: E402
from cpg.ablation import v4_power as vp  # noqa: E402

_HEX = "a" * 64
TARGET_TOKENS = 1000


def _w(p: Path, data: bytes):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)


class Fixture:
    """完整工件目录 + 自洽的 `FrozenContext` / `FrozenRuntime`。"""

    def __init__(self, tmp):
        self.base = Path(tmp)
        b = self.base
        _w(b / "tree" / "m.py", b"x = 1\n")
        _w(b / "tree" / "pkg" / "n.py", b"pass\n")
        _w(b / "tree" / "blob.bin", b"\x00\xff\x01")
        _w(b / "post" / "m.py", b"x = 2\n")
        _w(b / "post" / "pkg" / "n.py", b"pass\n")
        _w(b / "poc.py", b"print('poc')\n")
        _w(b / "fix.diff", b"--- a\n+++ b\n")
        _w(b / "checker.py", b"assert True\n")
        _w(b / "residual.md", b"residual exploitation path\n")
        _w(b / "r1.json", b'{"reviewer": "R1"}\n')
        _w(b / "r2.json", b'{"reviewer": "R2"}\n')
        _w(b / "adj.json", b'{"adjudicator": "R3"}\n')
        self.tree_sha = va.normalized_tree_sha256(b / "tree")
        self.post_sha = va.normalized_tree_sha256(b / "post")
        self.sha = lambda n: va.file_content_sha256(b / n)[1]
        self.runtime = va.FrozenRuntime(tokenizer_sha256=_HEX, envelope_sha256=_HEX,
                                       apply_runner_sha256=_HEX)
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

    # ---- 证据构造 ----
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
        return va.TargetBaseline(sample_id="TARGET", target_tree_sha256=self.tree_sha,
                                 base_final_prompt_tokens=tokens,
                                 base_prompt_sha256=_HEX)

    def donor(self, sid="D", **kw):
        d = {"sample_id": sid, "language": "python", "cwe_family": "injection",
             "n_files": 1, "is_composite": False}
        d.update(kw)
        return d

    def donor_patch(self, sid="D"):
        return va.DonorPatch(sample_id=sid, real_patch_sha256=self.sha("fix.diff"))

    def pair(self, sid="D", tokens=950, **kw):
        kw.setdefault("post_apply_tree_dir", "post")
        kw.setdefault("donor_patch_path", "fix.diff")
        kw.setdefault("candidate_prompt_sha256", _HEX)
        kw.setdefault("apply_command", "git apply donor.diff")
        kw.setdefault("target_tree_dir", "tree")
        return va.make_pair_candidate("TARGET", sid, base_dir=self.base,
                                      candidate_final_prompt_tokens=tokens,
                                      runtime=self.runtime, **kw)

    def select(self, donors, patches=None, pairs=None, baseline=None):
        return va.select_donor(
            self.target, donors,
            target_baseline=baseline or self.baseline(),
            donor_patches=patches if patches is not None else {"D": self.donor_patch()},
            pair_candidates=pairs if pairs is not None else {"D": self.pair()},
            runtime=self.runtime, base_dir=self.base)


# ===========================================================================
# 步 2：token 搜索 —— 先过滤界内再排序
# ===========================================================================
def _cand(key, tokens):
    return va.Candidate(key=key, tokens=tokens, tokenizer_sha256=_HEX,
                        envelope_sha256=_HEX, prompt_sha256=_HEX)


class TestTokenSearchInBoundsFirst(unittest.TestCase):
    def test_named_regression_79_125_100(self):
        r = va.token_match_search([_cand("A", 79), _cand("B", 125)], 100)
        self.assertEqual(r["status"], "OK", r)
        self.assertEqual(r["selected"].key, "B")

    def test_nearer_but_out_of_bounds_never_wins(self):
        for target, items, want in [(100, [("oob", 70), ("ib", 81)], "ib"),
                                    (100, [("oob", 130), ("ib", 124)], "ib"),
                                    (1000, [("oob", 700), ("ib", 800)], "ib"),
                                    (1000, [("oob", 1300), ("ib", 1250)], "ib")]:
            with self.subTest(target=target, items=items):
                self.assertEqual(
                    va.token_match_search([_cand(k, t) for k, t in items],
                                          target)["selected"].key, want)

    def test_only_out_of_bounds_then_fail(self):
        r = va.token_match_search([_cand("A", 79), _cand("B", 70)], 100)
        self.assertEqual(r["status"], "NO_IN_BOUNDS_CANDIDATE")
        self.assertIn("不可放宽", r["reason"])

    def test_boundaries_and_auditability(self):
        for tok, want in ((80, "OK"), (125, "OK"), (79, "NO_IN_BOUNDS_CANDIDATE"),
                          (126, "NO_IN_BOUNDS_CANDIDATE")):
            with self.subTest(tok=tok):
                self.assertEqual(va.token_match_search([_cand("b", tok)], 100)["status"], want)
        r = va.token_match_search([_cand("A", 79), _cand("B", 125)], 100)
        self.assertEqual({e["key"] for e in r["excluded_out_of_bounds"]}, {"A"})

    def test_invalid_candidates_and_args(self):
        for cands in ([], [_cand("x", 100.0)], [_cand("x", 0)], [_cand("x", True)],
                      [_cand("d", 100), _cand("d", 110)], [va.Candidate(key="n", tokens=100)]):
            self.assertEqual(va.token_match_search(cands, 100)["status"], "INVALID_CANDIDATES")
        for bad in [(1.0, 0.5), (0, 1), "x", (0.8,), (0.8, 0.8), (True, 2)]:
            with self.assertRaises(ValueError):
                va.token_match_search([_cand("a", 100)], 100, bounds=bad)
        for bad in (0, -1, 1.5, True, "100"):
            with self.assertRaises(ValueError):
                va.token_match_search([_cand("a", 100)], bad)


# ===========================================================================
# P0-1（评审 5）：构造门禁不得消费模型输出（结果感知分母为 0）
# ===========================================================================
class TestNoModelOutputInInclusion(unittest.TestCase):
    MODEL_TOKENS = ("model", "verdict", "is_vulnerable", "response", "prediction",
                    "benign", "vulnerable")

    def test_construction_gate_signature_has_no_model_input(self):
        names = set(inspect.signature(va.construction_gate).parameters)
        self.assertEqual(names, {"arm", "apply_clean", "evidence", "base_dir", "ctx"})
        for n in names:
            self.assertFalse(any(t in n.lower() for t in self.MODEL_TOKENS),
                             f"构造门禁出现了疑似模型输出参数: {n}")

    def test_old_result_aware_api_removed(self):
        self.assertFalse(hasattr(va, "evaluate_arm"))

    def test_inclusion_set_invariant_under_model_verdicts(self):
        """同一批候选，模型判定取遍所有取值，纳入集恒等。"""
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            cases = [
                ("annotated-security-complete", {"evidence": fx.t1()},
                 {"base_dir": fx.base, "ctx": fx.ctx}),
                ("placebo", {}, {}),
                ("placebo", {"evidence": fx.t1(arm="placebo", verdict="still_vulnerable")},
                 {"base_dir": fx.base, "ctx": fx.ctx}),
            ]

            def eligibility():
                return [va.construction_gate(a, apply_clean=True, **ev, **extra)["eligible"]
                        for a, ev, extra in cases]

            before = eligibility()
            self.assertEqual(before, [True, True, True])
            for mv in va.MODEL_VERDICTS:
                for a, _, _ in cases:
                    va.outcome_evaluation(a, model_verdict=mv)
            self.assertEqual(eligibility(), before)

    def test_placebo_and_shuffled_need_no_oracle_and_no_model_verdict(self):
        for arm in ("placebo", "shuffled"):
            with self.subTest(arm=arm):
                r = va.construction_gate(arm, apply_clean=True)
                self.assertTrue(r["eligible"], r)
                self.assertFalse(r["consumes_model_output"])

    def test_outcome_evaluation_never_changes_inclusion(self):
        for mv in va.MODEL_VERDICTS:
            with self.subTest(mv=mv):
                r = va.outcome_evaluation("placebo", model_verdict=mv)
                self.assertIs(r["changes_inclusion"], False)
                self.assertEqual(r["is_vulnerable"], mv == "vulnerable")
        self.assertEqual(va.outcome_evaluation("placebo",
                                               model_verdict="benign")["manipulation_check"],
                         "observed-flip")
        with self.assertRaises(ValueError):
            va.outcome_evaluation("placebo", model_verdict="maybe")

    def test_oracle_required_arms_still_gated_by_oracle(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            self.assertFalse(va.construction_gate("annotated-security-complete",
                                                  apply_clean=True)["eligible"])
            self.assertTrue(va.construction_gate(
                "annotated-security-complete", apply_clean=True, evidence=fx.t1(),
                base_dir=fx.base, ctx=fx.ctx)["eligible"])
            wrong = fx.t1(verdict="still_vulnerable")
            self.assertFalse(va.construction_gate(
                "annotated-security-complete", apply_clean=True, evidence=wrong,
                base_dir=fx.base, ctx=fx.ctx)["eligible"])

    def test_placebo_rejects_non_neutral_target_state(self):
        """附加 oracle 显示目标被意外修复 → 该臂非中性，属**构造**失败（非模型筛选）。"""
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            r = va.construction_gate("placebo", apply_clean=True,
                                     evidence=fx.t1(arm="placebo", verdict="fixed"),
                                     base_dir=fx.base, ctx=fx.ctx)
            self.assertFalse(r["eligible"])
            self.assertIn("非行为中性", r["reason"])

    def test_apply_not_clean_blocks_inclusion(self):
        self.assertFalse(va.construction_gate("placebo", apply_clean=False)["eligible"])
        with self.assertRaises(KeyError):
            va.construction_gate("nope", apply_clean=True)

    def test_registry_declares_inclusion_rule(self):
        rule = va.arms_registry()["inclusion_rule"]
        self.assertIn("construction_gate", rule)
        self.assertIn("changes_inclusion", rule)


# ===========================================================================
# 步 4：oracle 分层契约（exit code 不决定漏洞状态）
# ===========================================================================
class TestOracleTierContracts(unittest.TestCase):
    def test_no_exit_code_to_verdict_mapping(self):
        self.assertFalse(hasattr(va, "EXIT_CODE_CONVENTION"))
        self.assertEqual(
            va.parse_oracle_verdict("pytest-security-regression", "1 failed", 1),
            va.ORACLE_ERROR)
        self.assertEqual(
            va.parse_oracle_verdict("pytest-security-regression", "VERDICT: fixed", 1),
            "fixed")
        self.assertEqual(
            va.parse_oracle_verdict("poc-exploit-script", "exploit done", 0),
            va.ORACLE_ERROR)
        self.assertEqual(
            va.parse_oracle_verdict("poc-exploit-script", "VERDICT: still_vulnerable", 0),
            "still_vulnerable")

    def test_infra_and_unknown_exit_codes(self):
        for name, c in va.ORACLE_CONTRACTS.items():
            if not c.machine_decidable:
                continue
            for code in c.infra_exit_codes:
                with self.subTest(contract=name, code=code):
                    self.assertEqual(va.parse_oracle_verdict(name, "VERDICT: fixed", code),
                                     va.ORACLE_ERROR)
        self.assertEqual(
            va.parse_oracle_verdict("pytest-security-regression", "VERDICT: fixed", 99),
            va.ORACLE_ERROR)

    def test_marker_rules(self):
        for raw, want in [("no marker", va.ORACLE_ERROR),
                          ("VERDICT: maybe", va.ORACLE_ERROR),
                          ("VERDICT: fixed\nVERDICT: still_vulnerable", va.ORACLE_ERROR),
                          ("VERDICT: still_vulnerable", "still_vulnerable"),
                          ("  VERDICT: FIXED  ", "fixed"),
                          ("not a marker: VERDICT: fixed", va.ORACLE_ERROR)]:
            with self.subTest(raw=raw):
                self.assertEqual(
                    va.parse_oracle_verdict("pytest-security-regression", raw, 0), want)

    def test_t3_not_machine_decidable(self):
        with self.assertRaises(ValueError):
            va.parse_oracle_verdict("reviewer-residual-path", "VERDICT: fixed", 0)
        with self.assertRaises(ValueError):
            va.parse_oracle_verdict("nope", "x", 0)

    def test_derive_t3_verdict(self):
        self.assertEqual(va.derive_t3_verdict("fixed", "fixed", ""), "fixed")
        self.assertEqual(va.derive_t3_verdict("fixed", "still_vulnerable",
                                              "still_vulnerable"), "still_vulnerable")
        self.assertEqual(va.derive_t3_verdict("fixed", "still_vulnerable", ""),
                         va.ORACLE_ERROR)
        self.assertEqual(va.derive_t3_verdict("fixed", "bogus", "fixed"), va.ORACLE_ERROR)

    def test_registry_documents_tiers(self):
        reg = va.contracts_registry()
        self.assertEqual(set(reg["tiers"]), set(va.ORACLE_TIERS))
        self.assertIn("不可机器判定", reg["tiers"][va.ORACLE_TIER_T3])
        self.assertIn("不参与", reg["exit_code_role"])
        self.assertIn("分别报告", reg["separation_rule"])
        for name, c in reg["contracts"].items():
            with self.subTest(contract=name):
                for f in ("command_template", "tool_version", "valid_exit_codes",
                          "infra_exit_codes", "control_samples", "fault_injection",
                          "machine_decidable", "notes"):
                    self.assertIn(f, c)
                self.assertTrue(c["control_samples"])
                self.assertTrue(c["fault_injection"])

    def test_parser_sha_stable(self):
        self.assertEqual(len(va.oracle_parser_sha256()), 64)
        self.assertEqual(va.oracle_parser_sha256(), va.oracle_parser_sha256())
        self.assertEqual(va.oracle_parser_sha256(),
                         va.arms_registry()["oracle_parser_sha256"])


# ===========================================================================
# P0-2（评审 5）：PairCandidateArtifact 与实际 post-apply 树重算
# ===========================================================================
class TestPairCandidateBinding(unittest.TestCase):
    def test_valid_selection_reports_token_window(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            r = fx.select([fx.donor()])
            self.assertEqual(r["status"], "OK", r)
            self.assertEqual(r["token_window"]["base_final_prompt_tokens"], TARGET_TOKENS)
            self.assertEqual(r["token_window"]["candidate_final_prompt_tokens"], 950)
            self.assertAlmostEqual(r["token_window"]["ratio"], 0.95, places=6)

    def test_token_window_uses_baseline_vs_candidate(self):
        """候选 token 与**基准臂**比较，而不是 donor 自身 prompt。"""
        for tok, want in ((790, "NO_DONOR"), (800, "OK"), (1250, "OK"), (1260, "NO_DONOR")):
            with self.subTest(tok=tok):
                with tempfile.TemporaryDirectory() as t:
                    fx = Fixture(t)
                    r = fx.select([fx.donor()], pairs={"D": fx.pair(tokens=tok)})
                    self.assertEqual(r["status"], want, r)

    def test_forged_post_apply_tree_is_rejected(self):
        """**评审 5 P0-2 点名的反例**：自报 post-apply SHA 与实际目录不符 → 必拒。"""
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            pc = fx.pair()
            pc.post_apply_tree_sha256 = "9" * 64
            pc.apply_record.post_apply_tree_sha256 = "9" * 64
            r = fx.select([fx.donor()], pairs={"D": pc})
            self.assertEqual(r["status"], "NO_DONOR", r)
            joined = " ".join(r["hard_reject_reasons"][0]["reasons"])
            self.assertIn("post-apply 树 SHA 与实际目录不符", joined)

    def test_post_apply_dir_content_swap_is_rejected(self):
        """同一工件复用：目录内容被换后，原先记录的 post-apply SHA 必须失效。"""
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            pc = fx.pair()                      # 先按当前目录内容定型
            r = fx.select([fx.donor()], pairs={"D": pc})
            self.assertEqual(r["status"], "OK", r)
            _w(fx.base / "post" / "m.py", b"x = 3\n")
            r2 = fx.select([fx.donor()], pairs={"D": pc})
            self.assertEqual(r2["status"], "NO_DONOR", r2)
            joined = " ".join(r2["hard_reject_reasons"][0]["reasons"])
            self.assertIn("post-apply 树 SHA 与实际目录不符", joined)

    def test_post_apply_identical_to_target_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            pc = fx.pair()
            pc.post_apply_tree_sha256 = fx.tree_sha
            pc.apply_record.post_apply_tree_sha256 = fx.tree_sha
            r = fx.select([fx.donor()], pairs={"D": pc})
            self.assertEqual(r["status"], "NO_DONOR")

    def test_missing_post_dir_or_apply_record_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            pc = fx.pair()
            pc.post_apply_tree_dir = None
            self.assertIn("post_apply_tree_dir", " ".join(pc.errors()))
            pc2 = fx.pair()
            pc2.apply_record = None
            self.assertIn("apply_record", " ".join(pc2.errors()))

    def test_apply_record_binding(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            pc = fx.pair()
            pc.apply_record.runner_sha256 = "7" * 64
            r = fx.select([fx.donor()], pairs={"D": pc})
            self.assertEqual(r["status"], "NO_DONOR")
            pc2 = fx.pair()
            pc2.apply_record.exit_code = 1
            self.assertIn("exit_code", " ".join(pc2.apply_record.errors()))

    def test_tree_patch_runtime_and_identity_bindings(self):
        cases = ["target_tree_sha256", "donor_patch_sha256", "tokenizer_sha256",
                 "envelope_sha256", "target_id", "donor_id"]
        for f in cases:
            with self.subTest(field=f):
                with tempfile.TemporaryDirectory() as t:
                    fx = Fixture(t)
                    pc = fx.pair()
                    setattr(pc, f, "9" * 64 if "sha256" in f else "OTHER")
                    r = fx.select([fx.donor()], pairs={"D": pc})
                    self.assertEqual(r["status"], "NO_DONOR", (f, r))

    def test_authority_missing_fail_closed(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            r = va.select_donor(fx.target, [fx.donor()], target_baseline=None,
                                donor_patches={"D": fx.donor_patch()},
                                pair_candidates={"D": fx.pair()},
                                runtime=fx.runtime, base_dir=fx.base)
            self.assertEqual(r["status"], "NO_AUTHORITY")
            r2 = va.select_donor(fx.target, [fx.donor()], target_baseline=fx.baseline(),
                                 donor_patches={"D": fx.donor_patch()},
                                 pair_candidates={"D": fx.pair()},
                                 runtime=None, base_dir=fx.base)
            self.assertEqual(r2["status"], "NO_AUTHORITY")

    def test_donor_ne_target_and_missing_artifacts(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            self.assertEqual(fx.select([fx.donor(sid="TARGET")])["status"], "NO_DONOR")
            r = fx.select([fx.donor()], pairs={})
            self.assertEqual(r["status"], "NO_DONOR")
            self.assertIn("pair_candidate", " ".join(r["hard_reject_reasons"][0]["reasons"]))

    def test_soft_relaxation_and_covariates(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            r = fx.select([fx.donor(language="java")])
            self.assertEqual(r["status"], "OK", r)
            self.assertEqual(r["relaxations"][0], "not_composite")
            self.assertEqual(set(r["covariates"]), {"target", "donor"})
            self.assertIn("candidate_final_prompt_tokens", va.COVARIATE_FIELDS)

    def test_registry_documents_pair_candidate(self):
        sh = va.arms_registry()["shuffle"]
        self.assertEqual(set(sh["pair_candidate_fields"]), set(va.PAIR_CANDIDATE_FIELDS))
        self.assertEqual(set(sh["apply_record_fields"]), set(va.APPLY_RECORD_FIELDS))
        self.assertIn("实际 post-apply 树重算", sh["binding"])
        self.assertIn("基准臂", sh["token_window_semantics"])


# ===========================================================================
# P0-3（评审 5）：T1/T2/T3 严格 provenance（无提前返回绕过）
# ===========================================================================
class TestOracleStrictProvenance(unittest.TestCase):
    def test_t1_valid_and_tree_swap_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            ev = fx.t1()
            self.assertEqual(ev.verify(fx.base, fx.ctx), [])
            _w(fx.base / "tree" / "m.py", b"x = 999\n")
            self.assertTrue(any("target 树 SHA" in e for e in ev.verify(fx.base, fx.ctx)))
            _w(fx.base / "tree" / "m.py", b"x = 1\n")
            self.assertEqual(ev.verify(fx.base, fx.ctx), [])

    def test_t1_requires_all_artifacts(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            for drop in ("poc_path", "patch_path", "target_tree_dir"):
                with self.subTest(drop=drop):
                    ev = fx.t1(**{drop: None})
                    self.assertTrue(any("强制要求工件引用" in e
                                        for e in ev.verify(fx.base, fx.ctx)))

    def test_t2_requires_and_rehashes_checker(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            ev = fx.t2()
            self.assertEqual(ev.verify(fx.base, fx.ctx), [])
            # ③ 反例：checker 内容被替换
            _w(fx.base / "checker.py", b"assert False  # tampered\n")
            errs = ev.verify(fx.base, fx.ctx)
            self.assertTrue(any("checker 内容 SHA" in e for e in errs), errs)
            _w(fx.base / "checker.py", b"assert True\n")
            self.assertEqual(ev.verify(fx.base, fx.ctx), [])
            # checker 路径缺失 → 拒绝
            self.assertTrue(any("强制要求工件引用 checker_path" in e
                                for e in fx.t2(checker_path=None).verify(fx.base, fx.ctx)))

    def test_t2_checker_bound_to_frozen_arm_spec(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            old = dict(fx.ctx.samples["TARGET"])
            bad_arms = {a: dict(old["arms"][a]) for a in va.ARM_ORACLE}
            bad_arms["placebo"]["checker_sha256"] = "c" * 64
            ctx2 = va.FrozenContext(manifest_sha256=_HEX, template_sha256=_HEX,
                                    samples={"TARGET": {"target_tree_sha256": fx.tree_sha,
                                                        "arms": bad_arms}},
                                    runtime=fx.runtime)
            errs = fx.t2().verify(fx.base, ctx2)
            self.assertTrue(any("checker_sha256 与冻结 arm 规格不符" in e for e in errs), errs)

    def test_t3_valid_dual_submission(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            self.assertEqual(fx.t3().verify(fx.base, fx.ctx), [])

    def test_t3_forged_reviewers_rejected(self):
        """④ 反例：伪造 T3 reviewer（同人 / 同文件 / 缺仲裁）。"""
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            same_person = fx.t3(reviewer2_id="R1")
            self.assertTrue(any("不得为同一人" in e
                                for e in same_person.verify(fx.base, fx.ctx)))
            same_file = fx.t3(reviewer2_submission="r1.json")
            self.assertTrue(any("不得为同一文件" in e
                                for e in same_file.verify(fx.base, fx.ctx)))
            disagree = fx.t3(reviewer2_verdict="fixed")
            self.assertEqual(disagree.parsed_verdict, va.ORACLE_ERROR)
            errs = disagree.verify(fx.base, fx.ctx)
            self.assertTrue(any("必须提供仲裁工件" in e for e in errs), errs)
            missing_ids = fx.t3(reviewer1_id="", reviewer2_id="")
            self.assertTrue(any("reviewer1_id" in e
                                for e in missing_ids.verify(fx.base, fx.ctx)))

    def test_t3_disagreement_with_adjudication_passes(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            ev = fx.t3(reviewer2_verdict="fixed", adjudication_path="adj.json",
                       adjudicated_verdict="still_vulnerable")
            self.assertEqual(ev.parsed_verdict, "still_vulnerable")
            self.assertEqual(ev.verify(fx.base, fx.ctx), [])
            bad = fx.t3(reviewer2_verdict="fixed", adjudication_path="adj.json")
            self.assertTrue(any("adjudicated_verdict" in e
                                for e in bad.verify(fx.base, fx.ctx)))

    def test_t3_has_no_early_return_bypass(self):
        """**评审 5 P0-3 的核心**：T3 必须同样执行通用 provenance 检查。"""
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            self.assertEqual(fx.t3().verify(fx.base, fx.ctx), [], "基线应通过")

            ev = fx.t3()
            ev.raw_result_sha256 = "b" * 64
            self.assertTrue(any("raw_result_sha256" in e for e in ev.verify(fx.base, fx.ctx)))

            ev2 = fx.t3()
            ev2.oracle_parser_sha256 = "c" * 64
            self.assertTrue(any("冻结 parser" in e for e in ev2.verify(fx.base, fx.ctx)))

            ev3 = fx.t3()
            ev3.manifest_sha256 = "d" * 64
            self.assertTrue(any("manifest_sha256 与冻结上下文不符" in e
                                for e in ev3.verify(fx.base, fx.ctx)))

            ev4 = fx.t3()
            ev4.template_sha256 = "e" * 64
            self.assertTrue(any("template_sha256 与冻结上下文不符" in e
                                for e in ev4.verify(fx.base, fx.ctx)))

            ev5 = fx.t3()
            ev5.sample_id = "OTHER"
            self.assertTrue(any("无样本" in e for e in ev5.verify(fx.base, fx.ctx)))

            ev6 = fx.t3()
            ev6.arm = "shuffled"
            limited = va.FrozenContext(
                manifest_sha256=_HEX, template_sha256=_HEX,
                samples={"TARGET": {"target_tree_sha256": fx.tree_sha,
                                    "arms": {"placebo": dict(
                                        fx.ctx.samples["TARGET"]["arms"]["placebo"])}}},
                runtime=fx.runtime)
            errs6 = ev6.verify(fx.base, limited)
            self.assertTrue(any("无 arm 规格" in e for e in errs6), errs6)

    def test_t3_rehashes_written_materials(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            ev = fx.t3()
            _w(fx.base / "residual.md", b"changed residual path\n")
            self.assertTrue(any("残余路径书面材料 内容 SHA" in e
                                for e in ev.verify(fx.base, fx.ctx)))
            _w(fx.base / "residual.md", b"residual exploitation path\n")
            ev2 = fx.t3()
            _w(fx.base / "r2.json", b'{"reviewer": "R2-changed"}\n')
            self.assertTrue(any("reviewer2 submission 内容 SHA" in e
                                for e in ev2.verify(fx.base, fx.ctx)))

    def test_t3_conclusion_must_match_marker(self):
        """两人一致判 fixed，但书面材料标记行写 still_vulnerable → 自相矛盾，拒绝。"""
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            ev = fx.t3(raw="review notes\nVERDICT: still_vulnerable\n",
                       reviewer1_verdict="fixed", reviewer2_verdict="fixed")
            self.assertEqual(ev.parsed_verdict, "fixed")
            errs = ev.verify(fx.base, fx.ctx)
            self.assertTrue(any("标记行一致" in e for e in errs), errs)
            # 结论被篡改（派生结果与 parsed_verdict 不符）同样被拒
            ev2 = fx.t3()
            ev2.parsed_verdict = "fixed"
            self.assertTrue(ev2.verify(fx.base, fx.ctx))

    def test_context_and_forgery_fail_closed(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            self.assertEqual(fx.t1().verify(fx.base, None),
                             ["缺冻结上下文 FrozenContext（fail-closed）"])
            forged = va.OracleEvidence(
                contract="pytest-security-regression", tier=va.ORACLE_TIER_T1,
                arm="annotated-security-complete", sample_id="TARGET",
                manifest_sha256=_HEX, template_sha256=_HEX, poc_sha256="d" * 64,
                target_tree_sha256="e" * 64, patch_sha256="f" * 64,
                command="pytest -q x", exit_code=0, raw_result="VERDICT: fixed",
                raw_result_sha256=va._sha_text("VERDICT: fixed"), parsed_verdict="fixed",
                oracle_parser_sha256=va.oracle_parser_sha256(),
                poc_path="poc.py", patch_path="fix.diff", target_tree_dir="tree")
            errs = forged.verify(fx.base, fx.ctx)
            self.assertTrue(errs, "伪造证据竟然通过")
            self.assertFalse(va.construction_gate(
                "annotated-security-complete", apply_clean=True, evidence=forged,
                base_dir=fx.base, ctx=fx.ctx)["eligible"])

    def test_tier_mismatch_and_bad_hex(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            ev = fx.t1()
            ev.tier = va.ORACLE_TIER_T2
            self.assertTrue(any("tier 与契约不符" in e for e in ev.verify(fx.base, fx.ctx)))
            ev2 = fx.t1()
            ev2.poc_sha256 = "nothex"
            self.assertTrue(ev2.verify(fx.base, fx.ctx))


# ===========================================================================
# P1：功效 —— 首次跨越命名 / 措辞绑定
# ===========================================================================
class TestPowerFirstCrossing(unittest.TestCase):
    def test_old_misleading_names_removed(self):
        for name in ("required_discordant_pairs", "required_N_for_target"):
            self.assertFalse(hasattr(vp, name), f"{name} 应已改名")

    def test_conditional_power_is_not_monotone(self):
        self.assertLess(vp.conditional_power(11, 0.90), vp.conditional_power(10, 0.90))

    def test_first_crossing_matches_prereg(self):
        self.assertEqual(vp.first_crossing_m(), vp.PREREG_M_FOR_TARGET)
        self.assertEqual(vp.first_crossing_m(), 12)
        self.assertIn("不等于", vp.power_report()["first_crossing_naming_warning"])

    def test_sustained_crossing_m_no_drop(self):
        s = vp.sustained_crossing_m()
        self.assertEqual(s["first_crossing"], 12)
        self.assertTrue(s["no_drop_through_upto"])
        self.assertEqual(s["n_drops"], 0)

    def test_sustained_crossing_beyond_window_not_claimable(self):
        for q in (0.3, 0.5, 0.7):
            with self.subTest(q=q):
                s = vp.sustained_crossing_N(0.90, q)
                self.assertGreater(s["first_crossing"], vp.PLANNED_MAX_N)
                self.assertFalse(s["no_drop_through_upto"])
                self.assertIsNone(s["contiguous_end"])
                self.assertIn("不得", s["claim"])

    def test_enforce_upto_validation(self):
        with self.assertRaises(ValueError):
            vp.sustained_crossing_m(enforce_upto=0)
        with self.assertRaises(ValueError):
            vp.sustained_crossing_N(enforce_upto=-3)
        self.assertFalse(vp.sustained_crossing_m(enforce_upto=11)["no_drop_through_upto"])

    def test_underpowered_combinations_are_specific(self):
        cells = vp.underpowered_cells()
        self.assertTrue(cells)
        for c in cells:
            with self.subTest(c=c):
                for f in ("N", "p1", "discordance"):
                    self.assertIn(f, c)
                self.assertLess(c["unconditional_power"], vp.DEFAULT_TARGET_POWER)

    def test_wording_rule_binds_to_combinations(self):
        rule = vp.power_report()["wording_rule"]
        self.assertIn("具体参数组合", rule)
        self.assertIn("不得对整张敏感性表作笼统判断", rule)
        self.assertIn("不得据此单独推断模型真实判别能力", rule)

    def test_N_active_source_and_validation(self):
        rep = vp.power_report()
        self.assertEqual(rep["N_active"], vp.PLANNED_MAX_N)
        self.assertIn("planned_max", rep["N_source"])
        self.assertIn("frozen active universe", vp.power_report(10)["N_source"])
        for bad in (0, -1, 1.5, True, "10"):
            with self.assertRaises(ValueError):
                vp.power_report(bad)
        with self.assertRaises(ValueError):
            vp.power_report(vp.PLANNED_MAX_N + 1)

    def test_schema_and_basic_statistics(self):
        self.assertEqual(vp.POWER_SCHEMA, "v4-power/4")
        self.assertNotIn("p", inspect.signature(vp.exact_two_sided_p).parameters)
        self.assertAlmostEqual(vp.exact_two_sided_p(2, 12), 0.03857, places=4)
        self.assertAlmostEqual(vp.conditional_power(8, 0.90), 0.4305, places=3)
        self.assertGreater(vp.unconditional_power(40, 0.90, 0.5),
                           vp.unconditional_power(10, 0.90, 0.5))
        self.assertAlmostEqual(vp.unconditional_power(14, 0.90, 1.0),
                               vp.conditional_power(14, 0.90), places=12)

    def test_homogeneity_assumptions_declared(self):
        rep = vp.power_report()
        self.assertEqual(tuple(rep["homogeneity_assumptions"]),
                         tuple(vp.HOMOGENEITY_ASSUMPTIONS))
        self.assertIn("仅", rep["assumption_scope_note"])

    def test_bad_inputs(self):
        with self.assertRaises(ValueError):
            vp.conditional_power(10, 1.5)
        with self.assertRaises(ValueError):
            vp.unconditional_power(10, 0.9, 1.5)


# ===========================================================================
# 结构守卫
# ===========================================================================
class TestSourceHygiene(unittest.TestCase):
    def test_no_unparse_and_ast_parses(self):
        src = (ROOT / "cpg/ablation/v4_arms.py").read_text(encoding="utf-8")
        ast.parse(src)
        self.assertNotIn("ast.unparse", src)
        self.assertIn("from __future__ import annotations", src)

    def test_arms_schema_version(self):
        self.assertEqual(va.ARMS_SCHEMA, "v4-arms/5")
        self.assertEqual(va.arms_registry()["schema"], va.ARMS_SCHEMA)


if __name__ == "__main__":
    unittest.main()
