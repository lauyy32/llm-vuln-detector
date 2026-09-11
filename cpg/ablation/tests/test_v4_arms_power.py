# -*- coding: utf-8 -*-
"""A-3 步 2/3/4/5（第三次返工）验收：评审 4 的 P0-1/P0-2/P0-3/P1 + 两处自查。

本文件的存在意义：把**曾经被错误契约固化成 PASS 的情形**改成反向断言，例如
  · 退出码 1 曾被解读为「漏洞仍存在」——现断言它**不得**决定漏洞状态；
  · 不提供工件路径时曾被期待通过 —— 现断言 T1/T2 缺工件引用即拒绝；
  · 换目录内容保留旧 tree SHA 曾无法被发现 —— 现断言必被拒绝；
  · placebo 曾被强制要求 oracle 证据 —— 现断言按预注册 §3.3 不要求。
"""
import ast
import hashlib
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


# ===========================================================================
# 夹具
# ===========================================================================
def _w(p: Path, data: bytes):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)


class Fixture:
    """临时工件目录 + 与之自洽的 `FrozenContext`。"""

    def __init__(self, tmp):
        self.base = Path(tmp)
        _w(self.base / "tree" / "m.py", b"x = 1\n")
        _w(self.base / "tree" / "pkg" / "n.py", b"print('hi')\n")
        _w(self.base / "tree" / "blob.bin", b"\x00\xff\x01")
        _w(self.base / "poc.py", b"print('poc')\n")
        _w(self.base / "fix.diff", b"--- a\n+++ b\n")
        self.tree_sha = va.normalized_tree_sha256(self.base / "tree")
        self.poc_sha = va.file_content_sha256(self.base / "poc.py")[1]
        self.patch_sha = va.file_content_sha256(self.base / "fix.diff")[1]
        arms = {a: {"poc_sha256": self.poc_sha, "patch_sha256": self.patch_sha}
                for a in va.ARM_ORACLE}
        self.ctx = va.FrozenContext(
            manifest_sha256=_HEX,
            samples={"TARGET": {"target_tree_sha256": self.tree_sha, "arms": arms}},
            runtime=va.FrozenRuntime(tokenizer_sha256=_HEX, envelope_sha256=_HEX))

    def t1(self, arm="annotated-security-complete", verdict="fixed", code=0, **kw):
        raw = kw.pop("raw", f"collected 1 item\nVERDICT: {verdict}\n")
        kw.setdefault("poc_path", "poc.py")
        kw.setdefault("patch_path", "fix.diff")
        kw.setdefault("target_tree_dir", "tree")
        kw.setdefault("command", "pytest -q tests/security/test_x.py")
        return va.make_evidence("pytest-security-regression", arm, "TARGET", raw, code,
                               base_dir=self.base, context=self.ctx, **kw)

    def t2(self, arm="placebo", verdict="still_vulnerable", code=0, **kw):
        raw = kw.pop("raw", f"checked\nVERDICT: {verdict}\n")
        kw.setdefault("patch_path", "fix.diff")
        kw.setdefault("target_tree_dir", "tree")
        kw.setdefault("command", "python checker.py --target tree")
        kw.setdefault("checker_sha256", _HEX)
        return va.make_evidence("semantic-assertion", arm, "TARGET", raw, code,
                               base_dir=self.base, context=self.ctx, **kw)

    def t3(self, arm="placebo", verdict="still_vulnerable", agreement=True, **kw):
        raw = kw.pop("raw", f"review notes\nVERDICT: {verdict}\n")
        kw.setdefault("residual_path_sha256", _HEX)
        kw.setdefault("reviewer_1", "R1")
        kw.setdefault("reviewer_2", "R2")
        kw.setdefault("command", "manual review")
        return va.make_evidence("reviewer-residual-path", arm, "TARGET", raw, 0,
                               base_dir=self.base, context=self.ctx,
                               agreement=agreement, **kw)


# ===========================================================================
# 步 2：token 搜索 —— 先过滤界内再排序
# ===========================================================================
def _cand(key, tokens):
    return va.Candidate(key=key, tokens=tokens, tokenizer_sha256=_HEX,
                        envelope_sha256=_HEX, prompt_sha256=_HEX)


class TestTokenSearchInBoundsFirst(unittest.TestCase):
    def test_named_regression_79_125_100(self):
        """A=79（0.79 超界，差 21）、B=125（1.25 界内，差 25）→ 必须选 B。"""
        r = va.token_match_search([_cand("A", 79), _cand("B", 125)], 100)
        self.assertEqual(r["status"], "OK", r)
        self.assertEqual(r["selected"].key, "B")
        self.assertEqual(r["int_distance"], 25)

    def test_nearer_but_out_of_bounds_never_wins(self):
        cases = [(100, [("near_oob", 70), ("far_ib", 81)], "far_ib"),
                 (100, [("near_oob", 130), ("far_ib", 124)], "far_ib"),
                 (1000, [("near_oob", 700), ("far_ib", 800)], "far_ib"),
                 (1000, [("near_oob", 1300), ("far_ib", 1250)], "far_ib")]
        for target, items, want in cases:
            with self.subTest(target=target, items=items):
                r = va.token_match_search([_cand(k, t) for k, t in items], target)
                self.assertEqual(r["selected"].key, want)

    def test_only_out_of_bounds_then_fail(self):
        r = va.token_match_search([_cand("A", 79), _cand("B", 70)], 100)
        self.assertEqual(r["status"], "NO_IN_BOUNDS_CANDIDATE")
        self.assertIn("不可放宽", r["reason"])
        self.assertEqual(r["closest"]["key"], "A")

    def test_boundary_ratios_inclusive(self):
        for tok, want in ((80, "OK"), (125, "OK"), (79, "NO_IN_BOUNDS_CANDIDATE"),
                          (126, "NO_IN_BOUNDS_CANDIDATE")):
            with self.subTest(tok=tok):
                self.assertEqual(
                    va.token_match_search([_cand("b", tok)], 100)["status"], want)

    def test_exclusion_is_auditable(self):
        r = va.token_match_search([_cand("A", 79), _cand("B", 125)], 100)
        self.assertEqual({t["key"] for t in r["trace"]}, {"B"})
        exc = {e["key"]: e for e in r["excluded_out_of_bounds"]}
        self.assertEqual(set(exc), {"A"})
        self.assertAlmostEqual(exc["A"]["ratio"], 0.79, places=6)
        self.assertIn("界外候选不参与排序", r["filter_policy"])

    def test_order_independent_and_tie_break(self):
        items = [_cand("A", 79), _cand("B", 125), _cand("C", 100)]
        self.assertEqual(va.token_match_search(items, 100)["selected"].key,
                         va.token_match_search(list(reversed(items)), 100)["selected"].key)
        r = va.token_match_search([_cand("zzz", 90), _cand("aaa", 110)], 100)
        self.assertEqual(r["selected"].key, "aaa")

    def test_invalid_candidates_and_args(self):
        for cands in ([], [_cand("x", 100.0)], [_cand("x", 0)], [_cand("x", True)],
                      [_cand("d", 100), _cand("d", 110)],
                      [va.Candidate(key="n", tokens=100)]):
            with self.subTest(cands=len(cands)):
                self.assertEqual(
                    va.token_match_search(cands, 100)["status"], "INVALID_CANDIDATES")
        for bad in [(1.0, 0.5), (0, 1), "x", (0.8,), (0.8, 0.8), (True, 2)]:
            with self.assertRaises(ValueError):
                va.token_match_search([_cand("a", 100)], 100, bounds=bad)
        for bad in (0, -1, 1.5, True, "100"):
            with self.assertRaises(ValueError):
                va.token_match_search([_cand("a", 100)], bad)


# ===========================================================================
# P0-3：oracle 分层契约（exit code **不**决定漏洞状态）
# ===========================================================================
class TestOracleTierContracts(unittest.TestCase):
    def test_no_exit_code_to_verdict_mapping_exists(self):
        """旧版 `EXIT_CODE_CONVENTION` 必须已被彻底移除。"""
        self.assertFalse(hasattr(va, "EXIT_CODE_CONVENTION"))

    def test_exit_code_does_not_determine_verdict(self):
        # pytest exit 1（有测试失败）不再是「漏洞仍存在」的证据
        self.assertEqual(
            va.parse_oracle_verdict("pytest-security-regression", "1 failed", 1),
            va.ORACLE_ERROR)
        # 同一 exit 1，标记行给 fixed → 必须以标记为准
        self.assertEqual(
            va.parse_oracle_verdict("pytest-security-regression", "VERDICT: fixed", 1),
            "fixed")
        # PoC exit 0 不再自动等于 fixed（旧版自相矛盾处）
        self.assertEqual(
            va.parse_oracle_verdict("poc-exploit-script", "exploit done", 0),
            va.ORACLE_ERROR)
        self.assertEqual(
            va.parse_oracle_verdict("poc-exploit-script",
                                    "VERDICT: still_vulnerable", 0),
            "still_vulnerable")

    def test_infra_exit_codes_yield_oracle_error(self):
        for name, c in va.ORACLE_CONTRACTS.items():
            if not c.machine_decidable:
                continue
            for code in c.infra_exit_codes:
                with self.subTest(contract=name, code=code):
                    self.assertEqual(
                        va.parse_oracle_verdict(name, "VERDICT: fixed", code),
                        va.ORACLE_ERROR)

    def test_unknown_exit_code_is_oracle_error(self):
        self.assertEqual(
            va.parse_oracle_verdict("pytest-security-regression", "VERDICT: fixed", 99),
            va.ORACLE_ERROR)

    def test_marker_required_and_unambiguous(self):
        cases = [("no marker here", va.ORACLE_ERROR),
                 ("VERDICT: maybe", va.ORACLE_ERROR),
                 ("VERDICT: fixed\nVERDICT: still_vulnerable", va.ORACLE_ERROR),
                 ("VERDICT: still_vulnerable\nVERDICT: still_vulnerable",
                  "still_vulnerable"),
                 ("  VERDICT: FIXED  ", "fixed"),          # 行首 + 大小写不敏感
                 ("not a marker: VERDICT: fixed", va.ORACLE_ERROR)]  # 非行首不识别
        for raw, want in cases:
            with self.subTest(raw=raw):
                self.assertEqual(
                    va.parse_oracle_verdict("pytest-security-regression", raw, 0), want)

    def test_unknown_contract_and_t3_raise(self):
        with self.assertRaises(ValueError):
            va.parse_oracle_verdict("nope", "x", 0)
        with self.assertRaises(ValueError):
            va.parse_oracle_verdict("reviewer-residual-path", "VERDICT: fixed", 0)

    def test_tiers_are_declared_and_separated(self):
        reg = va.contracts_registry()
        self.assertEqual(set(reg["tiers"]), set(va.ORACLE_TIERS))
        self.assertIn("不可机器判定", reg["tiers"][va.ORACLE_TIER_T3])
        self.assertIn("不参与", reg["exit_code_role"])
        self.assertIn("分别报告", reg["separation_rule"])
        # 每个契约必须自带命令/版本/退出码语义/对照样本/故障注入
        for name, c in reg["contracts"].items():
            with self.subTest(contract=name):
                for f in ("command_template", "tool_version", "valid_exit_codes",
                          "infra_exit_codes", "control_samples", "fault_injection",
                          "machine_decidable", "notes"):
                    self.assertIn(f, c)
                self.assertTrue(c["notes"])
                self.assertTrue(c["control_samples"])
                self.assertTrue(c["fault_injection"])

    def test_parser_sha_binds_contracts(self):
        sha = va.oracle_parser_sha256()
        self.assertEqual(len(sha), 64)
        self.assertEqual(sha, va.oracle_parser_sha256())
        self.assertEqual(sha, va.arms_registry()["oracle"]["contracts"]["pytest-security-regression"]
                         and va.arms_registry()["oracle_parser_sha256"])
        src = (inspect.getsource(va.read_verdict_marker)
               + inspect.getsource(va.parse_oracle_verdict))
        self.assertTrue(src.strip())

    def test_oracle_error_is_distinct_from_binary(self):
        self.assertIn(va.ORACLE_ERROR, va.ORACLE_VERDICT_VALUES)
        self.assertNotIn(va.ORACLE_ERROR, va.VALID_ORACLE_RESULTS)


# ===========================================================================
# P0-1：严格工件绑定与 tree SHA 重算
# ===========================================================================
class TestOracleStrictArtifactBinding(unittest.TestCase):
    def test_valid_t1_evidence_passes(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            self.assertEqual(fx.t1().verify(fx.base, fx.ctx), [])

    def test_swapping_tree_content_with_stale_sha_is_rejected(self):
        """**评审 4 P0-1 点名的反例**：目录内容被换、tree SHA 记录不变 → 必须拒绝。"""
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            ev = fx.t1()
            self.assertEqual(ev.verify(fx.base, fx.ctx), [])
            _w(fx.base / "tree" / "m.py", b"x = 2\n")      # 内容被换
            errs = ev.verify(fx.base, fx.ctx)
            self.assertTrue(any("target 树 SHA" in e for e in errs), errs)
            _w(fx.base / "tree" / "m.py", b"x = 1\n")      # 还原
            self.assertEqual(ev.verify(fx.base, fx.ctx), [])

    def test_adding_or_removing_file_changes_tree_sha(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            ev = fx.t1()
            _w(fx.base / "tree" / "extra.py", b"y = 1\n")
            self.assertTrue(any("target 树 SHA" in e for e in ev.verify(fx.base, fx.ctx)))
            (fx.base / "tree" / "extra.py").unlink()
            self.assertEqual(ev.verify(fx.base, fx.ctx), [])

    def test_crlf_does_not_change_tree_sha(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            base_sha = fx.tree_sha
            _w(fx.base / "tree" / "m.py", b"x = 1\r\n")
            self.assertEqual(va.normalized_tree_sha256(fx.base / "tree"), base_sha)

    def test_binary_files_use_raw_bytes_mode(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            self.assertEqual(va.file_content_sha256(fx.base / "tree" / "blob.bin")[0],
                             va.HASH_MODE_BYTES)
            self.assertEqual(va.file_content_sha256(fx.base / "tree" / "m.py")[0],
                             va.HASH_MODE_TEXT)

    def test_missing_tree_dir_raises(self):
        with tempfile.TemporaryDirectory() as t:
            with self.assertRaises(FileNotFoundError):
                va.normalized_tree_sha256(Path(t) / "nope")

    def test_poc_and_patch_content_are_rehashed(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            ev = fx.t1()
            _w(fx.base / "poc.py", b"print('changed')\n")
            self.assertTrue(any("PoC 内容 SHA" in e for e in ev.verify(fx.base, fx.ctx)))
            _w(fx.base / "poc.py", b"print('poc')\n")
            _w(fx.base / "fix.diff", b"--- c\n")
            self.assertTrue(any("patch 内容 SHA" in e for e in ev.verify(fx.base, fx.ctx)))

    def test_missing_artifact_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            ev = fx.t1()
            (fx.base / "poc.py").unlink()
            self.assertTrue(any("不存在" in e for e in ev.verify(fx.base, fx.ctx)))

    def test_t1_requires_all_artifact_refs(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            for drop in ("poc_path", "patch_path", "target_tree_dir"):
                with self.subTest(drop=drop):
                    ev = fx.t1(**{drop: None})
                    errs = ev.verify(fx.base, fx.ctx)
                    self.assertTrue(any("强制要求工件引用" in e for e in errs), errs)

    def test_t2_does_not_require_poc_but_requires_checker(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            self.assertEqual(fx.t2().verify(fx.base, fx.ctx), [])
            ev = fx.t2(checker_sha256="")
            self.assertTrue(any("checker_sha256" in e for e in ev.verify(fx.base, fx.ctx)))

    def test_t3_needs_no_artifacts_but_needs_dual_reviewers(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            self.assertEqual(fx.t3().verify(fx.base, fx.ctx), [])
            same = fx.t3(reviewer_2="R1")
            self.assertTrue(any("不得为同一人" in e for e in same.verify(fx.base, fx.ctx)))
            nores = fx.t3(residual_path_sha256="")
            self.assertTrue(any("residual_path_sha256" in e
                                for e in nores.verify(fx.base, fx.ctx)))

    def test_t3_disagreement_must_be_undecided(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            disagree = fx.t3(agreement=False)
            self.assertEqual(disagree.parsed_verdict, va.ORACLE_ERROR)
            self.assertEqual(disagree.verify(fx.base, fx.ctx), [])
            bad = fx.t3(agreement=False)
            bad.parsed_verdict = "fixed"        # 分歧却给确定结论
            self.assertTrue(any("ORACLE_ERROR" in e for e in bad.verify(fx.base, fx.ctx)))

    def test_t3_conclusion_must_match_marker(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            ev = fx.t3()
            ev.parsed_verdict = "fixed"
            self.assertTrue(any("标记行一致" in e for e in ev.verify(fx.base, fx.ctx)))

    def test_missing_or_bad_context_is_fail_closed(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            ev = fx.t1()
            self.assertEqual(ev.verify(fx.base, None), ["缺冻结上下文 FrozenContext（fail-closed）"])
            bad_ctx = va.FrozenContext(manifest_sha256="zz", samples={},
                                       runtime=va.FrozenRuntime(tokenizer_sha256="", envelope_sha256=""))
            self.assertTrue(ev.verify(fx.base, bad_ctx))
            other = va.FrozenContext(manifest_sha256="b" * 64, samples=fx.ctx.samples,
                                     runtime=fx.ctx.runtime)
            self.assertTrue(any("manifest_sha256" in e for e in ev.verify(fx.base, other)))

    def test_binding_to_sample_and_arm_spec(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            ev = fx.t1()
            no_sample = va.FrozenContext(manifest_sha256=_HEX, samples={"OTHER": {"arms": {}}},
                                        runtime=fx.ctx.runtime)
            self.assertTrue(any("无样本" in e for e in ev.verify(fx.base, no_sample)))
            # arm 规格里的 poc SHA 与证据不符
            broken = dict(fx.ctx.samples["TARGET"])
            broken["arms"] = {a: {"poc_sha256": "c" * 64, "patch_sha256": fx.patch_sha}
                              for a in va.ARM_ORACLE}
            ctx2 = va.FrozenContext(manifest_sha256=_HEX,
                                    samples={"TARGET": broken}, runtime=fx.ctx.runtime)
            self.assertTrue(any("poc_sha256 与冻结 arm 规格不符" in e
                                for e in ev.verify(fx.base, ctx2)))

    def test_fully_forged_evidence_is_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            forged = va.OracleEvidence(
                contract="pytest-security-regression", tier=va.ORACLE_TIER_T1,
                arm="support-only-insufficient", sample_id="TARGET",
                manifest_sha256=_HEX, poc_sha256="d" * 64,
                target_tree_sha256="e" * 64, patch_sha256="f" * 64,
                command="pytest -q x", exit_code=0, raw_result="VERDICT: still_vulnerable",
                raw_result_sha256="1" * 64, parsed_verdict="still_vulnerable",
                oracle_parser_sha256=va.oracle_parser_sha256(),
                poc_path="poc.py", patch_path="fix.diff", target_tree_dir="tree")
            errs = forged.verify(fx.base, fx.ctx)
            self.assertTrue(errs, "伪造证据竟然通过")
            self.assertFalse(va.evaluate_arm(
                "support-only-insufficient", True, target_oracle="still_vulnerable",
                evidence=forged, base_dir=fx.base, ctx=fx.ctx)["accept"])

    def test_tampering_raw_and_verdict_detected(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            ev = fx.t1()
            ev.raw_result_sha256 = "b" * 64
            self.assertTrue(any("raw_result_sha256" in e for e in ev.verify(fx.base, fx.ctx)))
            ev2 = fx.t1()
            ev2.parsed_verdict = "still_vulnerable"
            self.assertTrue(ev2.verify(fx.base, fx.ctx))
            ev3 = fx.t1()
            ev3.oracle_parser_sha256 = "c" * 64
            self.assertTrue(any("冻结 parser" in e for e in ev3.verify(fx.base, fx.ctx)))

    def test_tier_mismatch_detected(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            ev = fx.t1()
            ev.tier = va.ORACLE_TIER_T2
            self.assertTrue(any("tier 与契约不符" in e for e in ev.verify(fx.base, fx.ctx)))


# ===========================================================================
# P0-2：shuffled 内容交叉绑定
# ===========================================================================
def _apply_ev(tree_sha, patch_sha, code=0, target="TARGET", donor="D1"):
    return {"target_id": target, "donor_id": donor, "target_tree_sha256": tree_sha,
            "donor_patch_sha256": patch_sha, "apply_command": "git apply --check d.diff",
            "apply_exit_code": code, "post_apply_tree_sha256": "b" * 64}


def _tok_ev(tok=950, target_tok=TARGET_TOKENS, **kw):
    ev = {"target_final_prompt_tokens": target_tok, "donor_final_prompt_tokens": tok,
          "target_prompt_sha256": _HEX, "candidate_prompt_sha256": _HEX,
          "tokenizer_sha256": _HEX, "envelope_sha256": _HEX}
    ev.update(kw)
    return ev


class TestShuffleContentBinding(unittest.TestCase):
    def setUp(self):
        self.tsha, self.psha = "1" * 64, "2" * 64
        self.tgt = {"sample_id": "TARGET", "language": "python", "cwe_family": "injection",
                    "n_files": 1, "is_composite": False}
        self.ta = va.TargetArtifact(sample_id="TARGET", target_tree_sha256=self.tsha,
                                    final_prompt_tokens=TARGET_TOKENS,
                                    prompt_sha256=_HEX)
        self.rt = va.FrozenRuntime(tokenizer_sha256=_HEX, envelope_sha256=_HEX)

    def _donor(self, sid="D1", tok=950, **kw):
        d = {"sample_id": sid, "language": "python", "cwe_family": "injection",
             "n_files": 1, "is_composite": False,
             "apply_evidence": _apply_ev(self.tsha, self.psha, target="TARGET", donor=sid),
             "token_evidence": _tok_ev(tok)}
        d.update(kw)
        return d

    def _da(self, sid="D1", tok=950, patch=None):
        return va.DonorArtifact(sample_id=sid, real_patch_sha256=patch or self.psha,
                                final_prompt_tokens=tok, prompt_sha256=_HEX)

    def _sel(self, donors, arts=None):
        return va.select_donor(self.tgt, donors, target_artifact=self.ta,
                               donor_artifacts=arts if arts is not None else {"D1": self._da()},
                               runtime=self.rt)

    def test_accepts_only_when_all_content_matches(self):
        r = self._sel([self._donor()])
        self.assertEqual(r["status"], "OK", r)
        self.assertIn("内容交叉绑定", r["binding"])

    def test_wrong_prompt_sha_rejected(self):
        for field in ("candidate_prompt_sha256", "target_prompt_sha256"):
            with self.subTest(field=field):
                d = self._donor()
                d["token_evidence"] = _tok_ev(**{field: "9" * 64})
                self.assertEqual(self._sel([d])["status"], "NO_DONOR")

    def test_wrong_tokenizer_or_envelope_rejected(self):
        for field in ("tokenizer_sha256", "envelope_sha256"):
            with self.subTest(field=field):
                d = self._donor()
                d["token_evidence"] = _tok_ev(**{field: "9" * 64})
                self.assertEqual(self._sel([d])["status"], "NO_DONOR")

    def test_declared_token_count_must_match_authority(self):
        d = self._donor()
        d["token_evidence"] = _tok_ev(tok=700)      # 申报 700，权威 950
        self.assertEqual(self._sel([d])["status"], "NO_DONOR")

    def test_ratio_recomputed_from_authority_not_declared(self):
        """申报值看似在界内，但**权威** ratio 超界 → 必须拒绝（ratio 由权威重算）。"""
        d = self._donor(tok=950)
        d["token_evidence"] = _tok_ev(tok=950)      # 申报 950/1000 = 0.95 在界内
        r = self._sel([d], arts={"D1": self._da(tok=1300)})   # 权威 1.30 超界
        self.assertEqual(r["status"], "NO_DONOR", r)

    def test_wrong_apply_tree_or_patch_rejected(self):
        d = self._donor(apply_evidence=_apply_ev("9" * 64, self.psha))
        self.assertEqual(self._sel([d])["status"], "NO_DONOR")
        d2 = self._donor(apply_evidence=_apply_ev(self.tsha, "9" * 64))
        self.assertEqual(self._sel([d2])["status"], "NO_DONOR")

    def test_post_apply_identical_tree_rejected(self):
        ev = _apply_ev(self.tsha, self.psha)
        ev["post_apply_tree_sha256"] = self.tsha
        self.assertEqual(self._sel([self._donor(apply_evidence=ev)])["status"], "NO_DONOR")

    def test_donor_artifact_missing_or_mismatched(self):
        self.assertEqual(self._sel([self._donor()], arts={})["status"], "NO_DONOR")
        self.assertEqual(self._sel([self._donor()], arts={"D1": self._da(sid="OTHER")})["status"],
                         "NO_DONOR")

    def test_authority_required_fail_closed(self):
        for ta, arts, rt in [(None, {"D1": self._da()}, self.rt),
                             (self.ta, None, self.rt),
                             (self.ta, {"D1": self._da()}, None)]:
            with self.subTest(ta=ta, arts=arts, rt=rt):
                r = va.select_donor(self.tgt, [self._donor()], target_artifact=ta,
                                    donor_artifacts=arts, runtime=rt)
                self.assertEqual(r["status"], "NO_AUTHORITY", r)

    def test_target_artifact_must_match_target_sample(self):
        bad = va.TargetArtifact(sample_id="OTHER", target_tree_sha256=self.tsha,
                                final_prompt_tokens=TARGET_TOKENS, prompt_sha256=_HEX)
        r = va.select_donor(self.tgt, [self._donor()], target_artifact=bad,
                            donor_artifacts={"D1": self._da()}, runtime=self.rt)
        self.assertEqual(r["status"], "NO_AUTHORITY")

    def test_donor_ne_target_and_missing_evidence(self):
        self.assertEqual(self._sel([self._donor(sid="TARGET")])["status"], "NO_DONOR")
        d = self._donor()
        d.pop("token_evidence")
        self.assertEqual(self._sel([d])["status"], "NO_DONOR")
        d2 = self._donor()
        d2.pop("apply_evidence")
        self.assertEqual(self._sel([d2])["status"], "NO_DONOR")

    def test_soft_relaxation_still_works(self):
        d = self._donor(language="java")
        r = self._sel([d])
        self.assertEqual(r["status"], "OK", r)
        self.assertEqual(r["relaxations"][0], "not_composite")

    def test_registry_documents_binding(self):
        reg = va.arms_registry()
        self.assertIn("内容交叉绑定", reg["shuffle"]["binding"])
        hard = {h["name"] for h in reg["shuffle"]["hard"]}
        self.assertIn("final_prompt_token_window", hard)
        self.assertIn("不可放宽", reg["shuffle"]["relax_policy"])
        self.assertEqual(set(reg["token_evidence_fields"]), set(va.TOKEN_EVIDENCE_FIELDS))


# ===========================================================================
# 自查：四臂接受标准对齐预注册 §3.3
# ===========================================================================
class TestArmAcceptanceAlignedWithPrereg(unittest.TestCase):
    def test_oracle_requirement_per_arm(self):
        self.assertTrue(va.ARM_ORACLE["annotated-security-complete"]["oracle_required"])
        self.assertTrue(va.ARM_ORACLE["support-only-insufficient"]["oracle_required"])
        self.assertFalse(va.ARM_ORACLE["placebo"]["oracle_required"])
        self.assertFalse(va.ARM_ORACLE["shuffled"]["oracle_required"])

    def test_registry_cites_prereg(self):
        reg = va.arms_registry()
        self.assertIn("预注册", reg["arm_acceptance_source"])
        self.assertIn("3.3", reg["arm_acceptance_source"])

    def test_placebo_accepts_without_oracle(self):
        r = va.evaluate_arm("placebo", True, model_verdict="vulnerable")
        self.assertTrue(r["accept"], r)
        self.assertFalse(r["oracle_evidence_provided"])
        self.assertIn("不要求 oracle", r["reason"])

    def test_placebo_rejects_non_vulnerable_model_verdict(self):
        for mv in ("benign", None, "maybe"):
            with self.subTest(mv=mv):
                self.assertFalse(va.evaluate_arm("placebo", True, model_verdict=mv)["accept"])

    def test_placebo_rejects_when_extra_oracle_shows_fixed(self):
        """附加 oracle 显示目标被意外修复 → 操纵检验失败。"""
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            r = va.evaluate_arm("placebo", True, model_verdict="vulnerable",
                                evidence=fx.t1(arm="placebo", verdict="fixed"),
                                base_dir=fx.base, ctx=fx.ctx)
            self.assertFalse(r["accept"])
            self.assertIn("操纵检验失败", r["reason"])

    def test_placebo_records_extra_oracle_when_consistent(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            r = va.evaluate_arm("placebo", True, model_verdict="vulnerable",
                                evidence=fx.t1(arm="placebo", verdict="still_vulnerable"),
                                base_dir=fx.base, ctx=fx.ctx)
            self.assertTrue(r["accept"], r)
            self.assertTrue(r["oracle_evidence_verified"])

    def test_placebo_rejects_unverifiable_extra_evidence(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            ev = fx.t1(arm="placebo", verdict="still_vulnerable")
            ev.poc_sha256 = "9" * 64
            self.assertFalse(va.evaluate_arm("placebo", True, model_verdict="vulnerable",
                                             evidence=ev, base_dir=fx.base,
                                             ctx=fx.ctx)["accept"])

    def test_oracle_required_arms_need_evidence(self):
        r = va.evaluate_arm("annotated-security-complete", True, target_oracle="fixed")
        self.assertFalse(r["accept"])
        self.assertIn("要求 oracle 证据", r["reason"])

    def test_oracle_error_not_accepted(self):
        for arm in ("annotated-security-complete", "support-only-insufficient"):
            with self.subTest(arm=arm):
                r = va.evaluate_arm(arm, True, target_oracle=va.ORACLE_ERROR)
                self.assertFalse(r["accept"])
                self.assertIn("不可判定", r["reason"])

    def test_expected_verdicts_enforced(self):
        with tempfile.TemporaryDirectory() as t:
            fx = Fixture(t)
            ok = fx.t1(arm="annotated-security-complete", verdict="fixed")
            self.assertTrue(va.evaluate_arm("annotated-security-complete", True,
                                            target_oracle="fixed", evidence=ok,
                                            base_dir=fx.base, ctx=fx.ctx)["accept"])
            wrong = fx.t1(arm="annotated-security-complete", verdict="still_vulnerable")
            r = va.evaluate_arm("annotated-security-complete", True,
                                target_oracle="still_vulnerable", evidence=wrong,
                                base_dir=fx.base, ctx=fx.ctx)
            self.assertFalse(r["accept"])
            self.assertIn("预期目标漏洞 fixed", r["reason"])

    def test_apply_not_clean_and_unknown_arm(self):
        self.assertFalse(va.evaluate_arm("placebo", False,
                                         model_verdict="vulnerable")["accept"])
        with self.assertRaises(KeyError):
            va.evaluate_arm("nope", True, model_verdict="vulnerable")


# ===========================================================================
# P1：功效 —— 首次跨越命名 / 措辞绑定
# ===========================================================================
class TestPowerFirstCrossing(unittest.TestCase):
    def test_old_misleading_names_removed(self):
        for name in ("required_discordant_pairs", "required_N_for_target"):
            self.assertFalse(hasattr(vp, name), f"{name} 应已改名")

    def test_conditional_power_is_not_monotone(self):
        """**P1 的事实依据**：功效非单调，故首次跨越点 ≠ 最小所需样本量。"""
        p10 = vp.conditional_power(10, 0.90)
        p11 = vp.conditional_power(11, 0.90)
        self.assertLess(p11, p10)          # m=11 反而低于 m=10
        self.assertGreater(p10, vp.DEFAULT_TARGET_POWER * 0.9 - 0.1)

    def test_first_crossing_m_matches_prereg(self):
        self.assertEqual(vp.first_crossing_m(), vp.PREREG_M_FOR_TARGET)
        self.assertEqual(vp.first_crossing_m(), 12)

    def test_first_crossing_carries_naming_warning(self):
        rep = vp.power_report()
        self.assertEqual(rep["first_crossing_m"], 12)
        self.assertIn("不等于", rep["first_crossing_naming_warning"])

    def test_sustained_crossing_m_no_drop(self):
        s = vp.sustained_crossing_m()
        self.assertEqual(s["first_crossing"], 12)
        self.assertTrue(s["no_drop_through_upto"])
        self.assertEqual(s["n_drops"], 0)
        self.assertIn("最低", s["claim"])

    def test_sustained_crossing_beyond_window_is_not_claimable(self):
        """N 的首次跨越（17–41）超出计划窗口 14 → 不得称「最低所需」。"""
        for q in (0.3, 0.5, 0.7):
            with self.subTest(q=q):
                s = vp.sustained_crossing_N(0.90, q)
                self.assertGreater(s["first_crossing"], vp.PLANNED_MAX_N)
                self.assertFalse(s["no_drop_through_upto"])
                self.assertIsNone(s["contiguous_end"])
                self.assertIn("不得", s["claim"])

    def test_enforce_upto_validation_and_short_window(self):
        with self.assertRaises(ValueError):
            vp.sustained_crossing_m(enforce_upto=0)
        with self.assertRaises(ValueError):
            vp.sustained_crossing_N(enforce_upto=-3)
        s = vp.sustained_crossing_m(enforce_upto=11)
        self.assertFalse(s["no_drop_through_upto"])

    def test_underpowered_combinations_bound_to_specific_cells(self):
        cells = vp.underpowered_cells()
        self.assertTrue(cells)
        for c in cells:
            with self.subTest(c=c):
                self.assertIn("N", c)
                self.assertIn("p1", c)
                self.assertIn("discordance", c)
                self.assertLess(c["unconditional_power"], vp.DEFAULT_TARGET_POWER)
                self.assertTrue(c["below_target"])
        # 不低于目标的组合不得出现
        self.assertTrue(all(c["unconditional_power"] < vp.DEFAULT_TARGET_POWER
                            for c in cells))

    def test_wording_rule_binds_to_combinations(self):
        rule = vp.power_report()["wording_rule"]
        self.assertIn("具体参数组合", rule)
        self.assertIn("不得对整张敏感性表作笼统判断", rule)
        self.assertIn("不得据此单独推断模型真实判别能力", rule)
        self.assertIn("判别力有限", rule)

    def test_N_active_source_and_validation(self):
        rep = vp.power_report()
        self.assertEqual(rep["N_active"], vp.PLANNED_MAX_N)
        self.assertIn("planned_max", rep["N_source"])
        r10 = vp.power_report(10)
        self.assertEqual(r10["N_active"], 10)
        self.assertIn("frozen active universe", r10["N_source"])
        for bad in (0, -1, 1.5, True, "10"):
            with self.assertRaises(ValueError):
                vp.power_report(bad)
        with self.assertRaises(ValueError):
            vp.power_report(vp.PLANNED_MAX_N + 1)

    def test_schema_and_basic_statistics(self):
        self.assertEqual(vp.POWER_SCHEMA, "v4-power/4")
        self.assertEqual(vp.power_report()["schema"], vp.POWER_SCHEMA)
        self.assertNotIn("p", inspect.signature(vp.exact_two_sided_p).parameters)
        self.assertAlmostEqual(vp.exact_two_sided_p(2, 12), 0.03857, places=4)
        self.assertAlmostEqual(vp.conditional_power(8, 0.90), 0.4305, places=3)
        self.assertGreater(vp.unconditional_power(40, 0.90, 0.5),
                           vp.unconditional_power(10, 0.90, 0.5))
        self.assertEqual(vp.unconditional_power(14, 0.90, 0.0), 0.0)
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
            vp.conditional_power(10, 0.0)
        with self.assertRaises(ValueError):
            vp.unconditional_power(10, 0.9, 1.5)
        with self.assertRaises(ValueError):
            vp.unconditional_power(10, 0.9, -0.1)


if __name__ == "__main__":
    unittest.main()
