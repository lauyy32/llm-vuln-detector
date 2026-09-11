# -*- coding: utf-8 -*-
"""A-3 步 2/3/4/5（第二次返工）验收：覆盖评审 3 的 P0-1/2/3 与 P1。

覆盖点：
  * P0-1 **先过滤界内候选再排序** —— 含评审点名的 79 / 125 / 100 反例。
  * P0-2 shuffled 长度门禁统一到**最终完整 prompt token** + `TOKEN_RATIO_BOUNDS`。
  * P0-3 `OracleEvidence` 真验证器：重算 raw SHA / 冻结 parser 派生 verdict /
        绑定 parser 实现 SHA / exit_code 约定 / 文件重哈希。
  * P1   功效报告声明同质性假设，`N` 从 active universe 读取。
"""
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


# ---------------------------------------------------------------------------
# 构造器
# ---------------------------------------------------------------------------
def _cand(key, tokens):
    return va.Candidate(key=key, tokens=tokens, tokenizer_sha256=_HEX,
                        envelope_sha256=_HEX, prompt_sha256=_HEX)


def _apply_ev(target_id="TARGET", donor_id="D1", code=0):
    return {"target_id": target_id, "donor_id": donor_id,
            "target_tree_sha256": _HEX, "donor_patch_sha256": _HEX,
            "apply_command": "git apply --check donor.diff",
            "apply_exit_code": code, "post_apply_tree_sha256": _HEX}


def _tok_ev(donor_tokens, target_tokens=TARGET_TOKENS, **kw):
    ev = {"target_final_prompt_tokens": target_tokens,
          "donor_final_prompt_tokens": donor_tokens,
          "target_prompt_sha256": _HEX, "candidate_prompt_sha256": _HEX,
          "tokenizer_sha256": _HEX, "envelope_sha256": _HEX}
    ev.update(kw)
    return ev


TARGET = {"sample_id": "TARGET", "language": "python", "cwe_family": "injection",
          "n_files": 1, "is_composite": False, "patch_tokens": 100,
          "token_evidence": _tok_ev(TARGET_TOKENS)}


def _donor(sid, tokens=TARGET_TOKENS, **kw):
    d = {"sample_id": sid, "language": "python", "cwe_family": "injection",
         "n_files": 1, "is_composite": False, "patch_tokens": 100,
         "token_evidence": _tok_ev(tokens), "apply_evidence": _apply_ev("TARGET", sid)}
    d.update(kw)
    return d


def _ok_evidence(verdict="still_vulnerable"):
    """构造**可通过 verify()** 的证据（类型与 exit_code 自洽）。"""
    if verdict == "still_vulnerable":
        return va.make_evidence("pytest-regression", "1 failed, 0 passed", 1,
                                command="pytest -q tests/security")
    return va.make_evidence("pytest-regression", "2 passed", 0,
                            command="pytest -q tests/security")


# ===========================================================================
# P0-1：token 搜索 —— 先过滤界内再排序
# ===========================================================================
class TestTokenSearchInBoundsFirst(unittest.TestCase):
    def test_codex_regression_79_125_100(self):
        """**评审 3 P0-1 点名反例**：A=79（ratio 0.79 超界，差 21）、
        B=125（ratio 1.25 界内，差 25）。
        旧实现先取最小绝对差 → 选中超界的 A 后报"无界内候选"；须改选 B。
        """
        r = va.token_match_search([_cand("A", 79), _cand("B", 125)], 100)
        self.assertEqual(r["status"], "OK", r)
        self.assertEqual(r["selected"].key, "B")
        self.assertEqual(r["int_distance"], 25)
        self.assertTrue(r["in_bounds"])
        self.assertEqual(r["n_in_bounds"], 1)

    def test_nearer_but_out_of_bounds_never_wins(self):
        """系统性反例：距离更小但在界外者不得胜出。"""
        cases = [
            # (target, [(key, tokens)], 期望选中 key)
            (100, [("near_oob", 70), ("far_ib", 81)], "far_ib"),
            (100, [("near_oob", 130), ("far_ib", 124)], "far_ib"),
            (1000, [("near_oob", 700), ("far_ib", 800)], "far_ib"),
            (1000, [("near_oob", 1300), ("far_ib", 1250)], "far_ib"),
        ]
        for target, items, want in cases:
            with self.subTest(target=target, items=items):
                r = va.token_match_search([_cand(k, t) for k, t in items], target)
                self.assertEqual(r["status"], "OK", r)
                self.assertEqual(r["selected"].key, want)

    def test_only_out_of_bounds_then_fail(self):
        r = va.token_match_search([_cand("A", 79), _cand("B", 70)], 100)
        self.assertEqual(r["status"], "NO_IN_BOUNDS_CANDIDATE")
        self.assertIsNone(r["selected"])
        self.assertEqual(r["n_in_bounds"], 0)
        self.assertIn("不可放宽", r["reason"])
        self.assertEqual(r["closest"]["key"], "A")   # 差 21 < 差 30

    def test_boundary_ratios_inclusive(self):
        for tok in (80, 125):
            with self.subTest(tok=tok):
                r = va.token_match_search([_cand("b", tok)], 100)
                self.assertEqual(r["status"], "OK", r)
        for tok in (79, 126):
            with self.subTest(tok=tok):
                r = va.token_match_search([_cand("b", tok)], 100)
                self.assertEqual(r["status"], "NO_IN_BOUNDS_CANDIDATE", r)

    def test_integer_distance_and_tie_break_by_key(self):
        r = va.token_match_search([_cand("zzz", 90), _cand("aaa", 110)], 100)
        self.assertEqual(r["int_distance"], 10)
        self.assertEqual(r["selected"].key, "aaa")

    def test_order_independent(self):
        items = [_cand("A", 79), _cand("B", 125), _cand("C", 100)]
        r1 = va.token_match_search(items, 100)
        r2 = va.token_match_search(list(reversed(items)), 100)
        self.assertEqual(r1["selected"].key, r2["selected"].key)

    def test_trace_and_exclusion_are_auditable(self):
        """OK 分支：`trace` 只含**界内**候选（真正参与排序者），
        被界外过滤掉的候选进入 `excluded_out_of_bounds` 留痕。"""
        r = va.token_match_search([_cand("A", 79), _cand("B", 125)], 100)
        self.assertEqual({t["key"] for t in r["trace"]}, {"B"})
        self.assertEqual(r["n_candidates"], 2)
        self.assertEqual(r["n_out_of_bounds"], 1)
        exc = {e["key"]: e for e in r["excluded_out_of_bounds"]}
        self.assertEqual(set(exc), {"A"})
        self.assertAlmostEqual(exc["A"]["ratio"], 0.79, places=6)
        self.assertEqual(exc["A"]["int_distance"], 21)
        self.assertIn("界外候选不参与排序", r["filter_policy"])

    def test_invalid_candidates(self):
        self.assertEqual(va.token_match_search([], 100)["status"], "INVALID_CANDIDATES")
        self.assertEqual(
            va.token_match_search([_cand("x", 100.0)], 100)["status"], "INVALID_CANDIDATES")
        self.assertEqual(
            va.token_match_search([_cand("x", 0)], 100)["status"], "INVALID_CANDIDATES")
        self.assertEqual(
            va.token_match_search([_cand("x", True)], 100)["status"], "INVALID_CANDIDATES")
        self.assertEqual(
            va.token_match_search([_cand("d", 100), _cand("d", 110)], 100)["status"],
            "INVALID_CANDIDATES")
        # 证据缺失（非 64 位 hex）不采信
        self.assertEqual(
            va.token_match_search([va.Candidate(key="n", tokens=100)], 100)["status"],
            "INVALID_CANDIDATES")

    def test_bad_bounds_and_target_raise(self):
        for bad in [(1.0, 0.5), (0, 1), "x", (0.8,), (0.8, 0.8)]:
            with self.subTest(bounds=bad):
                with self.assertRaises(ValueError):
                    va.token_match_search([_cand("a", 100)], 100, bounds=bad)
        for bad in (0, -1, 1.5, True, "100"):
            with self.subTest(target=bad):
                with self.assertRaises(ValueError):
                    va.token_match_search([_cand("a", 100)], bad)


# ===========================================================================
# P0-2：shuffled 约束 —— 最终 prompt token + 统一 bounds
# ===========================================================================
class TestShuffleFinalPromptTokens(unittest.TestCase):
    def test_hard_constraint_is_final_prompt_token_window(self):
        hard = {n for n, _ in va.SHUFFLE_HARD_CONSTRAINTS}
        soft = {n for n, _ in va.SHUFFLE_SOFT_CONSTRAINTS}
        self.assertIn("final_prompt_token_window", hard)
        self.assertNotIn("final_prompt_token_window", soft)

    def test_uses_final_prompt_tokens_not_patch_tokens(self):
        """**评审 3 P0-2**：长度门禁必须看**最终 prompt token**。
        patch_tokens 与门禁无关：patch 长度离谱但 prompt 比值合格 → 仍可选；
        patch 长度正常但 prompt 比值超界 → 必须拒。
        """
        # ① patch_tokens 是目标的 10 倍，但最终 prompt token 比 = 1.0
        ok = _donor("BIGPATCH", tokens=TARGET_TOKENS, patch_tokens=1000)
        self.assertEqual(va.select_donor(TARGET, [ok])["status"], "OK")
        # ② patch_tokens 与目标相同，但最终 prompt token 比 = 1.26（超界）
        bad = _donor("SMALLPATCH", tokens=1260, patch_tokens=100)
        self.assertEqual(va.select_donor(TARGET, [bad])["status"], "NO_DONOR")

    def test_ratio_bounds_boundary(self):
        for tok, want in ((790, "NO_DONOR"), (800, "OK"),
                          (1250, "OK"), (1260, "NO_DONOR")):
            with self.subTest(tok=tok):
                r = va.select_donor(TARGET, [_donor("D", tokens=tok)])
                self.assertEqual(r["status"], want, r)

    def test_bounds_unified_with_token_ratio_bounds(self):
        self.assertEqual(va.TOKEN_RATIO_BOUNDS, (0.8, 1.25))
        reg = va.arms_registry()
        self.assertEqual(tuple(reg["token_bounds"]), va.TOKEN_RATIO_BOUNDS)

    def test_missing_token_evidence_is_fail_closed(self):
        d = _donor("D1")
        d.pop("token_evidence")
        self.assertEqual(va.select_donor(TARGET, [d])["status"], "NO_DONOR")
        d2 = _donor("D2", token_evidence={"target_final_prompt_tokens": 1000})
        self.assertEqual(va.select_donor(TARGET, [d2])["status"], "NO_DONOR")

    def test_token_evidence_requires_hex_provenance(self):
        d = _donor("D1", token_evidence=_tok_ev(TARGET_TOKENS, tokenizer_sha256="short"))
        self.assertEqual(va.select_donor(TARGET, [d])["status"], "NO_DONOR")

    def test_apply_evidence_required_and_target_bound(self):
        d = _donor("D1")
        d.pop("apply_evidence")
        self.assertEqual(va.select_donor(TARGET, [d])["status"], "NO_DONOR")
        cases = [
            _apply_ev("TARGET", "D1", 1),      # exit != 0
            _apply_ev("OTHER", "D1"),          # target 不符
            _apply_ev("TARGET", "OTHER"),      # donor 不符
        ]
        for ev in cases:
            with self.subTest(ev=ev):
                r = va.select_donor(TARGET, [_donor("D1", apply_evidence=ev)])
                self.assertEqual(r["status"], "NO_DONOR")

    def test_donor_ne_target(self):
        self.assertEqual(
            va.select_donor(TARGET, [_donor("TARGET")])["status"], "NO_DONOR")

    def test_soft_relaxation_reverse_order_and_recorded(self):
        r = va.select_donor(TARGET, [_donor("D1", language="java")])
        self.assertEqual(r["status"], "OK", r)
        self.assertEqual(r["relaxations"][0], "not_composite")
        seq = r["relaxations"]
        self.assertEqual(seq, list(reversed([n for n, _ in va.SHUFFLE_SOFT_CONSTRAINTS]))[:len(seq)])

    def test_no_relaxation_when_soft_all_satisfied(self):
        r = va.select_donor(TARGET, [_donor("D1")])
        self.assertEqual(r["relaxations"], [])

    def test_token_tie_break_by_sample_id(self):
        donors = [_donor("ZZZ", tokens=1100), _donor("AAA", tokens=900)]
        r = va.select_donor(TARGET, donors)
        self.assertEqual(r["status"], "OK")
        self.assertIn(r["donor"]["sample_id"], {"ZZZ", "AAA"})
        # 两个候选 |Δ|=100 相同 → 字典序取 AAA
        self.assertEqual(r["donor"]["sample_id"], "AAA")

    def test_covariates_reported(self):
        r = va.select_donor(TARGET, [_donor("D1")])
        self.assertEqual(set(r["covariates"]), {"target", "donor"})
        for side in ("target", "donor"):
            self.assertEqual(set(r["covariates"][side]), set(va.COVARIATE_FIELDS))
        self.assertIn("final_prompt_tokens", va.COVARIATE_FIELDS)

    def test_registry_exposes_shuffle_contract(self):
        reg = va.arms_registry()
        self.assertEqual(set(reg["shuffle"]["apply_evidence_fields"]),
                         set(va.APPLY_EVIDENCE_FIELDS))
        self.assertEqual(set(reg["token_evidence_fields"]), set(va.TOKEN_EVIDENCE_FIELDS))
        self.assertIn("final_prompt_token_window",
                      {h["name"] for h in reg["shuffle"]["hard"]})
        self.assertIn("不可放宽", reg["shuffle"]["relax_policy"])


# ===========================================================================
# P0-3：oracle 真验证器
# ===========================================================================
class TestOracleVerifier(unittest.TestCase):
    def test_frozen_parser_derives_from_exit_code(self):
        self.assertEqual(
            va.parse_oracle_verdict("pytest-regression", "any text", 0), "fixed")
        self.assertEqual(
            va.parse_oracle_verdict("pytest-regression", "any text", 1), "still_vulnerable")
        for t in ("poc-exploit", "sast-diff"):
            self.assertEqual(va.parse_oracle_verdict(t, "x", 0), "fixed")
            self.assertEqual(va.parse_oracle_verdict(t, "x", 1), "still_vulnerable")

    def test_unregistered_type_requires_explicit_marker(self):
        """未登记类型**不做自然语言猜测**（`"not vulnerable"` 含 `"vulnerable"` 会判反）。"""
        with self.assertRaises(ValueError):
            va.parse_oracle_verdict("custom", "the target is not vulnerable", 1)
        with self.assertRaises(ValueError):
            va.parse_oracle_verdict("custom", "still_vulnerable", 1)
        self.assertEqual(
            va.parse_oracle_verdict("custom", "log...\nVERDICT: still_vulnerable", 3),
            "still_vulnerable")
        self.assertEqual(
            va.parse_oracle_verdict("custom", "VERDICT: FIXED", 3), "fixed")
        with self.assertRaises(ValueError):
            va.parse_oracle_verdict("custom", "VERDICT: maybe", 3)

    def test_parser_sha_is_bound_and_stable(self):
        sha = va.oracle_parser_sha256()
        self.assertEqual(len(sha), 64)
        self.assertEqual(sha, va.oracle_parser_sha256())
        self.assertEqual(sha, va.arms_registry()["oracle_parser_sha256"])
        self.assertEqual(sha, hashlib.sha256(
            inspect.getsource(va.parse_oracle_verdict).encode("utf-8")).hexdigest())

    def test_valid_evidence_passes(self):
        for v in ("still_vulnerable", "fixed"):
            with self.subTest(v=v):
                self.assertEqual(_ok_evidence(v).verify(), [])

    def test_tampered_raw_sha_detected(self):
        ev = _ok_evidence()
        ev.raw_result_sha256 = "b" * 64
        self.assertTrue(any("raw_result_sha256" in e for e in ev.verify()))

    def test_tampered_verdict_detected(self):
        ev = _ok_evidence("still_vulnerable")
        ev.parsed_verdict = "fixed"
        self.assertTrue(any("parser 派生" in e for e in ev.verify()))

    def test_tampered_parser_sha_detected(self):
        ev = _ok_evidence()
        ev.oracle_parser_sha256 = "c" * 64
        self.assertTrue(any("冻结 parser" in e for e in ev.verify()))

    def test_inconsistent_exit_code_detected(self):
        ev = _ok_evidence()
        ev.exit_code = 999            # 与 pytest 约定不符
        self.assertTrue(ev.verify())

    def test_forged_evidence_rejected_by_evaluate_arm(self):
        """整体伪造（假 SHA + 越界 exit_code）必须被拒。"""
        forged = va.OracleEvidence(
            oracle_type="pytest-regression", oracle_version="1.0",
            oracle_parser_sha256="d" * 64, poc_sha256="e" * 64,
            target_tree_sha256="f" * 64, patch_sha256="0" * 64,
            command="pytest -q", exit_code=999, raw_result="forged",
            raw_result_sha256="1" * 64, parsed_verdict="still_vulnerable")
        r = va.evaluate_arm("placebo", True, "still_vulnerable", forged)
        self.assertFalse(r["accept"])
        self.assertIn("验证失败", r["reason"])

    def test_missing_fields_detected(self):
        ev = _ok_evidence()
        ev.poc_sha256 = ""
        self.assertTrue(any("缺 poc_sha256" in e for e in ev.verify()))
        ev2 = _ok_evidence()
        ev2.command = "   "
        self.assertTrue(any("command" in e for e in ev2.verify()))

    def test_hex_format_enforced(self):
        ev = _ok_evidence()
        ev.poc_sha256 = "nothex"
        self.assertTrue(any("非 64 位 hex" in e for e in ev.verify()))

    def test_poc_file_rehash(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "poc.py").write_bytes(b"print(1)\n")
            good = hashlib.sha256(b"print(1)\n").hexdigest()
            ev = _ok_evidence()
            ev.poc_path, ev.poc_sha256 = "poc.py", good
            self.assertEqual(ev.verify(base), [])
            ev.poc_sha256 = "2" * 64
            self.assertTrue(any("PoC 文件 SHA" in e for e in ev.verify(base)))
            ev.poc_sha256 = good
            ev.poc_path = "missing.py"
            self.assertTrue(any("不存在" in e for e in ev.verify(base)))

    def test_patch_file_rehash(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "fix.diff").write_bytes(b"--- a\n+++ b\n")
            good = hashlib.sha256(b"--- a\n+++ b\n").hexdigest()
            ev = _ok_evidence()
            ev.patch_path, ev.patch_sha256 = "fix.diff", good
            self.assertEqual(ev.verify(base), [])

    def test_target_tree_dir_checked(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "tree").mkdir()
            ev = _ok_evidence()
            ev.target_tree_dir = "tree"
            self.assertEqual(ev.verify(base), [])
            ev.target_tree_dir = "nope"
            self.assertTrue(any("target 树不存在" in e for e in ev.verify(base)))


class TestArmEvaluation(unittest.TestCase):
    def test_expected_verdicts(self):
        expect = {"annotated-security-complete": "fixed",
                  "support-only-insufficient": "still_vulnerable",
                  "placebo": "still_vulnerable",
                  "shuffled": "still_vulnerable"}
        for arm, want in expect.items():
            with self.subTest(arm=arm):
                r = va.evaluate_arm(arm, True, want, _ok_evidence(want))
                self.assertTrue(r["accept"], r)
                self.assertEqual(r["expected_target_oracle"], want)

    def test_wrong_verdict_rejected(self):
        r = va.evaluate_arm("annotated-security-complete", True, "still_vulnerable",
                            _ok_evidence("still_vulnerable"))
        self.assertFalse(r["accept"])
        self.assertIn("预期目标漏洞 fixed", r["reason"])

    def test_shuffled_checks_target_state_not_donor(self):
        """shuffled 的 ground truth 是**目标**漏洞状态：意外修好目标 → 拒绝。"""
        r = va.evaluate_arm("shuffled", True, "fixed", _ok_evidence("fixed"))
        self.assertFalse(r["accept"])
        self.assertIn("目标漏洞", r["reason"])

    def test_no_donor_state_option_in_registry(self):
        self.assertNotIn("donor_state",
                         {v["expect_target_oracle"] for v in va.ARM_ORACLE.values()})
        for spec in va.ARM_ORACLE.values():
            self.assertIn("expect_target_oracle", spec)
            self.assertNotIn("expect_oracle", spec)

    def test_evidence_verdict_must_match_argument(self):
        ev = _ok_evidence("fixed")
        r = va.evaluate_arm("placebo", True, "still_vulnerable", ev)
        self.assertFalse(r["accept"])
        self.assertIn("不符", r["reason"])

    def test_fail_closed_paths(self):
        self.assertFalse(va.evaluate_arm("placebo", False, "still_vulnerable",
                                         _ok_evidence())["accept"])
        self.assertFalse(va.evaluate_arm("placebo", True, "garbage",
                                         _ok_evidence())["accept"])
        self.assertFalse(va.evaluate_arm("placebo", True, None, _ok_evidence())["accept"])
        r = va.evaluate_arm("placebo", True, "still_vulnerable", None)
        self.assertFalse(r["accept"])
        self.assertIn("证据", r["reason"])
        with self.assertRaises(KeyError):
            va.evaluate_arm("nope", True, "fixed", _ok_evidence("fixed"))

    def test_accept_includes_evidence_payload(self):
        r = va.evaluate_arm("placebo", True, "still_vulnerable", _ok_evidence())
        self.assertTrue(r["accept"])
        self.assertEqual(set(r["oracle_evidence"]), set(va.ORACLE_EVIDENCE_FIELDS))
        self.assertEqual(set(va.arms_registry()["oracle_evidence_fields"]),
                         set(va.ORACLE_EVIDENCE_FIELDS))


# ===========================================================================
# P1：功效报告（条件 vs 非条件；同质性假设；N 来源）
# ===========================================================================
class TestPowerReworked(unittest.TestCase):
    def test_schema_and_no_p_parameter(self):
        self.assertEqual(vp.POWER_SCHEMA, "v4-power/3")
        self.assertNotIn("p", inspect.signature(vp.exact_two_sided_p).parameters)

    def test_exact_p_known_value(self):
        self.assertAlmostEqual(vp.exact_two_sided_p(2, 12), 0.03857, places=4)
        self.assertEqual(vp.exact_two_sided_p(0, 0), 1.0)

    def test_conditional_power_named_and_bounded(self):
        rep = vp.power_report()
        self.assertEqual(rep["quantity_name"], "conditional power given m discordant pairs")
        self.assertIn("不是", rep["quantity_note"])
        self.assertAlmostEqual(vp.conditional_power(8, 0.90), 0.4305, places=3)
        self.assertEqual(vp.required_discordant_pairs(0.90, 0.05, 0.80), 12)
        self.assertEqual(vp.conditional_power(0), 0.0)

    def test_unconditional_power_monotone(self):
        self.assertLess(vp.unconditional_power(10, 0.90, 0.3),
                        vp.unconditional_power(30, 0.90, 0.7))
        self.assertLess(vp.unconditional_power(14, 0.90, 0.5),
                        vp.unconditional_power(40, 0.90, 0.5))
        self.assertEqual(vp.unconditional_power(14, 0.90, 0.0), 0.0)
        self.assertAlmostEqual(vp.unconditional_power(14, 0.90, 1.0),
                               vp.conditional_power(14, 0.90), places=12)

    def test_homogeneity_assumptions_declared(self):
        rep = vp.power_report()
        self.assertGreaterEqual(len(rep["homogeneity_assumptions"]), 3)
        self.assertEqual(tuple(rep["homogeneity_assumptions"]),
                         tuple(vp.HOMOGENEITY_ASSUMPTIONS))
        self.assertIn("仅", rep["assumption_scope_note"])
        self.assertIn("conditional_power", rep["assumption_scope_note"])
        self.assertTrue(any("同质" in a for a in rep["homogeneity_assumptions"]))

    def test_N_from_active_universe(self):
        rep = vp.power_report()
        self.assertEqual(rep["N_active"], vp.PLANNED_MAX_N)
        self.assertIn("planned_max", rep["N_source"])
        rep10 = vp.power_report(10)
        self.assertEqual(rep10["N_active"], 10)
        self.assertIn("frozen active universe", rep10["N_source"])
        self.assertIn("N=10", rep10["caveats"][1])

    def test_N_validation(self):
        for bad in (0, -1, 1.5, True, "10"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    vp.power_report(bad)
        with self.assertRaises(ValueError):
            vp.power_report(vp.PLANNED_MAX_N + 1)

    def test_sensitivity_table_grid(self):
        rows = vp.sensitivity_table(N_list=(8, 14), p1_list=(0.6, 0.9),
                                    discordance_list=(0.3, 0.5))
        self.assertEqual(len(rows), 2 * 2 * 2)
        for r in rows:
            self.assertIn("expected_m", r)
            self.assertIn("unconditional_power", r)
            self.assertAlmostEqual(r["expected_m"], r["N"] * r["discordance"], places=2)

    def test_required_N_monotone_in_discordance(self):
        n_low = vp.required_N_for_target(0.90, 0.3)
        n_high = vp.required_N_for_target(0.90, 0.7)
        self.assertNotEqual(n_low, -1)
        self.assertNotEqual(n_high, -1)
        self.assertGreater(n_low, n_high)

    def test_wording_rule_phrasing(self):
        rule = vp.power_report()["wording_rule"]
        self.assertIn("不得据此单独推断模型真实判别能力", rule)
        self.assertIn("判别力有限", rule)

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
