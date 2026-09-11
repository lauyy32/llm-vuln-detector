# -*- coding: utf-8 -*-
"""A-3 步 2/3/4/5（返工版）验收：覆盖评审 2 指出的全部 P0 反例。"""
import inspect
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from cpg.ablation import v4_arms as va  # noqa: E402
from cpg.ablation import v4_power as vp  # noqa: E402

_HEX = "a" * 64


def _cand(key, tokens):
    return va.Candidate(key=key, tokens=tokens, tokenizer_sha256=_HEX,
                        envelope_sha256=_HEX, prompt_sha256=_HEX)


def _apply_ev(target_id="T", donor_id="D", code=0):
    return {"target_id": target_id, "donor_id": donor_id,
            "target_tree_sha256": _HEX, "donor_patch_sha256": _HEX,
            "apply_command": "git apply --check donor.diff",
            "apply_exit_code": code, "post_apply_tree_sha256": _HEX}


def _donor(sid, **kw):
    d = {"sample_id": sid, "language": "python", "cwe_family": "injection",
         "patch_tokens": 100, "n_files": 1, "is_composite": False,
         "apply_evidence": _apply_ev("TARGET", sid)}
    d.update(kw)
    return d


TARGET = {"sample_id": "TARGET", "language": "python", "cwe_family": "injection",
          "patch_tokens": 100, "n_files": 1, "is_composite": False}


def _ev(oracle="still_vulnerable"):
    return va.OracleEvidence(oracle_type="pytest-regression", oracle_version="1.0",
                             poc_sha256=_HEX, target_tree_sha256=_HEX,
                             patch_sha256=_HEX, command="pytest -q tests/security",
                             exit_code=1, raw_result_sha256=_HEX,
                             parsed_verdict=oracle)


# ===========================================================================
# P0-2：token 搜索（整数距离；超界是失败状态）
# ===========================================================================
class TestTokenSearchReworked(unittest.TestCase):
    def test_integer_distance_no_float(self):
        r = va.token_match_search([_cand("a", 90), _cand("b", 111)], 100)
        self.assertEqual(r["status"], "OK")
        self.assertEqual(r["selected"].key, "a")      # |90-100|=10 < |111-100|=11
        self.assertEqual(r["int_distance"], 10)

    def test_tie_break_pure_integer(self):
        """90 与 110 距 100 都是 10 → 按 key 字典序（整数距离无浮点歧义）。"""
        r = va.token_match_search([_cand("zzz", 90), _cand("aaa", 110)], 100)
        self.assertEqual(r["selected"].key, "aaa")

    def test_out_of_bounds_is_failure_status(self):
        """**评审 P0-2**：超界不得返回 OK。"""
        r = va.token_match_search([_cand("far", 1000)], 100)
        self.assertEqual(r["status"], "NO_IN_BOUNDS_CANDIDATE")
        self.assertIsNone(r["selected"])
        self.assertIn("不可放宽", r["reason"])

    def test_borderline_in_bounds_ok(self):
        r = va.token_match_search([_cand("lo", 80), _cand("hi", 125)], 100)
        self.assertEqual(r["status"], "OK")

    def test_non_integer_tokens_rejected(self):
        r = va.token_match_search([_cand("x", 100.0)], 100)
        self.assertEqual(r["status"], "INVALID_CANDIDATES")

    def test_zero_tokens_rejected(self):
        r = va.token_match_search([_cand("x", 0)], 100)
        self.assertEqual(r["status"], "INVALID_CANDIDATES")

    def test_duplicate_key_rejected(self):
        r = va.token_match_search([_cand("dup", 100), _cand("dup", 110)], 100)
        self.assertEqual(r["status"], "INVALID_CANDIDATES")

    def test_missing_evidence_rejected(self):
        """候选缺 tokenizer/envelope/prompt SHA → 不采信。"""
        c = va.Candidate(key="noev", tokens=100)
        r = va.token_match_search([c], 100)
        self.assertEqual(r["status"], "INVALID_CANDIDATES")

    def test_bad_bounds_raises(self):
        for bad in [(1.0, 0.5), (0, 1), "x", (0.8,)]:
            with self.assertRaises(ValueError):
                va.token_match_search([_cand("a", 100)], 100, bounds=bad)

    def test_bad_target_raises(self):
        for bad in (0, -1, 1.5, True):
            with self.assertRaises(ValueError):
                va.token_match_search([_cand("a", 100)], bad)


# ===========================================================================
# P0-3：apply_clean 是 target×donor 关系；token_window 为硬约束
# ===========================================================================
class TestShuffleReworked(unittest.TestCase):
    def test_hard_includes_token_window(self):
        names = {n for n, _ in va.SHUFFLE_HARD_CONSTRAINTS}
        self.assertIn("token_window", names)
        self.assertNotIn("token_window", {n for n, _ in va.SHUFFLE_SOFT_CONSTRAINTS})

    def test_apply_evidence_required(self):
        d = _donor("D1")
        d.pop("apply_evidence")
        r = va.select_donor(TARGET, [d])
        self.assertEqual(r["status"], "NO_DONOR")

    def test_apply_exit_code_nonzero_rejected(self):
        r = va.select_donor(TARGET, [_donor("D1", apply_evidence=_apply_ev("TARGET", "D1", 1))])
        self.assertEqual(r["status"], "NO_DONOR")

    def test_apply_evidence_target_mismatch_rejected(self):
        r = va.select_donor(TARGET, [_donor("D1", apply_evidence=_apply_ev("OTHER", "D1"))])
        self.assertEqual(r["status"], "NO_DONOR")

    def test_apply_evidence_donor_mismatch_rejected(self):
        r = va.select_donor(TARGET, [_donor("D1", apply_evidence=_apply_ev("TARGET", "OTHER"))])
        self.assertEqual(r["status"], "NO_DONOR")

    def test_token_window_cannot_be_relaxed(self):
        """token 超出门禁的 donor 即便其它约束都不满足，也不得被选中。"""
        far = _donor("FAR", patch_tokens=1000, language="java")
        r = va.select_donor(TARGET, [far])
        self.assertEqual(r["status"], "NO_DONOR")

    def test_selects_and_reports_covariates(self):
        r = va.select_donor(TARGET, [_donor("D1")])
        self.assertEqual(r["status"], "OK")
        self.assertEqual(set(r["covariates"]), {"target", "donor"})

    def test_relaxation_recorded_and_reverse_order(self):
        r = va.select_donor(TARGET, [_donor("D1", language="java")])
        self.assertEqual(r["status"], "OK")
        self.assertEqual(r["relaxations"][0], "not_composite")

    def test_evidence_field_list_in_registry(self):
        reg = va.arms_registry()
        self.assertEqual(set(reg["shuffle"]["apply_evidence_fields"]),
                         set(va.APPLY_EVIDENCE_FIELDS))


# ===========================================================================
# P0-4：shuffled 的 ground truth 是**目标**漏洞状态；oracle 需证据链
# ===========================================================================
class TestOracleReworked(unittest.TestCase):
    def test_shuffled_checks_target_not_donor_state(self):
        """**评审 P0-4**：donor 自身 fixed 也不影响判定 —— 只看目标漏洞状态。"""
        self.assertTrue(va.evaluate_arm("shuffled", True, "still_vulnerable",
                                        _ev("still_vulnerable"))["accept"])
        r = va.evaluate_arm("shuffled", True, "fixed", _ev("fixed"))
        self.assertFalse(r["accept"], "目标漏洞被意外修复 → 必须拒绝")
        self.assertIn("目标漏洞", r["reason"])

    def test_no_donor_state_option_in_registry(self):
        self.assertNotIn("donor_state",
                         {v["expect_target_oracle"] for v in va.ARM_ORACLE.values()})

    def test_oracle_result_enum_enforced(self):
        """非枚举值（含旧版的 'garbage'）必须拒绝。"""
        for bad in ("garbage", "donor_state", "", None, 1):
            r = va.evaluate_arm("shuffled", True, bad, _ev("still_vulnerable"))
            self.assertFalse(r["accept"], f"{bad!r} 不应通过")

    def test_missing_evidence_rejected(self):
        r = va.evaluate_arm("placebo", True, "still_vulnerable", None)
        self.assertFalse(r["accept"])
        self.assertIn("证据", r["reason"])

    def test_incomplete_evidence_rejected(self):
        ev = _ev()
        ev.poc_sha256 = ""
        self.assertFalse(va.evaluate_arm("placebo", True, "still_vulnerable", ev)["accept"])

    def test_evidence_verdict_must_match(self):
        ev = _ev("fixed")
        r = va.evaluate_arm("placebo", True, "still_vulnerable", ev)
        self.assertFalse(r["accept"])

    def test_accept_includes_evidence(self):
        r = va.evaluate_arm("placebo", True, "still_vulnerable", _ev())
        self.assertTrue(r["accept"], r)
        self.assertEqual(set(r["oracle_evidence"]), set(va.ORACLE_EVIDENCE_FIELDS))

    def test_all_arms_use_target_oracle_key(self):
        for spec in va.ARM_ORACLE.values():
            self.assertIn("expect_target_oracle", spec)
            self.assertNotIn("expect_oracle", spec)

    def test_registry_lists_oracle_evidence_fields(self):
        self.assertEqual(set(va.arms_registry()["oracle_evidence_fields"]),
                         set(va.ORACLE_EVIDENCE_FIELDS))


# ===========================================================================
# P0-5：功效 —— 条件 vs 非条件；无 p 参数；敏感性
# ===========================================================================
class TestPowerReworked(unittest.TestCase):
    def test_exact_p_has_no_p_parameter(self):
        """**评审 P0-5**：'双倍较小尾部'只对 p=0.5 成立 → 不暴露 p 参数。"""
        sig = inspect.signature(vp.exact_two_sided_p)
        self.assertNotIn("p", sig.parameters)

    def test_exact_p_known_value(self):
        self.assertAlmostEqual(vp.exact_two_sided_p(2, 12), 0.03857, places=4)

    def test_conditional_power_named_and_documented(self):
        rep = vp.power_report()
        self.assertEqual(rep["quantity_name"], "conditional power given m discordant pairs")
        self.assertIn("不是", rep["quantity_note"])
        self.assertTrue(any("m 只有跑完才知道" in c for c in rep["caveats"]))

    def test_conditional_power_values(self):
        self.assertAlmostEqual(vp.conditional_power(8, 0.90), 0.4305, places=3)
        self.assertEqual(vp.required_discordant_pairs(0.90, 0.05, 0.80), 12)

    def test_unconditional_power_uses_N_and_discordance(self):
        """非条件功效必须随 N 与 discordance 变化（这才是样本量相关量）。"""
        low = vp.unconditional_power(10, 0.90, 0.3)
        high = vp.unconditional_power(30, 0.90, 0.7)
        self.assertLess(low, high)
        self.assertGreater(vp.unconditional_power(14, 0.90, 0.5), 0.0)

    def test_sensitivity_table_covers_grid(self):
        rows = vp.sensitivity_table(N_list=(8, 14), p1_list=(0.6, 0.9),
                                    discordance_list=(0.3, 0.5))
        self.assertEqual(len(rows), 2 * 2 * 2)
        for r in rows:
            self.assertIn("expected_m", r)
            self.assertIn("unconditional_power", r)

    def test_required_N_monotone_in_discordance(self):
        """discordance 越低，达到目标功效所需的 N 越大（或不可达 -1）。"""
        n_low = vp.required_N_for_target(0.90, 0.3)
        n_high = vp.required_N_for_target(0.90, 0.7)
        if n_low != -1 and n_high != -1:
            self.assertGreater(n_low, n_high)

    def test_report_warns_about_V4_size(self):
        rep = vp.power_report()
        self.assertTrue(any("CVE" in c for c in rep["caveats"]))
        self.assertIn("判别力有限", rep["wording_rule"])

    def test_bad_inputs(self):
        with self.assertRaises(ValueError):
            vp.conditional_power(10, 1.5)
        with self.assertRaises(ValueError):
            vp.unconditional_power(10, 0.9, 1.5)


if __name__ == "__main__":
    unittest.main()
