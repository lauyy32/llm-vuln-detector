# -*- coding: utf-8 -*-
"""A-3 步 2/3/4/5 验收：token 匹配 / shuffled 约束 / oracle 判据 / 功效脚本。

纪律：**确定性**（同输入同输出）、**fail-closed**（无候选/未知状态不得静默通过）、
**已知值校验**（功效与既有 McNemar 口径交叉核对）。
"""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from cpg.ablation import v4_arms as va  # noqa: E402
from cpg.ablation import v4_power as vp  # noqa: E402


# ===========================================================================
# 步 2：token 匹配搜索
# ===========================================================================
class TestTokenMatchSearch(unittest.TestCase):
    def _cands(self):
        return [va.Candidate(key=f"c{i}", tokens=t)
                for i, t in enumerate((80, 100, 120, 160))]

    def test_selects_closest_and_ratio_unrounded(self):
        r = va.token_match_search(self._cands(), 100)
        self.assertEqual(r["status"], "OK")
        self.assertEqual(r["selected"].key, "c1")     # tokens=100
        self.assertEqual(r["ratio"], 1.0)
        self.assertTrue(r["in_bounds"])

    def test_deterministic(self):
        a = va.token_match_search(self._cands(), 110)
        b = va.token_match_search(self._cands(), 110)
        self.assertEqual(a["selected"].key, b["selected"].key)

    def test_tie_break_by_key(self):
        """|ratio-1| 相同时按 key 字典序最小者。"""
        cands = [va.Candidate(key="zzz", tokens=90), va.Candidate(key="aaa", tokens=110)]
        r = va.token_match_search(cands, 100)
        self.assertEqual(r["selected"].key, "aaa")

    def test_out_of_bounds_flagged_not_hidden(self):
        r = va.token_match_search([va.Candidate(key="far", tokens=1000)], 100)
        self.assertFalse(r["in_bounds"])
        self.assertIn("bounds", r)

    def test_empty_candidates_fail_closed(self):
        r = va.token_match_search([], 100)
        self.assertEqual(r["status"], "NO_CANDIDATE")
        self.assertIsNone(r["selected"])
        self.assertIn("不得静默跳过", r["reason"])

    def test_bad_target_raises(self):
        with self.assertRaises(ValueError):
            va.token_match_search(self._cands(), 0)

    def test_trace_present(self):
        r = va.token_match_search(self._cands(), 100)
        self.assertEqual(len(r["trace"]), 4)
        self.assertIn("tie_break", r)


# ===========================================================================
# 步 3：shuffled 约束
# ===========================================================================
def _donor(sid, **kw):
    d = {"sample_id": sid, "apply_clean": True, "language": "python",
         "cwe_family": "injection", "patch_tokens": 100, "n_files": 1,
         "is_composite": False}
    d.update(kw)
    return d


TARGET = _donor("TARGET", patch_tokens=100)


class TestShuffleConstraints(unittest.TestCase):
    def test_donor_equal_target_rejected_by_hard(self):
        r = va.select_donor(TARGET, [_donor("TARGET")])
        self.assertEqual(r["status"], "NO_DONOR")
        self.assertIn("硬约束", r["reason"])

    def test_not_apply_clean_rejected_by_hard(self):
        r = va.select_donor(TARGET, [_donor("D1", apply_clean=False)])
        self.assertEqual(r["status"], "NO_DONOR")

    def test_exact_match_no_relaxation(self):
        r = va.select_donor(TARGET, [_donor("D1")])
        self.assertEqual(r["status"], "OK")
        self.assertEqual(r["relaxations"], [])
        self.assertEqual(r["donor"]["sample_id"], "D1")

    def test_relaxation_order_is_reverse_of_priority(self):
        """只有语言不同的 donor → 必须记录放宽了哪些软约束，且顺序为**逆序**。"""
        r = va.select_donor(TARGET, [_donor("D1", language="java")])
        self.assertEqual(r["status"], "OK")
        # 逆序放宽：先放最弱的 not_composite，再 same_file_count，再 token_window，再 same_cwe_family，最后 same_language
        self.assertTrue(r["relaxations"], r)
        self.assertEqual(r["relaxations"][0], "not_composite")
        self.assertIn("same_language", r["relaxations"])

    def test_no_donor_after_all_relaxations(self):
        """唯一候选是目标自己 → 硬约束淘汰 → NO_DONOR（不静默降级）。"""
        r = va.select_donor(TARGET, [_donor("TARGET", language="java")])
        self.assertEqual(r["status"], "NO_DONOR")
        self.assertEqual(r["n_donors"], 1)

    def test_covariates_reported(self):
        r = va.select_donor(TARGET, [_donor("D1")])
        self.assertEqual(set(r["covariates"]), {"target", "donor"})
        for side in ("target", "donor"):
            self.assertEqual(set(r["covariates"][side]), set(va.COVARIATE_FIELDS))

    def test_tie_break_deterministic(self):
        ds = [_donor("D2"), _donor("D1"), _donor("D3")]
        a = va.select_donor(TARGET, ds)
        b = va.select_donor(TARGET, list(reversed(ds)))
        self.assertEqual(a["donor"]["sample_id"], b["donor"]["sample_id"])

    def test_registry_lists_constraints(self):
        reg = va.arms_registry()
        self.assertEqual(reg["schema"], va.ARMS_SCHEMA)
        self.assertEqual(len(reg["fingerprint"]), 64)
        hard = {x["name"] for x in reg["shuffle"]["hard"]}
        soft = {x["name"] for x in reg["shuffle"]["soft_in_relax_order"]}
        self.assertEqual(hard, {"donor_ne_target", "apply_clean"})
        self.assertIn("same_language", soft)
        self.assertEqual(len(soft), len(va.SHUFFLE_SOFT_CONSTRAINTS))


# ===========================================================================
# 步 4：oracle 判据
# ===========================================================================
class TestArmOracle(unittest.TestCase):
    def test_four_arms_registered(self):
        reg = va.arms_registry()
        self.assertEqual(reg["n_arms"], 4)
        self.assertEqual(set(reg["arms"]),
                         {"annotated-security-complete", "support-only-insufficient",
                          "placebo", "shuffled"})

    def test_complete_arm_requires_fixed(self):
        self.assertTrue(va.evaluate_arm("annotated-security-complete", True, "fixed")["accept"])
        self.assertFalse(va.evaluate_arm("annotated-security-complete", True,
                                         "still_vulnerable")["accept"])

    def test_support_only_requires_still_vulnerable(self):
        self.assertTrue(va.evaluate_arm("support-only-insufficient", True,
                                        "still_vulnerable")["accept"])
        self.assertFalse(va.evaluate_arm("support-only-insufficient", True, "fixed")["accept"])

    def test_placebo_requires_state_unchanged(self):
        """行为中性 → 漏洞必须仍在。"""
        self.assertTrue(va.evaluate_arm("placebo", True, "still_vulnerable")["accept"])
        self.assertFalse(va.evaluate_arm("placebo", True, "fixed")["accept"])

    def test_unknown_oracle_fail_closed(self):
        for arm in va.ARM_ORACLE:
            r = va.evaluate_arm(arm, True, "unknown")
            self.assertFalse(r["accept"], arm)
            self.assertIn("fail-closed", r["reason"])

    def test_dirty_apply_rejected(self):
        for arm in va.ARM_ORACLE:
            self.assertFalse(va.evaluate_arm(arm, False, "fixed")["accept"], arm)

    def test_unknown_arm_raises(self):
        with self.assertRaises(KeyError):
            va.evaluate_arm("no_such_arm", True, "fixed")

    def test_shuffled_accepts_donor_state(self):
        for st in ("fixed", "still_vulnerable"):
            self.assertTrue(va.evaluate_arm("shuffled", True, st)["accept"], st)


# ===========================================================================
# 步 5：功效脚本（**与既有 McNemar 口径交叉核对**）
# ===========================================================================
class TestPower(unittest.TestCase):
    def test_exact_p_matches_frozen_mcnemar(self):
        """b=10, c=2, n=12 → 2*(1+12+66)/4096 = 0.03857（与 strict_recompute 口径一致）。"""
        self.assertAlmostEqual(vp.exact_two_sided_p(2, 12), 0.03857, places=4)

    def test_exact_p_symmetric(self):
        self.assertAlmostEqual(vp.exact_two_sided_p(1, 7), vp.exact_two_sided_p(6, 7), places=9)

    def test_zero_discordant_p_is_one(self):
        self.assertEqual(vp.exact_two_sided_p(0, 0), 1.0)

    def test_power_at_m8_matches_prior_analysis(self):
        """先前的功效分析：m=8、p1=0.90 → 功效约 0.43。"""
        p = vp.mcnemar_power(8, 0.90)
        self.assertAlmostEqual(p, 0.43, delta=0.03)

    def test_required_m_is_12(self):
        self.assertEqual(vp.required_discordant_pairs(0.90, 0.05, 0.80), 12)

    def test_power_not_monotone_small_m_but_rises_after_steps(self):
        """**精确检验的拒绝域离散** → 功效在小 m 下**非单调**（m=6 高于 m=7）。

        这**不是实现错误**，而是 McNemar 精确检验的固有性质：拒绝域随 m 阶跃
        （t=0→1→2），在阶跃之间功效反而下降。本测试**固定该现象**，
        并要求"每一阶跃之后整体上升"。
        """
        ps = {m: vp.mcnemar_power(m, 0.90) for m in range(6, 15)}
        self.assertGreater(ps[6], ps[7])          # 非单调（离散性）
        self.assertLess(ps[8], ps[9])             # 阶跃后跃升
        self.assertLess(ps[11], ps[12])           # 再次阶跃
        self.assertGreater(ps[12], ps[8])         # 整体上升趋势

    def test_power_rises_at_least_over_large_range(self):
        self.assertLess(vp.mcnemar_power(10, 0.90), vp.mcnemar_power(30, 0.90))

    def test_reject_threshold_is_stepwise(self):
        ts = [vp.mcnemar_reject_threshold(m) for m in range(6, 15)]
        self.assertEqual(ts, sorted(ts))          # 阈值单调不减
        self.assertEqual(len(set(ts)), 3)         # 6..14 内出现 0,1,2 三档

    def test_power_monotone_in_p1(self):
        ps = [vp.mcnemar_power(20, p1) for p1 in (0.6, 0.7, 0.8, 0.9)]
        self.assertEqual(ps, sorted(ps))

    def test_power_at_p1_half_is_alpha(self):
        """p1=0.5 时功效应约等于 α（双侧检验）。"""
        self.assertAlmostEqual(vp.mcnemar_power(40, 0.5), 0.05, delta=0.03)

    def test_bad_p1_raises(self):
        with self.assertRaises(ValueError):
            vp.mcnemar_power(10, 1.5)

    def test_report_declares_all_parameters(self):
        rep = vp.power_report()
        for k in ("test", "h0", "effect_p1", "alpha", "target_power", "unit"):
            self.assertIn(k, rep, k)
        self.assertEqual(rep["unit"], "discordant pairs")
        self.assertEqual(rep["alpha"], 0.05)
        self.assertEqual(rep["required_m_for_target"], 12)
        self.assertIn("判别力有限", rep["wording_rule"])
        self.assertIn("underpowered", rep["wording_rule"])   # 明确禁止当作结论性表述


if __name__ == "__main__":
    unittest.main()
