# -*- coding: utf-8 -*-
"""A-3 第 1 项 步 5：主 estimand 的**统计功效脚本**（口径可复算）。

口径（与 `V4-四臂算法预注册.md` §5.2 一致，**参数全部显式**）：
    检验      : McNemar 精确检验（**双侧**）
    零假设    : H0: p = 0.5（discordant 对中无方向偏好）
    效应       : p1 = P(判别成功 | discordant)
    样本单位   : **discordant pairs**（不是 arm、不是 CVE）
    α = 0.05，目标功效 = 0.80

关键纪律：功效**只在引用本节时讨论**；结论性表述不得写 `underpowered`，
只能写"判别力有限"。
"""
from __future__ import annotations

import math

POWER_SCHEMA = "v4-power/1"
DEFAULT_ALPHA = 0.05
DEFAULT_TARGET_POWER = 0.80
DEFAULT_P1 = 0.90


def _binom_pmf(k: int, n: int, p: float) -> float:
    return math.comb(n, k) * (p ** k) * ((1 - p) ** (n - k))


def binom_cdf(k: int, n: int, p: float) -> float:
    """P(X <= k)。"""
    return sum(_binom_pmf(i, n, p) for i in range(0, k + 1))


def exact_two_sided_p(k: int, n: int, p: float = 0.5) -> float:
    """**精确双侧**二项检验 p 值（按"等可能更极端"定义，用于 McNemar）。

    `k` = 较少方向的 discordant 计数（与既有 `mcnemar_exact` 口径一致）。
    """
    if n <= 0:
        return 1.0
    tail = binom_cdf(min(k, n - k), n, p)
    return min(1.0, 2 * tail)


def mcnemar_reject_threshold(m: int, alpha: float = DEFAULT_ALPHA) -> int:
    """给定 discordant 对总数 `m`，返回**拒绝域**：`min(b,c) <= t` 时拒绝 H0。"""
    if m <= 0:
        return -1
    for t in range(0, m // 2 + 1):
        if exact_two_sided_p(t, m) <= alpha:
            continue
        return t - 1        # 最后一个仍可拒绝的 t
    return m // 2


def mcnemar_power(m: int, p1: float = DEFAULT_P1,
                  alpha: float = DEFAULT_ALPHA) -> float:
    """给定 discordant 对数 `m` 与效应 `p1`，计算**精确功效**。

    在 H1 下，判别成功数 `K ~ Binomial(m, p1)`；当
    `min(K, m-K) <= t`（等价于 `K` 落在拒绝域）时拒绝 H0。
    """
    if m <= 0:
        return 0.0
    if not (0.0 < p1 < 1.0):
        raise ValueError("p1 必须在 (0,1)")
    t = mcnemar_reject_threshold(m, alpha)
    if t < 0:
        return 0.0
    lo, hi = t, m - t        # 拒绝域: K <= t 或 K >= m - t
    return sum(_binom_pmf(k, m, p1) for k in range(0, lo + 1)) + \
        sum(_binom_pmf(k, m, p1) for k in range(hi, m + 1))


def required_discordant_pairs(p1: float = DEFAULT_P1,
                              alpha: float = DEFAULT_ALPHA,
                              power: float = DEFAULT_TARGET_POWER,
                              m_max: int = 200) -> int:
    """达到目标功效所需的**最小** discordant 对数；找不到返回 -1（fail-closed）。"""
    for m in range(1, m_max + 1):
        if mcnemar_power(m, p1, alpha) >= power:
            return m
    return -1


def power_curve(ms, p1: float = DEFAULT_P1, alpha: float = DEFAULT_ALPHA) -> dict:
    return {str(m): round(mcnemar_power(m, p1, alpha), 6) for m in ms}


def power_report() -> dict:
    """预注册口径下的功效报告（可直接引用，参数全部显式）。"""
    m8 = mcnemar_power(8)
    need = required_discordant_pairs()
    return {
        "schema": POWER_SCHEMA,
        "test": "McNemar exact, two-sided",
        "h0": "p = 0.5",
        "effect_p1": DEFAULT_P1,
        "alpha": DEFAULT_ALPHA,
        "target_power": DEFAULT_TARGET_POWER,
        "unit": "discordant pairs",
        "power_at_m8": round(m8, 4),
        "required_m_for_target": need,
        "curve_m6_to_m16": power_curve(range(6, 17)),
        "wording_rule": ("若最终 m < required，结论标注'**判别力有限**'；"
                         "**不得**把 underpowered 当作结论性表述，功效不足只在引用本报告时讨论"),
    }
