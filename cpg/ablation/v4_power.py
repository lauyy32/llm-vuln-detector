# -*- coding: utf-8 -*-
"""A-3 步 5（返工版）：主 estimand 的**条件功效**与样本量敏感性。

返工要点（评审 2 的 P0-5）：
  - 原 `power_report()` 只给"给定恰好 m 个 discordant pairs 时的功效"，
    却容易被读成"V4 需要 12 个样本"。现**强制命名为** `conditional power given m`，
    并显式声明它**不是**总体样本量保证。
  - `m` 是运行后才知道的；实验只有约 14 个 CVE → `m ≤ N`。
  - 补 `p1 × discordance rate × N` 敏感性表与"在 N 人下可达功效"。
  - `exact_two_sided_p` 的"双倍较小尾部"实现**仅对 p=0.5 成立** → 参数 `p` 移除，
    避免误用（如需一般 p，必须实现真正的概率质量排序双侧检验）。
"""
from __future__ import annotations

import math

POWER_SCHEMA = "v4-power/3"
DEFAULT_ALPHA = 0.05
DEFAULT_TARGET_POWER = 0.80
DEFAULT_P1 = 0.90
# **计划上限**（当前语料规模）；最终 N 须从 frozen active universe 读取
PLANNED_MAX_N = 14

# `unconditional_power` 所依赖的**假设**（必须随报告一起给出，不得当作数据事实）
HOMOGENEITY_ASSUMPTIONS = (
    "M ~ Binomial(N, discordance_rate)：各配对样本的 discordance 概率同质且相互独立",
    "判别方向概率 p1 在所有 discordant 对中同质",
    "p1 与 discordance_rate 相互独立",
    "不涉及多重性调整（若做多重比较须另行校正）",
)


def _binom_pmf(k: int, n: int, p: float) -> float:
    return math.comb(n, k) * (p ** k) * ((1 - p) ** (n - k))


def binom_cdf(k: int, n: int, p: float) -> float:
    return sum(_binom_pmf(i, n, p) for i in range(0, k + 1))


def exact_two_sided_p(k: int, n: int) -> float:
    """McNemar 的**精确双侧** p 值（**仅 p=0.5 口径**）。

    实现为"2 × 较小尾部"，该式**只在对称零假设 p=0.5 下成立**；
    故此处不暴露 `p` 参数，避免被用于一般比例检验（那需按概率质量排序）。
    """
    if n <= 0:
        return 1.0
    tail = binom_cdf(min(k, n - k), n, 0.5)
    return min(1.0, 2 * tail)


def mcnemar_reject_threshold(m: int, alpha: float = DEFAULT_ALPHA) -> int:
    """`min(b,c) <= t` 时拒绝 H0；返回最后一个可拒绝的 `t`（不存在则 -1）。"""
    if m <= 0:
        return -1
    last = -1
    for t in range(0, m // 2 + 1):
        if exact_two_sided_p(t, m) <= alpha:
            last = t
        else:
            break
    return last


def conditional_power(m: int, p1: float = DEFAULT_P1,
                      alpha: float = DEFAULT_ALPHA) -> float:
    """**条件功效**：给定**恰好** m 个 discordant pairs 时拒绝 H0 的概率。

    在 H1 下判别成功数 `K ~ Binomial(m, p1)`；`K <= t` 或 `K >= m-t` 时拒绝。
    ——注意：这是**条件**于 m 的功效，不是样本量保证。
    """
    if m <= 0:
        return 0.0
    if not (0.0 < p1 < 1.0):
        raise ValueError("p1 必须在 (0,1)")
    t = mcnemar_reject_threshold(m, alpha)
    if t < 0:
        return 0.0
    return (sum(_binom_pmf(k, m, p1) for k in range(0, t + 1))
            + sum(_binom_pmf(k, m, p1) for k in range(m - t, m + 1)))


def required_discordant_pairs(p1: float = DEFAULT_P1, alpha: float = DEFAULT_ALPHA,
                              power: float = DEFAULT_TARGET_POWER, m_max: int = 500) -> int:
    """达到目标功效所需的**最小** discordant 对数（找不到 → -1）。"""
    for m in range(1, m_max + 1):
        if conditional_power(m, p1, alpha) >= power:
            return m
    return -1


def conditional_power_curve(ms, p1: float = DEFAULT_P1,
                            alpha: float = DEFAULT_ALPHA) -> dict:
    return {str(m): round(conditional_power(m, p1, alpha), 6) for m in ms}


def unconditional_power(N: int, p1: float = DEFAULT_P1, discordance: float = 0.5,
                        alpha: float = DEFAULT_ALPHA) -> float:
    """**非条件功效**：`N` 个配对样本、discordance rate = `q` 时的整体拒绝概率。

    `M ~ Binomial(N, q)` 为 discordant 对数；对每个 m 取条件功效后按 `P(M=m)` 加权。
    这**才是**与"样本量"直接相关的量。
    """
    if N <= 0:
        return 0.0
    if not (0.0 <= discordance <= 1.0):
        raise ValueError("discordance 必须在 [0,1]")
    return sum(_binom_pmf(m, N, discordance) * conditional_power(m, p1, alpha)
               for m in range(0, N + 1))


def sensitivity_table(N_list=(8, 10, 12, 14, 20),
                      p1_list=(0.6, 0.7, 0.8, 0.9),
                      discordance_list=(0.3, 0.5, 0.7)) -> list:
    """`p1 × discordance rate × N` 敏感性表（每行一个组合）。"""
    rows = []
    for p1 in p1_list:
        for q in discordance_list:
            for N in N_list:
                rows.append({
                    "p1": p1, "discordance": q, "N": N,
                    "expected_m": round(N * q, 2),
                    "unconditional_power": round(unconditional_power(N, p1, q), 4),
                })
    return rows


def required_N_for_target(p1: float = DEFAULT_P1, discordance: float = 0.5,
                          alpha: float = DEFAULT_ALPHA,
                          power: float = DEFAULT_TARGET_POWER, n_max: int = 400) -> int:
    """在给定 discordance rate 下，达到目标功效所需的**配对样本数 N**（-1 = 不可达）。"""
    for N in range(1, n_max + 1):
        if unconditional_power(N, p1, discordance, alpha) >= power:
            return N
    return -1


def power_report(N_active: int | None = None) -> dict:
    """**准确命名**的功效报告：条件功效 + 非条件敏感性 + 可行性判断。

    `N_active`：**确认性合格样本数**，应由 frozen active universe 提供
    （例如 corpus 门禁输出的合格集大小）。未提供时退回 `PLANNED_MAX_N`
    并显式标注 `N_source = "planned_max"`，**不得**被当作最终样本量引用。
    """
    if N_active is None:
        n_use, n_source = PLANNED_MAX_N, "planned_max (未提供 frozen active universe)"
    else:
        if not isinstance(N_active, int) or isinstance(N_active, bool) or N_active <= 0:
            raise ValueError("N_active 必须为正整数")
        if N_active > PLANNED_MAX_N:
            raise ValueError(f"N_active={N_active} 超过计划上限 {PLANNED_MAX_N}；"
                             "若语料扩容请先更新 PLANNED_MAX_N 与冻结协议")
        n_use, n_source = N_active, "frozen active universe"

    need = required_discordant_pairs()
    return {
        "schema": POWER_SCHEMA,
        "quantity_name": "conditional power given m discordant pairs",
        "quantity_note": ("这是**条件**功效：只在'恰好有 m 个 discordant pairs'的前提下成立；"
                          "**不是**总体样本量保证。m 是运行后才知道的量，且 m ≤ 配对样本数 N。"),
        "test": "McNemar exact, two-sided (p=0.5 only)",
        "h0": "p = 0.5",
        "effect_p1": DEFAULT_P1,
        "alpha": DEFAULT_ALPHA,
        "target_power": DEFAULT_TARGET_POWER,
        "unit": "discordant pairs",
        "N_active": n_use,
        "N_source": n_source,
        "planned_max_N": PLANNED_MAX_N,
        "conditional_power_at_m8": round(conditional_power(8), 4),
        "required_m_for_target": need,
        "curve_m6_to_m16": conditional_power_curve(range(6, 17)),
        "homogeneity_assumptions": list(HOMOGENEITY_ASSUMPTIONS),
        "assumption_scope_note": ("上列假设**仅**用于 `unconditional_power` 及其敏感性表；"
                                  "`conditional_power` 不依赖它们（m 为给定值）。"
                                  "假设不可作为数据事实引用，若与实测 discordance 分布冲突须重算。"),
        "caveats": [
            "m 只有跑完才知道；本报告不能推出'V4 需要 m=12 个样本'",
            f"当前 N={n_use}（来源：{n_source}）→ m ≤ {n_use}",
            "p1=0.90 是乐观单点假设，须用敏感性表覆盖 0.6–0.9",
            f"在 N={n_use}、q=0.5 下非条件功效仅 "
            f"{round(unconditional_power(n_use, 0.90, 0.5), 4)}（该值依赖同质性假设）",
        ],
        "unconditional_required_N": {
            f"q={q}": required_N_for_target(0.90, q) for q in (0.3, 0.5, 0.7)
        },
        "sensitivity_p1_x_discordance_x_N": sensitivity_table(),
        "wording_rule": (
            "在所列 p1 与 discordance-rate 假设下，本实验的统计功效低于预设目标；"
            "**不得据此单独推断模型真实判别能力**，亦不得把 underpowered 表述为'无效应'。"
            "可写'判别力有限'；功效数值仅在引用本报告时讨论。"),
    }
