# -*- coding: utf-8 -*-
"""A-3 步 5（第三次返工，schema `v4-power/4`）：条件/非条件功效与样本量敏感性。

返工要点（评审 4 的 P1）：
  · 旧名 `required_discordant_pairs` / `required_N_for_target` 暗示"所需最小样本量"，
    但离散精确检验（McNemar exact）的功效**不保证随样本量单调**，首次达到阈值
    并不意味着之后一直维持在阈值以上。故改名为 `first_crossing_m` /
    `first_crossing_N`，并新增 `sustained_crossing_*`：显式核验从首个跨越点
    到预注册上限是否**再未跌破**目标，只有全程不跌破才允许称"最低所需"。
  · `wording_rule` 不再对整张敏感性表作笼统判断，改为**绑定具体参数组合**
    （见 `underpowered_cells`）。

口径约定（与预注册 §5.2 一致）：
  检验 = McNemar 精确双侧（**仅 p=0.5 成立**）；α=0.05；目标功效 0.80；
  效应 p1=0.90；样本单位 = **discordant pairs**。
"""
from __future__ import annotations

import math
from functools import lru_cache

POWER_SCHEMA = "v4-power/4"
DEFAULT_ALPHA = 0.05
DEFAULT_TARGET_POWER = 0.80
DEFAULT_P1 = 0.90
# **计划上限**（当前语料规模）；最终 N 须从 frozen active universe 读取
PLANNED_MAX_N = 14
PREREG_M_FOR_TARGET = 12      # 预注册 §5.2 记录：达 0.80 需 m=12 discordant pairs

# `unconditional_power` 所依赖的**假设**（必须随报告一起给出，不得当作数据事实）
HOMOGENEITY_ASSUMPTIONS = (
    "M ~ Binomial(N, discordance_rate)：各配对样本的 discordance 概率同质且相互独立",
    "判别方向概率 p1 在所有 discordant 对中同质",
    "p1 与 discordance_rate 相互独立",
    "不涉及多重性调整（若做多重比较须另行校正）",
)


@lru_cache(maxsize=200000)
def _binom_pmf(k: int, n: int, p: float) -> float:
    return math.comb(n, k) * (p ** k) * ((1 - p) ** (n - k))


@lru_cache(maxsize=200000)
def binom_cdf(k: int, n: int, p: float) -> float:
    return sum(_binom_pmf(i, n, p) for i in range(0, k + 1))


@lru_cache(maxsize=200000)
def exact_two_sided_p(k: int, n: int) -> float:
    """McNemar 的**精确双侧** p 值（**仅 p=0.5 口径**）。

    实现为"2 × 较小尾部"，该式**只在对称零假设 p=0.5 下成立**；
    故此处不暴露 `p` 参数，避免被用于一般比例检验（那需按概率质量排序）。
    """
    if n <= 0:
        return 1.0
    tail = binom_cdf(min(k, n - k), n, 0.5)
    return min(1.0, 2 * tail)


@lru_cache(maxsize=200000)
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


@lru_cache(maxsize=200000)
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


@lru_cache(maxsize=200000)
def unconditional_power(N: int, p1: float = DEFAULT_P1, discordance: float = 0.5,
                        alpha: float = DEFAULT_ALPHA) -> float:
    """**非条件功效**：`N` 个配对样本、discordance rate = `q` 时的整体拒绝概率。

    `M ~ Binomial(N, q)` 为 discordant 对数；对每个 m 取条件功效后按 `P(M=m)` 加权。
    这**才是**与"样本量"直接相关的量（依赖 `HOMOGENEITY_ASSUMPTIONS`）。
    """
    if N <= 0:
        return 0.0
    if not (0.0 <= discordance <= 1.0):
        raise ValueError("discordance 必须在 [0,1]")
    return sum(_binom_pmf(m, N, discordance) * conditional_power(m, p1, alpha)
               for m in range(0, N + 1))


def conditional_power_curve(ms, p1: float = DEFAULT_P1,
                            alpha: float = DEFAULT_ALPHA) -> dict:
    return {str(m): round(conditional_power(m, p1, alpha), 6) for m in ms}


# ---------------------------------------------------------------------------
# 首次跨越 vs 持续维持（**命名修正**）
# ---------------------------------------------------------------------------
def first_crossing_m(p1: float = DEFAULT_P1, alpha: float = DEFAULT_ALPHA,
                     power: float = DEFAULT_TARGET_POWER, m_max: int = 500):
    """**首次**达到目标功效的 discordant 对数；找不到返回 `None`。

    **不得**据此称"所需最小 m"：离散精确检验的功效非单调，后续 m 可能跌破阈值。
    若要使用"最低所需"措辞，须改用 `sustained_crossing_m` 并确认全程不跌破。
    """
    for m in range(1, m_max + 1):
        if conditional_power(m, p1, alpha) >= power:
            return m
    return None


def first_crossing_N(p1: float = DEFAULT_P1, discordance: float = 0.5,
                     alpha: float = DEFAULT_ALPHA, power: float = DEFAULT_TARGET_POWER,
                     n_max: int = 400):
    """**首次**达到目标功效的配对样本数 N；找不到返回 `None`。同上，不得称"最低所需"。"""
    for N in range(1, n_max + 1):
        if unconditional_power(N, p1, discordance, alpha) >= power:
            return N
    return None


def _sustained(power_fn, first, power: float, upto: int, scan_max: int, unit: str) -> dict:
    """通用「首次跨越 + 是否持续维持」核验。

    `power_fn(x)` 给出 x 处的功效；`first()` 给出首次跨越点；`upto` 为核验上限。
    """
    fc = first()
    if fc is None:
        return {"first_crossing": None, "contiguous_end": None,
                "no_drop_through_upto": False, "drops": [], "n_drops": 0,
                "enforced_upto": upto,
                "claim": (f"在 {unit} ≤ {scan_max} 内未跨越目标功效；"
                          f"不得声明任何「所需样本量」")}
    if fc > upto:
        return {"first_crossing": fc, "contiguous_end": None,
                "no_drop_through_upto": False, "drops": [], "n_drops": 0,
                "enforced_upto": upto,
                "claim": (f"首个跨越点在 {unit}={fc}，已超出核验窗口 "
                          f"{unit} ≤ {upto} → 窗口内未跨越，"
                          f"**不得**称「最低所需」，只能称「首次跨越点」")}
    drops = [x for x in range(fc + 1, upto + 1) if power_fn(x) < power]
    first_drop = drops[0] if drops else None
    no_drop = first_drop is None
    return {"first_crossing": fc,
            "contiguous_end": upto if no_drop else first_drop - 1,
            "no_drop_through_upto": no_drop,
            "drops": drops[:20], "n_drops": len(drops),
            "enforced_upto": upto,
            "claim": (f"首个跨越 {unit}={fc} 后至 {unit}={upto} 全程未跌破目标 → "
                      f"可称「在 ≤{upto} 范围内所需的最低 {unit}」"
                      if no_drop else
                      f"首个跨越 {unit}={fc}，但随后于 {unit}={first_drop} 处跌破目标 → "
                      f"**不得**称「最低所需」，只能称「首次跨越点」")}


def sustained_crossing_m(p1: float = DEFAULT_P1, alpha: float = DEFAULT_ALPHA,
                         power: float = DEFAULT_TARGET_POWER,
                         enforce_upto: int | None = None, m_max: int = 500) -> dict:
    """从首个跨越点到 `enforce_upto`（默认 `m_max`）核验功效是否再未跌破目标。"""
    upto = m_max if enforce_upto is None else int(enforce_upto)
    if upto < 1:
        raise ValueError("enforce_upto 必须为正整数")
    return _sustained(lambda x: conditional_power(x, p1, alpha),
                      lambda: first_crossing_m(p1, alpha, power, m_max),
                      power, upto, m_max, "m")


def sustained_crossing_N(p1: float = DEFAULT_P1, discordance: float = 0.5,
                         alpha: float = DEFAULT_ALPHA,
                         power: float = DEFAULT_TARGET_POWER,
                         enforce_upto: int | None = None, n_max: int = 400) -> dict:
    """从首个跨越点到 `enforce_upto`（默认 `PLANNED_MAX_N`）核验是否再未跌破目标。"""
    upto = PLANNED_MAX_N if enforce_upto is None else int(enforce_upto)
    if upto < 1:
        raise ValueError("enforce_upto 必须为正整数")
    return _sustained(lambda x: unconditional_power(x, p1, discordance, alpha),
                      lambda: first_crossing_N(p1, discordance, alpha, power, n_max),
                      power, upto, n_max, "N")


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


def underpowered_cells(N_list=(8, 10, 12, 14, 20),
                       p1_list=(0.6, 0.7, 0.8, 0.9),
                       discordance_list=(0.3, 0.5, 0.7),
                       target: float = DEFAULT_TARGET_POWER,
                       limit: int = 12) -> list:
    """**低于目标功效的具体参数组合**（措辞只能绑定到这些组合，不得笼统概括全表）。"""
    rows = [r for r in sensitivity_table(N_list, p1_list, discordance_list)
            if r["unconditional_power"] < target]
    rows.sort(key=lambda r: r["unconditional_power"])
    out = [dict(r, below_target=True) for r in rows[:limit]]
    return out


def power_report(N_active: int | None = None) -> dict:
    """**准确命名**的功效报告：条件功效 + 首次/持续跨越 + 绑定组合的措辞规则。

    `N_active`：**确认性合格样本数**，应由 frozen active universe 提供。
    未提供时退回 `PLANNED_MAX_N` 并显式标注 `N_source = "planned_max"`，
    **不得**被当作最终样本量引用。
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

    fc_m = first_crossing_m()
    sus_m = sustained_crossing_m(enforce_upto=PLANNED_MAX_N)
    cells = underpowered_cells()
    at_n = round(unconditional_power(n_use, DEFAULT_P1, 0.5), 4)
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
        "prereg_m_for_target": PREREG_M_FOR_TARGET,
        "conditional_power_at_m8": round(conditional_power(8), 4),
        "first_crossing_m": fc_m,
        "first_crossing_naming_warning": (
            "首次跨越点**不等于**'所需最小 m'：离散精确检验功效非单调，"
            "须以 sustained_crossing_m 判定能否使用'最低所需'措辞。"),
        "sustained_crossing_m": sus_m,
        "curve_m6_to_m16": conditional_power_curve(range(6, 17)),
        "homogeneity_assumptions": list(HOMOGENEITY_ASSUMPTIONS),
        "assumption_scope_note": ("上列假设**仅**用于 `unconditional_power` 及其敏感性表；"
                                  "`conditional_power` 不依赖它们（m 为给定值）。"
                                  "假设不可作为数据事实引用，若与实测 discordance 分布冲突须重算。"),
        "unconditional_power_at_N_active_q0.5": at_n,
        "first_crossing_N": {
            f"q={q}": first_crossing_N(DEFAULT_P1, q) for q in (0.3, 0.5, 0.7)
        },
        "sustained_crossing_N": {
            f"q={q}": sustained_crossing_N(DEFAULT_P1, q) for q in (0.3, 0.5, 0.7)
        },
        "underpowered_combinations": cells,
        "sensitivity_p1_x_discordance_x_N": sensitivity_table(),
        "wording_rule": (
            "功效结论只能针对**具体参数组合**表述（N / p1 / discordance 三者给出）；"
            "不得对整张敏感性表作笼统判断。"
            f"本报告中低于目标的组合见 `underpowered_combinations`（共 {len(cells)} 组，已按功效升序）。"
            "在这些组合下，功效低于预设目标；**不得据此单独推断模型真实判别能力**，"
            "亦不得把 underpowered 表述为'无效应'。可写'判别力有限'。"),
    }
