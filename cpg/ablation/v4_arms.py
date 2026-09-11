# -*- coding: utf-8 -*-
"""A-3 第 1 项 步 2/3/4：token 匹配搜索 + shuffled 约束 + 逐臂 oracle 判据。

**边界**（A-3）：只实现**算法与判据**，不生成任何正式四臂工件；
目标 token 数须由冻结后的 minimal-real 提供，本模块只接受它作为参数。

三条设计纪律：
  - **确定性**：候选枚举与排序全部可复算（无隐藏随机）；
  - **fail-closed**：无候选/约束不可满足时返回显式状态，**不静默降级**；
  - **可审计**：每次选择都返回 trace（含放宽了哪些软约束）。
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

ARMS_SCHEMA = "v4-arms/1"

# ---------------------------------------------------------------------------
# 步 2：token 匹配搜索（目标 = **最终 prompt token**，非 patch token）
# ---------------------------------------------------------------------------
TOKEN_RATIO_BOUNDS = (0.8, 1.25)   # 与预注册一致；**未舍入**判定


@dataclass
class Candidate:
    """一个候选变换（含其可复算的标识）。"""
    key: str              # 稳定标识（如 "<file>:<lineno>:<operator>"）
    tokens: int           # 该候选**最终 prompt** 的 token 数
    payload: object = None
    meta: dict = None


def candidate_key(c) -> tuple:
    return (c.key,)


def token_match_search(candidates: list, target_tokens: int,
                       bounds: tuple = TOKEN_RATIO_BOUNDS) -> dict:
    """在候选集中选 token 最接近 `target_tokens` 者（**确定性**）。

    排序键（越小越优先）：`(|ratio - 1|, candidate.key)` —— 先最近，再按 key 字典序，
    保证**同分时结果唯一**；`ratio` 用**未舍入**值计算。

    返回：`selected`（Candidate 或 None）、`ratio`、`in_bounds`、`n_candidates`、
    `trace`（排序前若干项，便于审计）。
    """
    if target_tokens <= 0:
        raise ValueError("target_tokens 必须为正")
    if not candidates:
        return {"status": "NO_CANDIDATE", "selected": None, "n_candidates": 0,
                "reason": "候选集为空（不得静默跳过）"}
    scored = []
    for c in candidates:
        ratio = c.tokens / target_tokens
        # **先按固定精度取整再比较**：否则浮点误差会让"理论同分"的两项（如 90 与 110
        # 相对 100）算出 0.09999999999999998 vs 0.10000000000000009，导致 tie-break 失效。
        dist = round(abs(ratio - 1.0), 9)
        scored.append((dist, c.key, ratio, c))
    scored.sort(key=lambda t: (t[0], t[1]))
    _, _, ratio, best = scored[0]
    lo, hi = bounds
    return {
        "status": "OK",
        "selected": best,
        "ratio": round(ratio, 6),
        "in_bounds": lo <= ratio <= hi,
        "n_candidates": len(candidates),
        "bounds": list(bounds),
        "trace": [{"key": k, "tokens": c.tokens, "ratio": round(r, 6)}
                  for _, k, r, c in scored[:5]],
        "tie_break": "(|ratio-1|, key) 字典序最小者优先",
    }


# ---------------------------------------------------------------------------
# 步 3：shuffled 的硬/软约束与放宽顺序
# ---------------------------------------------------------------------------
# **硬约束**：违反即淘汰（不可放宽）；**软约束**：按**下方顺序**逐条放宽。
SHUFFLE_HARD_CONSTRAINTS = (
    ("donor_ne_target", "donor 不得等于目标样本"),
    ("apply_clean", "donor patch 必须 apply-clean"),
)
SHUFFLE_SOFT_CONSTRAINTS = (
    ("same_language", "donor 与目标同语言"),
    ("same_cwe_family", "donor 与目标同 CWE 族"),
    ("token_window", "donor patch token 在目标 ±25% 内"),
    ("same_file_count", "donor 触及文件数与目标相差 ≤1"),
    ("not_composite", "donor 不是复合提交"),
)
COVARIATE_FIELDS = ("language", "cwe_family", "patch_tokens", "n_files", "is_composite")


def _passes_hard(donor: dict, target: dict) -> list:
    errs = []
    if donor.get("sample_id") == target.get("sample_id"):
        errs.append("donor_ne_target")
    if donor.get("apply_clean") is not True:
        errs.append("apply_clean")
    return errs


def _passes_soft(donor: dict, target: dict, name: str) -> bool:
    if name == "same_language":
        return donor.get("language") == target.get("language")
    if name == "same_cwe_family":
        return donor.get("cwe_family") == target.get("cwe_family")
    if name == "token_window":
        t = target.get("patch_tokens") or 0
        if not t:
            return False
        r = (donor.get("patch_tokens") or 0) / t
        return 0.75 <= r <= 1.25
    if name == "same_file_count":
        return abs((donor.get("n_files") or 0) - (target.get("n_files") or 0)) <= 1
    if name == "not_composite":
        return donor.get("is_composite") is False
    return False


def select_donor(target: dict, donors: list) -> dict:
    """按**预注册顺序**逐条放宽软约束，选第一个满足者（**确定性**）。

    无候选 → `status="NO_DONOR"`（**不静默降级**；调用方须记录该样本不可构造）。
    """
    # 硬约束先过滤
    hard_ok, hard_rejected = [], []
    for d in donors:
        (hard_rejected if _passes_hard(d, target) else hard_ok).append(d)
    if not hard_ok:
        return {"status": "NO_DONOR", "donor": None, "n_donors": len(donors),
                "reason": f"无候选通过硬约束（{len(hard_rejected)} 个被拒）",
                "hard_rejected": len(hard_rejected), "relaxations": []}

    active = list(SHUFFLE_SOFT_CONSTRAINTS)
    relaxations = []
    for _step in range(len(active) + 1):
        pool = [d for d in hard_ok
                if all(_passes_soft(d, target, n) for n, _ in active)]
        if pool:
            pool.sort(key=lambda d: (abs((d.get("patch_tokens") or 0)
                                         - (target.get("patch_tokens") or 0)),
                                     d.get("sample_id", "")))
            chosen = pool[0]
            return {"status": "OK", "donor": chosen, "n_donors": len(donors),
                    "n_pool_after_relax": len(pool),
                    "relaxations": relaxations,
                    "active_constraints": [n for n, _ in active],
                    "covariates": {"target": {k: target.get(k) for k in COVARIATE_FIELDS},
                                   "donor": {k: chosen.get(k) for k in COVARIATE_FIELDS}},
                    "tie_break": "(|patch_tokens 差|, sample_id) 字典序最小者优先"}
        if not active:
            break
        dropped = active.pop()          # 按**逆序**放宽（先放最弱的约束）
        relaxations.append(dropped[0])
    return {"status": "NO_DONOR", "donor": None, "n_donors": len(donors),
            "reason": "全部软约束放宽后仍无候选", "relaxations": relaxations}


# ---------------------------------------------------------------------------
# 步 4：逐臂 oracle 判据（机器化）
# ---------------------------------------------------------------------------
# 每臂 = (apply-clean 要求, oracle 期望, 说明)
ARM_ORACLE = {
    "annotated-security-complete": {
        "require_apply_clean": True,
        "expect_oracle": "fixed",       # oracle 显示漏洞已修复
        "desc": "标注意义上的安全完备补丁：应当修好（若 oracle 显示仍存在 → 该样本排除）",
    },
    "support-only-insufficient": {
        "require_apply_clean": True,
        "expect_oracle": "still_vulnerable",
        "desc": "去掉直接修复后应当复现漏洞",
    },
    "placebo": {
        "require_apply_clean": True,
        "expect_oracle": "still_vulnerable",   # 行为中性 → 漏洞仍在
        "desc": "行为中性改造：漏洞状态必须**不变**（仍存在）",
    },
    "shuffled": {
        "require_apply_clean": True,
        "expect_oracle": "donor_state",        # donor 自带状态
        "desc": "donor 补丁：其漏洞状态按 donor 自身判定",
    },
}


def evaluate_arm(arm: str, apply_clean: bool, oracle_result: str) -> dict:
    """机器化判定某臂在该样本上是否**合格**。

    `oracle_result ∈ {"fixed", "still_vulnerable", "unknown"}`。
    `unknown` 一律**不合格**（fail-closed，不允许用未知状态充数）。
    """
    if arm not in ARM_ORACLE:
        raise KeyError(f"未知臂: {arm}")
    spec = ARM_ORACLE[arm]
    if spec["require_apply_clean"] and apply_clean is not True:
        return {"accept": False, "reason": "apply 不干净", "arm": arm}
    if oracle_result == "unknown":
        return {"accept": False, "reason": "oracle 结果未知（fail-closed）", "arm": arm}
    want = spec["expect_oracle"]
    if want == "donor_state":
        return {"accept": True, "reason": "donor 状态自身有效", "arm": arm,
                "expected": "donor_state", "got": oracle_result}
    ok = (oracle_result == want)
    return {"accept": ok, "arm": arm, "expected": want, "got": oracle_result,
            "reason": "符合预期" if ok else f"预期 {want}，实得 {oracle_result}"}


def arms_registry() -> dict:
    """四臂判据的预注册登记表（含指纹，供冻结引用）。"""
    payload = json.dumps(ARM_ORACLE, sort_keys=True, ensure_ascii=False)
    return {
        "schema": ARMS_SCHEMA,
        "n_arms": len(ARM_ORACLE),
        "arms": {k: dict(v) for k, v in ARM_ORACLE.items()},
        "fingerprint": hashlib.sha256(payload.encode("utf-8")).hexdigest(),
        "shuffle": {
            "hard": [{"name": n, "doc": d} for n, d in SHUFFLE_HARD_CONSTRAINTS],
            "soft_in_relax_order": [{"name": n, "doc": d} for n, d in SHUFFLE_SOFT_CONSTRAINTS],
            "relax_policy": "按 soft_in_relax_order 的**逆序**逐条放宽（先放最弱约束）",
            "covariates": list(COVARIATE_FIELDS),
        },
    }
