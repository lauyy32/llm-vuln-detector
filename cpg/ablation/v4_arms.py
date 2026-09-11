# -*- coding: utf-8 -*-
"""A-3 步 2/3/4（返工版）：token 匹配 / shuffled 约束 / oracle 判据。

返工要点（评审 2 的 P0）：
  P0-2 token 搜索用**整数距离** `|tokens - target|`（token 是整数，无需浮点）；
       超出 `[0.8,1.25]` **不是成功状态** → `NO_IN_BOUNDS_CANDIDATE`；
       并校验 tokens 为**正**整数、key 唯一、bounds 合法、候选带**tokenizer/envelope/prompt
       SHA 证据**。
  P0-3 `apply_clean` 是 **(target, donor_patch) 二元关系**，必须记录
       target_id / donor_id / target_tree_sha256 / donor_patch_sha256 / apply_command /
       apply_exit_code / post_apply_tree_sha256；**`token_window` 提升为硬约束**
       （与预注册 `[0.8,1.25]` 门禁一致，不再允许放宽）。
  P0-4 shuffled 的 ground truth 是**目标漏洞状态**：应用 donor patch 后目标漏洞仍可复现
       → `target_oracle == still_vulnerable`；意外修复目标漏洞 → 拒绝（不得因 donor 自身
       fixed 而通过）。`oracle_result` 必须是**枚举内**值。
  P0-5 oracle 须绑定**可复算执行证据**（见 `OracleEvidence`）。
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

ARMS_SCHEMA = "v4-arms/2"

# ---------------------------------------------------------------------------
# 步 2：token 匹配（整数距离；超界即失败）
# ---------------------------------------------------------------------------
TOKEN_RATIO_BOUNDS = (0.8, 1.25)
CANDIDATE_EVIDENCE_FIELDS = ("tokenizer_sha256", "envelope_sha256", "prompt_sha256")


@dataclass
class Candidate:
    """一个候选变换。`tokens` 必须是**该候选最终 prompt** 的整数 token 数，
    并附 tokenizer/envelope/prompt 三类 SHA 证据（否则不予采信）。"""
    key: str
    tokens: int
    tokenizer_sha256: str = ""
    envelope_sha256: str = ""
    prompt_sha256: str = ""
    payload: object = None
    meta: dict = field(default_factory=dict)


def _is_hex64(v) -> bool:
    return isinstance(v, str) and len(v) == 64 and all(c in "0123456789abcdef" for c in v)


def validate_candidates(candidates: list) -> list:
    """候选集校验（fail-closed）：正整 tokens、key 唯一、证据 SHA 齐备。"""
    errs = []
    if not isinstance(candidates, list) or not candidates:
        errs.append("候选集为空或非列表")
        return errs
    keys = [c.key for c in candidates]
    if len(keys) != len(set(keys)):
        errs.append("候选 key 重复")
    for c in candidates:
        if not isinstance(c.tokens, int) or isinstance(c.tokens, bool) or c.tokens <= 0:
            errs.append(f"{c.key}: tokens 必须为正整数（实得 {c.tokens!r}）")
        for f in CANDIDATE_EVIDENCE_FIELDS:
            if not _is_hex64(getattr(c, f, "")):
                errs.append(f"{c.key}: {f} 缺失或非法（候选须带最终 prompt 证据）")
    return errs


def validate_bounds(bounds) -> list:
    errs = []
    if not (isinstance(bounds, (tuple, list)) and len(bounds) == 2):
        return ["bounds 必须是二元组"]
    lo, hi = bounds
    if not (isinstance(lo, (int, float)) and isinstance(hi, (int, float))):
        errs.append("bounds 必须为数值")
    elif not (0 < lo < hi):
        errs.append(f"bounds 非法: {bounds}")
    return errs


def token_match_search(candidates: list, target_tokens: int,
                       bounds: tuple = TOKEN_RATIO_BOUNDS) -> dict:
    """选 token 最接近 `target_tokens` 的候选（**整数距离，确定性**）。

    排序键：`(|tokens - target|, key)`。
    **超出 bounds 一律返回失败状态** `NO_IN_BOUNDS_CANDIDATE`（不再返回 OK+in_bounds=false）。
    """
    if not isinstance(target_tokens, int) or isinstance(target_tokens, bool) or target_tokens <= 0:
        raise ValueError("target_tokens 必须为正整数")
    berr = validate_bounds(bounds)
    if berr:
        raise ValueError("; ".join(berr))
    cerr = validate_candidates(candidates)
    if cerr:
        return {"status": "INVALID_CANDIDATES", "selected": None,
                "errors": cerr[:5], "n_candidates": len(candidates or [])}

    scored = sorted(((abs(c.tokens - target_tokens), c.key, c) for c in candidates),
                    key=lambda t: (t[0], t[1]))
    dist, _, best = scored[0]
    ratio = best.tokens / target_tokens
    lo, hi = bounds
    in_bounds = lo <= ratio <= hi
    if not in_bounds:
        return {"status": "NO_IN_BOUNDS_CANDIDATE", "selected": None,
                "n_candidates": len(candidates), "bounds": list(bounds),
                "closest": {"key": best.key, "tokens": best.tokens, "ratio": round(ratio, 6)},
                "reason": (f"最接近候选 ratio={ratio:.4f} 超出 {list(bounds)}；"
                           "长度门禁不可放宽，该样本不可构造"),
                "trace": [{"key": k, "tokens": c.tokens, "int_distance": d}
                          for d, k, c in scored[:5]]}
    return {"status": "OK", "selected": best, "ratio": round(ratio, 6),
            "in_bounds": True, "int_distance": dist, "n_candidates": len(candidates),
            "bounds": list(bounds),
            "tie_break": "(|tokens-target|, key) 字典序最小者优先",
            "trace": [{"key": k, "tokens": c.tokens, "int_distance": d}
                      for d, k, c in scored[:5]]}


# ---------------------------------------------------------------------------
# 步 3：shuffled 约束（apply_clean 为 target×donor 证据；token_window 为硬约束）
# ---------------------------------------------------------------------------
SHUFFLE_HARD_CONSTRAINTS = (
    ("donor_ne_target", "donor 不得等于目标样本"),
    ("apply_clean_target_relation", "donor patch 必须在**目标树**上 apply-clean（须二元证据）"),
    ("token_window", "donor patch token 与目标之比须落在预注册门禁内（不可放宽）"),
)
SHUFFLE_SOFT_CONSTRAINTS = (
    ("same_language", "donor 与目标同语言"),
    ("same_cwe_family", "donor 与目标同 CWE 族"),
    ("same_file_count", "donor 触及文件数与目标相差 ≤1"),
    ("not_composite", "donor 不是复合提交"),
)
COVARIATE_FIELDS = ("language", "cwe_family", "patch_tokens", "n_files", "is_composite")
# apply-clean 关系证据的必备字段
APPLY_EVIDENCE_FIELDS = ("target_id", "donor_id", "target_tree_sha256",
                         "donor_patch_sha256", "apply_command", "apply_exit_code",
                         "post_apply_tree_sha256")


def validate_apply_evidence(ev: dict) -> list:
    errs = []
    if not isinstance(ev, dict):
        return ["apply 证据缺失"]
    for f in APPLY_EVIDENCE_FIELDS:
        if f not in ev:
            errs.append(f"缺 {f}")
    if ev.get("apply_exit_code") != 0:
        errs.append(f"apply_exit_code != 0: {ev.get('apply_exit_code')!r}")
    for f in ("target_tree_sha256", "donor_patch_sha256", "post_apply_tree_sha256"):
        if not _is_hex64(ev.get(f)):
            errs.append(f"{f} 非 64 位 hex")
    if not isinstance(ev.get("apply_command"), str) or not ev.get("apply_command"):
        errs.append("apply_command 必须为非空字符串")
    return errs


def _hard_errors(donor: dict, target: dict) -> list:
    errs = []
    if donor.get("sample_id") == target.get("sample_id"):
        errs.append("donor_ne_target")
    # apply-clean 必须是**目标相关**的二元证据
    ev = donor.get("apply_evidence") or {}
    for e in validate_apply_evidence(ev):
        errs.append(f"apply_clean_target_relation: {e}")
    else:
        if ev.get("target_id") != target.get("sample_id"):
            errs.append("apply 证据的 target_id 与当前目标不符")
        if ev.get("donor_id") != donor.get("sample_id"):
            errs.append("apply 证据的 donor_id 与当前 donor 不符")
    # token_window 是**硬约束**，不可放宽
    t = target.get("patch_tokens") or 0
    d = donor.get("patch_tokens") or 0
    if not t or not d:
        errs.append("token_window: 缺 patch_tokens")
    else:
        r = d / t
        if not (0.75 <= r <= 1.25):
            errs.append(f"token_window: ratio={r:.3f} 超出门禁")
    return errs


def _passes_soft(donor: dict, target: dict, name: str) -> bool:
    if name == "same_language":
        return donor.get("language") == target.get("language")
    if name == "same_cwe_family":
        return donor.get("cwe_family") == target.get("cwe_family")
    if name == "same_file_count":
        return abs((donor.get("n_files") or 0) - (target.get("n_files") or 0)) <= 1
    if name == "not_composite":
        return donor.get("is_composite") is False
    return False


def select_donor(target: dict, donors: list) -> dict:
    """硬约束（**含 token_window**）先过滤；软约束按**逆序**逐条放宽（先放最弱）。"""
    hard_ok, hard_rejected = [], []
    for d in donors:
        (hard_rejected if _hard_errors(d, target) else hard_ok).append(d)
    if not hard_ok:
        return {"status": "NO_DONOR", "donor": None, "n_donors": len(donors),
                "reason": f"无候选通过硬约束（{len(hard_rejected)} 个被拒）",
                "hard_rejected": len(hard_rejected), "relaxations": []}

    active = list(SHUFFLE_SOFT_CONSTRAINTS)
    relaxations = []
    for _step in range(len(active) + 1):
        pool = [d for d in hard_ok if all(_passes_soft(d, target, n) for n, _ in active)]
        if pool:
            pool.sort(key=lambda d: (abs((d.get("patch_tokens") or 0)
                                         - (target.get("patch_tokens") or 0)),
                                     d.get("sample_id", "")))
            chosen = pool[0]
            return {"status": "OK", "donor": chosen, "n_donors": len(donors),
                    "n_pool_after_relax": len(pool), "relaxations": relaxations,
                    "active_constraints": [n for n, _ in active],
                    "covariates": {"target": {k: target.get(k) for k in COVARIATE_FIELDS},
                                   "donor": {k: chosen.get(k) for k in COVARIATE_FIELDS}},
                    "tie_break": "(|patch_tokens 差|, sample_id) 字典序最小者优先"}
        if not active:
            break
        relaxations.append(active.pop()[0])
    return {"status": "NO_DONOR", "donor": None, "n_donors": len(donors),
            "reason": "全部软约束放宽后仍无候选", "relaxations": relaxations}


# ---------------------------------------------------------------------------
# 步 4：逐臂 oracle 判据（含**执行证据**约束）
# ---------------------------------------------------------------------------
VALID_ORACLE_RESULTS = {"fixed", "still_vulnerable"}
ORACLE_EVIDENCE_FIELDS = ("oracle_type", "oracle_version", "poc_sha256",
                          "target_tree_sha256", "patch_sha256", "command",
                          "exit_code", "raw_result_sha256", "parsed_verdict")


@dataclass
class OracleEvidence:
    """oracle 的**可复算执行证据**（P0-5）。"""
    oracle_type: str
    oracle_version: str
    poc_sha256: str
    target_tree_sha256: str
    patch_sha256: str
    command: str
    exit_code: int
    raw_result_sha256: str
    parsed_verdict: str

    def as_dict(self) -> dict:
        return {f: getattr(self, f) for f in ORACLE_EVIDENCE_FIELDS}

    def errors(self) -> list:
        errs = []
        for f in ORACLE_EVIDENCE_FIELDS:
            v = getattr(self, f)
            if v is None or v == "":
                errs.append(f"缺 {f}")
        for f in ("poc_sha256", "target_tree_sha256", "patch_sha256", "raw_result_sha256"):
            if not _is_hex64(getattr(self, f)):
                errs.append(f"{f} 非 64 位 hex")
        if self.parsed_verdict not in VALID_ORACLE_RESULTS:
            errs.append(f"parsed_verdict 非法: {self.parsed_verdict!r}")
        if not isinstance(self.exit_code, int):
            errs.append("exit_code 必须为 int")
        return errs


# 每臂的期望（**均以目标漏洞状态为准**）
ARM_ORACLE = {
    "annotated-security-complete": {
        "expect_target_oracle": "fixed",
        "desc": "标注意义上的安全完备补丁：目标漏洞应已修复",
    },
    "support-only-insufficient": {
        "expect_target_oracle": "still_vulnerable",
        "desc": "去掉直接修复后，目标漏洞应仍可复现",
    },
    "placebo": {
        "expect_target_oracle": "still_vulnerable",
        "desc": "行为中性改造：目标漏洞状态必须不变（仍在）",
    },
    "shuffled": {
        # P0-4：**评估对象始终是目标漏洞**，donor 自身状态无关
        "expect_target_oracle": "still_vulnerable",
        "desc": ("负向 shuffled control：应用 donor patch 到**目标**后，"
                 "目标漏洞仍须可复现；若意外修复目标漏洞 → 拒绝该 target-donor 组合"),
    },
}


def evaluate_arm(arm: str, apply_clean: bool, target_oracle: str,
                 evidence: OracleEvidence | None = None) -> dict:
    """机器化判定某臂是否合格。

    - `target_oracle ∈ {"fixed","still_vulnerable"}`（**枚举校验**，其它值一律拒绝）；
    - `evidence` 必须给全且自洽（fail-closed）；
    - 一切判定以**目标漏洞状态**为准。
    """
    if arm not in ARM_ORACLE:
        raise KeyError(f"未知臂: {arm}")
    spec = ARM_ORACLE[arm]
    if apply_clean is not True:
        return {"accept": False, "reason": "apply 不干净", "arm": arm}
    if target_oracle not in VALID_ORACLE_RESULTS:
        return {"accept": False, "arm": arm,
                "reason": f"oracle 结果不在枚举内: {target_oracle!r}（fail-closed）"}
    if evidence is None:
        return {"accept": False, "arm": arm, "reason": "缺 oracle 执行证据（fail-closed）"}
    eerr = evidence.errors()
    if eerr:
        return {"accept": False, "arm": arm, "reason": "oracle 证据不完整: " + "; ".join(eerr[:3])}
    if evidence.parsed_verdict != target_oracle:
        return {"accept": False, "arm": arm,
                "reason": f"证据的 parsed_verdict({evidence.parsed_verdict}) 与传入 oracle 不符"}
    want = spec["expect_target_oracle"]
    ok = (target_oracle == want)
    return {"accept": ok, "arm": arm, "expected_target_oracle": want,
            "got_target_oracle": target_oracle,
            "reason": "符合预期" if ok else f"预期目标漏洞 {want}，实得 {target_oracle}",
            "oracle_evidence": evidence.as_dict()}


def arms_registry() -> dict:
    payload = json.dumps(ARM_ORACLE, sort_keys=True, ensure_ascii=False)
    return {
        "schema": ARMS_SCHEMA,
        "n_arms": len(ARM_ORACLE),
        "arms": {k: dict(v) for k, v in ARM_ORACLE.items()},
        "fingerprint": hashlib.sha256(payload.encode("utf-8")).hexdigest(),
        "token_bounds": list(TOKEN_RATIO_BOUNDS),
        "shuffle": {
            "hard": [{"name": n, "doc": d} for n, d in SHUFFLE_HARD_CONSTRAINTS],
            "soft_in_relax_order": [{"name": n, "doc": d} for n, d in SHUFFLE_SOFT_CONSTRAINTS],
            "relax_policy": "按 soft_in_relax_order 的**逆序**逐条放宽；硬约束（含 token_window）不可放宽",
            "apply_evidence_fields": list(APPLY_EVIDENCE_FIELDS),
            "covariates": list(COVARIATE_FIELDS),
        },
        "oracle_evidence_fields": list(ORACLE_EVIDENCE_FIELDS),
    }
