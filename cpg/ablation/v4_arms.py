# -*- coding: utf-8 -*-
"""A-3 步 2/3/4（第二次返工）：token 匹配 / shuffled 约束 / oracle 验证器。

本次返工（评审 3）：
  P0-1 **先过滤界内候选再排序**。原实现"先选绝对差最小、再判界"，会把
       「A=79 超界(差21)、B=125 合法(差25)」误判为"无界内候选"。
  P0-2 shuffled 长度门禁**统一到最终完整 prompt token + `TOKEN_RATIO_BOUNDS`**。
       原实现退化为 patch token 且下界写成 0.75（与冻结口径 0.8 冲突）。
  P0-3 `OracleEvidence` 升级为**真验证器**：读原始输出、**重算 raw SHA**、
       用**冻结 parser**从原始输出派生 verdict、绑定 **parser 实现 SHA**、
       按 oracle 类型校验 **exit_code 约定**、并在给出路径时**重算文件 SHA**。
       未登记 oracle 类型**不做自然语言猜测**，要求显式 `VERDICT:` 标记（fail-closed）。
  P1   功效报告声明同质性假设；`N` 从 active universe 读取（未给则标 planned_max）。
"""
from __future__ import annotations

import hashlib
import inspect
import json
from dataclasses import dataclass, field
from pathlib import Path

ARMS_SCHEMA = "v4-arms/3"

# ---------------------------------------------------------------------------
# 步 2：token 匹配（**先过滤界内，再按整数距离排序**）
# ---------------------------------------------------------------------------
TOKEN_RATIO_BOUNDS = (0.8, 1.25)
CANDIDATE_EVIDENCE_FIELDS = ("tokenizer_sha256", "envelope_sha256", "prompt_sha256")


def _sha_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _is_hex64(v) -> bool:
    return isinstance(v, str) and len(v) == 64 and all(c in "0123456789abcdef" for c in v)


@dataclass
class Candidate:
    key: str
    tokens: int
    tokenizer_sha256: str = ""
    envelope_sha256: str = ""
    prompt_sha256: str = ""
    payload: object = None
    meta: dict = field(default_factory=dict)


def validate_candidates(candidates: list) -> list:
    errs = []
    if not isinstance(candidates, list) or not candidates:
        return ["候选集为空或非列表"]
    keys = [c.key for c in candidates]
    if len(keys) != len(set(keys)):
        errs.append("候选 key 重复")
    for c in candidates:
        if not isinstance(c.tokens, int) or isinstance(c.tokens, bool) or c.tokens <= 0:
            errs.append(f"{c.key}: tokens 必须为正整数（实得 {c.tokens!r}）")
        for f in CANDIDATE_EVIDENCE_FIELDS:
            if not _is_hex64(getattr(c, f, "")):
                errs.append(f"{c.key}: {f} 缺失或非法")
    return errs


def validate_bounds(bounds) -> list:
    if not (isinstance(bounds, (tuple, list)) and len(bounds) == 2):
        return ["bounds 必须是二元组"]
    lo, hi = bounds
    if not (isinstance(lo, (int, float)) and isinstance(hi, (int, float))):
        return ["bounds 必须为数值"]
    if not (0 < lo < hi):
        return [f"bounds 非法: {bounds}"]
    return []


def token_match_search(candidates: list, target_tokens: int,
                       bounds: tuple = TOKEN_RATIO_BOUNDS) -> dict:
    """**先过滤出界内候选**，再按 `(|tokens-target|, key)` 排序（P0-1）。

    只有**界内为空**时才返回 `NO_IN_BOUNDS_CANDIDATE`。
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

    lo, hi = bounds
    in_bounds = [c for c in candidates if lo <= c.tokens / target_tokens <= hi]
    oob = [c for c in candidates if not (lo <= c.tokens / target_tokens <= hi)]
    oob_trace = [{"key": c.key, "tokens": c.tokens,
                  "ratio": round(c.tokens / target_tokens, 6),
                  "int_distance": abs(c.tokens - target_tokens)}
                 for c in sorted(oob, key=lambda x: (abs(x.tokens - target_tokens), x.key))]
    if not in_bounds:
        nearest = min(candidates, key=lambda c: (abs(c.tokens - target_tokens), c.key))
        return {"status": "NO_IN_BOUNDS_CANDIDATE", "selected": None,
                "n_candidates": len(candidates), "n_in_bounds": 0,
                "n_out_of_bounds": len(oob),
                "bounds": list(bounds),
                "closest": {"key": nearest.key, "tokens": nearest.tokens,
                            "ratio": round(nearest.tokens / target_tokens, 6)},
                "reason": (f"界内候选为空（最接近 ratio="
                           f"{nearest.tokens / target_tokens:.4f}）；长度门禁不可放宽"),
                "trace": [{"key": c.key, "tokens": c.tokens,
                           "int_distance": abs(c.tokens - target_tokens)}
                          for c in sorted(candidates,
                                          key=lambda x: (abs(x.tokens - target_tokens), x.key))[:5]]}
    scored = sorted(((abs(c.tokens - target_tokens), c.key, c) for c in in_bounds),
                    key=lambda t: (t[0], t[1]))
    dist, _, best = scored[0]
    return {"status": "OK", "selected": best,
            "ratio": round(best.tokens / target_tokens, 6), "in_bounds": True,
            "int_distance": dist, "n_candidates": len(candidates),
            "n_in_bounds": len(in_bounds), "n_out_of_bounds": len(oob),
            "bounds": list(bounds),
            "excluded_out_of_bounds": oob_trace,
            "filter_policy": "先按 bounds 过滤，**界外候选不参与排序**（评审 3 P0-1）",
            "tie_break": "(|tokens-target|, key) 字典序最小者优先（**先过滤界内**）",
            "trace": [{"key": k, "tokens": c.tokens, "int_distance": d}
                      for d, k, c in scored[:5]]}


# ---------------------------------------------------------------------------
# 步 3：shuffled 约束（**最终 prompt token + 统一 bounds**）
# ---------------------------------------------------------------------------
SHUFFLE_HARD_CONSTRAINTS = (
    ("donor_ne_target", "donor 不得等于目标样本"),
    ("apply_clean_target_relation", "donor patch 必须在**目标树**上 apply-clean（须二元证据）"),
    ("final_prompt_token_window",
     "donor 与目标的**最终完整 prompt token** 之比须落在 TOKEN_RATIO_BOUNDS 内（不可放宽）"),
)
SHUFFLE_SOFT_CONSTRAINTS = (
    ("same_language", "donor 与目标同语言"),
    ("same_cwe_family", "donor 与目标同 CWE 族"),
    ("same_file_count", "donor 触及文件数与目标相差 ≤1"),
    ("not_composite", "donor 不是复合提交"),
)
COVARIATE_FIELDS = ("language", "cwe_family", "final_prompt_tokens", "n_files", "is_composite")

APPLY_EVIDENCE_FIELDS = ("target_id", "donor_id", "target_tree_sha256",
                         "donor_patch_sha256", "apply_command", "apply_exit_code",
                         "post_apply_tree_sha256")
# P0-2：长度门禁的证据字段（**最终 prompt token** 而非 patch token）
TOKEN_EVIDENCE_FIELDS = ("target_final_prompt_tokens", "donor_final_prompt_tokens",
                         "target_prompt_sha256", "candidate_prompt_sha256",
                         "tokenizer_sha256", "envelope_sha256")


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


def validate_token_evidence(ev: dict, bounds: tuple = TOKEN_RATIO_BOUNDS) -> list:
    """长度门禁证据（P0-2）：必须是**最终 prompt token** 且落在统一 bounds 内。"""
    errs = []
    if not isinstance(ev, dict):
        return ["token 证据缺失"]
    for f in TOKEN_EVIDENCE_FIELDS:
        if f not in ev:
            errs.append(f"缺 {f}")
    for f in ("target_prompt_sha256", "candidate_prompt_sha256",
              "tokenizer_sha256", "envelope_sha256"):
        if not _is_hex64(ev.get(f)):
            errs.append(f"{f} 非 64 位 hex")
    t, d = ev.get("target_final_prompt_tokens"), ev.get("donor_final_prompt_tokens")
    if not (isinstance(t, int) and isinstance(d, int) and t > 0 and d > 0):
        errs.append("最终 prompt token 必须为正整数")
        return errs
    lo, hi = bounds
    r = d / t
    if not (lo <= r <= hi):
        errs.append(f"final prompt token ratio={r:.4f} 超出 {list(bounds)}")
    return errs


def _hard_errors(donor: dict, target: dict,
                 bounds: tuple = TOKEN_RATIO_BOUNDS) -> list:
    errs = []
    if donor.get("sample_id") == target.get("sample_id"):
        errs.append("donor_ne_target")
    ev = donor.get("apply_evidence") or {}
    aerr = validate_apply_evidence(ev)
    errs += [f"apply_clean_target_relation: {e}" for e in aerr]
    if not aerr:
        if ev.get("target_id") != target.get("sample_id"):
            errs.append("apply 证据 target_id 与当前目标不符")
        if ev.get("donor_id") != donor.get("sample_id"):
            errs.append("apply 证据 donor_id 与当前 donor 不符")
    terr = validate_token_evidence(donor.get("token_evidence") or {}, bounds)
    errs += [f"final_prompt_token_window: {e}" for e in terr]
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


def select_donor(target: dict, donors: list,
                 bounds: tuple = TOKEN_RATIO_BOUNDS) -> dict:
    """硬约束（含**最终 prompt token 门禁**）先过滤；软约束按逆序逐条放宽。"""
    hard_ok, hard_rejected = [], []
    for d in donors:
        (hard_rejected if _hard_errors(d, target, bounds) else hard_ok).append(d)
    if not hard_ok:
        return {"status": "NO_DONOR", "donor": None, "n_donors": len(donors),
                "reason": f"无候选通过硬约束（{len(hard_rejected)} 个被拒）",
                "hard_rejected": len(hard_rejected), "relaxations": []}

    active = list(SHUFFLE_SOFT_CONSTRAINTS)
    relaxations = []
    for _step in range(len(active) + 1):
        pool = [d for d in hard_ok if all(_passes_soft(d, target, n) for n, _ in active)]
        if pool:
            def _tokens(d):
                return (d.get("token_evidence") or {}).get("donor_final_prompt_tokens") or 0
            tgt = (target.get("token_evidence") or {}).get("target_final_prompt_tokens") or 0
            pool.sort(key=lambda d: (abs(_tokens(d) - tgt), d.get("sample_id", "")))
            chosen = pool[0]
            return {"status": "OK", "donor": chosen, "n_donors": len(donors),
                    "n_pool_after_relax": len(pool), "relaxations": relaxations,
                    "active_constraints": [n for n, _ in active],
                    "covariates": {"target": {k: target.get(k) for k in COVARIATE_FIELDS},
                                   "donor": {k: chosen.get(k) for k in COVARIATE_FIELDS}},
                    "bounds": list(bounds),
                    "tie_break": "(|final_prompt_tokens 差|, sample_id) 字典序最小者优先"}
        if not active:
            break
        relaxations.append(active.pop()[0])
    return {"status": "NO_DONOR", "donor": None, "n_donors": len(donors),
            "reason": "全部软约束放宽后仍无候选", "relaxations": relaxations}


# ---------------------------------------------------------------------------
# 步 4：oracle **验证器**（读原始输出 → 冻结 parser → 派生 verdict）
# ---------------------------------------------------------------------------
VALID_ORACLE_RESULTS = {"fixed", "still_vulnerable"}

# exit_code 约定（按 oracle 类型）：True 表示"该 exit_code 与 verdict 自洽"
EXIT_CODE_CONVENTION = {
    "pytest-regression": {0: "fixed", 1: "still_vulnerable"},   # 测试通过=fixed；失败=仍存在
    "poc-exploit": {0: "fixed", 1: "still_vulnerable"},         # PoC 成功利用=仍存在
    "sast-diff": {0: "fixed", 1: "still_vulnerable"},
}


ORACLE_VERDICT_MARKER = "VERDICT:"


def parse_oracle_verdict(oracle_type: str, raw_result: str, exit_code: int) -> str:
    """**冻结 parser**：从 oracle 原始输出派生 verdict（唯一权威）。

    两条路径，**均不允许默认通过**：
      ① `oracle_type` 已登记在 `EXIT_CODE_CONVENTION` → 由 `exit_code` 派生的
         唯一映射给出；`exit_code` 不在约定内即抛错。
      ② 未登记类型 → 要求原始输出含**显式标记行** `VERDICT: fixed|still_vulnerable`。

    明确**不使用自然语言关键字猜测**：`"not vulnerable"` 含子串 `"vulnerable"`，
    任何子串式判别都会把否定式判反，故整类启发式被移除（fail-closed）。
    """
    conv = EXIT_CODE_CONVENTION.get(oracle_type)
    if conv is not None:
        if exit_code not in conv:
            raise ValueError(f"{oracle_type}: exit_code {exit_code} 不在约定 {sorted(conv)} 内")
        return conv[exit_code]
    for line in (raw_result or "").splitlines():
        s = line.strip()
        if s.upper().startswith(ORACLE_VERDICT_MARKER):
            v = s.split(":", 1)[1].strip().lower()
            if v in VALID_ORACLE_RESULTS:
                return v
            raise ValueError(f"未登记 oracle 的标记值非法: {v!r}")
    raise ValueError(f"未登记 oracle_type={oracle_type} 且原始输出无 "
                     f"'{ORACLE_VERDICT_MARKER}' 标记 → fail-closed")


def oracle_parser_sha256() -> str:
    """冻结 parser 的**实现 SHA**（绑定到证据里，防止 parser 被换）。"""
    return _sha_text(inspect.getsource(parse_oracle_verdict))


ORACLE_EVIDENCE_FIELDS = ("oracle_type", "oracle_version", "oracle_parser_sha256",
                          "poc_sha256", "target_tree_sha256", "patch_sha256",
                          "command", "exit_code", "raw_result", "raw_result_sha256",
                          "parsed_verdict")
ORACLE_EVIDENCE_OPTIONAL_FILES = ("poc_path", "target_tree_dir", "patch_path")


@dataclass
class OracleEvidence:
    """oracle 执行证据（**可验证**，非仅 schema）。"""
    oracle_type: str
    oracle_version: str
    poc_sha256: str
    target_tree_sha256: str
    patch_sha256: str
    command: str
    exit_code: int
    raw_result: str
    parsed_verdict: str
    oracle_parser_sha256: str = ""
    raw_result_sha256: str = ""
    poc_path: str | None = None
    target_tree_dir: str | None = None
    patch_path: str | None = None

    def as_dict(self) -> dict:
        return {f: getattr(self, f) for f in ORACLE_EVIDENCE_FIELDS}

    def verify(self, base_dir: Path | None = None) -> list:
        """**真 fail-closed 验证**（P0-3）：

        ① 必填字段齐备；
        ② `raw_result_sha256` == 对 `raw_result` **重算**的 SHA；
        ③ `oracle_parser_sha256` == 当前**冻结 parser** 的实现 SHA；
        ④ verdict == 用**冻结 parser** 从 `raw_result + exit_code` 派生的结果；
        ⑤ 给出路径时**重算 PoC/patch 文件 SHA**、并校验 target 树存在。
        """
        errs = []
        for f in ORACLE_EVIDENCE_FIELDS:
            v = getattr(self, f)
            if v is None or v == "":
                errs.append(f"缺 {f}")
        if errs:
            return errs
        for f in ("oracle_parser_sha256", "poc_sha256", "target_tree_sha256",
                  "patch_sha256", "raw_result_sha256"):
            if not _is_hex64(getattr(self, f)):
                errs.append(f"{f} 非 64 位 hex")
        if self.parsed_verdict not in VALID_ORACLE_RESULTS:
            errs.append(f"parsed_verdict 不在枚举内: {self.parsed_verdict!r}")
        if not isinstance(self.exit_code, int) or isinstance(self.exit_code, bool):
            errs.append("exit_code 必须为整数")
        if not isinstance(self.command, str) or not self.command.strip():
            errs.append("command 必须为非空字符串")
        if errs:
            return errs
        actual_raw = _sha_text(self.raw_result)
        if self.raw_result_sha256 != actual_raw:
            errs.append(f"raw_result_sha256 与原始输出重算不符（{actual_raw[:12]}）")
        if self.oracle_parser_sha256 != oracle_parser_sha256():
            errs.append("oracle_parser_sha256 与当前冻结 parser 不符")
        try:
            derived = parse_oracle_verdict(self.oracle_type, self.raw_result, self.exit_code)
        except ValueError as e:
            errs.append(f"parser 派生失败: {e}")
            derived = None
        if derived is not None and derived != self.parsed_verdict:
            errs.append(f"parsed_verdict({self.parsed_verdict}) 与 parser 派生({derived}) 不符")
        if self.poc_path:
            p = (base_dir or Path(".")) / self.poc_path
            if not p.exists():
                errs.append(f"PoC 文件不存在: {self.poc_path}")
            elif hashlib.sha256(p.read_bytes()).hexdigest() != self.poc_sha256:
                errs.append("PoC 文件 SHA 与记录不符")
        if self.patch_path:
            p = (base_dir or Path(".")) / self.patch_path
            if not p.exists():
                errs.append(f"patch 文件不存在: {self.patch_path}")
            elif hashlib.sha256(p.read_bytes()).hexdigest() != self.patch_sha256:
                errs.append("patch 文件 SHA 与记录不符")
        if self.target_tree_dir:
            d = (base_dir or Path(".")) / self.target_tree_dir
            if not d.is_dir():
                errs.append(f"target 树不存在: {self.target_tree_dir}")
        return errs


ARM_ORACLE = {
    "annotated-security-complete": {"expect_target_oracle": "fixed",
                                    "desc": "安全完备补丁：目标漏洞应已修复"},
    "support-only-insufficient": {"expect_target_oracle": "still_vulnerable",
                                  "desc": "去掉直接修复后，目标漏洞应仍可复现"},
    "placebo": {"expect_target_oracle": "still_vulnerable",
                "desc": "行为中性改造：目标漏洞状态不变（仍在）"},
    "shuffled": {"expect_target_oracle": "still_vulnerable",
                 "desc": ("负向 shuffled control：应用 donor patch 到**目标**后目标漏洞仍须可复现；"
                          "意外修复目标漏洞 → 拒绝该组合")},
}


def evaluate_arm(arm: str, apply_clean: bool, target_oracle: str,
                 evidence: OracleEvidence | None = None,
                 base_dir: Path | None = None) -> dict:
    """机器化判定（**证据必须通过 `verify()`**）。"""
    if arm not in ARM_ORACLE:
        raise KeyError(f"未知臂: {arm}")
    if apply_clean is not True:
        return {"accept": False, "reason": "apply 不干净", "arm": arm}
    if target_oracle not in VALID_ORACLE_RESULTS:
        return {"accept": False, "arm": arm,
                "reason": f"oracle 结果不在枚举内: {target_oracle!r}（fail-closed）"}
    if evidence is None:
        return {"accept": False, "arm": arm, "reason": "缺 oracle 执行证据（fail-closed）"}
    eerr = evidence.verify(base_dir)
    if eerr:
        return {"accept": False, "arm": arm,
                "reason": "oracle 证据验证失败: " + "; ".join(eerr[:3])}
    if evidence.parsed_verdict != target_oracle:
        return {"accept": False, "arm": arm,
                "reason": f"证据 verdict 与传入 oracle 不符"}
    want = ARM_ORACLE[arm]["expect_target_oracle"]
    ok = (target_oracle == want)
    return {"accept": ok, "arm": arm, "expected_target_oracle": want,
            "got_target_oracle": target_oracle,
            "reason": "符合预期" if ok else f"预期目标漏洞 {want}，实得 {target_oracle}",
            "oracle_evidence": evidence.as_dict()}


def make_evidence(oracle_type: str, raw_result: str, exit_code: int,
                  poc_sha256: str = "0" * 64, target_tree_sha256: str = "0" * 64,
                  patch_sha256: str = "0" * 64, command: str = "",
                  oracle_version: str = "1.0") -> OracleEvidence:
    """便捷构造（**自动填入 raw SHA 与 parser SHA**，避免手填导致假通过）。"""
    derived = parse_oracle_verdict(oracle_type, raw_result, exit_code)
    return OracleEvidence(oracle_type=oracle_type, oracle_version=oracle_version,
                          oracle_parser_sha256=oracle_parser_sha256(),
                          poc_sha256=poc_sha256, target_tree_sha256=target_tree_sha256,
                          patch_sha256=patch_sha256, command=command,
                          exit_code=exit_code, raw_result=raw_result,
                          raw_result_sha256=_sha_text(raw_result),
                          parsed_verdict=derived)


def arms_registry() -> dict:
    payload = json.dumps(ARM_ORACLE, sort_keys=True, ensure_ascii=False)
    return {
        "schema": ARMS_SCHEMA,
        "n_arms": len(ARM_ORACLE),
        "arms": {k: dict(v) for k, v in ARM_ORACLE.items()},
        "fingerprint": hashlib.sha256(payload.encode("utf-8")).hexdigest(),
        "token_bounds": list(TOKEN_RATIO_BOUNDS),
        "token_evidence_fields": list(TOKEN_EVIDENCE_FIELDS),
        "shuffle": {
            "hard": [{"name": n, "doc": d} for n, d in SHUFFLE_HARD_CONSTRAINTS],
            "soft_in_relax_order": [{"name": n, "doc": d} for n, d in SHUFFLE_SOFT_CONSTRAINTS],
            "relax_policy": "软约束按逆序逐条放宽；硬约束（含最终 prompt token 门禁）不可放宽",
            "apply_evidence_fields": list(APPLY_EVIDENCE_FIELDS),
            "covariates": list(COVARIATE_FIELDS),
        },
        "oracle_evidence_fields": list(ORACLE_EVIDENCE_FIELDS),
        "oracle_parser_sha256": oracle_parser_sha256(),
        "oracle_verdict_marker": ORACLE_VERDICT_MARKER,
        "exit_code_convention": {k: dict(v) for k, v in EXIT_CODE_CONVENTION.items()},
    }
