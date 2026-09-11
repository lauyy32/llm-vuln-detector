# -*- coding: utf-8 -*-
"""A-3 步 2/3/4（第三次返工，schema `v4-arms/4`）。

本次返工 = 评审 4 的 P0-1/P0-2/P0-3/P1 + 两处自查。

P0-3 **oracle 契约按层拆分**（对齐 `docs/EXPERIMENT-FREEZE.md` 的 T1/T2/T3 分层）。
    旧实现把 `exit_code` 直接映射为漏洞状态，存在三处不成立：
      · `poc-exploit` 注释写"PoC 成功利用=仍存在"，映射却是 `0 → fixed`，自相矛盾；
      · `pytest` 退出码 1 只说明测试失败，不证明目标漏洞仍存在（可能是断言错误/
        环境错误/无关回归）；
      · SAST 退出码跨工具语义不一致，不能统一解释为漏洞状态。
    现改为：
      · verdict **唯一来源**是 oracle 原始输出中的显式标记行 `VERDICT: <值>`；
      · `exit_code` 只用于分类本次运行是否有效（valid / infra / 未知）；
      · 无法判定 → 第三状态 `ORACLE_ERROR`，**不得**压成二分类；
      · T3（无可执行、无可脚本化 oracle）显式 `machine_decidable=False`，
        只能由"冻结的书面残余利用路径 + 双人独立确认"承载，且**不与 T1/T2 混计**。

P0-1 `OracleEvidence` 升级为**严格工件绑定**：正式模式强制提供 PoC / patch / target tree
    工件引用；重算 PoC SHA、patch SHA 与 **LF 归一化递归 tree SHA**；并与 arm、目标样本、
    冻结构造清单 SHA 逐项绑定（`FrozenContext` 缺失即 fail-closed）。

P0-2 shuffled 硬约束改为**内容交叉核对**：target tree / donor patch / 最终 prompt /
    tokenizer / envelope 逐项与权威工件比对；token ratio 由**权威值重算**，不采信申报值。

自查 ① 四臂接受标准对齐预注册 §3.3：`placebo` / `shuffled` **不要求 oracle 复现**，
     仅需 apply-clean + 模型判为 vulnerable；旧实现对四臂一律强制 oracle 证据，属偏离。
    ② `dead_branch` 前置排除单行函数体（见 `v4_placebo.py`）。
"""
from __future__ import annotations

import hashlib
import inspect
import json
from dataclasses import dataclass, field
from pathlib import Path

ARMS_SCHEMA = "v4-arms/4"

# ---------------------------------------------------------------------------
# 通用工具
# ---------------------------------------------------------------------------


def _sha_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _sha_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _is_hex64(v) -> bool:
    return isinstance(v, str) and len(v) == 64 and all(c in "0123456789abcdef" for c in v)


def _is_pos_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v > 0


# 文本文件的哈希口径：**LF 归一化**（跨平台可复算）；不可解码者按原始字节。
HASH_MODE_TEXT = "lf-normalized-text"
HASH_MODE_BYTES = "raw-bytes"
TREE_EXCLUDE_PARTS = frozenset({".git", "__pycache__", ".venv", "site-packages"})


def file_content_sha256(path: Path) -> tuple:
    """返回 `(mode, sha256)`：可按 UTF-8 解码者用 LF 归一化，否则用原始字节。"""
    b = path.read_bytes()
    try:
        t = b.decode("utf-8")
    except UnicodeDecodeError:
        return HASH_MODE_BYTES, _sha_bytes(b)
    return HASH_MODE_TEXT, _sha_bytes(t.replace("\r\n", "\n").encode("utf-8"))


def normalized_tree_sha256(root: Path, *, exclude_parts=TREE_EXCLUDE_PARTS) -> str:
    """**LF 归一化递归 tree SHA**（确定性，跨平台可复算）。

    对树内每个文件记录 `(相对路径, 哈希口径, 内容哈希)`，按相对路径排序后整体哈希。
    行尾差异不改变结果；二进制按原始字节。缺失目录抛 `FileNotFoundError`（fail-closed）。
    """
    root = Path(root)
    if not root.is_dir():
        raise FileNotFoundError(f"tree 目录不存在: {root}")
    entries = []
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        if exclude_parts & set(p.parts):
            continue
        rel = p.relative_to(root).as_posix()
        mode, sha = file_content_sha256(p)
        entries.append(f"{rel}\0{mode}\0{sha}")
    return _sha_bytes("\n".join(entries).encode("utf-8"))


# ===========================================================================
# 步 2：token 匹配（**先过滤界内，再按整数距离排序**）
# ===========================================================================
TOKEN_RATIO_BOUNDS = (0.8, 1.25)
CANDIDATE_EVIDENCE_FIELDS = ("tokenizer_sha256", "envelope_sha256", "prompt_sha256")


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
        if not _is_pos_int(c.tokens):
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
    if isinstance(lo, bool) or isinstance(hi, bool):
        return ["bounds 必须为数值"]
    if not (0 < lo < hi):
        return [f"bounds 非法: {bounds}"]
    return []


def token_match_search(candidates: list, target_tokens: int,
                       bounds: tuple = TOKEN_RATIO_BOUNDS) -> dict:
    """**先过滤出界内候选**，再按 `(|tokens-target|, key)` 排序。

    只有**界内为空**时才返回 `NO_IN_BOUNDS_CANDIDATE`；界外候选进入
    `excluded_out_of_bounds` 留痕（过滤行为本身可审计）。
    """
    if not _is_pos_int(target_tokens):
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
                "n_out_of_bounds": len(oob), "bounds": list(bounds),
                "closest": {"key": nearest.key, "tokens": nearest.tokens,
                            "ratio": round(nearest.tokens / target_tokens, 6)},
                "reason": (f"界内候选为空（最接近 ratio="
                           f"{nearest.tokens / target_tokens:.4f}）；长度门禁不可放宽"),
                "trace": [{"key": c.key, "tokens": c.tokens,
                           "int_distance": abs(c.tokens - target_tokens)}
                          for c in sorted(candidates,
                                          key=lambda x: (abs(x.tokens - target_tokens),
                                                         x.key))[:5]]}
    scored = sorted(((abs(c.tokens - target_tokens), c.key, c) for c in in_bounds),
                    key=lambda t: (t[0], t[1]))
    dist, _, best = scored[0]
    return {"status": "OK", "selected": best,
            "ratio": round(best.tokens / target_tokens, 6), "in_bounds": True,
            "int_distance": dist, "n_candidates": len(candidates),
            "n_in_bounds": len(in_bounds), "n_out_of_bounds": len(oob),
            "bounds": list(bounds), "excluded_out_of_bounds": oob_trace,
            "filter_policy": "先按 bounds 过滤，**界外候选不参与排序**",
            "tie_break": "(|tokens-target|, key) 字典序最小者优先（**先过滤界内**）",
            "trace": [{"key": k, "tokens": c.tokens, "int_distance": d}
                      for d, k, c in scored[:5]]}


# ===========================================================================
# 冻结运行时（tokenizer / envelope）—— 权威值，不由候选自报
# ===========================================================================
@dataclass
class FrozenRuntime:
    tokenizer_sha256: str
    envelope_sha256: str
    token_bounds: tuple = TOKEN_RATIO_BOUNDS

    def errors(self) -> list:
        errs = []
        for f in ("tokenizer_sha256", "envelope_sha256"):
            if not _is_hex64(getattr(self, f)):
                errs.append(f"frozen_runtime.{f} 缺失或非法")
        errs += [f"frozen_runtime.token_bounds: {e}"
                 for e in validate_bounds(self.token_bounds)]
        return errs


@dataclass
class TargetArtifact:
    """目标的**权威工件**（来自冻结构造清单）。"""
    sample_id: str
    target_tree_sha256: str
    final_prompt_tokens: int
    prompt_sha256: str

    def errors(self) -> list:
        errs = []
        if not self.sample_id:
            errs.append("target_artifact.sample_id 缺失")
        if not _is_hex64(self.target_tree_sha256):
            errs.append("target_artifact.target_tree_sha256 缺失或非法")
        if not _is_pos_int(self.final_prompt_tokens):
            errs.append("target_artifact.final_prompt_tokens 必须为正整数")
        if not _is_hex64(self.prompt_sha256):
            errs.append("target_artifact.prompt_sha256 缺失或非法")
        return errs


@dataclass
class DonorArtifact:
    """donor 的**权威工件**（冻结构造清单中的 real patch 与最终 prompt）。"""
    sample_id: str
    real_patch_sha256: str
    final_prompt_tokens: int
    prompt_sha256: str

    def errors(self) -> list:
        errs = []
        if not self.sample_id:
            errs.append("donor_artifact.sample_id 缺失")
        if not _is_hex64(self.real_patch_sha256):
            errs.append("donor_artifact.real_patch_sha256 缺失或非法")
        if not _is_pos_int(self.final_prompt_tokens):
            errs.append("donor_artifact.final_prompt_tokens 必须为正整数")
        if not _is_hex64(self.prompt_sha256):
            errs.append("donor_artifact.prompt_sha256 缺失或非法")
        return errs


# ===========================================================================
# 步 3：shuffled 约束（硬约束 = **内容交叉绑定**）
# ===========================================================================
SHUFFLE_HARD_CONSTRAINTS = (
    ("donor_ne_target", "donor 不得等于目标样本"),
    ("apply_clean_target_relation",
     "donor patch 须在**目标树**上 apply-clean，且 patch/tree SHA 与权威工件一致"),
    ("final_prompt_token_window",
     "**权威**最终完整 prompt token 之比须落在 frozen_runtime.token_bounds 内（不可放宽）"),
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
TOKEN_EVIDENCE_FIELDS = ("target_final_prompt_tokens", "donor_final_prompt_tokens",
                         "target_prompt_sha256", "candidate_prompt_sha256",
                         "tokenizer_sha256", "envelope_sha256")


def cross_check_apply_evidence(ev: dict, target_art: TargetArtifact,
                               donor_art: DonorArtifact) -> list:
    """apply 证据的**内容**交叉核对（不只 schema）。"""
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
    if errs:
        return errs
    if ev["target_tree_sha256"] != target_art.target_tree_sha256:
        errs.append("apply 证据 target_tree_sha256 与权威目标树不符")
    if ev["donor_patch_sha256"] != donor_art.real_patch_sha256:
        errs.append("apply 证据 donor_patch_sha256 与权威 real patch 不符")
    if ev["post_apply_tree_sha256"] == ev["target_tree_sha256"]:
        errs.append("post_apply_tree_sha256 与 target tree 相同 → 补丁未生效")
    return errs


def cross_check_token_evidence(ev: dict, target_art: TargetArtifact,
                               donor_art: DonorArtifact,
                               runtime: FrozenRuntime) -> list:
    """token 证据的**内容**交叉核对；ratio 由**权威值**重算。"""
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
    for f in ("target_final_prompt_tokens", "donor_final_prompt_tokens"):
        if not _is_pos_int(ev.get(f)):
            errs.append(f"{f} 必须为正整数")
    if errs:
        return errs
    # —— 逐项与权威工件比对 ——
    if ev["tokenizer_sha256"] != runtime.tokenizer_sha256:
        errs.append("tokenizer_sha256 与 frozen_runtime 不符")
    if ev["envelope_sha256"] != runtime.envelope_sha256:
        errs.append("envelope_sha256 与 frozen_runtime 不符")
    if ev["target_prompt_sha256"] != target_art.prompt_sha256:
        errs.append("target_prompt_sha256 与权威目标 prompt 不符")
    if ev["target_final_prompt_tokens"] != target_art.final_prompt_tokens:
        errs.append("target_final_prompt_tokens 与权威值不符")
    if ev["candidate_prompt_sha256"] != donor_art.prompt_sha256:
        errs.append("candidate_prompt_sha256 与权威 donor prompt 不符")
    if ev["donor_final_prompt_tokens"] != donor_art.final_prompt_tokens:
        errs.append("donor_final_prompt_tokens 与权威值不符")
    # —— ratio 用**权威值**重算，不采信申报值 ——
    lo, hi = runtime.token_bounds
    r = donor_art.final_prompt_tokens / target_art.final_prompt_tokens
    if not (lo <= r <= hi):
        errs.append(f"权威 final prompt token ratio={r:.4f} 超出 {list(runtime.token_bounds)}")
    return errs


def _hard_errors(donor: dict, target: dict, target_art: TargetArtifact,
                 donor_art: DonorArtifact, runtime: FrozenRuntime) -> list:
    errs = []
    if donor.get("sample_id") == target.get("sample_id"):
        errs.append("donor_ne_target")
    if donor.get("sample_id") != donor_art.sample_id:
        errs.append("donor_artifact 与候选 donor 不匹配")
    ev = donor.get("apply_evidence") or {}
    aerrs = cross_check_apply_evidence(ev, target_art, donor_art)
    errs += [f"apply_clean_target_relation: {e}" for e in aerrs]
    if not aerrs:                       # 结构齐备后才做身份核对（避免重复报错）
        if ev.get("target_id") != target.get("sample_id"):
            errs.append("apply 证据 target_id 与当前目标不符")
        if ev.get("donor_id") != donor.get("sample_id"):
            errs.append("apply 证据 donor_id 与当前 donor 不符")
    errs += [f"final_prompt_token_window: {e}"
             for e in cross_check_token_evidence(donor.get("token_evidence") or {},
                                                 target_art, donor_art, runtime)]
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


def select_donor(target: dict, donors: list, *, target_artifact: TargetArtifact,
                 donor_artifacts: dict, runtime: FrozenRuntime) -> dict:
    """硬约束（含**内容交叉绑定**）先过滤；软约束按逆序逐条放宽。

    权威输入（`target_artifact` / `donor_artifacts` / `runtime`）缺失或非法即
    fail-closed 返回 `NO_AUTHORITY`，不得退化为 schema 检查。
    """
    aerrs = []
    if not isinstance(target_artifact, TargetArtifact):
        aerrs.append("缺 target_artifact（权威目标工件）")
    if not isinstance(runtime, FrozenRuntime):
        aerrs.append("缺 frozen_runtime（权威 tokenizer/envelope）")
    if aerrs:
        return {"status": "NO_AUTHORITY", "donor": None, "n_donors": len(donors or []),
                "reason": "权威工件缺失或非法: " + "; ".join(aerrs), "relaxations": []}
    aerrs = list(target_artifact.errors()) + list(runtime.errors())
    if not isinstance(donor_artifacts, dict):
        aerrs.append("donor_artifacts 必须是 mapping")
        donor_artifacts = {}
    if target_artifact.sample_id != target.get("sample_id"):
        aerrs.append("target_artifact 与当前目标样本不匹配")
    if aerrs:
        return {"status": "NO_AUTHORITY", "donor": None, "n_donors": len(donors or []),
                "reason": "权威工件缺失或非法: " + "; ".join(aerrs[:4]),
                "relaxations": []}

    hard_ok, hard_rejected = [], []
    for d in donors or []:
        da = donor_artifacts.get(d.get("sample_id"))
        if da is None:
            hard_rejected.append(d)
            continue
        derr = da.errors()
        if derr or _hard_errors(d, target, target_artifact, da, runtime):
            hard_rejected.append(d)
        else:
            hard_ok.append((d, da))
    if not hard_ok:
        return {"status": "NO_DONOR", "donor": None, "n_donors": len(donors or []),
                "reason": f"无候选通过硬约束（{len(hard_rejected)} 个被拒）",
                "hard_rejected": len(hard_rejected), "relaxations": []}

    active = list(SHUFFLE_SOFT_CONSTRAINTS)
    relaxations = []
    for _step in range(len(active) + 1):
        pool = [(d, da) for d, da in hard_ok
                if all(_passes_soft(d, target, n) for n, _ in active)]
        if pool:
            pool.sort(key=lambda t: (abs(t[1].final_prompt_tokens
                                          - target_artifact.final_prompt_tokens),
                                     t[0].get("sample_id", "")))
            chosen, _chosen_art = pool[0]
            return {"status": "OK", "donor": chosen, "n_donors": len(donors or []),
                    "n_pool_after_relax": len(pool), "relaxations": relaxations,
                    "active_constraints": [n for n, _ in active],
                    "covariates": {
                        "target": {k: target.get(k) for k in COVARIATE_FIELDS},
                        "donor": {k: chosen.get(k) for k in COVARIATE_FIELDS}},
                    "bounds": list(runtime.token_bounds),
                    "binding": "内容交叉绑定（tree/patch/prompt/tokenizer/envelope）",
                    "tie_break": "(|权威 final_prompt_tokens 差|, sample_id) 字典序最小者优先"}
        if not active:
            break
        relaxations.append(active.pop()[0])
    return {"status": "NO_DONOR", "donor": None, "n_donors": len(donors or []),
            "reason": "全部软约束放宽后仍无候选", "relaxations": relaxations}


# ===========================================================================
# 步 4：oracle **分层契约**（T1 / T2 / T3）
# ===========================================================================
ORACLE_TIER_T1 = "T1-executable"
ORACLE_TIER_T2 = "T2-semantic-assertion"
ORACLE_TIER_T3 = "T3-reviewer-residual-path"
ORACLE_TIERS = (ORACLE_TIER_T1, ORACLE_TIER_T2, ORACLE_TIER_T3)

# verdict **标记行**：唯一权威来源（exit code 不参与漏洞状态判定）
VERDICT_MARKER = "VERDICT:"
VALID_ORACLE_RESULTS = ("fixed", "still_vulnerable")
ORACLE_ERROR = "ORACLE_ERROR"                       # 第三状态：不可判定 / 基础设施失败
ORACLE_VERDICT_VALUES = VALID_ORACLE_RESULTS + (ORACLE_ERROR,)


@dataclass(frozen=True)
class OracleContract:
    """单个 oracle 的**独立冻结契约**（不跨 oracle 统一解释 exit code）。"""
    name: str
    tier: str
    machine_decidable: bool
    command_template: str
    tool_version: str
    valid_exit_codes: tuple
    infra_exit_codes: tuple
    requires_marker: bool
    control_samples: tuple
    fault_injection: tuple
    notes: str

    def as_dict(self) -> dict:
        return {"name": self.name, "tier": self.tier,
                "machine_decidable": self.machine_decidable,
                "command_template": self.command_template,
                "tool_version": self.tool_version,
                "valid_exit_codes": list(self.valid_exit_codes),
                "infra_exit_codes": list(self.infra_exit_codes),
                "requires_marker": self.requires_marker,
                "control_samples": list(self.control_samples),
                "fault_injection": list(self.fault_injection),
                "notes": self.notes}


_COMMON_FAULT_INJECTION = (
    "exit 码改为 infra 集合内的值 → 必须得 ORACLE_ERROR",
    "抹掉标记行 → 必须得 ORACLE_ERROR",
    "写入两个互相冲突的标记行 → 必须得 ORACLE_ERROR",
)

ORACLE_CONTRACTS = {
    "pytest-security-regression": OracleContract(
        name="pytest-security-regression", tier=ORACLE_TIER_T1, machine_decidable=True,
        command_template="pytest -q <security_test_id>",
        tool_version="pytest>=7,<9",
        valid_exit_codes=(0, 1),        # 0=全过；1=有测试失败（**不等于**漏洞仍存在）
        infra_exit_codes=(2, 3, 4, 5),  # 中断/内部错误/用法错误/未收集到测试
        requires_marker=True,
        control_samples=("已知已修复样本须输出 fixed", "已知仍可利用样本须输出 still_vulnerable"),
        fault_injection=_COMMON_FAULT_INJECTION,
        notes=("退出码 1 只表示「有测试失败」，可能来自断言错误/环境问题/无关回归，"
               "故**不得**直接解读为「漏洞仍存在」；必须由专用安全回归测试打印标记行。"
               "运行须限定到单一测试 id，避免无关失败污染。"),
    ),
    "poc-exploit-script": OracleContract(
        name="poc-exploit-script", tier=ORACLE_TIER_T1, machine_decidable=True,
        command_template="python <poc_script>",
        tool_version="CPython 3.9/3.13",
        valid_exit_codes=(0,),          # 脚本跑完即为有效运行（不含利用成败语义）
        infra_exit_codes=(2,),          # 解释器用法错误/脚本崩溃前的解释层错误
        requires_marker=True,
        control_samples=("vuln 树须输出 still_vulnerable", "fix 树须输出 fixed"),
        fault_injection=_COMMON_FAULT_INJECTION,
        notes=("**纠正旧版自相矛盾**：旧注释称「PoC 成功利用=仍存在」，映射却写 `0 → fixed`。"
               "exploit 是否成功是脚本语义，不能由退出码承载；退出码 0 只说明脚本正常结束。"
               "漏洞状态一律由标记行给出。"),
    ),
    "semantic-assertion": OracleContract(
        name="semantic-assertion", tier=ORACLE_TIER_T2, machine_decidable=True,
        command_template="python <checker_script> --target <tree>",
        tool_version="CPython 3.9/3.13",
        valid_exit_codes=(0, 1),
        infra_exit_codes=(2,),
        requires_marker=True,
        control_samples=("断言对象已知满足时须输出 fixed", "已知不满足时须输出 still_vulnerable"),
        fault_injection=_COMMON_FAULT_INJECTION + ("checker 脚本 SHA 与冻结值不符 → 必须拒绝",),
        notes=("确定性语义断言（路径/权限/返回字段等领域检查）。checker 脚本自身以 SHA 冻结，"
               "防止「改断言迁就结果」。"),
    ),
    "reviewer-residual-path": OracleContract(
        name="reviewer-residual-path", tier=ORACLE_TIER_T3, machine_decidable=False,
        command_template="(无可执行 oracle；书面残余利用路径)",
        tool_version="n/a",
        valid_exit_codes=(),
        infra_exit_codes=(),
        requires_marker=False,
        control_samples=("双人独立确认一致", "分歧须第三人仲裁并记录"),
        fault_injection=("缺任一 reviewer 身份 → 必须拒绝", "两 reviewer 相同 → 必须拒绝"),
        notes=("**不可机器判定**：只能由冻结的书面残余利用路径 + 双人独立确认承载。"
               "T3 数量必须与 T1/T2 **分别报告**，不得混为同一证据等级。"),
    ),
}


def contracts_registry() -> dict:
    return {"schema": ARMS_SCHEMA,
            "tiers": {
                ORACLE_TIER_T1: "可执行 oracle（机器可证）",
                ORACLE_TIER_T2: "确定性语义断言（可脚本化）",
                ORACLE_TIER_T3: "无可执行/可脚本化 oracle → 书面残余路径 + 双人独立确认（**不可机器判定**）",
            },
            "verdict_marker": VERDICT_MARKER,
            "verdict_values": list(ORACLE_VERDICT_VALUES),
            "exit_code_role": "仅用于分类本次运行是否有效（valid / infra / 未知）；**不参与**漏洞状态判定",
            "contracts": {k: v.as_dict() for k, v in ORACLE_CONTRACTS.items()},
            "separation_rule": "T1 / T2 / T3 三类数量分别报告，不混为同一证据等级"}


# 标记值的**大小写规范化**映射（`VERDICT: FIXED` 亦被接受并还原为规范值）
_VERDICT_CANON = {v.lower(): v for v in ORACLE_VERDICT_VALUES}


def read_verdict_marker(raw_result: str) -> str:
    """从原始输出读取**显式标记行**；无标记 / 值非法 / 互相冲突 → `ORACLE_ERROR`。

    标记必须**位于行首**（允许前导空白）；同一输出中多个标记若取值不一致按
    `ORACLE_ERROR` 处理（fail-closed）。
    """
    found = []
    for line in (raw_result or "").splitlines():
        s = line.strip()
        if s.upper().startswith(VERDICT_MARKER):
            v = s.split(":", 1)[1].strip().lower()
            found.append(_VERDICT_CANON.get(v, "INVALID"))
    if not found:
        return ORACLE_ERROR
    if "INVALID" in found:
        return ORACLE_ERROR
    if len(set(found)) != 1:
        return ORACLE_ERROR
    return found[0]


def parse_oracle_verdict(contract: str, raw_result: str, exit_code: int) -> str:
    """**冻结 parser**：按 oracle 的独立契约派生 verdict。

    规则（`exit_code` **不再**映射为漏洞状态）：
      ① 契约须已登记，否则 `ValueError`；
      ② T3 不可机器判定 → `ValueError`（须走双人确认记录）；
      ③ `exit_code` 落在 `infra_exit_codes` 或不在 `valid_exit_codes` → `ORACLE_ERROR`；
      ④ 否则从标记行读取；无标记/冲突 → `ORACLE_ERROR`（**不默认通过**）。
    """
    c = ORACLE_CONTRACTS.get(contract)
    if c is None:
        raise ValueError(f"未登记的 oracle 契约: {contract!r}")
    if not c.machine_decidable:
        raise ValueError(f"{contract}: T3 不可机器判定，须由双人独立确认记录承载")
    if not isinstance(exit_code, int) or isinstance(exit_code, bool):
        return ORACLE_ERROR
    if exit_code in c.infra_exit_codes:
        return ORACLE_ERROR
    if exit_code not in c.valid_exit_codes:
        return ORACLE_ERROR
    return read_verdict_marker(raw_result)


def oracle_parser_sha256() -> str:
    """冻结 parser 的**实现 SHA**（绑定到证据里，防止 parser 或契约被换）。"""
    payload = "\n".join([
        inspect.getsource(read_verdict_marker),
        inspect.getsource(parse_oracle_verdict),
        json.dumps(contracts_registry(), sort_keys=True, ensure_ascii=False),
    ])
    return _sha_text(payload)


ORACLE_EVIDENCE_FIELDS = ("contract", "tier", "arm", "sample_id", "manifest_sha256",
                          "poc_sha256", "target_tree_sha256", "patch_sha256",
                          "command", "exit_code", "raw_result", "raw_result_sha256",
                          "parsed_verdict", "oracle_parser_sha256")
ORACLE_EVIDENCE_OPTIONAL_FIELDS = ("poc_path", "target_tree_dir", "patch_path",
                                   "checker_sha256", "residual_path_sha256",
                                   "reviewer_1", "reviewer_2", "agreement")
# 任何层都必须齐备的字段（工件 SHA 由各层自行要求，见下）
EVIDENCE_ALWAYS_REQUIRED = ("contract", "tier", "arm", "sample_id", "manifest_sha256",
                            "command", "exit_code", "raw_result", "raw_result_sha256",
                            "parsed_verdict", "oracle_parser_sha256")
EVIDENCE_ALWAYS_HEX = ("manifest_sha256", "raw_result_sha256", "oracle_parser_sha256")
# 各层**必须**提供的工件引用（路径）与其对应 SHA 字段
TIER_REQUIRED_ARTIFACTS = {
    ORACLE_TIER_T1: ("poc_path", "patch_path", "target_tree_dir"),
    ORACLE_TIER_T2: ("patch_path", "target_tree_dir"),
    ORACLE_TIER_T3: (),
}
TIER_REQUIRED_HEX = {
    ORACLE_TIER_T1: ("poc_sha256", "patch_sha256", "target_tree_sha256"),
    ORACLE_TIER_T2: ("patch_sha256", "target_tree_sha256"),
    ORACLE_TIER_T3: (),
}
# arm 规格中应出现的字段：只含**臂专属**工件；目标树 SHA 是样本级属性，
# 由 `FrozenContext.samples[sample_id]["target_tree_sha256"]` 单独核对，不在此重复。
ARM_SPEC_HEX = {
    ORACLE_TIER_T1: ("poc_sha256", "patch_sha256"),
    ORACLE_TIER_T2: ("patch_sha256",),
    ORACLE_TIER_T3: (),
}


@dataclass
class FrozenContext:
    """验证期的**权威上下文**（来自冻结构造清单）；缺任一即 fail-closed。

    `samples[sample_id] = {"target_tree_sha256": str, "arms": {arm: {"poc_sha256":..,"patch_sha256":..}}}`
    """
    manifest_sha256: str
    samples: dict
    runtime: FrozenRuntime

    def errors(self) -> list:
        errs = []
        if not _is_hex64(self.manifest_sha256):
            errs.append("frozen_context.manifest_sha256 缺失或非法")
        if not isinstance(self.samples, dict) or not self.samples:
            errs.append("frozen_context.samples 为空或非 mapping")
        errs += self.runtime.errors()
        return errs


@dataclass
class OracleEvidence:
    """oracle 执行证据（**严格工件绑定**，非仅 schema）。"""
    contract: str
    arm: str
    sample_id: str
    raw_result: str
    exit_code: int
    manifest_sha256: str = ""
    poc_sha256: str = ""
    target_tree_sha256: str = ""
    patch_sha256: str = ""
    command: str = ""
    parsed_verdict: str = ""
    raw_result_sha256: str = ""
    oracle_parser_sha256: str = ""
    tier: str = ""
    poc_path: str | None = None
    target_tree_dir: str | None = None
    patch_path: str | None = None
    checker_sha256: str = ""
    residual_path_sha256: str = ""
    reviewer_1: str = ""
    reviewer_2: str = ""
    agreement: object = None

    def as_dict(self) -> dict:
        d = {f: getattr(self, f) for f in ORACLE_EVIDENCE_FIELDS}
        d.update({f: getattr(self, f) for f in ORACLE_EVIDENCE_OPTIONAL_FIELDS})
        return d

    # ------------------------------------------------------------------
    def verify(self, base_dir: Path, ctx: FrozenContext) -> list:
        """**严格验证**（P0-1）：

        ① 上下文与通用字段齐备（缺任一即错，不跳过）；
        ② 各层**强制工件引用**齐备（T1: poc+patch+tree；T2: patch+tree）；
        ③ `raw_result_sha256` == 对 `raw_result` 重算；
        ④ `oracle_parser_sha256` == 当前冻结 parser 实现 SHA；
        ⑤ verdict == 冻结 parser 从 `raw_result + exit_code` 派生者；
        ⑥ **重算** PoC SHA / patch SHA / **LF 归一化递归 tree SHA**，与证据记录值比对；
        ⑦ 与 `FrozenContext` 逐项绑定：manifests SHA、样本存在、arm 存在、
           arm 规格中的 poc/patch SHA、目标树 SHA；
        ⑧ T3 走双人确认记录（不得声称机器可判定）。
        """
        errs = []
        if not isinstance(ctx, FrozenContext):
            return ["缺冻结上下文 FrozenContext（fail-closed）"]
        cerr = ctx.errors()
        if cerr:
            return ["冻结上下文非法: " + "; ".join(cerr[:3])]

        c = ORACLE_CONTRACTS.get(self.contract)
        if c is None:
            return [f"未登记的 oracle 契约: {self.contract!r}"]
        if self.tier != c.tier:
            errs.append(f"tier 与契约不符: 证据={self.tier!r} 契约={c.tier!r}")

        # ① 通用字段（工件 SHA 由各层在 ② 中要求）
        for f in EVIDENCE_ALWAYS_REQUIRED:
            v = getattr(self, f)
            if v is None or v == "":
                errs.append(f"缺 {f}")
        if errs:
            return errs
        if self.arm not in ARM_ORACLE:
            errs.append(f"未登记的臂: {self.arm!r}")
        if self.parsed_verdict not in ORACLE_VERDICT_VALUES:
            errs.append(f"parsed_verdict 不在枚举内: {self.parsed_verdict!r}")
        if not isinstance(self.exit_code, int) or isinstance(self.exit_code, bool):
            errs.append("exit_code 必须为整数")
        if not isinstance(self.command, str) or not self.command.strip():
            errs.append("command 必须为非空字符串")
        for f in EVIDENCE_ALWAYS_HEX:
            if not _is_hex64(getattr(self, f)):
                errs.append(f"{f} 非 64 位 hex")

        # ② 层次专属要求
        if c.machine_decidable:
            for f in TIER_REQUIRED_ARTIFACTS.get(c.tier, ()):
                if not getattr(self, f, None):
                    errs.append(f"{c.tier} 强制要求工件引用 {f}（不得省略）")
            for f in TIER_REQUIRED_HEX.get(c.tier, ()):
                if not _is_hex64(getattr(self, f)):
                    errs.append(f"{f} 非 64 位 hex（{c.tier} 必填）")
            if c.tier == ORACLE_TIER_T2 and not _is_hex64(self.checker_sha256):
                errs.append("T2 须提供 checker_sha256")
        else:
            if not self.reviewer_1 or not self.reviewer_2:
                errs.append("T3 须提供 reviewer_1 与 reviewer_2")
            elif self.reviewer_1 == self.reviewer_2:
                errs.append("T3 的两名 reviewer 不得为同一人")
            if not _is_hex64(self.residual_path_sha256):
                errs.append("T3 须提供 residual_path_sha256（冻结的书面残余利用路径）")
            if self.agreement not in (True, False):
                errs.append("T3 须显式记录 agreement（是否一致）")
            elif self.agreement is True:
                if self.parsed_verdict not in VALID_ORACLE_RESULTS:
                    errs.append("T3 一致时 parsed_verdict 须为 fixed / still_vulnerable")
                elif read_verdict_marker(self.raw_result) != self.parsed_verdict:
                    errs.append("T3 的结论须与原始输出中的标记行一致")
            else:
                if self.parsed_verdict != ORACLE_ERROR:
                    errs.append("T3 双人未达成一致 → parsed_verdict 须为 ORACLE_ERROR（待仲裁）")
        if errs:
            return errs

        # ③ T3 到此为止：不执行、不重算工件（**不可机器判定**）
        if not c.machine_decidable:
            return errs

        base = Path(base_dir)

        # ③④⑤ 原始输出与 parser
        if self.raw_result_sha256 != _sha_text(self.raw_result):
            errs.append("raw_result_sha256 与原始输出重算不符")
        if self.oracle_parser_sha256 != oracle_parser_sha256():
            errs.append("oracle_parser_sha256 与当前冻结 parser 不符")
        try:
            derived = parse_oracle_verdict(self.contract, self.raw_result, self.exit_code)
        except ValueError as e:
            errs.append(f"parser 派生失败: {e}")
            derived = None
        if derived is not None and derived != self.parsed_verdict:
            errs.append(f"parsed_verdict({self.parsed_verdict}) 与 parser 派生({derived}) 不符")

        # ⑥ **重算**工件哈希（不采信记录值）；路径缺失由 ② 的层次要求负责报错
        def _rehash(path_field, sha_field, label):
            rel = getattr(self, path_field)
            if not rel:                     # 该层不要求此工件
                return
            p = base / rel
            if not p.is_file():
                errs.append(f"{label} 文件不存在: {rel}")
                return
            mode, sha = file_content_sha256(p)
            if sha != getattr(self, sha_field):
                errs.append(f"{label} 内容 SHA 与记录不符（重算 {sha[:12]}，"
                            f"记录 {str(getattr(self, sha_field))[:12]}，口径 {mode}）")

        _rehash("poc_path", "poc_sha256", "PoC")
        _rehash("patch_path", "patch_sha256", "patch")
        if self.target_tree_dir:
            tdir = base / self.target_tree_dir
            if not tdir.is_dir():
                errs.append(f"target 树不存在: {self.target_tree_dir}")
            else:
                recomputed_tree = normalized_tree_sha256(tdir)
                if recomputed_tree != self.target_tree_sha256:
                    errs.append(f"target 树 SHA 与记录不符（重算 {recomputed_tree[:12]}，"
                                f"记录 {self.target_tree_sha256[:12]}）")

        # ⑦ 与冻结构造清单逐项绑定
        if self.manifest_sha256 != ctx.manifest_sha256:
            errs.append("manifest_sha256 与冻结上下文不符")
        samp = ctx.samples.get(self.sample_id)
        if not isinstance(samp, dict):
            errs.append(f"冻结上下文中无样本 {self.sample_id}")
        else:
            if "target_tree_sha256" in TIER_REQUIRED_HEX.get(c.tier, ()) \
                    and samp.get("target_tree_sha256") != self.target_tree_sha256:
                errs.append("目标树 SHA 与冻结上下文不符")
            arm_spec = (samp.get("arms") or {}).get(self.arm)
            if not isinstance(arm_spec, dict):
                errs.append(f"冻结上下文中无 arm 规格: {self.sample_id}/{self.arm}")
            else:
                for f in ARM_SPEC_HEX.get(c.tier, ()):
                    if arm_spec.get(f) != getattr(self, f):
                        errs.append(f"{f} 与冻结 arm 规格不符")
        return errs


# ===========================================================================
# 四臂接受标准（**对齐预注册 §3.3**）
# ===========================================================================
ARM_ORACLE = {
    "annotated-security-complete": {
        "expect_target_oracle": "fixed", "oracle_required": True,
        "desc": "安全完备补丁：oracle 须显示目标漏洞已修复"},
    "support-only-insufficient": {
        "expect_target_oracle": "still_vulnerable", "oracle_required": True,
        "desc": "去掉直接修复后，oracle 须显示目标漏洞重新出现"},
    "placebo": {
        "expect_target_oracle": "still_vulnerable", "oracle_required": False,
        "desc": ("行为中性改造：**仅需 apply-clean + 模型判为 vulnerable**；"
                 "预注册 §3.3 明确不要求 oracle 复现")},
    "shuffled": {
        "expect_target_oracle": "still_vulnerable", "oracle_required": False,
        "desc": ("负向 shuffled control：**仅需 apply-clean + 模型判为 vulnerable**；"
                 "若额外 oracle 显示目标漏洞被意外修复 → 操纵检验失败，拒绝该组合")},
}

MODEL_VERDICTS = ("vulnerable", "benign")


def evaluate_arm(arm: str, apply_clean: bool, *,
                 target_oracle: str | None = None,
                 model_verdict: str | None = None,
                 evidence: OracleEvidence | None = None,
                 base_dir: Path | None = None,
                 ctx: FrozenContext | None = None) -> dict:
    """机器化判定（**按臂声明的 oracle 要求**，对齐预注册 §3.3）。

    `oracle_required=True` 的臂（annotated-security-complete / support-only-insufficient）：
      必须提供可验证的 oracle 证据，且 verdict 等于该臂期望值。
    `oracle_required=False` 的臂（placebo / shuffled）：
      接受条件 = apply-clean ∧ 模型判 `vulnerable`；**不要求** oracle。
      若额外提供了 oracle 证据：验证失败 → 拒绝（构造污染）；验证通过且显示
      `fixed` → 拒绝（操纵检验失败）。未提供 → 仅记录，不影响接受。
    """
    if arm not in ARM_ORACLE:
        raise KeyError(f"未知臂: {arm}")
    spec = ARM_ORACLE[arm]
    out = {"arm": arm, "oracle_required": spec["oracle_required"],
           "expected_target_oracle": spec["expect_target_oracle"]}

    if apply_clean is not True:
        return {"accept": False, "reason": "apply 不干净", **out}

    ev_state = {"oracle_evidence_provided": evidence is not None,
                "oracle_evidence_verified": False,
                "oracle_verdict": None}

    if spec["oracle_required"]:
        if target_oracle is None or target_oracle not in VALID_ORACLE_RESULTS:
            return {"accept": False, **out, **ev_state,
                    "reason": (f"oracle 结果不在可接受枚举内: {target_oracle!r}"
                               f"（{ORACLE_ERROR} 为不可判定，不得计入接纳；fail-closed）")}
        if evidence is None:
            return {"accept": False, **out, **ev_state,
                    "reason": "该臂要求 oracle 证据（fail-closed）"}
        eerr = evidence.verify(base_dir, ctx)
        if eerr:
            return {"accept": False, **out, **ev_state,
                    "reason": "oracle 证据验证失败: " + "; ".join(eerr[:3])}
        ev_state["oracle_evidence_verified"] = True
        ev_state["oracle_verdict"] = evidence.parsed_verdict
        if evidence.parsed_verdict == ORACLE_ERROR:
            return {"accept": False, **out, **ev_state,
                    "reason": "oracle 契约为 ORACLE_ERROR → 不可判定，不得接纳"}
        if evidence.parsed_verdict != target_oracle:
            return {"accept": False, **out, **ev_state,
                    "reason": "证据 verdict 与传入 oracle 不符"}
        ok = evidence.parsed_verdict == spec["expect_target_oracle"]
        return {"accept": ok, **out, **ev_state,
                "got_target_oracle": evidence.parsed_verdict,
                "reason": "符合预期" if ok else
                          f"预期目标漏洞 {spec['expect_target_oracle']}，"
                          f"实得 {evidence.parsed_verdict}",
                "oracle_evidence": evidence.as_dict()}

    # —— oracle 不要求（placebo / shuffled，预注册 §3.3）——
    if model_verdict not in MODEL_VERDICTS:
        return {"accept": False, **out, **ev_state,
                "reason": f"placebo/shuffled 须给出模型判定（{MODEL_VERDICTS}），"
                          f"实得 {model_verdict!r}"}
    if model_verdict != "vulnerable":
        return {"accept": False, **out, **ev_state,
                "reason": "模型未判为 vulnerable → 该臂的操纵前提不成立"}
    if evidence is not None:
        eerr = evidence.verify(base_dir, ctx)
        if eerr:
            return {"accept": False, **out, **ev_state,
                    "reason": "附加 oracle 证据验证失败: " + "; ".join(eerr[:3])}
        ev_state["oracle_evidence_verified"] = True
        ev_state["oracle_verdict"] = evidence.parsed_verdict
        if evidence.parsed_verdict == "fixed":
            return {"accept": False, **out, **ev_state,
                    "reason": "附加 oracle 显示目标漏洞被意外修复 → 操纵检验失败"}
    return {"accept": True, **out, **ev_state,
            "reason": ("apply-clean 且模型判 vulnerable"
                       + ("；附加 oracle 已通过并记录" if evidence is not None else
                          "；（预注册 §3.3：不要求 oracle 复现）")),
            "oracle_evidence": evidence.as_dict() if evidence is not None else None}


# ===========================================================================
# 便捷构造
# ===========================================================================
def make_evidence(contract: str, arm: str, sample_id: str, raw_result: str, exit_code: int,
                  *, base_dir: Path, context: FrozenContext,
                  poc_path: str | None = None, patch_path: str | None = None,
                  target_tree_dir: str | None = None,
                  command: str = "", checker_sha256: str = "",
                  residual_path_sha256: str = "", reviewer_1: str = "",
                  reviewer_2: str = "", agreement=None) -> OracleEvidence:
    """从**磁盘工件**构造证据（自动填入重算 SHA 与 parser SHA，避免手填造假）。"""
    c = ORACLE_CONTRACTS.get(contract)
    if c is None:
        raise KeyError(f"未登记的 oracle 契约: {contract!r}")
    if base_dir is None or context is None:
        raise ValueError("make_evidence 必须提供 base_dir 与 FrozenContext")
    base = Path(base_dir)

    def _fsha(rel):
        if not rel:
            return ""
        p = base / rel
        if not p.is_file():
            raise FileNotFoundError(f"工件不存在: {rel}")
        return file_content_sha256(p)[1]

    tree_sha = ""
    if target_tree_dir:
        tree_sha = normalized_tree_sha256(base / target_tree_dir)
    if c.machine_decidable:
        try:
            verdict = parse_oracle_verdict(contract, raw_result, exit_code)
        except ValueError:
            verdict = ORACLE_ERROR
    else:
        # T3：结论由双人复核给出；未达成一致时强制为待仲裁态
        verdict = ORACLE_ERROR if agreement is not True else read_verdict_marker(raw_result)
    return OracleEvidence(
        contract=contract, tier=c.tier, arm=arm, sample_id=sample_id,
        manifest_sha256=context.manifest_sha256,
        poc_sha256=_fsha(poc_path), target_tree_sha256=tree_sha,
        patch_sha256=_fsha(patch_path), command=command, exit_code=exit_code,
        raw_result=raw_result, raw_result_sha256=_sha_text(raw_result),
        parsed_verdict=verdict, oracle_parser_sha256=oracle_parser_sha256(),
        poc_path=poc_path, patch_path=patch_path, target_tree_dir=target_tree_dir,
        checker_sha256=checker_sha256, residual_path_sha256=residual_path_sha256,
        reviewer_1=reviewer_1, reviewer_2=reviewer_2, agreement=agreement)


def arms_registry() -> dict:
    payload = json.dumps(ARM_ORACLE, sort_keys=True, ensure_ascii=False)
    return {
        "schema": ARMS_SCHEMA,
        "n_arms": len(ARM_ORACLE),
        "arms": {k: dict(v) for k, v in ARM_ORACLE.items()},
        "fingerprint": hashlib.sha256(payload.encode("utf-8")).hexdigest(),
        "arm_acceptance_source": "预注册 §3.3（V4-四臂算法预注册.md）",
        "model_verdicts": list(MODEL_VERDICTS),
        "token_bounds": list(TOKEN_RATIO_BOUNDS),
        "token_evidence_fields": list(TOKEN_EVIDENCE_FIELDS),
        "hash_modes": {"text": HASH_MODE_TEXT, "bytes": HASH_MODE_BYTES},
        "tree_sha256": "LF 归一化递归 tree SHA（normalized_tree_sha256）",
        "shuffle": {
            "hard": [{"name": n, "doc": d} for n, d in SHUFFLE_HARD_CONSTRAINTS],
            "soft_in_relax_order": [{"name": n, "doc": d}
                                    for n, d in SHUFFLE_SOFT_CONSTRAINTS],
            "relax_policy": "软约束按逆序逐条放宽；硬约束（含内容交叉绑定与 token 门禁）不可放宽",
            "apply_evidence_fields": list(APPLY_EVIDENCE_FIELDS),
            "covariates": list(COVARIATE_FIELDS),
            "binding": "内容交叉绑定：tree / patch / prompt / tokenizer / envelope 逐项与权威工件比对",
        },
        "oracle": contracts_registry(),
        "oracle_evidence_fields": list(ORACLE_EVIDENCE_FIELDS),
        "oracle_evidence_optional_fields": list(ORACLE_EVIDENCE_OPTIONAL_FIELDS),
        "evidence_always_required": list(EVIDENCE_ALWAYS_REQUIRED),
        "tier_required_artifacts": {k: list(v) for k, v in TIER_REQUIRED_ARTIFACTS.items()},
        "tier_required_hex": {k: list(v) for k, v in TIER_REQUIRED_HEX.items()},
        "arm_spec_hex": {k: list(v) for k, v in ARM_SPEC_HEX.items()},
        "oracle_parser_sha256": oracle_parser_sha256(),
    }
