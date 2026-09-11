# -*- coding: utf-8 -*-
"""A-3 步 2/3/4（第五次返工，schema `v4-arms/5`）。

本次返工 = 评审 5 的五条（P0-1/P0-2/P0-3/P1/文档同步），逐条均已复现确认。

P0-1 **结果感知接纳**（最严重）。旧 `evaluate_arm` 对 placebo / shuffled 采用
    `apply-clean 且 model_verdict == vulnerable → accept`。模型判定是**因变量**，
    不得反过来决定样本是否有效，否则形成结果感知筛选（误判 benign 的样本被剔除、
    判 vulnerable 的被保留），使统计天然偏向预期。现**彻底拆开**：
      · `construction_gate(...)`：**运行前**构造门禁。其签名中**不存在**任何模型
        输出参数；只消费 apply-clean、工件、长度门禁与（该臂要求时）oracle 证据。
      · `outcome_evaluation(...)`：**运行后**结果与操纵检验记录，
        恒 `changes_inclusion = False`，不得改变 active universe / schedule / 分母。

P0-2 **shuffled 绑定了错误的 prompt 对象**。旧实现把 donor **自身 CVE** 的
    `final_prompt_tokens / prompt_sha256` 当作候选 prompt 去比对，但 shuffled 臂的
    真实候选 prompt 是「**目标**源码上下文 + **donor** patch + 目标 envelope」，
    两者通常不可能字节相同。现引入 `PairCandidateArtifact`（target×donor 级），
    token 窗口比较「目标**基准臂**最终 prompt token」vs「target×donor 候选最终
    prompt token」。同时 apply-clean 不再采信自报字段：从**实际 post-apply 目录**
    重算 tree SHA，并绑定受控 apply runner 的实现 SHA 与执行记录。

P0-3 **T3 存在提前返回绕过**（T2 同类）。旧实现对 T3 在检查少量字段后直接
    `return`，跳过了 raw_result 重算、parser SHA 核对、manifest/template 绑定、
    sample/arm 存在性核对与书面材料重算；且「双人确认」只是两个非空且不同的
    字符串 + 一个布尔值。现移除提前返回，T3 与 T1/T2 共用同一套 provenance 检查，
    并要求绑定**真实的两份 reviewer submission 文件**（路径 + 重算 SHA，不得同一
    文件或同一人）、两人**独立 verdict**，分歧时必须提供**仲裁工件与仲裁结论**。
    T2 亦新增 `checker_path`（重算内容 SHA 并与冻结 arm 规格绑定）。

自查（评审未提）：① `construction_gate` 的签名中不存在模型输出参数，并配结构性
    测试防回归；② 删除旧 `evaluate_arm`，避免错误契约残留。
"""
from __future__ import annotations

import hashlib
import inspect
import json
from dataclasses import dataclass, field
from pathlib import Path

ARMS_SCHEMA = "v4-arms/5"

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
    b = Path(path).read_bytes()
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


def _rehash_file(base: Path, rel, label: str, errs: list, sha_field: str, expected: str) -> None:
    """把 `rel` 指向的文件按内容重算并与 `expected` 比对（fail-closed）。

    路径为空即视为「该层不要求此工件」，直接返回（是否必填由分层要求负责报错）。
    """
    if not rel:
        return
    p = Path(base) / rel
    if not p.is_file():
        errs.append(f"{label} 文件不存在: {rel}")
        return
    mode, sha = file_content_sha256(p)
    if sha != expected:
        errs.append(f"{label} 内容 SHA 与记录不符（重算 {sha[:12]}，"
                    f"记录 {str(expected)[:12]}，口径 {mode}）")


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
    if isinstance(lo, bool) or isinstance(hi, bool):
        return ["bounds 必须为数值"]
    if not (isinstance(lo, (int, float)) and isinstance(hi, (int, float))):
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
# 冻结运行时（tokenizer / envelope / apply runner）—— 权威值，不由候选自报
# ===========================================================================
@dataclass
class FrozenRuntime:
    tokenizer_sha256: str
    envelope_sha256: str
    apply_runner_sha256: str = ""
    token_bounds: tuple = TOKEN_RATIO_BOUNDS

    def errors(self) -> list:
        errs = []
        for f in ("tokenizer_sha256", "envelope_sha256", "apply_runner_sha256"):
            if not _is_hex64(getattr(self, f)):
                errs.append(f"frozen_runtime.{f} 缺失或非法")
        errs += [f"frozen_runtime.token_bounds: {e}"
                 for e in validate_bounds(self.token_bounds)]
        return errs


@dataclass
class TargetBaseline:
    """目标样本在**基准臂**（real）下的权威 prompt 工件。

    shuffled 候选须与**它**做长度匹配 —— 而不是与 donor 自身的 prompt 比较。
    """
    sample_id: str
    target_tree_sha256: str
    base_final_prompt_tokens: int
    base_prompt_sha256: str

    def errors(self) -> list:
        errs = []
        if not self.sample_id:
            errs.append("target_baseline.sample_id 缺失")
        if not _is_hex64(self.target_tree_sha256):
            errs.append("target_baseline.target_tree_sha256 缺失或非法")
        if not _is_pos_int(self.base_final_prompt_tokens):
            errs.append("target_baseline.base_final_prompt_tokens 必须为正整数")
        if not _is_hex64(self.base_prompt_sha256):
            errs.append("target_baseline.base_prompt_sha256 缺失或非法")
        return errs


@dataclass
class DonorPatch:
    """donor 的**冻结 real patch**（被注入目标树的那个补丁）。"""
    sample_id: str
    real_patch_sha256: str

    def errors(self) -> list:
        errs = []
        if not self.sample_id:
            errs.append("donor_patch.sample_id 缺失")
        if not _is_hex64(self.real_patch_sha256):
            errs.append("donor_patch.real_patch_sha256 缺失或非法")
        return errs


@dataclass
class ApplyRecord:
    """**受控 apply runner** 的执行记录（绑定 runner 实现 SHA）。"""
    runner_sha256: str
    command: str
    exit_code: int
    stdout_sha256: str
    target_tree_sha256: str
    post_apply_tree_sha256: str

    def errors(self) -> list:
        errs = []
        for f in ("runner_sha256", "stdout_sha256", "target_tree_sha256",
                  "post_apply_tree_sha256"):
            if not _is_hex64(getattr(self, f)):
                errs.append(f"apply_record.{f} 缺失或非法")
        if not isinstance(self.command, str) or not self.command.strip():
            errs.append("apply_record.command 必须为非空字符串")
        if self.exit_code != 0:
            errs.append(f"apply_record.exit_code != 0: {self.exit_code!r}")
        return errs


@dataclass
class PairCandidateArtifact:
    """**target × donor** 级候选工件（shuffled 臂的真实候选）。

    候选 prompt = 目标源码上下文 + donor patch + 目标 envelope，
    因此其 SHA / token 数与 donor 自身 prompt 无关。
    """
    target_id: str
    donor_id: str
    target_tree_sha256: str
    donor_patch_sha256: str
    post_apply_tree_sha256: str
    candidate_prompt_sha256: str
    candidate_final_prompt_tokens: int
    tokenizer_sha256: str
    envelope_sha256: str
    post_apply_tree_dir: str | None = None
    apply_record: ApplyRecord | None = None

    def errors(self) -> list:
        errs = []
        for f in ("target_id", "donor_id"):
            if not getattr(self, f):
                errs.append(f"pair_candidate.{f} 缺失")
        for f in ("target_tree_sha256", "donor_patch_sha256", "post_apply_tree_sha256",
                  "candidate_prompt_sha256", "tokenizer_sha256", "envelope_sha256"):
            if not _is_hex64(getattr(self, f)):
                errs.append(f"pair_candidate.{f} 缺失或非法")
        if not _is_pos_int(self.candidate_final_prompt_tokens):
            errs.append("pair_candidate.candidate_final_prompt_tokens 必须为正整数")
        if not self.post_apply_tree_dir:
            errs.append("pair_candidate.post_apply_tree_dir 缺失（须能重算 post-apply 树）")
        if not isinstance(self.apply_record, ApplyRecord):
            errs.append("pair_candidate.apply_record 缺失（须绑定受控 runner 执行记录）")
        return errs


# ===========================================================================
# 步 3：shuffled 约束（硬约束 = **内容交叉绑定 + 实际 post-apply 树重算**）
# ===========================================================================
SHUFFLE_HARD_CONSTRAINTS = (
    ("donor_ne_target", "donor 不得等于目标样本"),
    ("apply_clean_target_relation",
     "donor patch 须在**目标树**上 apply-clean；apply 记录须与受控 runner 绑定，"
     "且 post-apply 树由**实际目录**重算后再比对"),
    ("final_prompt_token_window",
     "**目标基准臂 token** 与 **target×donor 候选 token** 之比须落在 "
     "frozen_runtime.token_bounds 内（由权威值重算，不可放宽）"),
)
SHUFFLE_SOFT_CONSTRAINTS = (
    ("same_language", "donor 与目标同语言"),
    ("same_cwe_family", "donor 与目标同 CWE 族"),
    ("same_file_count", "donor 触及文件数与目标相差 ≤1"),
    ("not_composite", "donor 不是复合提交"),
)
COVARIATE_FIELDS = ("language", "cwe_family", "base_final_prompt_tokens",
                    "candidate_final_prompt_tokens", "n_files", "is_composite")

PAIR_CANDIDATE_FIELDS = ("target_id", "donor_id", "target_tree_sha256",
                         "donor_patch_sha256", "post_apply_tree_sha256",
                         "candidate_prompt_sha256", "candidate_final_prompt_tokens",
                         "tokenizer_sha256", "envelope_sha256",
                         "post_apply_tree_dir")
APPLY_RECORD_FIELDS = ("runner_sha256", "command", "exit_code", "stdout_sha256",
                       "target_tree_sha256", "post_apply_tree_sha256")


def cross_check_pair_candidate(art: PairCandidateArtifact, target: dict, donor: dict,
                               baseline: TargetBaseline, donor_patch: DonorPatch,
                               runtime: FrozenRuntime, base_dir: Path) -> list:
    """对 target×donor 候选工件做**内容**交叉核对（含实际 post-apply 树重算）。"""
    errs = list(art.errors())
    if errs:
        return errs

    # —— 身份绑定 ——
    if art.target_id != target.get("sample_id"):
        errs.append("pair_candidate.target_id 与当前目标不符")
    if art.donor_id != donor.get("sample_id"):
        errs.append("pair_candidate.donor_id 与当前 donor 不符")
    if art.target_id != baseline.sample_id:
        errs.append("pair_candidate.target_id 与 target_baseline 不符")
    if art.donor_id != donor_patch.sample_id:
        errs.append("pair_candidate.donor_id 与 donor_patch 不符")

    # —— 树与补丁 ——
    if art.target_tree_sha256 != baseline.target_tree_sha256:
        errs.append("pair_candidate.target_tree_sha256 与权威目标树不符")
    if art.donor_patch_sha256 != donor_patch.real_patch_sha256:
        errs.append("pair_candidate.donor_patch_sha256 与权威 real patch 不符")
    if art.post_apply_tree_sha256 == art.target_tree_sha256:
        errs.append("post_apply_tree_sha256 与 target tree 相同 → 补丁未生效")

    # —— 运行时绑定 ——
    if art.tokenizer_sha256 != runtime.tokenizer_sha256:
        errs.append("pair_candidate.tokenizer_sha256 与 frozen_runtime 不符")
    if art.envelope_sha256 != runtime.envelope_sha256:
        errs.append("pair_candidate.envelope_sha256 与 frozen_runtime 不符")

    # —— 受控 apply runner 记录 ——
    rec = art.apply_record
    rerr = rec.errors()
    if rerr:
        errs += [f"apply_record: {e}" for e in rerr]
    else:
        if rec.runner_sha256 != runtime.apply_runner_sha256:
            errs.append("apply_record.runner_sha256 与 frozen_runtime 不符")
        if rec.target_tree_sha256 != art.target_tree_sha256:
            errs.append("apply_record.target_tree_sha256 与候选工件不符")
        if rec.post_apply_tree_sha256 != art.post_apply_tree_sha256:
            errs.append("apply_record.post_apply_tree_sha256 与候选工件不符")
    if errs:
        return errs

    # —— **从实际 post-apply 目录重算 tree SHA**（不采信自报值）——
    post_dir = Path(base_dir) / art.post_apply_tree_dir
    if not post_dir.is_dir():
        errs.append(f"post-apply 树不存在: {art.post_apply_tree_dir}")
    else:
        recomputed = normalized_tree_sha256(post_dir)
        if recomputed != art.post_apply_tree_sha256:
            errs.append(f"post-apply 树 SHA 与实际目录不符（重算 {recomputed[:12]}，"
                        f"记录 {art.post_apply_tree_sha256[:12]}）")
        if recomputed == art.target_tree_sha256:
            errs.append("实际 post-apply 树与 target tree 相同 → 补丁未生效")
    return errs


def cross_check_token_window(art: PairCandidateArtifact, baseline: TargetBaseline,
                             runtime: FrozenRuntime) -> list:
    """长度门禁：**目标基准臂 token** vs **target×donor 候选 token**（权威值重算）。"""
    errs = []
    if not _is_pos_int(art.candidate_final_prompt_tokens):
        errs.append("候选最终 prompt token 必须为正整数")
        return errs
    if not _is_pos_int(baseline.base_final_prompt_tokens):
        errs.append("目标基准臂最终 prompt token 必须为正整数")
        return errs
    lo, hi = runtime.token_bounds
    r = art.candidate_final_prompt_tokens / baseline.base_final_prompt_tokens
    if not (lo <= r <= hi):
        errs.append(f"候选/基准 final prompt token ratio={r:.4f} "
                    f"超出 {list(runtime.token_bounds)}")
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


def select_donor(target: dict, donors: list, *, target_baseline: TargetBaseline,
                 donor_patches: dict, pair_candidates: dict,
                 runtime: FrozenRuntime, base_dir: Path) -> dict:
    """硬约束（内容交叉绑定 + 实际 post-apply 树重算）先过滤；软约束按逆序放宽。

    权威输入缺失或非法即 fail-closed 返回 `NO_AUTHORITY`，不得退化为 schema 检查。
    """
    aerrs = []
    if not isinstance(target_baseline, TargetBaseline):
        aerrs.append("缺 target_baseline（权威基准臂 prompt 工件）")
    if not isinstance(runtime, FrozenRuntime):
        aerrs.append("缺 frozen_runtime（权威 tokenizer/envelope/runner）")
    if not isinstance(donor_patches, dict):
        aerrs.append("donor_patches 必须是 mapping")
        donor_patches = {}
    if not isinstance(pair_candidates, dict):
        aerrs.append("pair_candidates 必须是 mapping")
        pair_candidates = {}
    if aerrs:
        return {"status": "NO_AUTHORITY", "donor": None, "n_donors": len(donors or []),
                "reason": "权威工件缺失或非法: " + "; ".join(aerrs), "relaxations": []}
    aerrs = list(target_baseline.errors()) + list(runtime.errors())
    if target_baseline.sample_id != target.get("sample_id"):
        aerrs.append("target_baseline 与当前目标样本不匹配")
    if aerrs:
        return {"status": "NO_AUTHORITY", "donor": None, "n_donors": len(donors or []),
                "reason": "权威工件缺失或非法: " + "; ".join(aerrs[:4]),
                "relaxations": []}

    hard_ok, hard_reasons = [], []
    for d in donors or []:
        sid = d.get("sample_id")
        dp = donor_patches.get(sid)
        art = pair_candidates.get(sid)
        errs = []
        if d.get("sample_id") == target.get("sample_id"):
            errs.append("donor_ne_target")
        if dp is None:
            errs.append("缺 donor_patch（冻结 real patch）")
        else:
            errs += [f"donor_patch: {e}" for e in dp.errors()]
        if art is None:
            errs.append("缺 pair_candidate（target×donor 候选工件）")
        else:
            errs += [f"apply_clean_target_relation: {e}"
                     for e in cross_check_pair_candidate(art, target, d, target_baseline,
                                                         dp, runtime, base_dir)]
            errs += [f"final_prompt_token_window: {e}"
                     for e in cross_check_token_window(art, target_baseline, runtime)]
        if errs:
            hard_reasons.append({"sample_id": sid, "reasons": errs[:4]})
        else:
            hard_ok.append((d, art))
    if not hard_ok:
        return {"status": "NO_DONOR", "donor": None, "n_donors": len(donors or []),
                "reason": f"无候选通过硬约束（{len(hard_reasons)} 个被拒）",
                "hard_rejected": len(hard_reasons),
                "hard_reject_reasons": hard_reasons[:5], "relaxations": []}

    active = list(SHUFFLE_SOFT_CONSTRAINTS)
    relaxations = []
    for _step in range(len(active) + 1):
        pool = [(d, art) for d, art in hard_ok
                if all(_passes_soft(d, target, n) for n, _ in active)]
        if pool:
            pool.sort(key=lambda t: (abs(t[1].candidate_final_prompt_tokens
                                          - target_baseline.base_final_prompt_tokens),
                                     t[0].get("sample_id", "")))
            chosen, chosen_art = pool[0]
            return {"status": "OK", "donor": chosen, "n_donors": len(donors or []),
                    "n_pool_after_relax": len(pool), "relaxations": relaxations,
                    "active_constraints": [n for n, _ in active],
                    "covariates": {
                        "target": {k: target.get(k) for k in COVARIATE_FIELDS},
                        "donor": {k: chosen.get(k) for k in COVARIATE_FIELDS}},
                    "token_window": {
                        "base_final_prompt_tokens": target_baseline.base_final_prompt_tokens,
                        "candidate_final_prompt_tokens": chosen_art.candidate_final_prompt_tokens,
                        "ratio": round(chosen_art.candidate_final_prompt_tokens
                                       / target_baseline.base_final_prompt_tokens, 6),
                        "bounds": list(runtime.token_bounds)},
                    "binding": ("target×donor 候选工件：tree / patch / post-apply 树 / "
                                "候选 prompt / tokenizer / envelope 逐项与权威值比对，"
                                "post-apply 树由实际目录重算"),
                    "tie_break": "(|候选 token − 基准 token|, sample_id) 字典序最小者优先"}
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

VERDICT_MARKER = "VERDICT:"
VALID_ORACLE_RESULTS = ("fixed", "still_vulnerable")
ORACLE_ERROR = "ORACLE_ERROR"
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
        valid_exit_codes=(0, 1),
        infra_exit_codes=(2, 3, 4, 5),
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
        valid_exit_codes=(0,),
        infra_exit_codes=(2,),
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
        fault_injection=_COMMON_FAULT_INJECTION + ("checker 内容被替换 → 必须拒绝",),
        notes=("确定性语义断言（路径/权限/返回字段等领域检查）。checker 脚本须提供**文件路径**"
               "并重算内容 SHA，与冻结 arm 规格绑定，防止「改断言迁就结果」。"),
    ),
    "reviewer-residual-path": OracleContract(
        name="reviewer-residual-path", tier=ORACLE_TIER_T3, machine_decidable=False,
        command_template="(无可执行 oracle；书面残余利用路径)",
        tool_version="n/a",
        valid_exit_codes=(),
        infra_exit_codes=(),
        requires_marker=False,
        control_samples=("两份独立 reviewer submission 一致", "分歧须第三人仲裁并落盘"),
        fault_injection=("两名 reviewer 为同一人 → 必须拒绝",
                         "两名 reviewer 提交同一文件 → 必须拒绝",
                         "两人 verdict 分歧且缺仲裁工件 → 必须拒绝"),
        notes=("**不可机器判定**：由冻结的书面残余利用路径 + 两份**真实** review submission "
               "（路径须重算 SHA）+ 分歧时的仲裁工件共同承载。三者均须与目标样本、臂、"
               "冻结 template/manifest 绑定。T3 数量必须与 T1/T2 **分别报告**，不得混为同一证据等级。"),
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


def derive_t3_verdict(reviewer1_verdict: str, reviewer2_verdict: str,
                      adjudicated_verdict: str) -> str:
    """T3 结论派生（由两人的**独立 verdict** 与必要时的仲裁结论给出）。

    两人不一致且无仲裁结论 → `ORACLE_ERROR`（待仲裁），不得由单一 reviewer 定案。
    """
    if reviewer1_verdict not in VALID_ORACLE_RESULTS \
            or reviewer2_verdict not in VALID_ORACLE_RESULTS:
        return ORACLE_ERROR
    if reviewer1_verdict == reviewer2_verdict:
        return reviewer1_verdict
    if adjudicated_verdict in VALID_ORACLE_RESULTS:
        return adjudicated_verdict
    return ORACLE_ERROR


def parse_oracle_verdict(contract: str, raw_result: str, exit_code: int) -> str:
    """**冻结 parser**（T1/T2）：按 oracle 的独立契约派生 verdict。

    规则（`exit_code` **不再**映射为漏洞状态）：
      ① 契约须已登记，否则 `ValueError`；
      ② T3 不可机器判定 → `ValueError`（须走 `derive_t3_verdict` + 双人工件）；
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
        inspect.getsource(derive_t3_verdict),
        inspect.getsource(parse_oracle_verdict),
        json.dumps(contracts_registry(), sort_keys=True, ensure_ascii=False),
    ])
    return _sha_text(payload)


ORACLE_EVIDENCE_FIELDS = ("contract", "tier", "arm", "sample_id", "manifest_sha256",
                          "template_sha256", "poc_sha256", "target_tree_sha256",
                          "patch_sha256", "command", "exit_code", "raw_result",
                          "raw_result_sha256", "parsed_verdict", "oracle_parser_sha256")
ORACLE_EVIDENCE_OPTIONAL_FIELDS = (
    "poc_path", "target_tree_dir", "patch_path", "checker_path", "checker_sha256",
    "residual_path", "residual_path_sha256",
    "reviewer1_id", "reviewer2_id", "reviewer1_submission", "reviewer2_submission",
    "reviewer1_submission_sha256", "reviewer2_submission_sha256",
    "reviewer1_verdict", "reviewer2_verdict",
    "adjudication_path", "adjudication_sha256", "adjudicated_verdict",
)

# 任何层都必须齐备的字段（工件 SHA 由各层自行要求，见下）
EVIDENCE_ALWAYS_REQUIRED = ("contract", "tier", "arm", "sample_id", "manifest_sha256",
                            "template_sha256", "command", "exit_code", "raw_result",
                            "raw_result_sha256", "parsed_verdict", "oracle_parser_sha256")
EVIDENCE_ALWAYS_HEX = ("manifest_sha256", "template_sha256", "raw_result_sha256",
                       "oracle_parser_sha256")

# 各层**必须**提供的工件引用（路径）与其对应 SHA 字段
TIER_REQUIRED_ARTIFACTS = {
    ORACLE_TIER_T1: ("poc_path", "patch_path", "target_tree_dir"),
    ORACLE_TIER_T2: ("patch_path", "target_tree_dir", "checker_path"),
    ORACLE_TIER_T3: (),
}
TIER_REQUIRED_HEX = {
    ORACLE_TIER_T1: ("poc_sha256", "patch_sha256", "target_tree_sha256"),
    ORACLE_TIER_T2: ("patch_sha256", "target_tree_sha256", "checker_sha256"),
    ORACLE_TIER_T3: (),
}
# T3 专属：书面材料与双人提交工件（均须重算）
T3_REQUIRED_ARTIFACTS = ("residual_path", "reviewer1_submission", "reviewer2_submission")
T3_REQUIRED_HEX = ("residual_path_sha256", "reviewer1_submission_sha256",
                   "reviewer2_submission_sha256")

# arm 规格中应出现的字段：只含**臂专属**工件；目标树 SHA 是样本级属性，
# 由 `FrozenContext.samples[sample_id]["target_tree_sha256"]` 单独核对，不在此重复。
ARM_SPEC_HEX = {
    ORACLE_TIER_T1: ("poc_sha256", "patch_sha256"),
    ORACLE_TIER_T2: ("patch_sha256", "checker_sha256"),
    ORACLE_TIER_T3: ("residual_path_sha256",),
}


@dataclass
class FrozenContext:
    """验证期的**权威上下文**（来自冻结构造清单 / 冻结 template）；缺任一即 fail-closed。

    `samples[sample_id] = {"target_tree_sha256": str, "arms": {arm: {...}}}`
    """
    manifest_sha256: str
    template_sha256: str
    samples: dict
    runtime: FrozenRuntime

    def errors(self) -> list:
        errs = []
        if not _is_hex64(self.manifest_sha256):
            errs.append("frozen_context.manifest_sha256 缺失或非法")
        if not _is_hex64(self.template_sha256):
            errs.append("frozen_context.template_sha256 缺失或非法")
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
    template_sha256: str = ""
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
    checker_path: str | None = None
    checker_sha256: str = ""
    residual_path: str | None = None
    residual_path_sha256: str = ""
    reviewer1_id: str = ""
    reviewer2_id: str = ""
    reviewer1_submission: str | None = None
    reviewer2_submission: str | None = None
    reviewer1_submission_sha256: str = ""
    reviewer2_submission_sha256: str = ""
    reviewer1_verdict: str = ""
    reviewer2_verdict: str = ""
    adjudication_path: str | None = None
    adjudication_sha256: str = ""
    adjudicated_verdict: str = ""

    def as_dict(self) -> dict:
        d = {f: getattr(self, f) for f in ORACLE_EVIDENCE_FIELDS}
        d.update({f: getattr(self, f) for f in ORACLE_EVIDENCE_OPTIONAL_FIELDS})
        return d

    # ------------------------------------------------------------------
    def verify(self, base_dir: Path, ctx: FrozenContext) -> list:
        """**严格验证**：分层要求 + 重算工件 + 与冻结上下文逐项绑定。

        ① 上下文与通用字段齐备（缺任一即错，不跳过）；
        ② 分层强制工件引用（T1 poc+patch+tree；T2 patch+tree+checker；
           T3 书面材料 + 两份独立 reviewer submission）；
        ③ `raw_result_sha256` == 对 `raw_result` 重算（**T3 亦不例外**）；
        ④ `oracle_parser_sha256` == 当前冻结 parser 实现 SHA；
        ⑤ verdict == 冻结 parser 派生的结果（T3 用 `derive_t3_verdict`）；
        ⑥ **重算** PoC / patch / checker / target tree / post-apply 相关工件；
        ⑦ 与 `FrozenContext` 绑定：manifest、template、样本、arm、arm 规格；
        ⑧ T3：两份 submission 不得同人同文件、分歧须有仲裁工件。
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

        # ① 通用字段
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

        # ② 分层工件要求
        if c.machine_decidable:
            for f in TIER_REQUIRED_ARTIFACTS.get(c.tier, ()):
                if not getattr(self, f, None):
                    errs.append(f"{c.tier} 强制要求工件引用 {f}（不得省略）")
            for f in TIER_REQUIRED_HEX.get(c.tier, ()):
                if not _is_hex64(getattr(self, f)):
                    errs.append(f"{f} 非 64 位 hex（{c.tier} 必填）")
        else:
            for f in T3_REQUIRED_ARTIFACTS:
                if not getattr(self, f, None):
                    errs.append(f"T3 强制要求工件引用 {f}（不得省略）")
            for f in T3_REQUIRED_HEX:
                if not _is_hex64(getattr(self, f)):
                    errs.append(f"{f} 非 64 位 hex（T3 必填）")
            if not self.reviewer1_id or not self.reviewer2_id:
                errs.append("T3 须提供 reviewer1_id 与 reviewer2_id")
            elif self.reviewer1_id == self.reviewer2_id:
                errs.append("T3 的两名 reviewer 不得为同一人")
            if self.reviewer1_submission and self.reviewer2_submission \
                    and self.reviewer1_submission == self.reviewer2_submission:
                errs.append("T3 的两份 reviewer submission 不得为同一文件")
        if errs:
            return errs

        base = Path(base_dir)

        # ③④⑤ 原始输出与 parser（**T3 同样执行**）
        if self.raw_result_sha256 != _sha_text(self.raw_result):
            errs.append("raw_result_sha256 与原始输出重算不符")
        if self.oracle_parser_sha256 != oracle_parser_sha256():
            errs.append("oracle_parser_sha256 与当前冻结 parser 不符")
        if c.machine_decidable:
            try:
                derived = parse_oracle_verdict(self.contract, self.raw_result, self.exit_code)
            except ValueError as e:
                errs.append(f"parser 派生失败: {e}")
                derived = None
        else:
            derived = derive_t3_verdict(self.reviewer1_verdict, self.reviewer2_verdict,
                                        self.adjudicated_verdict)
            if self.reviewer1_verdict not in VALID_ORACLE_RESULTS \
                    or self.reviewer2_verdict not in VALID_ORACLE_RESULTS:
                errs.append("T3 两名 reviewer 的 verdict 须各为 fixed / still_vulnerable")
            if self.reviewer1_verdict != self.reviewer2_verdict:
                if not self.adjudication_path:
                    errs.append("T3 双人 verdict 分歧 → 必须提供仲裁工件")
                elif not _is_hex64(self.adjudication_sha256):
                    errs.append("T3 分歧须提供 adjudication_sha256")
                elif self.adjudicated_verdict not in VALID_ORACLE_RESULTS:
                    errs.append("T3 分歧须提供 adjudicated_verdict")
        if derived is not None and derived != self.parsed_verdict:
            errs.append(f"parsed_verdict({self.parsed_verdict}) 与派生结果({derived}) 不符")
        if derived is not None and derived != ORACLE_ERROR \
                and read_verdict_marker(self.raw_result) != derived:
            errs.append("结论须与原始输出中的标记行一致")

        # ⑥ 重算工件（不采信记录值）
        _rehash_file(base, self.poc_path, "PoC", errs, "poc_sha256", self.poc_sha256)
        _rehash_file(base, self.patch_path, "patch", errs, "patch_sha256", self.patch_sha256)
        _rehash_file(base, self.checker_path, "checker", errs,
                     "checker_sha256", self.checker_sha256)
        _rehash_file(base, self.residual_path, "残余路径书面材料", errs,
                     "residual_path_sha256", self.residual_path_sha256)
        _rehash_file(base, self.reviewer1_submission, "reviewer1 submission", errs,
                     "reviewer1_submission_sha256", self.reviewer1_submission_sha256)
        _rehash_file(base, self.reviewer2_submission, "reviewer2 submission", errs,
                     "reviewer2_submission_sha256", self.reviewer2_submission_sha256)
        if self.adjudication_path:
            _rehash_file(base, self.adjudication_path, "仲裁工件", errs,
                         "adjudication_sha256", self.adjudication_sha256)
        if self.target_tree_dir:
            tdir = base / self.target_tree_dir
            if not tdir.is_dir():
                errs.append(f"target 树不存在: {self.target_tree_dir}")
            else:
                recomputed = normalized_tree_sha256(tdir)
                if recomputed != self.target_tree_sha256:
                    errs.append(f"target 树 SHA 与记录不符（重算 {recomputed[:12]}，"
                                f"记录 {self.target_tree_sha256[:12]}）")

        # ⑦ 与冻结上下文逐项绑定
        if self.manifest_sha256 != ctx.manifest_sha256:
            errs.append("manifest_sha256 与冻结上下文不符")
        if self.template_sha256 != ctx.template_sha256:
            errs.append("template_sha256 与冻结上下文不符")
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
# 四臂：**构造门禁**（运行前）与**结果评估**（运行后）**彻底分离**
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
        "desc": ("行为中性改造：构造条件**仅**为 apply-clean 与结构/长度门禁；"
                 "oracle 不参与接纳。模型判定属运行后操纵检验，**不得**用于筛选样本")},
    "shuffled": {
        "expect_target_oracle": "still_vulnerable", "oracle_required": False,
        "desc": ("负向 shuffled control：构造条件**仅**为 apply-clean、target×donor 工件绑定"
                 "与长度门禁；oracle 不参与接纳。模型判定属运行后操纵检验")},
}

MODEL_VERDICTS = ("vulnerable", "benign")


def construction_gate(arm: str, *, apply_clean, evidence: OracleEvidence | None = None,
                      base_dir: Path | None = None,
                      ctx: FrozenContext | None = None) -> dict:
    """**运行前**构造门禁 —— 决定样本/臂是否纳入 active universe。

    ⚠ 本函数的签名中**不存在任何模型输出参数**：模型判定是**因变量**，
    绝不可反过来决定样本有效性，否则构成结果感知筛选（分母随结果变化）。

    `oracle_required=True` 的臂（annotated-security-complete / support-only-insufficient）：
      必须提供可验证 oracle 证据，且 verdict 等于该臂期望值。
    `oracle_required=False` 的臂（placebo / shuffled）：
      仅需 apply-clean 即纳入（模型判定与 oracle 均不作为纳入条件）；
      若额外提供了 oracle 证据，只做**构造一致性**检查：证据必须可验证，
      且不得显示目标漏洞被意外修复（那样该臂就不是中性的，属构造失败）。
    """
    if arm not in ARM_ORACLE:
        raise KeyError(f"未知臂: {arm}")
    spec = ARM_ORACLE[arm]
    out = {"arm": arm, "oracle_required": spec["oracle_required"],
           "gate_stage": "pre-run", "consumes_model_output": False,
           "expected_target_oracle": spec["expect_target_oracle"]}

    if apply_clean is not True:
        return {"eligible": False, "reason": "apply 不干净", **out}

    if spec["oracle_required"]:
        if evidence is None:
            return {"eligible": False, **out,
                    "reason": "该臂要求 oracle 证据（fail-closed）"}
        eerr = evidence.verify(base_dir, ctx)
        if eerr:
            return {"eligible": False, **out,
                    "reason": "oracle 证据验证失败: " + "; ".join(eerr[:3])}
        v = evidence.parsed_verdict
        if v not in VALID_ORACLE_RESULTS:
            return {"eligible": False, **out, "oracle_verdict": v,
                    "reason": f"oracle 不可判定（{v}）→ 不得计入接纳"}
        ok = v == spec["expect_target_oracle"]
        return {"eligible": ok, **out, "oracle_verdict": v,
                "reason": "符合预期" if ok else
                          f"预期目标漏洞 {spec['expect_target_oracle']}，实得 {v}",
                "oracle_evidence": evidence.as_dict()}

    # —— oracle 不要求：仅 apply-clean（+ 可选的构造一致性检查）——
    if evidence is None:
        return {"eligible": True, **out,
                "reason": "apply-clean（该臂不要求 oracle；模型判定属运行后评估）"}
    eerr = evidence.verify(base_dir, ctx)
    if eerr:
        return {"eligible": False, **out, "oracle_evidence_verified": False,
                "reason": "附加 oracle 证据验证失败: " + "; ".join(eerr[:3])}
    if evidence.parsed_verdict == "fixed":
        return {"eligible": False, **out, "oracle_evidence_verified": True,
                "oracle_verdict": "fixed",
                "reason": "附加 oracle 显示目标漏洞被意外修复 → 该臂非行为中性，构造失败"}
    return {"eligible": True, **out, "oracle_evidence_verified": True,
            "oracle_verdict": evidence.parsed_verdict,
            "oracle_evidence": evidence.as_dict(),
            "reason": "apply-clean 且附加 oracle 与中性预期一致"}


def outcome_evaluation(arm: str, *, model_verdict) -> dict:
    """**运行后**结果与操纵检验记录。

    `changes_inclusion` **恒为 False**：本函数的任何输出都不得改变 active universe、
    schedule 或统计分母。模型误判只作为**发现**报告（例如对 cosmetic 改造过度敏感）。
    """
    if arm not in ARM_ORACLE:
        raise KeyError(f"未知臂: {arm}")
    if model_verdict not in MODEL_VERDICTS:
        raise ValueError(f"model_verdict 必须属于 {MODEL_VERDICTS}，实得 {model_verdict!r}")
    return {"arm": arm, "stage": "post-run", "model_verdict": model_verdict,
            "is_vulnerable": model_verdict == "vulnerable",
            "manipulation_check": ("pass" if model_verdict == "vulnerable" else "observed-flip"),
            "changes_inclusion": False,
            "note": ("模型判定为因变量，仅作结果与操纵检验记录；"
                     "不得据此调整样本集或分母")}


# ===========================================================================
# 便捷构造
# ===========================================================================
def make_evidence(contract: str, arm: str, sample_id: str, raw_result: str, exit_code: int,
                  *, base_dir: Path, context: FrozenContext,
                  poc_path: str | None = None, patch_path: str | None = None,
                  target_tree_dir: str | None = None,
                  command: str = "", checker_path: str | None = None,
                  residual_path: str | None = None,
                  reviewer1_id: str = "", reviewer2_id: str = "",
                  reviewer1_submission: str | None = None,
                  reviewer2_submission: str | None = None,
                  reviewer1_verdict: str = "", reviewer2_verdict: str = "",
                  adjudication_path: str | None = None,
                  adjudicated_verdict: str = "") -> OracleEvidence:
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

    tree_sha = normalized_tree_sha256(base / target_tree_dir) if target_tree_dir else ""
    if c.machine_decidable:
        try:
            verdict = parse_oracle_verdict(contract, raw_result, exit_code)
        except ValueError:
            verdict = ORACLE_ERROR
    else:
        verdict = derive_t3_verdict(reviewer1_verdict, reviewer2_verdict,
                                    adjudicated_verdict)
    return OracleEvidence(
        contract=contract, tier=c.tier, arm=arm, sample_id=sample_id,
        manifest_sha256=context.manifest_sha256,
        template_sha256=context.template_sha256,
        poc_sha256=_fsha(poc_path), target_tree_sha256=tree_sha,
        patch_sha256=_fsha(patch_path), command=command, exit_code=exit_code,
        raw_result=raw_result, raw_result_sha256=_sha_text(raw_result),
        parsed_verdict=verdict, oracle_parser_sha256=oracle_parser_sha256(),
        poc_path=poc_path, patch_path=patch_path, target_tree_dir=target_tree_dir,
        checker_path=checker_path, checker_sha256=_fsha(checker_path),
        residual_path=residual_path, residual_path_sha256=_fsha(residual_path),
        reviewer1_id=reviewer1_id, reviewer2_id=reviewer2_id,
        reviewer1_submission=reviewer1_submission,
        reviewer2_submission=reviewer2_submission,
        reviewer1_submission_sha256=_fsha(reviewer1_submission),
        reviewer2_submission_sha256=_fsha(reviewer2_submission),
        reviewer1_verdict=reviewer1_verdict, reviewer2_verdict=reviewer2_verdict,
        adjudication_path=adjudication_path,
        adjudication_sha256=_fsha(adjudication_path),
        adjudicated_verdict=adjudicated_verdict)


def make_pair_candidate(target_id: str, donor_id: str, *, base_dir: Path,
                        post_apply_tree_dir: str, donor_patch_path: str,
                        candidate_prompt_sha256: str, candidate_final_prompt_tokens: int,
                        runtime: FrozenRuntime, apply_command: str = "",
                        apply_stdout: str = "", apply_stdout_path: str | None = None,
                        target_tree_dir: str | None = None) -> PairCandidateArtifact:
    """从**实际目录**构造 target×donor 候选工件（post-apply 树与 stdout 均重算）。"""
    base = Path(base_dir)
    post_sha = normalized_tree_sha256(base / post_apply_tree_dir)
    target_sha = normalized_tree_sha256(base / target_tree_dir) if target_tree_dir else ""
    if apply_stdout_path:
        mode, out_sha = file_content_sha256(base / apply_stdout_path)
    else:
        out_sha = _sha_text(apply_stdout)
    rec = ApplyRecord(runner_sha256=runtime.apply_runner_sha256, command=apply_command,
                      exit_code=0, stdout_sha256=out_sha,
                      target_tree_sha256=target_sha,
                      post_apply_tree_sha256=post_sha)
    return PairCandidateArtifact(
        target_id=target_id, donor_id=donor_id, target_tree_sha256=target_sha,
        donor_patch_sha256=file_content_sha256(base / donor_patch_path)[1],
        post_apply_tree_sha256=post_sha,
        candidate_prompt_sha256=candidate_prompt_sha256,
        candidate_final_prompt_tokens=candidate_final_prompt_tokens,
        tokenizer_sha256=runtime.tokenizer_sha256,
        envelope_sha256=runtime.envelope_sha256,
        post_apply_tree_dir=post_apply_tree_dir, apply_record=rec)


def arms_registry() -> dict:
    payload = json.dumps(ARM_ORACLE, sort_keys=True, ensure_ascii=False)
    return {
        "schema": ARMS_SCHEMA,
        "n_arms": len(ARM_ORACLE),
        "arms": {k: dict(v) for k, v in ARM_ORACLE.items()},
        "fingerprint": hashlib.sha256(payload.encode("utf-8")).hexdigest(),
        "arm_acceptance_source": "预注册 §3.3（V4-四臂算法预注册.md）",
        "inclusion_rule": ("active universe 只由 construction_gate（运行前）决定；"
                           "模型输出只进 outcome_evaluation，changes_inclusion 恒为 False"),
        "model_verdicts": list(MODEL_VERDICTS),
        "token_bounds": list(TOKEN_RATIO_BOUNDS),
        "hash_modes": {"text": HASH_MODE_TEXT, "bytes": HASH_MODE_BYTES},
        "tree_sha256": "LF 归一化递归 tree SHA（normalized_tree_sha256）",
        "shuffle": {
            "hard": [{"name": n, "doc": d} for n, d in SHUFFLE_HARD_CONSTRAINTS],
            "soft_in_relax_order": [{"name": n, "doc": d}
                                    for n, d in SHUFFLE_SOFT_CONSTRAINTS],
            "relax_policy": "软约束按逆序逐条放宽；硬约束（含内容交叉绑定与 token 门禁）不可放宽",
            "pair_candidate_fields": list(PAIR_CANDIDATE_FIELDS),
            "apply_record_fields": list(APPLY_RECORD_FIELDS),
            "covariates": list(COVARIATE_FIELDS),
            "binding": ("target×donor 候选工件：tree / patch / **实际 post-apply 树重算** / "
                        "候选 prompt / tokenizer / envelope / 受控 runner 记录"),
            "token_window_semantics": ("目标**基准臂**最终 prompt token vs "
                                       "**target×donor 候选**最终 prompt token"),
        },
        "oracle": contracts_registry(),
        "oracle_evidence_fields": list(ORACLE_EVIDENCE_FIELDS),
        "oracle_evidence_optional_fields": list(ORACLE_EVIDENCE_OPTIONAL_FIELDS),
        "evidence_always_required": list(EVIDENCE_ALWAYS_REQUIRED),
        "tier_required_artifacts": {k: list(v) for k, v in TIER_REQUIRED_ARTIFACTS.items()},
        "tier_required_hex": {k: list(v) for k, v in TIER_REQUIRED_HEX.items()},
        "t3_required_artifacts": list(T3_REQUIRED_ARTIFACTS),
        "t3_required_hex": list(T3_REQUIRED_HEX),
        "arm_spec_hex": {k: list(v) for k, v in ARM_SPEC_HEX.items()},
        "oracle_parser_sha256": oracle_parser_sha256(),
    }
