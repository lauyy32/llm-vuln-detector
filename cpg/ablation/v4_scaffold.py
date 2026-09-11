# -*- coding: utf-8 -*-
"""A-4 运行基础设施脚手架（**SCAFFOLD_ONLY —— 不得作为正式实验输入**）。

边界（外部验收写死）：
  ✅ 可以：tokenizer 封装 / Ollama envelope schema / 调度器 / resume /
          结果 verifier / RUN_LOCK **请求模板** / 统计代码 + 合成测试。
  🚫 不可以：把 `DRAFT_PREREG` 当权威设计；生成正式四臂 prompt/schedule；
           生成正式 RUN_LOCK；**调用模型**。

因此：
  - 所有 dict 产物带 `"SCAFFOLD_ONLY": True`；
  - `plan_runs()` 只产出**计划**，不写正式目录、不发起请求；
  - `build_lock_request()` 只产出**请求**（无签名、无 reviewer 身份）；
  - 本模块**从不**导入 `v4_prereg.json`。

统计实现为**纯 Python**（无 scipy 依赖），口径见 `V4-四臂算法预注册.md` §五。
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from pathlib import Path

SCAFFOLD_ONLY = True
SCAFFOLD_TAG = "SCAFFOLD_ONLY"

VALID_VERDICTS = {"vulnerable", "benign", "abstain", "RENDER_FAILURE"}


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


# ===========================================================================
# 1) Ollama envelope schema（请求形态冻结；不发送）
# ===========================================================================
ENVELOPE_SCHEMA = "v4-ollama-envelope/1"
ENVELOPE_REQUIRED = ("model", "prompt", "stream", "options")
ENVELOPE_OPTION_KEYS = ("num_ctx", "num_predict", "temperature", "seed")


def build_envelope(model: str, prompt: str, system: str | None = None,
                   num_ctx: int = 32768, num_predict: int = 1024,
                   temperature: float = 0.0, seed: int = 0) -> dict:
    """构造 `/api/generate` 请求体（**不发送**）。`stream=False` 固定。"""
    env = {
        "schema": ENVELOPE_SCHEMA,
        SCAFFOLD_TAG: SCAFFOLD_ONLY,
        "endpoint": "/api/generate",
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"num_ctx": num_ctx, "num_predict": num_predict,
                    "temperature": temperature, "seed": seed},
    }
    if system is not None:
        env["system"] = system
    return env


def validate_envelope(env: dict) -> list:
    """fail-closed 校验 envelope 结构（缺字段/越界/类型错均报错）。"""
    errs = []
    if not isinstance(env, dict):
        return ["envelope 非 dict"]
    for k in ENVELOPE_REQUIRED:
        if k not in env:
            errs.append(f"缺字段 {k}")
    if env.get("stream") is not False:
        errs.append("stream 必须为 False（确定性采集）")
    opts = env.get("options") or {}
    for k in ENVELOPE_OPTION_KEYS:
        if k not in opts:
            errs.append(f"options 缺 {k}")
    if opts.get("temperature") not in (0, 0.0):
        errs.append("temperature 必须为 0（可复现）")
    if not isinstance(opts.get("seed"), int):
        errs.append("seed 必须为 int")
    if not isinstance(env.get("prompt"), str) or not env["prompt"]:
        errs.append("prompt 必须为非空字符串")
    return errs


def envelope_sha256(env: dict) -> str:
    """envelope 的**内容指纹**（不含 SCAFFOLD 标记与 schema 元字段）。"""
    core = {k: v for k, v in env.items() if k not in (SCAFFOLD_TAG, "schema")}
    return _sha(json.dumps(core, sort_keys=True, ensure_ascii=False).encode("utf-8"))


# ===========================================================================
# 2) tokenizer 封装（真实 tokenizer + 身份指纹）
# ===========================================================================
def tokenizer_identity(tokenizer_path: Path) -> dict:
    if not tokenizer_path.exists():
        raise FileNotFoundError(f"tokenizer 不存在: {tokenizer_path}")
    return {"path": tokenizer_path.name, "bytes": tokenizer_path.stat().st_size,
            "sha256": _sha(tokenizer_path.read_bytes())}


def count_prompt_tokens(text: str, tokenizer_path: Path) -> int:
    """用真实 tokenizer 计数（**必须来自最终渲染的 prompt**）。"""
    from tokenizers import Tokenizer
    tok = Tokenizer.from_file(str(tokenizer_path))
    return len(tok.encode(text).ids)


def context_fit(prompt_tokens: int, num_ctx: int = 32768,
                num_predict: int = 1024) -> dict:
    """context-fit 判定：`prompt_tokens + num_predict <= num_ctx`。"""
    total = prompt_tokens + num_predict
    return {"prompt_tokens": prompt_tokens, "num_predict": num_predict,
            "num_ctx": num_ctx, "total": total,
            "fits": total <= num_ctx}


# ===========================================================================
# 3) 调度器（只产**计划**，不写正式目录、不发送）
# ===========================================================================
def plan_runs(arms: list, sample_ids: list, model: str,
              prompt_lookup: dict | None = None,
              shuffle_seed: int | None = None,
              repeats: int = 1) -> dict:
    """生成运行计划（**SCAFFOLD_ONLY**）。

    **P0-4b 修复**：顺序必须**冻结**，否则会产生顺序效应。
    - 先按 `(sample_id, arm, repeat)` 生成确定性顺序；
    - 若给出 `shuffle_seed`，用该 seed **确定性打乱**并记录 seed（可复算）；
    - `repeats > 1` 时同一 `(sid, arm)` 有多条，各带 `repeat` 序号。

    `prompt_lookup[(arm, sample_id)]` 缺失时该条目状态为 `MISSING_PROMPT`
    ——刻意不生成占位 prompt，避免"看似可跑"的假象。
    """
    import random as _random
    items, missing = [], 0
    base = []
    for sid in sample_ids:
        for arm in arms:
            for rep in range(repeats):
                base.append((sid, arm, rep))
    if shuffle_seed is not None:
        _random.Random(shuffle_seed).shuffle(base)
    for sid, arm, rep in base:
        has = bool(prompt_lookup and prompt_lookup.get((arm, sid)))
        if not has:
            missing += 1
        items.append({"sample_id": sid, "arm": arm, "repeat": rep,
                      "order": len(items),
                      "status": "READY" if has else "MISSING_PROMPT"})
    return {SCAFFOLD_TAG: SCAFFOLD_ONLY, "schema": "v4-run-plan/2",
            "model": model, "shuffle_seed": shuffle_seed, "repeats": repeats,
            "n_items": len(items), "n_ready": len(items) - missing,
            "n_missing_prompt": missing,
            "note": ("计划仅供脚手架自测；正式 schedule 必须由冻结流程生成"
                     + ("（顺序已用 recorded seed 确定性打乱）" if shuffle_seed is not None
                        else "（**未打乱**：存在顺序效应风险，正式运行前必须给出 shuffle_seed）")),
            "items": items}


def load_done_ids(results_path: Path) -> dict:
    """resume：读取已完成 `(sample_id, arm)` 集合。

    **P1-1 修复**：只容忍**文件末尾**的未完成半行（强杀进程的常见残留）；
    **中间**的损坏行属于数据损坏，必须显式报错（否则损坏结果会滞留并导致重复调用）。

    返回 `{"done": set, "truncated_tail": bool}`。
    """
    if not results_path.exists():
        return {"done": set(), "truncated_tail": False}
    text = results_path.read_text(encoding="utf-8")
    lines = text.split("\n")
    # 末尾若为空串（正常换行结尾）则去除；否则视为未完成半行
    truncated_tail = False
    if lines and lines[-1] == "":
        lines = lines[:-1]
    else:
        truncated_tail = True
        lines = lines[:-1]
        if lines and not lines[-1].strip():
            lines = lines[:-1]
    done, errs = set(), []
    for i, ln in enumerate(lines, 1):
        if not ln.strip():
            continue
        try:
            rec = json.loads(ln)
        except json.JSONDecodeError as e:
            errs.append(f"line {i}: {e.msg}（中间损坏行，拒绝静默跳过）")
            continue
        if rec.get("sample_id") and rec.get("arm"):
            done.add((rec["sample_id"], rec["arm"]))
    if errs:
        raise ValueError("结果文件存在损坏行: " + "; ".join(errs[:3]))
    return {"done": done, "truncated_tail": truncated_tail}


def append_result(results_path: Path, rec: dict) -> None:
    """原子追加一条结果（先写临时文件再 append 落盘，避免半行）。"""
    results_path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(rec, ensure_ascii=False) + "\n"
    tmp = results_path.with_suffix(results_path.suffix + ".tmp")
    existing = results_path.read_bytes() if results_path.exists() else b""
    tmp.write_bytes(existing + line.encode("utf-8"))
    tmp.replace(results_path)


LOCK_REQUEST_SCHEMA = "v4-run-lock-request/2"

# 与既有运行目录（rq1-r-canonical-v4/）**对齐**的锁字段结构：
#   { state, locked_at, git_commit, files: {name: {base, path, sha256}} }
# 其中 `files` 必须覆盖**全部承重输入**（P0-4）。
LOCK_REQUIRED_FILES = (
    "canonical_manifest",        # 语料清单
    "annotation_registry",       # frozen critical-hunk 注册表
    "gate_a_report",             # Gate A 报告
    "prompt_manifest",           # 逐 prompt SHA 清单
    "run_schedule",              # 冻结的调度（含 shuffle seed / repeat）
    "renderer_impl",             # prompt renderer 实现 SHA
    "selector_impl",             # selector 实现 SHA
    "tokenizer",                 # 真实 tokenizer
    "model_envelope_protocol",   # 模型身份 + 请求参数（含 model digest / ollama 版本）
)
LOCK_REQUEST_REQUIRED = ("schema", "state", "git_commit", "files",
                         "universe", "schedule_seed", "signatures")


def validate_lock_request(req: dict) -> list:
    """**正式字段集**校验（fail-closed，与既有锁件对齐）。"""
    errs = []
    if not isinstance(req, dict):
        return ["lock request 非 dict"]
    for k in LOCK_REQUEST_REQUIRED:
        if k not in req:
            errs.append(f"缺字段 {k}")
    if req.get("schema") != LOCK_REQUEST_SCHEMA:
        errs.append(f"schema 不符: {req.get('schema')}")
    if req.get("state") not in ("INPUTS_LOCKED",):
        errs.append(f"state 必须为 INPUTS_LOCKED: {req.get('state')}")
    gc = req.get("git_commit")
    if not (isinstance(gc, str) and len(gc) == 40
            and all(c in "0123456789abcdef" for c in gc)):
        errs.append("git_commit 必须为 40 位 hex")
    files = req.get("files")
    if not isinstance(files, dict) or not files:
        errs.append("files 必须为非空映射")
    else:
        missing = [n for n in LOCK_REQUIRED_FILES if n not in files]
        if missing:
            errs.append(f"files 缺承重输入: {missing}")
        for name, spec in files.items():
            if not isinstance(spec, dict):
                errs.append(f"files.{name} 非对象")
                continue
            if spec.get("base") not in ("repo", "run"):
                errs.append(f"files.{name}.base 非法: {spec.get('base')}")
            v = spec.get("sha256")
            if not (isinstance(v, str) and len(v) == 64
                    and all(c in "0123456789abcdef" for c in v)):
                errs.append(f"files.{name}.sha256 非 64 位 hex")
    uni = req.get("universe")
    if not isinstance(uni, list) or not uni:
        errs.append("universe 必须为非空样本列表")
    seed = req.get("schedule_seed")
    if not isinstance(seed, int):
        errs.append("schedule_seed 必须为 int（顺序效应防线）")
    if req.get("signatures") != []:
        errs.append("请求模板的 signatures 必须为空（签名由 reviewer 另出）")
    for forbidden in ("reviewer_id", "signature", "signed_at", "approver"):
        if forbidden in req:
            errs.append(f"请求模板不得含签名者字段 {forbidden}")
    return errs


def build_lock_request(files: dict, universe: list, git_commit: str,
                       schedule_seed: int, gate_a_pass: bool,
                       locked_at: str | None = None) -> dict:
    """生成 RUN_LOCK **请求**（不是签名结果）。

    **P0-4 修复**：字段结构与既有运行目录的 `lock_request.json` 对齐，
    且 `files` 必须覆盖 `LOCK_REQUIRED_FILES` 全部承重输入（缺一即 fail-closed）。
    `gate_a_pass=False` 时**不得**生成可签请求。
    """
    if not gate_a_pass:
        raise ValueError("Gate A 未通过，禁止生成 RUN_LOCK 请求")
    req = {SCAFFOLD_TAG: SCAFFOLD_ONLY, "schema": LOCK_REQUEST_SCHEMA,
           "state": "INPUTS_LOCKED",
           "locked_at": locked_at or "",
           "git_commit": git_commit,
           "files": dict(sorted(files.items())),
           "universe": sorted(universe),
           "schedule_seed": schedule_seed,
           "requested_by": "SCAFFOLD", "signatures": [],
           "note": ("本文件仅为请求模板；签名必须由 reviewer 在正式流程中出具。"
                    "字段结构与既有运行目录 lock_request.json 对齐。")}
    errs = validate_lock_request(req)
    if errs:
        raise ValueError("lock request 字段冻结校验失败: " + "; ".join(errs))
    return req


# ===========================================================================
# 3b) 调度计划持久化（含内容 SHA，供 resume 对账）
# ===========================================================================
def write_plan(path: Path, plan: dict) -> dict:
    """把计划落盘并返回其指纹（原子写：临时文件后 replace）。"""
    body = json.dumps(plan, ensure_ascii=False, indent=2) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(body.encode("utf-8"))
    tmp.replace(path)
    return {"path": path.name, "bytes": len(body.encode("utf-8")),
            "sha256": _sha(body.encode("utf-8"))}


def load_plan(path: Path, expect_sha: str | None = None) -> dict:
    """读取计划；给出 `expect_sha` 时校验指纹（fail-closed）。"""
    if not path.exists():
        raise FileNotFoundError(f"计划不存在: {path}")
    raw = path.read_bytes()
    got = _sha(raw)
    if expect_sha is not None and got != expect_sha:
        raise ValueError(f"计划指纹不符（{got[:12]} != {expect_sha[:12]}）")
    doc = json.loads(raw.decode("utf-8"))
    doc["_sha256"] = got
    return doc


# ===========================================================================
# 4) 结果 verifier（verdict 必须绑定原始响应）
# ===========================================================================
RESULT_REQUIRED = ("sample_id", "arm", "model", "verdict", "raw_response_text",
                   "raw_response_sha256", "envelope_sha256")

# verdict 解析规则（与既有 RQ1-R 口径一致：只在显式出现时判定，否则 abstain）
_VERDICT_PATTERNS = (
    ("vulnerable", re.compile(r"\bvulnerable\b", re.I)),
    ("benign", re.compile(r"\bbenign\b|\bnot\s+vulnerable\b", re.I)),
)


def parse_verdict(raw_response_text: str) -> str:
    """从**原始响应**解析 verdict（禁止只看派生字段）。

    规则：显式 `vulnerable` 优先；显式 `benign`/`not vulnerable` 次之；两者皆无 → `abstain`。
    出现歧义（同时含两者）时返回 `abstain` 并标注，交由人工复核。
    """
    t = raw_response_text or ""
    hit_v = bool(_VERDICT_PATTERNS[0][1].search(t))
    hit_b = bool(_VERDICT_PATTERNS[1][1].search(t))
    if hit_v and hit_b:
        return "abstain"          # 歧义 → 不擅自判定
    if hit_v:
        return "vulnerable"
    if hit_b:
        return "benign"
    return "abstain"


def verify_result(rec: dict) -> list:
    """单条结果校验（**真 fail-closed**，P0-3 修复）。

    必须同时满足：
      - 必填字段齐全（含 `raw_response_text`）；
      - `raw_response_sha256` == 对 `raw_response_text` **重算**的 SHA（拒绝伪造/占位摘要）；
      - `verdict` == 从原始响应**重新解析**的 verdict（拒绝手写 verdict）；
      - 两个 SHA 均为 64 位 hex；abstain 须给出理由。
    """
    errs = []
    for k in RESULT_REQUIRED:
        if not rec.get(k):
            errs.append(f"缺字段 {k}")
    raw = rec.get("raw_response_text")
    if raw:
        recomputed = _sha(raw.encode("utf-8"))
        if rec.get("raw_response_sha256") != recomputed:
            errs.append("raw_response_sha256 与原始响应重算值不符（伪造或占位摘要）")
        derived = parse_verdict(raw)
        if rec.get("verdict") != derived:
            errs.append(f"verdict 与从原始响应解析的结果不符（记录 {rec.get('verdict')} vs 解析 {derived}）")
    if rec.get("verdict") not in VALID_VERDICTS:
        errs.append(f"非法 verdict: {rec.get('verdict')}")
    for k in ("raw_response_sha256", "envelope_sha256"):
        v = rec.get(k)
        if v and not (isinstance(v, str) and len(v) == 64
                      and all(c in "0123456789abcdef" for c in v)):
            errs.append(f"{k} 非 64 位 hex")
    if rec.get("verdict") == "abstain" and not rec.get("abstain_reason"):
        errs.append("abstain 必须给出 abstain_reason")
    # 运行时身份：若记录则必须自洽（不强制存在，但存在即校验）
    for k in ("model_digest", "ollama_version", "prompt_sha256", "system_sha256"):
        v = rec.get(k)
        if v and k.endswith("sha256") and not (isinstance(v, str) and len(v) == 64):
            errs.append(f"{k} 非 64 位 hex")
    return errs


def verify_results_file(results_path: Path, expected_pairs: set | None = None) -> dict:
    """整份结果文件校验：逐条 + 覆盖率 + 重复。"""
    errs, seen, dup, n = [], set(), [], 0
    if not results_path.exists():
        return {"ok": False, "errors": ["结果文件不存在"], "n": 0}
    for i, ln in enumerate(results_path.read_text(encoding="utf-8").splitlines(), 1):
        if not ln.strip():
            continue
        try:
            rec = json.loads(ln)
        except json.JSONDecodeError as e:
            errs.append(f"line {i}: JSON 解析失败 {e.msg}")
            continue
        n += 1
        for e in verify_result(rec):
            errs.append(f"line {i}: {e}")
        key = (rec.get("sample_id"), rec.get("arm"))
        if key in seen:
            dup.append(key)
        seen.add(key)
    if dup:
        errs.append(f"重复条目 {len(dup)} 条")
    missing = sorted((expected_pairs or set()) - seen)
    if missing:
        errs.append(f"缺 {len(missing)} 条期望结果（示例 {missing[:3]}）")
    extra = sorted(seen - (expected_pairs or seen))
    if extra:
        errs.append(f"多 {len(extra)} 条非期望结果")
    return {"ok": not errs, "errors": errs[:20], "n": n}


# ===========================================================================
# 5) （RUN_LOCK 请求模板已上移至 3b 之前，见 `build_lock_request`）
# ===========================================================================


# ===========================================================================
# 6) 统计（纯 Python；口径见预注册 §五）
# ===========================================================================
def _binom_cdf_le(x: int, n: int, p: float) -> float:
    """P(X <= x)（二项）—— 与 strict_recompute.py 的 ble 同口径。"""
    return sum(math.comb(n, k) * p ** k * (1 - p) ** (n - k) for k in range(0, x + 1))


def _binom_sf_ge(x: int, n: int, p: float) -> float:
    """P(X >= x)（二项）—— 与 strict_recompute.py 的 bge 同口径。"""
    return sum(math.comb(n, k) * p ** k * (1 - p) ** (n - k) for k in range(x, n + 1))


def clopper_pearson(k: int, n: int, alpha: float = 0.05) -> tuple:
    """exact Clopper–Pearson CI（**全项目唯一实现**）。

    直接对**二项尾概率**做二分（与 `strict_recompute.py` 同口径），
    避免 Beta 连分数在 `a≫b` 时不收敛（该缺陷曾实际发生）。
    注意两个尾概率的单调性相反，故二分方向不同。
    """
    if n <= 0:
        return (0.0, 1.0)
    if k == 0:
        lo = 0.0
    else:
        # 下界：P(X >= k) 关于 p **递增**
        a, b = 0.0, 1.0
        for _ in range(200):
            mid = (a + b) / 2
            if _binom_sf_ge(k, n, mid) > alpha / 2:
                b = mid
            else:
                a = mid
        lo = (a + b) / 2
    if k == n:
        hi = 1.0
    else:
        # 上界：P(X <= k) 关于 p **递减**
        a, b = 0.0, 1.0
        for _ in range(200):
            mid = (a + b) / 2
            if _binom_cdf_le(k, n, mid) > alpha / 2:
                a = mid
            else:
                b = mid
        hi = (a + b) / 2
    return (round(lo, 6), round(hi, 6))


def mcnemar_exact(b: int, c: int) -> dict:
    """McNemar 精确检验（双侧）。b/c 为两个方向的 discordant 对数。"""
    n = b + c
    if n == 0:
        return {"b": b, "c": c, "n_discordant": 0, "p_two_sided": 1.0}
    k = min(b, c)
    tail = sum(math.comb(n, i) for i in range(0, k + 1)) / (2 ** n)
    return {"b": b, "c": c, "n_discordant": n,
            "p_two_sided": round(min(1.0, 2 * tail), 6)}


def pairwise_sufficiency_discrimination(real: dict, partial: dict) -> dict:
    """**主 estimand**：同一 CVE 上 real 判 benign **且** partial 判 vulnerable 才算正确区分。

    同时给出三分解（real-acceptance / partial-rejection / abstain）与 exact CI。
    """
    ids = sorted(set(real) & set(partial))
    ok = 0
    real_accept = partial_reject = abstain = 0
    for sid in ids:
        r, p = real[sid], partial[sid]
        if r == "abstain" or p == "abstain":
            abstain += 1
            continue
        if r == "benign":
            real_accept += 1
        if p == "vulnerable":
            partial_reject += 1
        if r == "benign" and p == "vulnerable":
            ok += 1
    n = len(ids)
    lo, hi = clopper_pearson(ok, n)
    return {SCAFFOLD_TAG: SCAFFOLD_ONLY,
            "n_pairs": n, "n_discriminated": ok,
            "rate": round(ok / n, 6) if n else None,
            "ci95_exact": [lo, hi],
            "real_acceptance": real_accept, "partial_rejection": partial_reject,
            "abstain": abstain,
            "trivial_baseline_note": ("F1=0.667 为 arm-level 平衡二分类的平凡基线，"
                                      "与主 estimand（配对判别率）**不可直接比较**"),
            "power_note": "m=8 时 p1=0.90 功效约 0.43；达 0.80 需 m=12 discordant pairs"}


def arm_level_metrics(y_true: list, y_pred: list) -> dict:
    """arm-level 二分类指标（**次级**），含平凡基线对照。"""
    n = len(y_true)
    if n == 0:
        return {"n": 0}
    tp = sum(1 for a, b in zip(y_true, y_pred) if a == 1 and b == 1)
    tn = sum(1 for a, b in zip(y_true, y_pred) if a == 0 and b == 0)
    fp = sum(1 for a, b in zip(y_true, y_pred) if a == 0 and b == 1)
    fn = sum(1 for a, b in zip(y_true, y_pred) if a == 1 and b == 0)
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    ba = 0.5 * (rec + (tn / (tn + fp) if (tn + fp) else 0.0))
    mcc_den = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = ((tp * tn - fp * fn) / mcc_den) if mcc_den else 0.0
    return {"n": n, "tp": tp, "tn": tn, "fp": fp, "fn": fn,
            "f1": round(f1, 6), "ba": round(ba, 6), "mcc": round(mcc, 6),
            "trivial_all_vulnerable_f1": 0.667,
            "must_report_with_baseline": "报 F1 必须并列 BA/MCC 与 0.667 基线"}
