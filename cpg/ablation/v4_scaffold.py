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
              prompt_lookup: dict | None = None) -> dict:
    """生成运行计划（**SCAFFOLD_ONLY**）。

    `prompt_lookup[(arm, sample_id)]` 若缺失，则该条目状态为 `MISSING_PROMPT`
    ——刻意不生成占位 prompt，避免"看似可跑"的假象。
    """
    items, missing = [], 0
    for sid in sample_ids:
        for arm in arms:
            key = (arm, sid)
            has = bool(prompt_lookup and prompt_lookup.get(key))
            if not has:
                missing += 1
            items.append({"sample_id": sid, "arm": arm, "order": len(items),
                          "status": "READY" if has else "MISSING_PROMPT"})
    return {SCAFFOLD_TAG: SCAFFOLD_ONLY, "schema": "v4-run-plan/1",
            "model": model, "n_items": len(items), "n_ready": len(items) - missing,
            "n_missing_prompt": missing,
            "note": "计划仅供脚手架自测；正式 schedule 必须由冻结流程生成",
            "items": items}


def load_done_ids(results_path: Path) -> set:
    """resume：读取已完成 `(sample_id, arm)` 集合（容忍半行）。"""
    if not results_path.exists():
        return set()
    done = set()
    for ln in results_path.read_text(encoding="utf-8").splitlines():
        ln = ln.strip()
        if not ln:
            continue
        try:
            rec = json.loads(ln)
        except json.JSONDecodeError:
            continue        # 半行/损坏行直接跳过，不阻断 resume
        if rec.get("sample_id") and rec.get("arm"):
            done.add((rec["sample_id"], rec["arm"]))
    return done


def append_result(results_path: Path, rec: dict) -> None:
    """原子追加一条结果（先写临时文件再 append 落盘，避免半行）。"""
    results_path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(rec, ensure_ascii=False) + "\n"
    tmp = results_path.with_suffix(results_path.suffix + ".tmp")
    existing = results_path.read_bytes() if results_path.exists() else b""
    tmp.write_bytes(existing + line.encode("utf-8"))
    tmp.replace(results_path)


# ===========================================================================
# 4) 结果 verifier（verdict 必须绑定原始响应）
# ===========================================================================
RESULT_REQUIRED = ("sample_id", "arm", "model", "verdict", "raw_response_sha256",
                   "envelope_sha256")


def verify_result(rec: dict) -> list:
    """单条结果校验（fail-closed）。"""
    errs = []
    for k in RESULT_REQUIRED:
        if not rec.get(k):
            errs.append(f"缺字段 {k}")
    if rec.get("verdict") not in VALID_VERDICTS:
        errs.append(f"非法 verdict: {rec.get('verdict')}")
    for k in ("raw_response_sha256", "envelope_sha256"):
        v = rec.get(k)
        if v and not (isinstance(v, str) and len(v) == 64
                      and all(c in "0123456789abcdef" for c in v)):
            errs.append(f"{k} 非 64 位 hex")
    if rec.get("verdict") == "abstain" and not rec.get("abstain_reason"):
        errs.append("abstain 必须给出 abstain_reason")
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
# 5) RUN_LOCK **请求**模板（无签名、不含 reviewer 身份）
# ===========================================================================
def build_lock_request(arm_artifact_shas: dict, envelope_sha: str,
                       gate_a_pass: bool, run_plan_sha: str,
                       tokenizer_sha: str, model: str) -> dict:
    """生成"请 reviewer 签锁"的**请求**（不是签名结果）。

    fail-closed：`gate_a_pass` 为 False 时**不得**生成可签请求。
    """
    if not gate_a_pass:
        raise ValueError("Gate A 未通过，禁止生成 RUN_LOCK 请求")
    return {SCAFFOLD_TAG: SCAFFOLD_ONLY, "schema": "v4-run-lock-request/1",
            "model": model, "tokenizer_sha256": tokenizer_sha,
            "envelope_sha256": envelope_sha, "run_plan_sha256": run_plan_sha,
            "arm_artifact_sha256": dict(sorted(arm_artifact_shas.items())),
            "requested_by": "SCAFFOLD", "signatures": [],
            "note": "本文件仅为请求模板；签名必须由 reviewer 在正式流程中出具"}


# ===========================================================================
# 6) 统计（纯 Python；口径见预注册 §五）
# ===========================================================================
def _betainc_reg(a: float, b: float, x: float) -> float:
    """正则化不完全 Beta（连分数展开），用于 Clopper–Pearson。"""
    if x <= 0:
        return 0.0
    if x >= 1:
        return 1.0
    lbeta = math.lgamma(a) + math.lgamma(b) - math.lgamma(a + b)
    front = math.exp(math.log(x) * a + math.log(1 - x) * b - lbeta) / a
    # 连分数（Lentz）
    f, c, d = 1.0, 1.0, 0.0
    for i in range(0, 300):
        m = i // 2
        if i == 0:
            num = 1.0
        elif i % 2 == 0:
            num = (m * (b - m) * x) / ((a + 2 * m - 1) * (a + 2 * m))
        else:
            num = -((a + m) * (a + b + m) * x) / ((a + 2 * m) * (a + 2 * m + 1))
        d = 1.0 + num * d
        d = 1e-30 if abs(d) < 1e-30 else d
        c = 1.0 + num / c
        c = 1e-30 if abs(c) < 1e-30 else c
        d = 1.0 / d
        delta = c * d
        f *= delta
        if abs(1 - delta) < 1e-12:
            break
    return front * (f - 1)


def _beta_quantile(p: float, a: float, b: float) -> float:
    lo, hi = 0.0, 1.0
    for _ in range(200):
        mid = (lo + hi) / 2
        if _betainc_reg(a, b, mid) < p:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2


def clopper_pearson(k: int, n: int, alpha: float = 0.05) -> tuple:
    """exact 95% CI（Clopper–Pearson）。k=成功数, n=配对总数。"""
    if n <= 0:
        return (0.0, 1.0)
    lo = 0.0 if k == 0 else _beta_quantile(alpha / 2, k, n - k + 1)
    hi = 1.0 if k == n else _beta_quantile(1 - alpha / 2, k + 1, n - k)
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
