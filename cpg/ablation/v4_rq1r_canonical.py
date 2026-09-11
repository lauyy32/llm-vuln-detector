# -*- coding: utf-8 -*-
"""A-5 正式：**canonical RQ1-R 报告**（消费并验证 v4 运行目录的锁链）。

与 `v4_rq1r.py`（历史补充分析）**严格分离**：
  - 本模块只消费 `rq1-r-canonical-v4/` 的运行时工件：
    `protocol.json` / `lock_request.json` / `review_approval.json` /
    `summary.json` / `state.json` / `results.jsonl` / `run_schedule.json`；
  - **先验证锁链**（VERIFIED + APPROVED + SHA 对账 + files 重算），再产出数字；
  - 报告中的主结果必须与 `summary.json` **逐项对账**，否则 fail-closed；
  - 发布副本匿名化（复用 scaffold 的 PII 规则）。

主口径（与既有 strict 一致）：判别 = vuln 显式 `vulnerable` **且** fixed 显式 `benign`；
`abstain` 不计任何一侧。
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUN_DIR = ROOT / "cpg" / "ablation" / ".work" / "rq1-r-canonical-v4"
OUT = ROOT / "cpg" / "ablation" / "artifacts" / "v4"

SCHEMA = "v4-rq1r-canonical-report/1"
SCHEMA_PUBLIC = "v4-rq1r-canonical-report-public/1"


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _sha_lf(b: bytes) -> str:
    """**行尾归一化**后的 SHA。

    锁件是在 Linux 侧生成的（LF）；Windows 检出会把文本文件变成 CRLF，
    直接比对会误判"锁链损坏"。故所有锁件比对统一按 LF 归一化，
    并在报告中标注 `normalized_lf=True`。
    """
    return hashlib.sha256(b.replace(b"\r\n", b"\n")).hexdigest()


def _fp(p: Path) -> dict:
    b = p.read_bytes()
    return {"name": p.name, "bytes": len(b), "lines": b.count(b"\n"), "sha256": _sha(b)}


def _rel(p) -> str:
    """安全相对路径：不在 ROOT 下（如测试用临时目录）时回退绝对路径。"""
    p = Path(p)
    try:
        return p.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return p.resolve().as_posix()


def _read_json(p: Path):
    if not p.exists():
        raise FileNotFoundError(f"缺工件: {p}")
    return json.loads(p.read_text(encoding="utf-8"))


def _read_jsonl(p: Path) -> list:
    if not p.exists():
        raise FileNotFoundError(f"缺工件: {p}")
    return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]


# ---------------------------------------------------------------------------
# 1) 锁链验证
# ---------------------------------------------------------------------------
def verify_lock_chain(run_dir: Path | None = None) -> dict:
    """验证运行目录的锁链完整性（fail-closed）。

    要求：`state=VERIFIED`、`review_approval.decision=APPROVED`、
    两份 `lock_request_sha256` 一致、`reviewed_git_commit == lock.git_commit == protocol.git_commit`、
    且 `lock_request.files` 中每个 `base=run` 的文件**重算 SHA 必须与登记值一致**。
    """
    d = run_dir or RUN_DIR
    proto = _read_json(d / "protocol.json")
    lock = _read_json(d / "lock_request.json")
    review = _read_json(d / "review_approval.json")
    state = _read_json(d / "state.json")
    errs = []

    if lock.get("state") != "INPUTS_LOCKED":
        errs.append(f"lock_request.state != INPUTS_LOCKED: {lock.get('state')}")
    if review.get("decision") != "APPROVED":
        errs.append(f"review_approval.decision != APPROVED: {review.get('decision')}")
    if state.get("state") != "VERIFIED":
        errs.append(f"state.state != VERIFIED: {state.get('state')}")

    lr_sha = _sha_lf((d / "lock_request.json").read_bytes())
    for label, v in (("review", review.get("lock_request_sha256")),
                     ("state", state.get("lock_request_sha256"))):
        if v != lr_sha:
            errs.append(f"{label}.lock_request_sha256 与 lock_request.json 实际 SHA 不符")

    commits = {lock.get("git_commit"), review.get("reviewed_git_commit"),
               proto.get("git_commit")}
    if len(commits) != 1 or None in commits:
        errs.append(f"三处 git_commit 不一致: {sorted(str(c) for c in commits)}")

    # files 重算（**LF 归一化**；base=run 在运行目录内，base=repo 在仓库内）
    file_checks = []
    for name, spec in (lock.get("files") or {}).items():
        base = spec.get("base")
        rel = spec.get("path", "")
        p = (d / rel) if base == "run" else (ROOT / rel)
        if not p.exists():
            errs.append(f"files.{name} 不存在: {base}:{rel}")
            continue
        raw = p.read_bytes()
        got_lf = _sha_lf(raw)
        ok = got_lf == spec.get("sha256")
        if not ok:
            errs.append(f"files.{name} SHA 不符（登记 {str(spec.get('sha256'))[:12]} "
                        f"vs 归一实算 {got_lf[:12]}）")
        file_checks.append({"name": name, "base": base, "ok": ok,
                            "sha256": spec.get("sha256"),
                            "normalized_lf": True,
                            "crlf_present": b"\r\n" in raw})

    if errs:
        raise ValueError("锁链验证失败（fail-closed）: " + "; ".join(errs[:5]))
    return {
        "ok": True, "run_dir": _rel(d),
        "git_commit": lock.get("git_commit"), "locked_at": lock.get("locked_at"),
        "reviewer": review.get("reviewer"), "approved_at": review.get("approved_at"),
        "lock_request_sha256": lr_sha, "file_checks": file_checks,
        "n_prompts": state.get("n_prompts"), "n_results": state.get("n_results"),
    }


# ---------------------------------------------------------------------------
# 2) 主结果（与 summary.json 对账）
# ---------------------------------------------------------------------------
VERDICT_ORDER = ("vulnerable", "benign", "abstain")


def build_pairs(results: list) -> dict:
    """按 (sample_id) 组对：{sid: {vuln: verdict, fixed: verdict}}。"""
    by = {}
    for r in results:
        sid, side = r.get("sample_id"), r.get("side")
        if not sid or side not in ("vuln", "fixed"):
            continue
        by.setdefault(sid, {})[side] = r.get("verdict")
    return by


def contingency_3x3(pairs: dict) -> dict:
    """3×3 配对列联表：行=vuln verdict，列=fixed verdict。"""
    tbl = {a: {b: 0 for b in VERDICT_ORDER} for a in VERDICT_ORDER}
    for _sid, v in pairs.items():
        a, b = v.get("vuln"), v.get("fixed")
        if a in tbl and b in tbl[a]:
            tbl[a][b] += 1
    return tbl


def classify_pairs(pairs: dict) -> dict:
    """主结果 + same-verdict + abstain-assisted 分解。"""
    n = strict = same = abstain_assisted = 0
    strict_ids = []
    for sid, v in pairs.items():
        a, b = v.get("vuln"), v.get("fixed")
        if a is None or b is None:
            continue
        n += 1
        if "abstain" in (a, b):
            abstain_assisted += 1
        if a == b:
            same += 1
        if a == "vulnerable" and b == "benign":
            strict += 1
            strict_ids.append(sid)
    return {"n_pairs": n, "strict_success": strict, "strict_ids": sorted(strict_ids),
            "rate": round(strict / n, 6) if n else None,
            "same_verdict": same,
            "same_verdict_rate": round(same / n, 6) if n else None,
            "abstain_assisted": abstain_assisted,
            "abstain_assisted_rate": round(abstain_assisted / n, 6) if n else None}


def reconcile_with_summary(main: dict, summary: dict) -> list:
    """主结果必须与 `summary.json` 逐项一致（fail-closed）。"""
    errs = []
    for k in ("n_pairs", "strict_success"):
        if k in summary and main.get(k) != summary[k]:
            errs.append(f"{k}: 报告 {main.get(k)} != summary {summary[k]}")
    if "rate" in summary:
        # summary 的 rate 精度可能较低（4 位），用 1e-3 容差
        if abs((main.get("rate") or 0) - summary["rate"]) > 1e-3:
            errs.append(f"rate: 报告 {main.get('rate')} != summary {summary['rate']}")
    return errs


# ---------------------------------------------------------------------------
# 3) CPG 行分层（数据可得性优先，缺失即显式声明而非编造）
# ---------------------------------------------------------------------------
def cpg_stratification(results: list, pairs: dict) -> dict:
    """按 results 中**实际可得**的 CPG 维度分层。

    当前 results 只提供 `canonical_cpg_rows_sha256` / `cpg_eval_sha256` / `cpg_cache_key`
    三类指纹，**没有 CPG 行数**。因此本函数只做**指纹存在性/一致性**分层，
    并显式声明"行数分层不可得"。
    """
    have_rows_sha = sum(1 for r in results if r.get("canonical_cpg_rows_sha256"))
    have_eval_sha = sum(1 for r in results if r.get("cpg_eval_sha256"))
    uniq_rows = len({r.get("canonical_cpg_rows_sha256") for r in results
                     if r.get("canonical_cpg_rows_sha256")})
    return {
        "available_dimensions": ["canonical_cpg_rows_sha256", "cpg_eval_sha256", "cpg_cache_key"],
        "n_with_rows_sha": have_rows_sha, "n_with_eval_sha": have_eval_sha,
        "n_unique_rows_sha": uniq_rows,
        "line_count_stratification": "NOT_AVAILABLE_IN_RESULTS",
        "note": ("results.jsonl 未记录 CPG 行数，仅记录指纹 → **行数分层不可得**；"
                 "如需按 CPG 覆盖分层，必须在运行协议中新增该字段后重跑，"
                 "**不得**用其它字段替代推断。"),
    }


# ---------------------------------------------------------------------------
# 4) 报告
# ---------------------------------------------------------------------------
def build_report(publish: bool = False) -> dict:
    run_dir = RUN_DIR
    chain = verify_lock_chain(run_dir)
    proto = _read_json(run_dir / "protocol.json")
    summary = _read_json(run_dir / "summary.json")
    results = _read_jsonl(run_dir / "results.jsonl")
    schedule = _read_json(run_dir / "run_schedule.json")

    pairs = build_pairs(results)
    main = classify_pairs(pairs)
    errs = reconcile_with_summary(main, summary)
    if errs:
        raise ValueError("主结果与 summary.json 对账失败（fail-closed）: " + "; ".join(errs))

    # 调度完整性：schedule 条数 == results 条数
    if len(schedule) != len(results):
        raise ValueError(f"schedule({len(schedule)}) 与 results({len(results)}) 条数不符")
    sched_keys = {(s.get("sample_id"), s.get("side"), s.get("arm")) for s in schedule}
    res_keys = {(r.get("sample_id"), r.get("side"), r.get("arm")) for r in results}
    if sched_keys != res_keys:
        raise ValueError("schedule 与 results 的 (sample_id, side, arm) 集合不符")

    from cpg.ablation.v4_scaffold import clopper_pearson
    lo, hi = clopper_pearson(main["strict_success"], main["n_pairs"])

    doc = {
        "schema": SCHEMA,
        "artifact_kind": "canonical_rq1r_main_result",
        "protocol": {
            "strict_rule": "判别 = vuln 显式 vulnerable 且 fixed 显式 benign；abstain 不计任何一侧",
            "model": proto.get("model"), "model_digest": proto.get("model_digest"),
            "representation": proto.get("representation"),
            "representation_sha256": proto.get("representation_sha256"),
            "temperature": proto.get("temperature"), "top_p": proto.get("top_p"),
            "seed": proto.get("seed"), "num_ctx": proto.get("num_ctx"),
            "num_predict": proto.get("num_predict"),
            "ollama_version": proto.get("ollama_version"),
            "prompt_renderer_sha256": proto.get("prompt_renderer_sha256"),
            "system_sha256": proto.get("system_sha256"),
            "canonical_cpg_rows_sha256": proto.get("canonical_cpg_rows_sha256"),
            "cpg_eval_sha256": proto.get("cpg_eval_sha256"),
            "query_set_sha256": proto.get("query_set_sha256"),
            "staged_manifest_sha256": proto.get("staged_manifest_sha256"),
            "git_commit": proto.get("git_commit"),
        },
        "lock_chain": chain,
        "sources": {n: _fp(run_dir / n) for n in
                    ("protocol.json", "lock_request.json", "review_approval.json",
                     "summary.json", "state.json", "results.jsonl", "run_schedule.json")},
        "main_result": main,
        "exact_ci95": [lo, hi],
        "contingency_vuln_x_fixed": contingency_3x3(pairs),
        "summary_reconciled": True,
        "summary_source": summary,
        "cpg_stratification": cpg_stratification(results, pairs),
        "n_results": len(results), "n_schedule": len(schedule),
        "note": ("这是 RQ1-R 的**canonical 正式主结果**（消费并验证 v4 运行锁链）。"
                 "历史口径的工具族补充分析见 rq1r_historical_supplement.json，两者"
                 "**样本口径不同（1/82 vs 2/82），不得混用或互相替代**。"),
    }
    if publish:
        from cpg.ablation.v4_rq1r import anonymize, anonymize_check
        pub = anonymize(doc)
        pub["schema"] = SCHEMA_PUBLIC
        pub["artifact_kind"] = "canonical_rq1r_main_result"
        pub["anonymized"] = True
        aerr = anonymize_check(pub)
        if aerr:
            raise ValueError("匿名化失败（fail-closed）: " + "; ".join(aerr))
        return pub
    return doc


def write_reports() -> dict:
    internal = build_report(publish=False)
    public = build_report(publish=True)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "rq1r_canonical_report.json").write_bytes(
        (json.dumps(internal, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
    (OUT / "rq1r_canonical_report_public.json").write_bytes(
        (json.dumps(public, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
    return {"internal": internal, "public": public}
