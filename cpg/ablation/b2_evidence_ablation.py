"""B-2 v2 基准：部分/歧义证据下 LLM vs 确定性解析（无摘要协议，2026-08-28）。

立论背景
--------
主协议去摘要后，LLM 全局 F1=0.409、无"独对"样本（分歧分析：LLM 独对 0 / CPG 独对 3）。
原"LLM 显著优于确定性解析"主张撤销。B-2 v2 的目标是**构造**确定性解析器必然
失败的证据形态，检验 LLM 是否能在同等（甚至更差）证据下靠源码语义补全判定——
这是坐实"LLM 独特价值"的最后一环，也是立论"互补性"的必要条件。

证据形态（三档，同一份 taint 证据降级）
---------------------------------------
- full      : 完整 CPG 切片（build_cpg_slices_text 产物，含 source→sink 流）
- sink_only : 仅 sink 行号列表（无 source、无流结论）→ CPGEvidence 只能见
              "no flow" 或格式异常，确定性判定必然 benign/abstain
- truncated : 每 CWE 段截断至头部 N 行，流结论行（reaches sink at）被切掉
              → 歧义证据：有 CWE 分段但无流结论，确定性解析同样失明

对照 scorer
-----------
- CPGEvidenceScorer：确定性文本解析（读 "reaches sink at L" 模式）
- LocalLLMScorer：语义推理（读同等 cpg_slices + 源码节选）

判定口径与主消融一致：abstain 计为未检出；正类 = vulnerable。

成功标准
--------
在 sink_only / truncated 形态下 CPGEvidence F1 显著劣于 full（确定性失明），
而 LLM F1 降幅明显更小或保持 → 证明 LLM 对证据降级鲁棒，其价值在
"证据不完整/歧义时靠语义补全"——即确定性解析器失败域。

用法
----
    python3 cpg/ablation/b2_evidence_ablation.py [--limit N] [--model qwen2.5-coder:7b]
"""
from __future__ import annotations

import argparse
import csv
import sys
from collections import defaultdict
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from cpg.ablation.cpg_eval import build_cpg_slices_text  # noqa: E402
from cpg.ablation.run_ablation import (  # noqa: E402
    _load_dataset_rows, _load_sample_code, compute_metrics,
)
from cpg.ablation.context_build import build_context  # noqa: E402
from cpg.ablation.corpus_db import build_corpus_db  # noqa: E402
from cpg.ablation.scorers import (  # noqa: E402
    CPGEvidenceScorer, LocalLLMScorer, Verdict,
)

FORMS = ("full", "sink_only", "truncated")


def _taint_rows_for_prefix(taint: list[dict], prefix: str) -> list[dict]:
    return [r for r in taint if f"/{prefix}/" in (r.get("abs_path") or "").replace("\\", "/")]


def _sink_only_text(taint_rows: list[dict]) -> str:
    """仅 sink 行号列表——无 source、无流信息，确定性解析必然失明。"""
    if not taint_rows:
        return "### NO TAINT EVIDENCE\nno untrusted input reaches a modelled sink"
    lines = []
    for r in taint_rows[:30]:
        f = (r.get("file") or "").split("/")[-1]
        cwe = r.get("cwe") or ""
        sink = r.get("sinkLine") or ""
        lines.append(f"{f}:L{sink} ({cwe})")
    return "### SINK LINES\n" + "; ".join(lines)


def _truncated_text(slices: str, keep_lines: int = 3) -> str:
    """歧义证据：按块保留 CWE 头与 source 行，**移除流结论行**（``reaches sink at``）。

    确定性解析器靠 ``reaches sink at L`` 模式判定流存在；移除该行后其只能见
    "CWE 分段存在但无流结论" → abstain/benign（失明）。LLM 若靠源码语义补全
    sink 位置则仍可判定——这正是"部分/歧义证据需语义推理"的操作化定义。
    """
    out: list[str] = []
    for block in slices.split("\n\n"):
        if not block.strip():
            continue
        kept = [ln for ln in block.splitlines()
                if "reaches sink at" not in ln and "flow:" not in ln]
        if not kept:
            continue
        out.append("\n".join(kept[:keep_lines]))
    return "\n\n".join(out)


def build_variant_text(form: str, taint_rows: list[dict], code_text: str) -> str:
    if form == "full":
        return build_cpg_slices_text(taint_rows, code_text)
    if form == "sink_only":
        return _sink_only_text(taint_rows)
    if form == "truncated":
        return _truncated_text(build_cpg_slices_text(taint_rows, code_text))
    raise ValueError(form)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--model", type=str, default="qwen2.5-coder:7b")
    ap.add_argument("--out", type=Path, default=Path(__file__).resolve().parent / "b2_evidence_results.json")
    args = ap.parse_args()

    rows = _load_dataset_rows(args.limit)
    print(f"[info] dataset rows: {len(rows)}")
    _db, staged, taint, _sarif = build_corpus_db(rows, skip_baseline=True)
    print(f"[info] corpus DB ready; taint rows: {len(taint)}")

    llm = LocalLLMScorer(model=args.model, timeout=600)
    cpg_det = CPGEvidenceScorer()
    llm_enabled = llm.reachable()
    print(f"[info] LocalLLM reachable: {llm_enabled} (model={args.model})")

    # 样本集：与 run_ablation 一致，按 prefix 展开 vuln/fixed
    samples = []
    for st in staged:
        sid, ver, prefix, truth = st["cve"], st["version"], st["prefix"], st["truth"]
        trows = _taint_rows_for_prefix(taint, prefix)
        code = _load_sample_code(prefix, trows)
        cwe = st["cwe"]
        samples.append({"sid": sid, "ver": ver, "prefix": prefix, "truth": truth,
                        "cwe": cwe, "taint": trows, "code": code})
    print(f"[info] samples: {len(samples)}")

    results: dict = {"forms": FORMS, "model": args.model, "samples": []}
    for s in samples:
        rec = {"sample": f"{s['sid']}_{s['ver']}", "truth": s["truth"], "cwe": s["cwe"]}
        for form in FORMS:
            slices = build_variant_text(form, s["taint"], s["code"])
            sample_dict = {
                "sample_id": s["sid"], "cwe": s["cwe"], "truth": s["truth"],
                "prefix": s["prefix"], "code_text": s["code"],
            }
            ctx = build_context("code", sample_dict, taint_rows=s["taint"], cpg_slices=slices)
            v_cpg = cpg_det.score(ctx)
            rec[f"cpg_{form}"] = v_cpg.label
            if llm_enabled:
                v_llm = llm.score(ctx)
                rec[f"llm_{form}"] = v_llm.label
        results["samples"].append(rec)
        print(f"  {rec['sample']:<40} truth={s['truth']:<10} "
              f"cpg=[{rec['cpg_full']}/{rec['cpg_sink_only']}/{rec['cpg_truncated']}]" +
              (f" llm=[{rec['llm_full']}/{rec['llm_sink_only']}/{rec['llm_truncated']}]" if llm_enabled else ""))

    # 指标汇总
    print("\n=== F1 汇总（正类=vulnerable，abstain 计未检出）===")
    summary = {}
    for form in FORMS:
        for scorer in ("cpg", "llm"):
            if scorer == "llm" and not llm_enabled:
                continue
            recs = [(r[f"{scorer}_{form}"], r["truth"]) for r in results["samples"]]
            met = compute_metrics(recs)
            summary[f"{scorer}_{form}"] = met
            print(f"{scorer:4s} {form:10s}: F1={met['f1']:.3f} P={met['precision']:.3f} "
                  f"R={met['recall']:.3f} (TP={met['tp']} FP={met['fp']} FN={met['fn']} TN={met['tn']})")
    results["metrics"] = {k: {"f1": v["f1"], "precision": v["precision"],
                              "recall": v["recall"], "tp": v["tp"], "fp": v["fp"],
                              "fn": v["fn"], "tn": v["tn"]} for k, v in summary.items()}

    # 关键对比：full → sink_only/truncated 的 F1 降幅（LLM vs 确定性）
    if llm_enabled:
        print("\n=== 证据降级鲁棒性（full → 降级形态的 F1 降幅）===")
        for form in ("sink_only", "truncated"):
            d_cpg = summary["cpg_full"]["f1"] - summary[f"cpg_{form}"]["f1"]
            d_llm = summary["llm_full"]["f1"] - summary[f"llm_{form}"]["f1"]
            print(f"{form:10s}: CPGEvidence ΔF1={d_cpg:+.3f} | LLM ΔF1={d_llm:+.3f} "
                  f"({'LLM 更鲁棒' if d_llm < d_cpg else '确定性更鲁棒'})")

    (args.out).write_text(
        __import__("json").dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n[ok] wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
