"""① 上下文形式消融：CPG 污点切片 vs 简单 sink 行号列表。

问题：CPG 增益是否来自「CPG 技术本身」，还是任何「指向可疑行的提示」都行？
对照：
- A: 源码 + CPG 切片文本（build_cpg_slices_text 产物，含 source→sink 流）
- A': 源码 + sink 行号列表（仅从 taint.csv 提取 sink 行与文件名——grep 级别信息）
只跑 code 模式（足够对比），7B。
"""
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from cpg.ablation.run_ablation import _load_dataset_rows, _load_sample_code
from cpg.ablation.cpg_eval import build_cpg_slices_text
from cpg.ablation.context_build import build_context
from cpg.ablation.scorers import LocalLLMScorer


def sink_line_list(rows: list[dict]) -> str:
    """从 taint 行提取 (file, sinkLine, cwe) 的简单列表——不含 source/流信息。"""
    if not rows:
        return "no sink lines found"
    lines = []
    for r in rows[:30]:
        f = (r.get("file") or "").split("/")[-1]
        lines.append(f"{f}:L{r.get('sinkLine')} ({r.get('cwe')})")
    return "; ".join(lines)


def main():
    dataset = _load_dataset_rows(None)
    summaries = {r["cve_id"]: (r.get("summary") or "") for r in dataset}
    llm = LocalLLMScorer(timeout=600)

    results = {"A_cpg_slices": [], "A2_sink_lines": []}
    for row in dataset:
        sid = row["cve_id"]
        for version, truth in (("vuln", "vulnerable"), ("fixed", "benign")):
            prefix = f"{sid}_{version}"
            trows = []
            for f in ("cpg/ablation/.work/taint.csv", "cpg/ablation/.work/tarslip.csv"):
                if Path(f).exists():
                    with open(f, newline="", encoding="utf-8") as fh:
                        for r in csv.DictReader(fh):
                            if f"/{prefix}/" in (r.get("abs_path") or ""):
                                trows.append(r)
            code = _load_sample_code(prefix, trows)
            sample = {"sample_id": sid, "cwes": ["CWE-022"], "cwe": "CWE-022", "truth": truth,
                      "prefix": prefix, "summary": summaries.get(sid, ""), "code_text": code}

            # A: CPG 切片文本
            slices = build_cpg_slices_text(trows, code)
            ctx = build_context("code", sample, taint_rows=trows, cpg_slices=slices)
            v = llm.score(ctx)
            results["A_cpg_slices"].append((prefix, v.label, truth))

            # A': sink 行号列表（替换切片，不含流信息）
            sink_txt = sink_line_list(trows)
            ctx2 = build_context("code", sample, taint_rows=[], cpg_slices=f"### SINK LINES\n{sink_txt}")
            v2 = llm.score(ctx2)
            results["A2_sink_lines"].append((prefix, v2.label, truth))

    # 指标
    for name, recs in results.items():
        tp = sum(1 for _, p, t in recs if p == "vulnerable" and t == "vulnerable")
        fp = sum(1 for _, p, t in recs if p == "vulnerable" and t == "benign")
        fn = sum(1 for _, p, t in recs if p != "vulnerable" and t == "vulnerable")
        tn = sum(1 for _, p, t in recs if p != "vulnerable" and t == "benign")
        p = tp / (tp + fp) if tp + fp else 0
        r = tp / (tp + fn) if tp + fn else 0
        f1 = 2 * p * r / (p + r) if p + r else 0
        print(f"{name}: TP={tp} FP={fp} FN={fn} TN={tn} P={p:.3f} R={r:.3f} F1={f1:.3f}")

    # 差异样本
    print("\n=== A vs A' 判定差异 ===")
    for (p1, v1, t1), (p2, v2, t2) in zip(results["A_cpg_slices"], results["A2_sink_lines"]):
        if v1 != v2:
            print(f"  {p1}: CPG切片={v1} sink列表={v2} (truth={t1})")


if __name__ == "__main__":
    main()
