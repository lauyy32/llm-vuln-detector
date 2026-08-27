"""B-3：2×2 隔离消融聚合 + 互补性报告生成（论文可用）。

输入：seeds/{A,B,C}{1,2,3}/results.csv（A=有码+taint, B=有码无taint, C=无码+taint）
输出：B3-消融与互补性报告.md
"""
import csv
import json
import re
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def load_f1(p: Path, scorer: str, mode: str = "code", group: str | None = None) -> dict | None:
    """从 seed 的 summary.md 解析指标行（results.csv 为样本级记录，指标在 summary）。
    全局行：| scorer | mode | P | R | F1 | support | TP | FP | TN | FN |  （10 列）
    分组行：| group | scorer | mode | P | R | F1 | support |                      （7 列）
    """
    sm = p.parent / "summary.md"
    if not sm.exists():
        return None
    text = sm.read_text(encoding="utf-8")
    for line in text.splitlines():
        if "|" not in line:
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if group is not None:
            if len(cells) == 7 and cells[0] == group and cells[1] == scorer and cells[2] == mode:
                return {"p": float(cells[3]), "r": float(cells[4]), "f1": float(cells[5]),
                        "tp": 0, "fp": 0, "tn": 0, "fn": 0}
        else:
            if len(cells) == 10 and cells[0] == scorer and cells[1] == mode:
                return {"p": float(cells[2]), "r": float(cells[3]), "f1": float(cells[4]),
                        "tp": int(cells[6]), "fp": int(cells[7]), "tn": int(cells[8]), "fn": int(cells[9])}
    return None


def agg(seeds: list[Path], scorer: str, group: str | None = None) -> dict:
    vals = []
    for s in seeds:
        d = load_f1(s, scorer, group=group)
        if d:
            vals.append(d)
    if not vals:
        return {}
    f1s = [v["f1"] for v in vals]
    return {"f1_mean": statistics.mean(f1s), "f1_std": statistics.stdev(f1s) if len(f1s) > 1 else 0.0,
            "f1_all": f1s, "n": len(vals)}


SETS = {
    "A_有码+taint": [ROOT / "seeds" / f"A{i}" / "results.csv" for i in (1, 2, 3)],
    "B_有码无taint": [ROOT / "seeds" / f"B{i}" / "results.csv" for i in (1, 2, 3)],
    "C_无码+taint": [ROOT / "seeds" / f"C{i}" / "results.csv" for i in (1, 2, 3)],
}
SCORERS = ("LocalLLMScorer", "CPGEvidenceScorer", "StructuralHeuristicScorer", "CodeQLBaselineScorer", "ConfigSigScorer")

lines = ["# B-3 消融与互补性报告（2×2 隔离 + 多 seed）", "",
         "> 数据：dataset.jsonl 干净版 28 样本 × 3 seed（temperature=0；7B 存在跨运行抖动，故多 seed 取均值）",
         "> 设置：A=源码+CPG 污点 / B=源码（无污点）/ C=摘要+污点（无源码）；D=request 模式（无码无污点）恒 abstain",
         "", "## 1. LLM 2×2 隔离消融（code 模式，全局 F1）", "",
         "| 设置 | seed1 | seed2 | seed3 | 均值±std |", "| --- | --- | --- | --- | --- |"]

for name, seeds in SETS.items():
    a = agg(seeds, "LocalLLMScorer")
    if a:
        alls = " / ".join(f"{x:.3f}" for x in a["f1_all"])
        lines.append(f"| {name} | {alls} | {a['f1_mean']:.3f}±{a['f1_std']:.3f} |")

lines += ["", "**增益分解（LLM，code）**：", f"- CPG 增益 = A − B（有码条件下加污点）",
          f"- 源码增益 = B − D（无污点条件下加源码，D=request 恒 0）",
          f"- 联合增益 = A − D", "", "## 2. 各 scorer 均值（A 设置，code）", "",
          "| scorer | 全局 F1 | taint 子集 | logic 子集 |", "| --- | --- | --- | --- |"]
for sc in SCORERS:
    g = agg(SETS["A_有码+taint"], sc)
    gt = agg(SETS["A_有码+taint"], sc, group="taint")
    gl = agg(SETS["A_有码+taint"], sc, group="logic")
    if g:
        lines.append(f"| {sc} | {g['f1_mean']:.3f} | {gt.get('f1_mean', float('nan')):.3f} | {gl.get('f1_mean', float('nan')):.3f} |")

lines += ["", "## 3. 静态工具边界（absence-based CWE）", "",
          "CWE-862/863/639（鉴权缺失/IDOR）属「基于缺失」漏洞：源码中无「缺失点」可锚定，",
          "签名/查询法原理性无法证明「某处缺少某个检查」。ConfigSig 对其显式 abstain 是正确设计；",
          "该类漏洞只能由语义层（LLM 结合公告摘要核查功能点）覆盖。CodeQL 官方亦无通用缺失检查查询。",
          "", "## 4. 结论（待 seed 完成后填充）", ""]

out = ROOT / "B3-消融与互补性报告.md"
out.write_text("\n".join(lines), encoding="utf-8")
print(f"[ok] wrote {out}")
