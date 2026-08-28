"""B-2 素材筛选：从干净版 results.csv 找 CPGEvidence vs LocalLLM 的分歧样本。

分歧 = LLM 价值（或缺陷）的候选。按 code 模式逐样本对比。
"""
import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

rows = []
with open("cpg/ablation/results.csv", newline="", encoding="utf-8") as fh:
    for r in csv.DictReader(fh):
        if r["mode"] != "code":
            continue
        rows.append(r)

by_sample = {}
for r in rows:
    key = (r["sample_id"], r["version"])
    by_sample.setdefault(key, {})[r["scorer"]] = r["predicted"]

print(f"{'sample':<38} {'cwe':<8} {'truth':<10} {'CPG':<10} {'LLM':<10} 分歧")
print("-" * 90)
llm_right = llm_wrong = 0
for (sid, ver), sc in sorted(by_sample.items()):
    truth = next(r["truth"] for r in rows if (r["sample_id"], r["version"]) == (sid, ver))
    cwe = next(r["cwe_truth"] for r in rows if (r["sample_id"], r["version"]) == (sid, ver))
    cpg = sc.get("CPGEvidenceScorer", "-")
    llm = sc.get("LocalLLMScorer", "-")
    if cpg == llm:
        div = "—"
    else:
        if llm == truth:
            div = "✅ LLM对"
            llm_right += 1
        elif cpg == truth:
            div = "❌ LLM错"
            llm_wrong += 1
        else:
            div = "⚠️ 都错"
    print(f"{sid}_{ver:<9} {cwe:<8} {truth:<10} {cpg:<10} {llm:<10} {div}")

print(f"\n分歧统计：LLM 独对 {llm_right}，LLM 独错 {llm_wrong}")
