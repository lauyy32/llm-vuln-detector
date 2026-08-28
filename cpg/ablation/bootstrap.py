"""Bootstrap 置信区间：按 CVE 配对重采样（vuln/fixed 成组），计算各 scorer F1 的 95% CI。

LLM 判定对每个样本固定（temperature=0），bootstrap 是对固定判定做重采样统计，
无需重调模型。回答：LLM 0.471 vs CPGEvidence 0.452 的差异是否在 CI 内显著。
"""
import csv
import random
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

N_BOOT = 2000
SEED = 42

SCORERS = ["LocalLLMScorer", "CPGEvidenceScorer", "StructuralHeuristicScorer",
           "CodeQLBaselineScorer", "ConfigSigScorer"]


def f1_from_counts(tp, fp, fn):
    if tp == 0:
        return 0.0
    p = tp / (tp + fp) if (tp + fp) else 0.0
    r = tp / (tp + fn) if (tp + fn) else 0.0
    return 2 * p * r / (p + r) if (p + r) else 0.0


def main():
    # 按 CVE 聚合逐样本判定（code 模式，每版本一条 item——以 LocalLLM 行为准建骨架）
    by_cve = defaultdict(list)
    with (ROOT / "cpg/ablation/results.csv").open(newline="", encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            if r["mode"] != "code" or r["scorer"] != "LocalLLMScorer":
                continue
            by_cve[r["sample_id"]].append({
                "version": r["version"], "truth": r["truth"],
                "pred": {s: None for s in SCORERS},
            })
    # 重新读一遍填 pred
    by_cve2 = defaultdict(list)
    with (ROOT / "cpg/ablation/results.csv").open(newline="", encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            if r["mode"] != "code" or r["scorer"] not in SCORERS:
                continue
            by_cve2[r["sample_id"]].append(r)
    for cve, rows in by_cve2.items():
        for r in rows:
            for item in by_cve[cve]:
                if item["version"] == r["version"]:
                    item["pred"][r["scorer"]] = r["predicted"]

    cves = sorted(by_cve.keys())
    print(f"CVE 数: {len(cves)}（版本数: {sum(len(v) for v in by_cve.values())}）")

    rng = random.Random(SEED)
    boot = {s: [] for s in SCORERS}
    for _ in range(N_BOOT):
        sample_cves = [rng.choice(cves) for _ in range(len(cves))]
        for s in SCORERS:
            tp = fp = fn = 0
            for cve in sample_cves:
                for item in by_cve[cve]:
                    pred = item["pred"][s]
                    truth = item["truth"]
                    if pred == "vulnerable":
                        if truth == "vulnerable":
                            tp += 1
                        else:
                            fp += 1
                    elif pred == "benign" and truth == "vulnerable":
                        fn += 1
            boot[s].append(f1_from_counts(tp, fp, fn))

    print("\n=== Bootstrap 95% CI（2000 次，按 CVE 配对重采样）===")
    print(f"{'scorer':<28} {'F1(原)':<8} {'mean':<8} {'95% CI'}")
    results = {}
    for s in SCORERS:
        vals = sorted(boot[s])
        lo = vals[int(N_BOOT * 0.025)]
        hi = vals[int(N_BOOT * 0.975)]
        mean = sum(vals) / N_BOOT
        results[s] = (lo, hi)
        print(f"{s:<28} {vals[N_BOOT//2]:<8.3f} {mean:<8.3f} [{lo:.3f}, {hi:.3f}]")

    # 差异检验：LLM vs CPGEvidence 的差值分布
    diff = [a - b for a, b in zip(boot["LocalLLMScorer"], boot["CPGEvidenceScorer"])]
    diff.sort()
    dlo, dhi = diff[int(N_BOOT * 0.025)], diff[int(N_BOOT * 0.975)]
    p_llm_gt = sum(1 for d in diff if d > 0) / N_BOOT
    print(f"\nLLM − CPGEvidence 差值: [{dlo:.3f}, {dhi:.3f}]（含 0 则差异不显著）")
    print(f"LLM F1 高于 CPGEvidence 的 bootstrap 比例: {p_llm_gt:.1%}")
    print(f"结论: {'LLM 显著高于 CPGEvidence（CI 不含 0）' if dlo > 0 else '差异未达显著（CI 含 0，需更多样本）'}")

    # 输出报告
    md = ["# Bootstrap 置信区间（P0-2）", "",
          f"> 36 版本 × {N_BOOT} 次按 CVE 配对重采样（seed={SEED}）", "",
          "| scorer | F1(原) | mean | 95% CI |", "| --- | --- | --- | --- |"]
    for s in SCORERS:
        md.append(f"| {s} | {results[s][0]:.3f}~ | — | [{results[s][0]:.3f}, {results[s][1]:.3f}] |")
    md += ["", f"**LLM − CPGEvidence 差值 CI: [{dlo:.3f}, {dhi:.3f}]；"
               f"LLM 高于 CPG 的比例 {p_llm_gt:.1%}**"]
    (ROOT / "cpg/ablation/bootstrap_report.md").write_text("\n".join(md), encoding="utf-8")
    print(f"[ok] wrote bootstrap_report.md")


if __name__ == "__main__":
    main()
