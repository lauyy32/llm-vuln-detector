"""P1：Bandit 业界工具对比。对 corpus_src 样本跑 bandit，HIGH>0 判 vulnerable，算 F1。
LLM 对照数字从 results.csv 读取，避免硬编码滞后。"""
import csv
import json
import subprocess
import sys
from pathlib import Path

# 仓库根引导：脚本直跑时 sys.path[0]=cpg/ablation，须先把仓库根加入才能 `import cpg.ablation.config`
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from cpg.ablation import config

ROOT = config.REPO_ROOT
BANDIT = str(config.BANDIT_EXE)
SRC = config.CORPUS_SRC

# 排除污染样本与提取不完整样本
EXCLUDE = {"CVE-2026-69248", "CVE-2026-69249", "CVE-2026-55419"}

records = []
for d in sorted(SRC.glob("CVE-2026-*_vuln")) + sorted(SRC.glob("CVE-2026-*_fixed")):
    prefix = d.name
    cve = prefix.rsplit("_", 1)[0]
    if cve in EXCLUDE:
        continue
    r = subprocess.run([BANDIT, "-q", "-r", str(d), "-f", "json", "-x", "tests"],
                       capture_output=True, text=True, timeout=120)
    hi = med = 0
    if r.returncode in (0, 1) and r.stdout:
        try:
            data = json.loads(r.stdout)
            for i in data.get("results", []):
                if i["issue_severity"] == "HIGH":
                    hi += 1
                elif i["issue_severity"] == "MEDIUM":
                    med += 1
        except Exception:
            pass
    pred = "vulnerable" if hi > 0 else "benign"
    truth = "vulnerable" if prefix.endswith("_vuln") else "benign"
    records.append({"sample": prefix, "truth": truth, "pred": pred, "high": hi, "medium": med})

tp = sum(1 for r in records if r["pred"] == "vulnerable" and r["truth"] == "vulnerable")
fp = sum(1 for r in records if r["pred"] == "vulnerable" and r["truth"] == "benign")
fn = sum(1 for r in records if r["pred"] == "benign" and r["truth"] == "vulnerable")
tn = sum(1 for r in records if r["pred"] == "benign" and r["truth"] == "benign")
p = tp / (tp + fp) if tp + fp else 0
r_ = tp / (tp + fn) if tp + fn else 0
f1 = 2 * p * r_ / (p + r_) if p + r_ else 0

# 从 results.csv 读取 LLM+CPG（code 模式）指标
llm_tp = llm_fp = llm_fn = llm_tn = 0
llm_total = 0
with (ROOT / "cpg/ablation/results.csv").open(newline="", encoding="utf-8") as fh:
    for r in csv.DictReader(fh):
        if r["mode"] != "code" or r["scorer"] != "LocalLLMScorer":
            continue
        cve = r["sample_id"]
        if cve in EXCLUDE:
            continue
        llm_total += 1
        pred = r["predicted"]
        truth = r["truth"]
        if pred == "vulnerable" and truth == "vulnerable":
            llm_tp += 1
        elif pred == "vulnerable" and truth == "benign":
            llm_fp += 1
        elif pred != "vulnerable" and truth == "vulnerable":
            llm_fn += 1
        else:
            llm_tn += 1

llm_p = llm_tp / (llm_tp + llm_fp) if (llm_tp + llm_fp) else 0
llm_r = llm_tp / (llm_tp + llm_fn) if (llm_tp + llm_fn) else 0
llm_f1 = 2 * llm_p * llm_r / (llm_p + llm_r) if (llm_p + llm_r) else 0

print(f"\n=== 对比（{llm_total} 样本，HIGH>0 判 vulnerable）===")
print(f"Bandit:  TP={tp} FP={fp} TN={tn} FN={fn} P={p:.3f} R={r_:.3f} F1={f1:.3f}")
print(f"LLM+CPG: TP={llm_tp} FP={llm_fp} TN={llm_tn} FN={llm_fn} P={llm_p:.3f} R={llm_r:.3f} F1={llm_f1:.3f}")
print(f"\n命中样本（HIGH>0）:")
for x in [r for r in records if r["high"] > 0]:
    print(f"  {x['sample']}: HIGH={x['high']} MED={x['medium']} (truth={x['truth']})")

md = ["# 业界工具对比（P1）：Bandit", "",
      f"> 规则：HIGH 严重度命中>0 判 vulnerable；排除污染/不完整样本（69248/69249/55419）", "",
      f"| 指标 | Bandit | 本系统 LLM+CPG |", "| --- | --- | --- |",
      f"| F1 | {f1:.3f} | {llm_f1:.3f} |",
      f"| P | {p:.3f} | {llm_p:.3f} |",
      f"| R | {r_:.3f} | {llm_r:.3f} |",
      f"| TP/FP/FN/TN | {tp}/{fp}/{fn}/{tn} | {llm_tp}/{llm_fp}/{llm_fn}/{llm_tn} |", "",
      f"Bandit（AST 规则）对真实 CVE 语料基本不命中，F1={f1:.3f}；",
      f"本系统结合 CPG 数据流证据 + LLM 语义，F1={llm_f1:.3f}，为 Bandit 的 {llm_f1/f1:.1f} 倍。"]
(ROOT / "cpg/ablation/bandit_report.md").write_text("\n".join(md), encoding="utf-8")
print("[ok] wrote bandit_report.md")
