"""B-2 素材分析：识别 vuln/fixed 版本 taint 一致的样本（部分证据候选）。

输出：
1. 每样本（cve）vuln/fixed 的 taint 行数与命中文件；
2. vuln/fixed taint 指纹一致（同文件+同行号窗口）的样本 → "修复未消除数据流"难例；
3. 无 taint 命中的样本（logic 型，B-2 语义推理候选）。
"""
import csv
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from cpg.ablation.run_ablation import _load_dataset_rows

# 1) taint 行按 prefix 分组
rows = []
with open("cpg/ablation/.work/taint.csv", newline="", encoding="utf-8") as fh:
    rows = list(csv.DictReader(fh))

by_prefix: dict[str, list[dict]] = defaultdict(list)
for r in rows:
    ap = (r.get("abs_path") or "").replace("\\", "/")
    for part in ap.split("/"):
        if part.startswith("CVE-") and "_" in part:
            by_prefix[part].append(r)
            break

# 2) dataset 元数据
dataset = _load_dataset_rows(None)
cve_info = {}
for row in dataset:
    cve = row.get("cve_id") or row.get("cve")
    cve_info[cve] = {"cwe": row.get("cwe"), "summary": (row.get("summary") or "")[:80]}

print(f"{'CVE':<20} {'CWE':<10} {'vuln_t':<8} {'fixed_t':<8} {'指纹一致':<6} 判定")
print("-" * 90)
same_fingerprint = []
no_taint = []
for cve, info in sorted(cve_info.items()):
    vuln = by_prefix.get(f"{cve}_vuln", [])
    fixed = by_prefix.get(f"{cve}_fixed", [])
    # 指纹： (文件, 源行, 汇行) 集合
    def fp(ts):
        out = set()
        for r in ts:
            ap = (r.get("abs_path") or "").replace("\\", "/")
            fname = ap.rsplit("/", 1)[-1]
            out.add((fname, r.get("sourceLine"), r.get("sinkLine")))
        return out
    fv, ff = fp(vuln), fp(fixed)
    # 一致判定：vuln 非空且 vuln 指纹 ⊆ fixed 指纹（修复未消除任何流）
    consistent = bool(fv) and fv.issubset(ff)
    verdict = "部分证据难例" if consistent else ("无taint(逻辑型)" if not fv else "修复消除/变更流")
    if consistent:
        same_fingerprint.append(cve)
    if not fv:
        no_taint.append(cve)
    print(f"{cve:<20} {info['cwe'] or '?':<10} {len(vuln):<8} {len(fixed):<8} "
          f"{'是' if consistent else '-':<6} {verdict}")

print("\n=== 指纹一致样本（修复未消除 taint 流）===")
print(", ".join(same_fingerprint) if same_fingerprint else "(无)")
print(f"\n=== 无 taint 样本（logic 型，共 {len(no_taint)}）===")
print(", ".join(no_taint) if no_taint else "(无)")
