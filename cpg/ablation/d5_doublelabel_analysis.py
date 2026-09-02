"""D5 双标 CVE 机制分析与门禁反事实测量（OPEN #25, 2026-09-02）。

事实来源：cpg/ablation/results.csv（74 CVE × {vuln,fixed} × 5 scorer，148 行）。
不重跑 CodeQL；门禁效果以「精确反事实」方式在既有结果上推导——等价于把
CPGEvidenceScorer 的目标 CWE 匹配门禁应用到原切片数据。

门禁规则（与 StructuralHeuristicScorer 对齐）：
    CPGEvidence 仅在「检测到的污点流 CWE == 目标 CWE」时判 vulnerable；
    否则（逻辑类 CVE 切片里出现无关的 taint 流 / taint CWE 与目标不匹配）
    → abstain（CPG 证据越界，不构成对本 CVE 的判定）。

输出：
    - 17 个双标 CVE 的机制分类（taint-matched / logic-scope-leak / taint-mismatch）
    - 门禁前后双标数、CPGEvidence 混淆矩阵、BA/MCC（abstain 排除于 2x2）
"""
from __future__ import annotations
import csv, json, math, sys
from pathlib import Path
from collections import defaultdict

HERE = Path(__file__).resolve().parent
RES = HERE / "results.csv"

# taint 组的 CodeQL 自建查询覆盖的 CWE（ablation config CWE_TAINT_QUERIES）
TAINT_CWES = {"CWE-022","CWE-078","CWE-079","CWE-089","CWE-094","CWE-918"}


def norm(cwe):
    if not cwe:
        return None
    s = str(cwe).strip().upper().lstrip("CWE-").strip("-")
    if s.isdigit():
        return "CWE-" + s.zfill(3)
    return "CWE-" + s.upper()


def load_rows():
    with RES.open(newline="", encoding="utf-8") as fh:
        return [r for r in csv.DictReader(fh)]


def confusion(rows, pred_key):
    """对 CPGEvidence 行计算 2x2（abstain 排除）。"""
    tp=fp=tn=fn=ab=0
    for r in rows:
        if r["scorer"] != "CPGEvidenceScorer":
            continue
        truth = r["truth"]
        pred = r[pred_key]
        if pred == "abstain":
            ab += 1; continue
        if pred == "vulnerable" and truth == "vulnerable": tp += 1
        elif pred == "vulnerable" and truth == "benign": fp += 1
        elif pred == "benign" and truth == "benign": tn += 1
        elif pred == "benign" and truth == "vulnerable": fn += 1
    return dict(tp=tp, fp=fp, tn=tn, fn=fn, abstain=ab)


def ba_mcc(c):
    tp,fp,tn,fn = c["tp"],c["fp"],c["tn"],c["fn"]
    tpr = tp/(tp+fn) if (tp+fn) else 0.0
    tnr = tn/(tn+fp) if (tn+fp) else 0.0
    ba = (tpr+tnr)/2
    denom = math.sqrt((tp+fp)*(tp+fn)*(tn+fp)*(tn+fn))
    mcc = (tp*tn - fp*fn)/denom if denom else 0.0
    return dict(tpr=round(tpr,4), tnr=round(tnr,4), ba=round(ba,4), mcc=round(mcc,4))


def gated_pred(r):
    """反事实：apply 目标 CWE 匹配门禁到 CPGEvidence 行。"""
    if r["predicted"] != "vulnerable":
        return r["predicted"]
    if norm(r["cwe_predicted"]) == norm(r["cwe_truth"]):
        return "vulnerable"
    return "abstain"


def main():
    rows = load_rows()
    cpg = [r for r in rows if r["scorer"] == "CPGEvidenceScorer"]

    # ---- 双标识别 + 机制分类 ----
    by_cve = defaultdict(dict)
    for r in cpg:
        by_cve[r["sample_id"]][r["version"]] = r
    double = []
    for cve, vers in by_cve.items():
        if "vuln" not in vers or "fixed" not in vers:
            continue
        if vers["vuln"]["predicted"] == "vulnerable" and vers["fixed"]["predicted"] == "vulnerable":
            double.append(cve)
    double.sort()

    mech = {}
    for cve in double:
        v = by_cve[cve]["vuln"]
        truth_cwe = norm(v["cwe_truth"])
        pred_cwe = norm(v["cwe_predicted"])
        if truth_cwe in TAINT_CWES:
            if pred_cwe == truth_cwe:
                mech[cve] = "taint-matched (真·taint CWE，两端均含同 CWE 流)"
            else:
                mech[cve] = f"taint-mismatch (目标={truth_cwe}, 预测={pred_cwe})"
        else:
            mech[cve] = f"logic-scope-leak (目标={truth_cwe} 逻辑类, 预测={pred_cwe} taint 越界)"

    # ---- 门禁前后双标数 ----
    gated_by_cve = defaultdict(dict)
    for r in cpg:
        gated_by_cve[r["sample_id"]][r["version"]] = gated_pred(r)
    double_after = [c for c in double
                    if gated_by_cve[c].get("vuln")=="vulnerable" and gated_by_cve[c].get("fixed")=="vulnerable"]
    double_after.sort()

    # ---- 混淆 / BA / MCC 前后 ----
    # 原判定用 r["predicted"]；门禁后逐行替换
    c_before = confusion(cpg, "predicted")
    gated_rows = [{**r, "predicted_g": gated_pred(r)} for r in cpg]
    c_after = confusion(gated_rows, "predicted_g")

    out = {
        "double_label_count_before": len(double),
        "double_label_count_after_gating": len(double_after),
        "double_labels_removed": sorted(set(double)-set(double_after)),
        "double_labels_remaining": double_after,
        "mechanism": mech,
        "confusion_before": c_before, "metrics_before": ba_mcc(c_before),
        "confusion_after": c_after, "metrics_after": ba_mcc(c_after),
    }
    print(json.dumps(out, ensure_ascii=False, indent=2))

    print("\n=== 双标机制分类 ===")
    for cve in double:
        print(f"  {cve}: {mech[cve]}")
    print(f"\n双标总数: {len(double)}  →  门禁后: {len(double_after)}  (移除 {len(double)-len(double_after)})")
    print("门禁后仍残留（真·taint CWE，需 pair-aware 判别性证据，属 CPG 补丁边界局限）:")
    for c in double_after:
        print(f"  {c}")


if __name__ == "__main__":
    main()
