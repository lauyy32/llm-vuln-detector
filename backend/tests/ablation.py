#!/usr/bin/env python
"""
消融实验脚本 — 对比「有上下文增强」vs「无上下文增强」的检测效果差异。

实验设计：
  - 实验组: POST /api/detect (有结构化解析 + 正则预扫描 + 上下文注入)
  - 对照组: POST /api/detect-no-context (直接发送 raw HTTP，无预处理)
  - 两组使用相同的 LLM、相同的 system prompt、相同的数据集

输出指标对比:
  - Accuracy, Precision, Recall, F1, FPR, FNR
  - 各漏洞类型检出率
  - 平均置信度
  - 平均耗时

用法:
  python tests/ablation.py                      # 全量消融实验
  python tests/ablation.py --limit 20           # 只跑前20条（快速验证）

前提: 后端服务运行在 localhost:8000
"""
import argparse
import json
import sys
import time
import os
from pathlib import Path

import httpx

API_URL = os.environ.get("VD_API_URL", "http://localhost:8000")
DATASET_PATH = Path(__file__).parent / "dataset" / "test_cases.json"
REPORT_DIR = Path(__file__).parent / "reports"


def load_dataset(limit: int = None) -> list[dict]:
    with open(DATASET_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    if limit:
        data = data[:limit]
    return data


def call_api(raw_http: str, endpoint: str, timeout: int = 90) -> dict:
    resp = httpx.post(
        f"{API_URL}{endpoint}",
        json={"raw_request": raw_http},
        timeout=timeout,
    )
    resp.raise_for_status()
    return resp.json()


def evaluate_single(case: dict, endpoint: str) -> dict:
    expected_vuln = case["expected_is_vulnerable"]
    start = time.time()
    try:
        result = call_api(case["raw_http"], endpoint)
        elapsed = round(time.time() - start, 2)
        actual_vuln = result.get("is_vulnerable", False)
        actual_vulns = result.get("vulnerabilities", [])
        max_conf = max((v["confidence"] for v in actual_vulns), default=0)

        tp = expected_vuln and actual_vuln
        tn = (not expected_vuln) and (not actual_vuln)
        fp = (not expected_vuln) and actual_vuln
        fn = expected_vuln and (not actual_vuln)

        return {
            "case_id": case["id"],
            "category": case["category"],
            "expected_vulnerable": expected_vuln,
            "actual_vulnerable": actual_vuln,
            "max_confidence": max_conf,
            "tp": tp, "tn": tn, "fp": fp, "fn": fn,
            "elapsed": elapsed,
            "error": None,
        }
    except Exception as e:
        return {
            "case_id": case["id"],
            "category": case["category"],
            "expected_vulnerable": expected_vuln,
            "actual_vulnerable": None,
            "error": str(e),
            "elapsed": round(time.time() - start, 2),
            "tp": False, "tn": False, "fp": False, "fn": False,
            "max_confidence": 0,
        }


def compute_metrics(results: list[dict]) -> dict:
    tp = sum(1 for r in results if r["tp"])
    tn = sum(1 for r in results if r["tn"])
    fp = sum(1 for r in results if r["fp"])
    fn = sum(1 for r in results if r["fn"])
    errors = sum(1 for r in results if r["error"])
    total = len(results)
    valid = total - errors

    accuracy = (tp + tn) / valid if valid else 0
    precision = tp / (tp + fp) if (tp + fp) else 0
    recall = tp / (tp + fn) if (tp + fn) else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0
    fpr = fp / (fp + tn) if (fp + tn) else 0
    fnr = fn / (fn + tp) if (fn + tp) else 0

    confs = [r["max_confidence"] for r in results if r["tp"] and r["max_confidence"]]
    avg_conf = round(sum(confs) / len(confs), 1) if confs else 0

    times = [r["elapsed"] for r in results if r["elapsed"]]
    avg_time = round(sum(times) / len(times), 2) if times else 0

    cat_det = {}
    for r in results:
        cat = r["category"]
        if cat not in cat_det:
            cat_det[cat] = {"total": 0, "tp": 0}
        cat_det[cat]["total"] += 1
        if r["tp"]:
            cat_det[cat]["tp"] += 1

    return {
        "total": total,
        "errors": errors,
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "accuracy": round(accuracy * 100, 1),
        "precision": round(precision * 100, 1),
        "recall": round(recall * 100, 1),
        "f1": round(f1 * 100, 1),
        "fpr": round(fpr * 100, 1),
        "fnr": round(fnr * 100, 1),
        "avg_confidence": avg_conf,
        "avg_time_seconds": avg_time,
        "category_detection": cat_det,
    }


def print_comparison(metrics_full: dict, metrics_noctx: dict):
    print("\n" + "=" * 70)
    print("  消融实验结果对比: 有上下文增强 vs 无上下文增强")
    print("=" * 70)

    rows = [
        ("样本总数", "total", ""),
        ("检测成功", "total", "errors", "subtract"),
        ("TP (真阳性)", "tp", ""),
        ("TN (真阴性)", "tn", ""),
        ("FP (误报)", "fp", ""),
        ("FN (漏报)", "fn", ""),
        ("准确率", "accuracy", "%"),
        ("精确率", "precision", "%"),
        ("召回率", "recall", "%"),
        ("F1-Score", "f1", "%"),
        ("误报率 FPR", "fpr", "%"),
        ("漏报率 FNR", "fnr", "%"),
        ("平均置信度", "avg_confidence", "%"),
        ("平均耗时(s)", "avg_time_seconds", ""),
    ]

    print(f"\n  {'指标':<16} {'有上下文增强':>14} {'无上下文增强':>14} {'差异':>10}")
    print(f"  {'-'*16} {'-'*14} {'-'*14} {'-'*10}")

    for row in rows:
        label = row[0]
        key = row[1]
        suffix = row[-1]

        val_full = metrics_full[key]
        val_noctx = metrics_noctx[key]

        if len(row) == 4 and row[2] == "errors":
            val_full = val_full - metrics_full["errors"]
            val_noctx = val_noctx - metrics_noctx["errors"]

        diff = round(val_full - val_noctx, 1)
        diff_str = f"+{diff}" if diff > 0 else str(diff)
        if suffix == "%":
            print(f"  {label:<16} {val_full:>13.1f}% {val_noctx:>13.1f}% {diff_str:>9}%")
        else:
            print(f"  {label:<16} {val_full:>14} {val_noctx:>14} {diff_str:>10}")

    # 各类别检出率对比
    print(f"\n  --- 各漏洞类型检出率对比 ---")
    print(f"  {'类别':<12} {'有上下文':>10} {'无上下文':>10} {'差异':>8}")
    print(f"  {'-'*12} {'-'*10} {'-'*10} {'-'*8}")
    all_cats = set(metrics_full["category_detection"].keys()) | set(metrics_noctx["category_detection"].keys())
    for cat in sorted(all_cats):
        f = metrics_full["category_detection"].get(cat, {"total": 0, "tp": 0})
        n = metrics_noctx["category_detection"].get(cat, {"total": 0, "tp": 0})
        f_rate = round(f["tp"] / f["total"] * 100, 1) if f["total"] else 0
        n_rate = round(n["tp"] / n["total"] * 100, 1) if n["total"] else 0
        diff = round(f_rate - n_rate, 1)
        diff_str = f"+{diff}" if diff > 0 else str(diff)
        print(f"  {cat:<12} {f_rate:>9.1f}% {n_rate:>9.1f}% {diff_str:>7}%")

    print("\n" + "=" * 70 + "\n")


def main():
    parser = argparse.ArgumentParser(description="消融实验: 有/无上下文增强对比")
    parser.add_argument("--limit", type=int, help="只跑前N条（快速验证）")
    parser.add_argument("--output", type=str, default="ablation_report.json", help="输出报告文件名")
    args = parser.parse_args()

    dataset = load_dataset(limit=args.limit)
    print(f"加载 {len(dataset)} 条测试用例")

    try:
        health = httpx.get(f"{API_URL}/health", timeout=5)
        health.raise_for_status()
    except Exception:
        print(f"错误: 无法连接后端 {API_URL}")
        sys.exit(1)

    # === 实验组: 有上下文增强 ===
    print(f"\n[1/2] 实验组: 有上下文增强 (/api/detect)")
    results_full = []
    for i, case in enumerate(dataset):
        print(f"  [{i+1}/{len(dataset)}] {case['id']}...", end=" ", flush=True)
        r = evaluate_single(case, "/api/detect")
        results_full.append(r)
        print(f"{'TP' if r['tp'] else 'TN' if r['tn'] else 'FP' if r['fp'] else 'FN' if r['fn'] else 'ERR'} ({r['elapsed']}s)")

    # === 对照组: 无上下文增强 ===
    print(f"\n[2/2] 对照组: 无上下文增强 (/api/detect-no-context)")
    results_noctx = []
    for i, case in enumerate(dataset):
        print(f"  [{i+1}/{len(dataset)}] {case['id']}...", end=" ", flush=True)
        r = evaluate_single(case, "/api/detect-no-context")
        results_noctx.append(r)
        print(f"{'TP' if r['tp'] else 'TN' if r['tn'] else 'FP' if r['fp'] else 'FN' if r['fn'] else 'ERR'} ({r['elapsed']}s)")

    metrics_full = compute_metrics(results_full)
    metrics_noctx = compute_metrics(results_noctx)

    print_comparison(metrics_full, metrics_noctx)

    # 保存报告
    REPORT_DIR.mkdir(exist_ok=True)
    report = {
        "experiment": "ablation_context_enhancement",
        "dataset_size": len(dataset),
        "full_context": metrics_full,
        "no_context": metrics_noctx,
        "detail_results": {
            "full_context": results_full,
            "no_context": results_noctx,
        },
    }
    out_path = REPORT_DIR / args.output
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(f"报告已保存: {out_path}")


if __name__ == "__main__":
    main()
