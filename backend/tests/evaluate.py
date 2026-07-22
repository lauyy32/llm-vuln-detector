#!/usr/bin/env python
"""
评测脚本 — 使用标准数据集评估 LLM-VulnDetector 的检测效果。

指标：
  - 准确率 (Accuracy)
  - 精确率 (Precision)
  - 召回率 (Recall)
  - F1-Score
  - 误报率 (FPR, False Positive Rate)
  - 漏报率 (FNR, False Negative Rate)
  - 各漏洞类型的检测率
  - 置信度分析

用法:
  python tests/evaluate.py                          # 检测全部用例
  python tests/evaluate.py --category SQL注入       # 只检测某类
  python tests/evaluate.py --limit 10               # 只检测前10条
  python tests/evaluate.py --output report.json     # 输出报告到文件

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


def load_dataset(category: str = None, limit: int = None) -> list[dict]:
    with open(DATASET_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    if category:
        data = [d for d in data if d["category"] == category]
    if limit:
        data = data[:limit]
    return data


def call_detect(raw_http: str, timeout: int = 90) -> dict:
    resp = httpx.post(
        f"{API_URL}/api/detect",
        json={"raw_request": raw_http},
        timeout=timeout,
    )
    resp.raise_for_status()
    return resp.json()


def evaluate_single(case: dict) -> dict:
    """检测单条用例，返回评测结果。"""
    case_id = case["id"]
    expected_vuln = case["expected_is_vulnerable"]
    expected_type = case.get("expected_type")
    expected_min_conf = case.get("expected_min_confidence", 0)

    start = time.time()
    try:
        result = call_detect(case["raw_http"])
        elapsed = round(time.time() - start, 2)

        actual_vuln = result.get("is_vulnerable", False)
        actual_vulns = result.get("vulnerabilities", [])
        actual_types = list({v["type"] for v in actual_vulns})
        max_conf = max((v["confidence"] for v in actual_vulns), default=0)

        # 判定
        tp = expected_vuln and actual_vuln
        tn = (not expected_vuln) and (not actual_vuln)
        fp = (not expected_vuln) and actual_vuln
        fn = expected_vuln and (not actual_vuln)

        # 类型匹配（仅对正例）
        type_match = None
        if expected_vuln and actual_vuln and expected_type:
            type_match = expected_type in actual_types

        # 置信度达标
        conf_ok = None
        if expected_vuln and actual_vuln:
            conf_ok = max_conf >= expected_min_conf

        return {
            "case_id": case_id,
            "category": case["category"],
            "expected_vulnerable": expected_vuln,
            "actual_vulnerable": actual_vuln,
            "expected_type": expected_type,
            "actual_types": actual_types,
            "type_match": type_match,
            "max_confidence": max_conf,
            "expected_min_confidence": expected_min_conf,
            "confidence_ok": conf_ok,
            "tp": tp, "tn": tn, "fp": fp, "fn": fn,
            "elapsed": elapsed,
            "error": None,
        }
    except Exception as e:
        elapsed = round(time.time() - start, 2)
        return {
            "case_id": case_id,
            "category": case["category"],
            "expected_vulnerable": expected_vuln,
            "actual_vulnerable": None,
            "error": str(e),
            "elapsed": elapsed,
            "tp": False, "tn": False, "fp": False, "fn": False,
        }


def compute_metrics(results: list[dict]) -> dict:
    tp = sum(1 for r in results if r["tp"])
    tn = sum(1 for r in results if r["tn"])
    fp = sum(1 for r in results if r["fp"])
    fn = sum(1 for r in results if r["fn"])
    errors = sum(1 for r in results if r["error"])

    total = len(results)
    actual_valid = total - errors

    accuracy = (tp + tn) / actual_valid if actual_valid else 0
    precision = tp / (tp + fp) if (tp + fp) else 0
    recall = tp / (tp + fn) if (tp + fn) else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0
    fpr = fp / (fp + tn) if (fp + tn) else 0
    fnr = fn / (fn + tp) if (fn + tp) else 0

    # 各类别统计
    cat_stats = {}
    for r in results:
        cat = r["category"]
        if cat not in cat_stats:
            cat_stats[cat] = {"total": 0, "correct": 0, "tp": 0, "fn": 0, "tn": 0, "fp": 0}
        cat_stats[cat]["total"] += 1
        if r["tp"]:
            cat_stats[cat]["tp"] += 1
            cat_stats[cat]["correct"] += 1
        elif r["tn"]:
            cat_stats[cat]["tn"] += 1
            cat_stats[cat]["correct"] += 1
        elif r["fp"]:
            cat_stats[cat]["fp"] += 1
        elif r["fn"]:
            cat_stats[cat]["fn"] += 1

    for cat, s in cat_stats.items():
        s["accuracy"] = round(s["correct"] / s["total"] * 100, 1) if s["total"] else 0
        if cat != "正常请求" and cat != "边界用例":
            s["detection_rate"] = round(s["tp"] / s["total"] * 100, 1) if s["total"] else 0

    # 置信度统计
    conf_values = [r["max_confidence"] for r in results if r.get("max_confidence") and r["tp"]]
    avg_conf = round(sum(conf_values) / len(conf_values), 1) if conf_values else 0

    # 平均耗时
    times = [r["elapsed"] for r in results if r["elapsed"]]
    avg_time = round(sum(times) / len(times), 2) if times else 0

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
        "category_stats": cat_stats,
    }


def print_report(metrics: dict, results: list[dict], mode: str = "full"):
    print("\n" + "=" * 60)
    print(f"  LLM-VulnDetector 评测报告  [{mode}]")
    print("=" * 60)
    print(f"\n  样本总数:     {metrics['total']}")
    print(f"  成功检测:     {metrics['total'] - metrics['errors']}")
    print(f"  检测失败:     {metrics['errors']}")
    print(f"  平均耗时:     {metrics['avg_time_seconds']}s / 条")

    print(f"\n  --- 核心指标 ---")
    print(f"  准确率 Accuracy:  {metrics['accuracy']:>6.1f}%")
    print(f"  精确率 Precision: {metrics['precision']:>6.1f}%")
    print(f"  召回率 Recall:    {metrics['recall']:>6.1f}%")
    print(f"  F1-Score:         {metrics['f1']:>6.1f}%")
    print(f"  误报率 FPR:       {metrics['fpr']:>6.1f}%")
    print(f"  漏报率 FNR:       {metrics['fnr']:>6.1f}%")
    print(f"  平均置信度:       {metrics['avg_confidence']:>6.1f}%")

    print(f"\n  --- 混淆矩阵 ---")
    print(f"  TP={metrics['tp']}  FP={metrics['fp']}  FN={metrics['fn']}  TN={metrics['tn']}")

    print(f"\n  --- 各类别统计 ---")
    print(f"  {'类别':<12} {'总数':>4} {'正确':>4} {'准确率':>7} {'检出率':>7}")
    print(f"  {'-'*12} {'-'*4} {'-'*4} {'-'*7} {'-'*7}")
    for cat, s in sorted(metrics["category_stats"].items()):
        det_rate = f"{s.get('detection_rate', '-')}%"
        print(f"  {cat:<12} {s['total']:>4} {s['correct']:>4} {s['accuracy']:>6.1f}% {det_rate:>7}")

    # 错误用例
    errors = [r for r in results if r["error"]]
    if errors:
        print(f"\n  --- 检测失败用例 ---")
        for r in errors:
            print(f"  [{r['case_id']}] {r['category']}: {r['error']}")

    # 误报用例
    fps = [r for r in results if r["fp"]]
    if fps:
        print(f"\n  --- 误报用例 (正常请求被判定为有漏洞) ---")
        for r in fps:
            print(f"  [{r['case_id']}] {r['category']}")

    # 漏报用例
    fns = [r for r in results if r["fn"]]
    if fns:
        print(f"\n  --- 漏报用例 (有漏洞但未检测出) ---")
        for r in fns:
            print(f"  [{r['case_id']}] {r['category']}")

    # 类型匹配失败
    type_mismatch = [r for r in results if r.get("type_match") is False]
    if type_mismatch:
        print(f"\n  --- 类型识别错误 ---")
        for r in type_mismatch:
            print(f"  [{r['case_id']}] 期望={r['expected_type']}, 实际={r['actual_types']}")

    print("\n" + "=" * 60 + "\n")


def main():
    parser = argparse.ArgumentParser(description="LLM-VulnDetector 评测脚本")
    parser.add_argument("--category", type=str, help="只评测某一类别")
    parser.add_argument("--limit", type=int, help="只评测前N条")
    parser.add_argument("--output", type=str, help="输出报告到JSON文件")
    parser.add_argument("--mode", type=str, default="full",
                       choices=["full", "no-context"],
                       help="full=有上下文增强, no-context=无上下文增强(消融)")
    args = parser.parse_args()

    dataset = load_dataset(category=args.category, limit=args.limit)
    print(f"加载 {len(dataset)} 条测试用例...")

    # 检查后端是否在线
    try:
        health = httpx.get(f"{API_URL}/health", timeout=5)
        health.raise_for_status()
        print(f"后端在线: {health.json()}")
    except Exception:
        print(f"错误: 无法连接后端 {API_URL}，请先启动服务")
        sys.exit(1)

    print(f"开始评测 (mode={args.mode})...\n")
    results = []
    for i, case in enumerate(dataset):
        print(f"  [{i+1}/{len(dataset)}] {case['id']} ({case['category']})...", end=" ", flush=True)
        r = evaluate_single(case)
        results.append(r)
        status = "OK" if not r["error"] else f"ERR: {r['error'][:30]}"
        if r["tp"]:
            status += f" TP conf={r['max_confidence']}%"
        elif r["tn"]:
            status += " TN"
        elif r["fp"]:
            status += " FP"
        elif r["fn"]:
            status += " FN"
        print(f"{status} ({r['elapsed']}s)")

    metrics = compute_metrics(results)
    print_report(metrics, results, mode=args.mode)

    if args.output:
        REPORT_DIR.mkdir(exist_ok=True)
        report = {"mode": args.mode, "metrics": metrics, "results": results}
        out_path = REPORT_DIR / args.output
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        print(f"报告已保存: {out_path}")


if __name__ == "__main__":
    main()
