#!/usr/bin/env python
"""
============================================================================
  综合评测脚本 v2.0 — 三模式对比 + 全量数据集

  测试维度:
    1. CoT 模式 (默认, /api/detect) — 增强上下文 + CoT 分步推理
    2. Standard 模式 (/api/detect-standard) — 增强上下文 + 标准 Prompt
    3. No-Context 模式 (/api/detect-no-context) — 无上下文增强基线

  测试数据集:
    - 56条标准测试用例 (dataset/test_cases.json)
    - 206条对抗样本 (dataset/adversarial_samples.json)

  产出:
    - 综合对比报告 JSON
    - 按分类/混淆模式/编码层级拆分的子报告
============================================================================
"""
import argparse
import json
import os
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Optional

import httpx

# ---- 配置 ----

API_URL = os.environ.get("VD_API_URL", "http://localhost:8000")
OUTPUT_DIR = Path(__file__).parent / "reports"
DATASET_DIR = Path(__file__).parent / "dataset"
REQUEST_TIMEOUT = 120  # LLM 调用可能很慢


def load_dataset(path: Path) -> list[dict]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def build_http_request(sample: dict) -> str:
    """根据样本生成 HTTP 请求文本。"""
    payload = sample.get("payload", "")
    expected_type = sample.get("expected_type", "未知")
    category = sample.get("category", expected_type)

    # 根据漏洞类型选择 HTTP 请求模板
    templates = {
        "SQL注入": 'GET /search?id={payload} HTTP/1.1\nHost: example.com\nUser-Agent: Mozilla/5.0\n\n',
        "XSS": 'GET /search?q={payload} HTTP/1.1\nHost: example.com\nUser-Agent: Mozilla/5.0\n\n',
        "命令注入": 'POST /ping HTTP/1.1\nHost: example.com\nContent-Type: application/x-www-form-urlencoded\n\nip={payload}',
        "路径穿越": 'GET /download?file={payload} HTTP/1.1\nHost: example.com\nUser-Agent: Mozilla/5.0\n\n',
        "SSRF": 'POST /fetch HTTP/1.1\nHost: example.com\nContent-Type: application/json\n\n{"url":"{payload}"}',
        "XXE": 'POST /parse HTTP/1.1\nHost: example.com\nContent-Type: application/xml\n\n{payload}',
        "SSTI": 'GET /render?template={payload} HTTP/1.1\nHost: example.com\nUser-Agent: Mozilla/5.0\n\n',
        "NoSQL注入": 'POST /login HTTP/1.1\nHost: example.com\nContent-Type: application/json\n\n{payload}',
        "开放重定向": 'GET /redirect?url={payload} HTTP/1.1\nHost: example.com\nUser-Agent: Mozilla/5.0\n\n',
        "文件上传": 'POST /upload HTTP/1.1\nHost: example.com\nContent-Type: application/x-www-form-urlencoded\n\nfile={payload}',
    }

    template = templates.get(category, templates.get(expected_type,
        'POST /api HTTP/1.1\nHost: example.com\nContent-Type: application/x-www-form-urlencoded\n\ndata={payload}'))

    return template.format(payload=payload)


def call_api(client: httpx.Client, raw_http: str, endpoint: str) -> dict:
    """调用检测 API，返回结果字典。"""
    try:
        resp = client.post(
            f"{API_URL}{endpoint}",
            json={"raw_request": raw_http},
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code == 200:
            return resp.json()
        return {"error": f"HTTP {resp.status_code}", "raw": resp.text[:200]}
    except httpx.TimeoutException:
        return {"error": "timeout"}
    except Exception as e:
        return {"error": str(e)[:200]}


def evaluate_sample(result: dict, sample: dict) -> dict:
    """评估单个检测结果。"""
    expected_type = sample.get("expected_type", "")
    expected_vulnerable = sample.get("expected_vulnerable", True)

    r = {
        "sample_id": sample.get("id", "?"),
        "category": sample.get("category", ""),
        "subcategory": sample.get("subcategory", ""),
        "payload": sample.get("payload", "")[:100],
        "difficulty": sample.get("difficulty", ""),
        "expected_type": expected_type,
        "expected_vulnerable": expected_vulnerable,
    }

    if "error" in result:
        r["error"] = result["error"]
        r["is_vulnerable"] = None
        r["risk_level"] = "error"
        r["vulnerabilities"] = []
        r["match"] = None
        return r

    is_vuln = result.get("is_vulnerable", False)
    vulns = result.get("vulnerabilities", [])
    risk_level = result.get("risk_level", "info")

    r["is_vulnerable"] = is_vuln
    r["risk_level"] = risk_level
    r["vulnerability_count"] = len(vulns)
    r["detected_types"] = [v.get("type", "") for v in vulns]
    r["confidence"] = max((v.get("confidence", 0) for v in vulns), default=0)

    # 判定正确性
    if expected_vulnerable:
        if is_vuln:
            # 检查类型是否匹配
            type_match = any(expected_type in str(t) or str(t) in expected_type
                           for t in r["detected_types"])
            r["match"] = "correct" if type_match else "wrong_type"
        else:
            r["match"] = "fn"  # 漏报
    else:
        if is_vuln:
            r["match"] = "fp"  # 误报
        else:
            r["match"] = "correct"

    return r


def compute_metrics(results: list[dict], name: str = "") -> dict:
    """计算检测指标。"""
    total = len(results)
    errors = sum(1 for r in results if r.get("error"))
    valid = total - errors
    if valid == 0:
        return {"name": name, "total": total, "errors": errors, "valid": 0}

    attack_samples = [r for r in results if r.get("expected_vulnerable") and not r.get("error")]
    benign_samples = [r for r in results if not r.get("expected_vulnerable", True) and not r.get("error")]

    tp = sum(1 for r in attack_samples if r["match"] == "correct")
    wrong_type = sum(1 for r in attack_samples if r["match"] == "wrong_type")
    fn = sum(1 for r in attack_samples if r["match"] == "fn")
    fp = sum(1 for r in benign_samples if r["match"] == "fp")
    tn = sum(1 for r in benign_samples if r["match"] == "correct")

    total_attack = len(attack_samples)
    total_benign = len(benign_samples)

    return {
        "name": name,
        "total": total,
        "errors": errors,
        "valid": valid,
        "attack_samples": total_attack,
        "benign_samples": total_benign,
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "wrong_type": wrong_type,
        "detection_rate": round(tp / total_attack * 100, 1) if total_attack > 0 else 0,
        "strict_detection_rate": round((tp + wrong_type) / total_attack * 100, 1) if total_attack > 0 else 0,
        "fpr": round(fp / total_benign * 100, 1) if total_benign > 0 else 0,
        "miss_rate": round(fn / total_attack * 100, 1) if total_attack > 0 else 0,
    }


def run_mode(client: httpx.Client, samples: list[dict], endpoint: str,
             mode_name: str, max_samples: Optional[int] = None) -> tuple[list[dict], dict]:
    """运行指定模式的评测。"""
    results = []
    sample_subset = samples[:max_samples] if max_samples else samples
    total = len(sample_subset)

    print(f"\n{'='*60}")
    print(f"  [{mode_name}] 开始评测 — {total} 条样本")
    print(f"{'='*60}")

    for i, sample in enumerate(sample_subset):
        raw_http = build_http_request(sample)
        api_result = call_api(client, raw_http, endpoint)
        eval_result = evaluate_sample(api_result, sample)
        eval_result["mode"] = mode_name
        results.append(eval_result)

        bar = "=" * ((i + 1) * 30 // total)
        space = " " * (30 - len(bar))
        progress = f"[{bar}{space}] {i+1}/{total}"
        status = eval_result.get("match", eval_result.get("error", "?"))
        print(f"  {progress}  {sample.get('id','?')} → {status}", end="\r")

    metrics = compute_metrics(results, mode_name)
    print(f"\n  [{mode_name}] 完成: 检出率={metrics['detection_rate']}% "
          f"严格={metrics['strict_detection_rate']}% 误报率={metrics['fpr']}% "
          f"漏报率={metrics['miss_rate']}% 错误={metrics['errors']}")

    return results, metrics


def by_category_breakdown(results: list[dict]) -> dict:
    """按分类汇总结果。"""
    cats = defaultdict(lambda: {"total": 0, "correct": 0, "wrong_type": 0, "fn": 0, "fp": 0, "error": 0})
    for r in results:
        cat = r.get("category", "未知")
        cats[cat]["total"] += 1
        match = r.get("match")
        if r.get("error"):
            cats[cat]["error"] += 1
        elif match == "correct":
            cats[cat]["correct"] += 1
        elif match == "wrong_type":
            cats[cat]["wrong_type"] += 1
        elif match == "fn":
            cats[cat]["fn"] += 1
        elif match == "fp":
            cats[cat]["fp"] += 1

    breakdown = {}
    for cat, counts in sorted(cats.items()):
        t = counts["total"]
        breakdown[cat] = {
            "total": t,
            "detection_rate": round(counts["correct"] / t * 100, 1) if t > 0 else 0,
            "correct": counts["correct"],
            "wrong_type": counts["wrong_type"],
            "miss": counts["fn"],
            "false_positive": counts["fp"],
            "error": counts["error"],
        }
    return breakdown


def generate_comparison_report(
    standard_results: list[dict], standard_metrics: dict,
    adversarial_results: list[dict], adversarial_metrics: dict,
    mode_results: dict,
) -> dict:
    """生成综合对比报告。"""
    # 汇总所有模式的对抗样本指标
    adv_by_mode = {}
    for mode_name, (results, metrics) in mode_results.items():
        adv_by_mode[mode_name] = metrics

    # 最差表现的样本（对抗样本中漏报的）
    worst_cases = []
    for r in adversarial_results:
        if r.get("match") in ("fn", "error"):
            worst_cases.append({
                "id": r["sample_id"],
                "category": r["category"],
                "payload": r["payload"][:150],
                "difficulty": r["difficulty"],
                "reason": r.get("match", "?"),
            })
    worst_cases.sort(key=lambda x: x["id"])

    report = {
        "meta": {
            "evaluation_version": "2.0",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "api_url": API_URL,
            "datasets": {
                "standard": f"{len(standard_results)} cases (56 original)",
                "adversarial": f"{len(adversarial_results)} cases (206 generated)",
            },
        },
        "standard_dataset": standard_metrics,
        "adversarial_dataset": adversarial_metrics,
        "comparison": {
            "standard_vs_adversarial": {
                "standard_detection": standard_metrics.get("detection_rate", 0),
                "adversarial_detection": adversarial_metrics.get("detection_rate", 0),
                "degradation_pct": round(
                    standard_metrics.get("detection_rate", 0) - adversarial_metrics.get("detection_rate", 0), 1
                ),
            },
        },
        "adversarial_by_category": by_category_breakdown(adversarial_results),
        "adversarial_by_mode": adv_by_mode,
        "worst_cases_top30": worst_cases[:30],
        "conclusions": {
            "encoding_impact": (
                "对抗样本引入编码绕过，预期检测率显著下降。"
                "若 CoT 模式检测率高于 Standard 模式 ≥5%，证明分步推理有效。"
            ),
            "confusion_impact": (
                "大小写混淆、空白符替代等手法增加检测难度。"
                "需关注各混淆手法下的漏报模式。"
            ),
            "ablation_findings": (
                "对比 CoT vs Standard vs No-Context 三种模式，"
                "量化上下文增强和 CoT 推理各自的贡献。"
            ),
        },
    }

    return report


def main():
    parser = argparse.ArgumentParser(description="LLM-VulnDetector v2.0 综合评测")
    parser.add_argument("--dataset", choices=["standard", "adversarial", "all"],
                        default="all", help="测试数据集 (default: all)")
    parser.add_argument("--modes", nargs="+",
                        default=["cot", "standard", "no-context"],
                        help="测试模式 (default: cot standard no-context)")
    parser.add_argument("--max-samples", type=int, default=None,
                        help="每数据集最大样本数（用于快速测试）")
    parser.add_argument("--output", type=str, default=None,
                        help="输出文件路径")
    parser.add_argument("--dry-run", action="store_true",
                        help="空跑模式：仅验证数据，不调用 API")
    args = parser.parse_args()

    OUTPUT_DIR.mkdir(exist_ok=True)

    # 加载数据集
    datasets = {}
    if args.dataset in ("standard", "all"):
        std_path = DATASET_DIR / "test_cases.json"
        if std_path.exists():
            datasets["standard"] = load_dataset(std_path)
            print(f"[数据] 标准数据集: {len(datasets['standard'])} 条")

    if args.dataset in ("adversarial", "all"):
        adv_path = DATASET_DIR / "adversarial_samples.json"
        if adv_path.exists():
            datasets["adversarial"] = load_dataset(adv_path)
            print(f"[数据] 对抗样本: {len(datasets['adversarial'])} 条")

    if not datasets:
        print("[错误] 未找到任何数据集文件")
        sys.exit(1)

    if args.dry_run:
        print("\n[Dry-Run] 数据验证通过，不调用 API")
        for name, samples in datasets.items():
            print(f"  {name}: {len(samples)} 条")
            cats = defaultdict(int)
            for s in samples:
                cats[s.get("category", "?")] += 1
            for cat, cnt in sorted(cats.items()):
                print(f"    {cat}: {cnt}")
        return

    # 模式 → endpoint 映射
    mode_endpoints = {
        "cot": "/api/detect",
        "standard": "/api/detect-standard",
        "no-context": "/api/detect-no-context",
    }

    print(f"\n[API] 目标: {API_URL}")
    print(f"[API] 模式: {args.modes}")

    # 测试连接
    try:
        resp = httpx.get(f"{API_URL}/health", timeout=10)
        if resp.status_code != 200:
            print(f"[警告] API 健康检查失败: {resp.status_code}, 尝试继续...")
        else:
            print("[API] 健康检查通过")
    except Exception as e:
        print(f"[错误] 无法连接到 API: {e}")
        print("[提示] 请先启动后端: docker-compose up -d backend")
        print("[提示] 或: cd backend && uvicorn app.main:app --reload --port 8000")
        sys.exit(1)

    client = httpx.Client(timeout=REQUEST_TIMEOUT)

    # 运行评测
    mode_results = {}  # mode_name -> (results_list, metrics_dict)
    standard_results = []
    adversarial_results = []

    for mode_name in args.modes:
        if mode_name not in mode_endpoints:
            print(f"[警告] 未知模式 {mode_name}, 跳过")
            continue
        endpoint = mode_endpoints[mode_name]

        for ds_name, samples in datasets.items():
            results, metrics = run_mode(
                client, samples, endpoint, f"{mode_name}/{ds_name}",
                max_samples=args.max_samples,
            )

            if f"{mode_name}/{ds_name}" not in mode_results:
                mode_results[f"{mode_name}/{ds_name}"] = (results, metrics)

            if ds_name == "standard":
                standard_results = results
            elif ds_name == "adversarial":
                adversarial_results = results

    # 计算各模式对抗样本的指标
    adv_metrics = {}
    for key, (results, metrics) in mode_results.items():
        if "adversarial" in key:
            adv_metrics[key] = metrics

    # 生成报告
    report = generate_comparison_report(
        standard_results or [],
        mode_results.get("cot/standard", ([], {}))[1],
        adversarial_results or [],
        mode_results.get("cot/adversarial", ([], {}))[1],
        {k: v for k, v in mode_results.items() if "adversarial" in k},
    )

    # 写入 JSON 报告
    output_path = Path(args.output) if args.output else (OUTPUT_DIR / "evaluation_v2_report.json")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"\n[报告] 已保存: {output_path}")

    # 写入详细结果
    detail_path = output_path.parent / f"{output_path.stem}_details.json"
    detail = {
        "standard_results": standard_results,
        "adversarial_results": adversarial_results,
    }
    with open(detail_path, "w", encoding="utf-8") as f:
        json.dump(detail, f, indent=2, ensure_ascii=False, default=str)
    print(f"[详情] 已保存: {detail_path}")

    # 打印摘要
    print("\n" + "=" * 60)
    print("  评测摘要")
    print("=" * 60)
    for key, metrics in adv_metrics.items():
        print(f"\n  [{key}]")
        print(f"    检测率: {metrics['detection_rate']}%")
        print(f"    严格检测率: {metrics['strict_detection_rate']}%")
        print(f"    漏报率: {metrics['miss_rate']}%")
        print(f"    误报率: {metrics['fpr']}%")
        print(f"    错误: {metrics['errors']}")

    client.close()
    print("\n评测完成!")


if __name__ == "__main__":
    main()
