#!/usr/bin/env python
"""
============================================================================
  综合评测脚本 v2.1 — 三模式消融对比 + 完整指标 + 类型级混淆矩阵

  测试维度 (消融实验):
    - CoT 模式 (默认, /api/detect)        — 增强上下文 + CoT 分步推理
    - Standard 模式 (/api/detect-standard) — 增强上下文 + 标准 Prompt
    - No-Context 模式 (/api/detect-no-context) — 无上下文增强基线

  核心研究问题: "上下文增强 + CoT 推理是否能提升 LLM 的攻击载荷识别效果?"
  => 通过三模式在同一数据集上的指标差异 (delta) 量化各自贡献。

  测试数据集:
    - 56 条标准测试用例 (dataset/test_cases.json)
    - 246 条对抗样本 (dataset/adversarial_samples.json) = 206 攻击 + 40 正常

  完整指标 (每个 mode × dataset):
    - 检出率 / 严格检出率 / 漏报率 / 误报率
    - Precision / Recall / F1 / Accuracy
    - 类型级混淆矩阵 (expected_type × detected_type)
    - 按攻击类别拆分
    - 逐条真实错误原因 (用于诊断 API 失败)

  运行:
    python tests/evaluate_v2.py --dataset all --modes cot standard no-context
    python tests/evaluate_v2.py --dataset adversarial --modes cot --max-samples 20
    python tests/evaluate_v2.py --dry-run
============================================================================
"""
import argparse
import asyncio
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
REQUEST_TIMEOUT = float(os.environ.get("VD_REQUEST_TIMEOUT", "90"))
CONCURRENCY = int(os.environ.get("VD_CONCURRENCY", "6"))
MAX_RETRIES = int(os.environ.get("VD_MAX_RETRIES", "4"))


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
        "文件包含": 'GET /download?file={payload} HTTP/1.1\nHost: example.com\nUser-Agent: Mozilla/5.0\n\n',
        # 正常请求: 多数看起来像查询串，用 GET 查询模板更自然；JSON/XML 走默认
        "正常请求": 'GET /search?{payload} HTTP/1.1\nHost: example.com\nUser-Agent: Mozilla/5.0\n\n',
    }

    # 良性样本若 payload 自身已是完整 JSON / XML，则包成对应 body
    if category == "正常请求":
        p = payload.strip()
        if p.startswith("{") or p.startswith("["):
            template = ('POST /api HTTP/1.1\nHost: example.com\n'
                        'Content-Type: application/json\n\n{payload}')
        elif p.startswith("<?xml"):
            template = ('POST /api HTTP/1.1\nHost: example.com\n'
                        'Content-Type: application/xml\n\n{payload}')
        else:
            template = templates["正常请求"]
    else:
        template = templates.get(category, templates.get(expected_type,
            'POST /api HTTP/1.1\nHost: example.com\nContent-Type: application/x-www-form-urlencoded\n\ndata={payload}'))

    return template.format(payload=payload)


def call_api(client: httpx.Client, raw_http: str, endpoint: str) -> dict:
    """调用检测 API (同步, 用于 dry-run 之外的兼容路径)。"""
    try:
        resp = client.post(
            f"{API_URL}{endpoint}",
            json={"raw_request": raw_http},
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code == 200:
            return resp.json()
        return {"error": f"HTTP {resp.status_code}: {resp.text[:200]}"}
    except httpx.TimeoutException:
        return {"error": "timeout"}
    except Exception as e:
        return {"error": str(e)[:200]}


async def call_api_async(client: httpx.AsyncClient, raw_http: str, endpoint: str) -> dict:
    """异步调用检测 API, 带重试退避 (覆盖超时 / 429 / 5xx)。"""
    last_err = "unknown"
    for attempt in range(MAX_RETRIES):
        try:
            resp = await client.post(
                f"{API_URL}{endpoint}",
                json={"raw_request": raw_http},
                timeout=REQUEST_TIMEOUT,
            )
            if resp.status_code == 200:
                return resp.json()
            if resp.status_code == 429 or resp.status_code >= 500:
                retry_after = resp.headers.get("retry-after")
                wait = float(retry_after) if retry_after and retry_after.isdigit() else (2 ** attempt)
                last_err = f"HTTP {resp.status_code} (retry {attempt+1})"
                await asyncio.sleep(wait + 0.5)
                continue
            return {"error": f"HTTP {resp.status_code}: {resp.text[:200]}"}
        except httpx.TimeoutException:
            last_err = "timeout"
            if attempt < MAX_RETRIES - 1:
                await asyncio.sleep(2 ** attempt)
                continue
            return {"error": "timeout"}
        except Exception as e:
            return {"error": str(e)[:200]}
    return {"error": f"max_retries_exceeded: {last_err}"}


def evaluate_sample(result: dict, sample: dict) -> dict:
    """评估单个检测结果, 并记录混淆矩阵所需字段。"""
    expected_type = sample.get("expected_type", "正常请求" if not sample.get("expected_vulnerable", True) else "未知")
    expected_vulnerable = sample.get("expected_vulnerable", True)

    r = {
        "sample_id": sample.get("id", "?"),
        "category": sample.get("category", ""),
        "subcategory": sample.get("subcategory", ""),
        "payload": sample.get("payload", "")[:120],
        "difficulty": sample.get("difficulty", ""),
        "expected_type": expected_type,
        "expected_vulnerable": expected_vulnerable,
    }

    if "error" in result:
        r["error"] = result["error"]
        r["is_vuln"] = None
        r["risk_level"] = "error"
        r["vulnerabilities"] = []
        r["detected_types"] = []
        r["best_detected_type"] = "API错误"
        r["match"] = None
        return r

    is_vuln = result.get("is_vulnerable", False)
    vulns = result.get("vulnerabilities", [])
    risk_level = result.get("risk_level", "info")

    r["is_vuln"] = is_vuln
    r["risk_level"] = risk_level
    r["vulnerability_count"] = len(vulns)
    r["detected_types"] = [v.get("type", "") for v in vulns]
    r["confidence"] = max((v.get("confidence", 0) for v in vulns), default=0)

    # 类型匹配: 检测出的类型中任一与期望类型一致 (或包含关系)
    def _type_match(et: str, dt: str) -> bool:
        if not et or not dt:
            return False
        return et in dt or dt in et

    if expected_vulnerable:
        if is_vuln:
            matched = [dt for dt in r["detected_types"] if _type_match(expected_type, dt)]
            r["best_detected_type"] = matched[0] if matched else (r["detected_types"][0] if r["detected_types"] else "未识别")
            r["match"] = "correct" if matched else "wrong_type"
        else:
            r["best_detected_type"] = "漏报/未识别"
            r["match"] = "fn"  # 漏报
    else:
        if is_vuln:
            r["best_detected_type"] = r["detected_types"][0] if r["detected_types"] else "未识别"
            r["match"] = "fp"  # 误报
        else:
            r["best_detected_type"] = "正常"
            r["match"] = "correct"

    return r


def compute_metrics(results: list[dict], name: str = "") -> dict:
    """计算完整检测指标。

    采用学术标准的两层定义:
    1) 攻击级 (二分类): is_vulnerable 预测 vs 真实标签
       - 攻击被识别为攻击 (类型对错不论) => 攻击级 TP
       - 攻击未被识别 => FN (漏报)
       - 正常被识别为攻击 => FP (误报)
       - 正常未被识别 => TN
       由此计算 Precision / Recall / F1 / Accuracy (标准定义)。
    2) 类型级 (辅助): 在攻击级 TP 中, 类型也判对的比例 => type_accuracy。
       另保留 detection_rate = 类型精确检出率 (类型也正确的攻击 / 总攻击)。
    """
    total = len(results)
    errors = [r for r in results if r.get("error")]
    valid = total - len(errors)
    if valid == 0:
        return {"name": name, "total": total, "errors": len(errors), "valid": 0,
                "error_reasons": _aggregate_errors(results)}

    attack_samples = [r for r in results if r.get("expected_vulnerable") and not r.get("error")]
    benign_samples = [r for r in results if not r.get("expected_vulnerable", True) and not r.get("error")]

    # ---- 攻击级二分类 ----
    tp_bin = sum(1 for r in attack_samples if r.get("is_vuln") is True)
    fn_bin = sum(1 for r in attack_samples if r.get("is_vuln") is False)
    fp_bin = sum(1 for r in benign_samples if r.get("is_vuln") is True)
    tn_bin = sum(1 for r in benign_samples if r.get("is_vuln") is False)

    # ---- 类型级 ----
    tp_type = sum(1 for r in attack_samples if r.get("match") == "correct")
    wrong_type = sum(1 for r in attack_samples if r.get("match") == "wrong_type")

    total_attack = len(attack_samples)
    total_benign = len(benign_samples)

    denom = tp_bin + tn_bin + fp_bin + fn_bin
    precision = round(tp_bin / (tp_bin + fp_bin) * 100, 1) if (tp_bin + fp_bin) > 0 else 0.0
    recall = round(tp_bin / (tp_bin + fn_bin) * 100, 1) if (tp_bin + fn_bin) > 0 else 0.0
    f1 = round(2 * precision * recall / (precision + recall), 1) if (precision + recall) > 0 else 0.0
    accuracy = round(denom and (tp_bin + tn_bin) / denom * 100, 1)
    type_accuracy = round(tp_type / tp_bin * 100, 1) if tp_bin > 0 else 0.0
    detection_rate = round(tp_type / total_attack * 100, 1) if total_attack > 0 else 0.0  # 类型精确检出
    strict_detection_rate = round(tp_bin / total_attack * 100, 1) if total_attack > 0 else 0.0  # 攻击级召回
    fpr = round(fp_bin / total_benign * 100, 1) if total_benign > 0 else 0.0
    miss_rate = round(fn_bin / total_attack * 100, 1) if total_attack > 0 else 0.0

    return {
        "name": name,
        "total": total,
        "errors": len(errors),
        "valid": valid,
        "attack_samples": total_attack,
        "benign_samples": total_benign,
        "tp": tp_bin, "tn": tn_bin, "fp": fp_bin, "fn": fn_bin,
        "type_correct": tp_type, "wrong_type": wrong_type,
        "detection_rate": detection_rate,
        "strict_detection_rate": strict_detection_rate,
        "type_accuracy": type_accuracy,
        "fpr": fpr,
        "miss_rate": miss_rate,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": accuracy,
        "error_reasons": _aggregate_errors(results),
    }


def _aggregate_errors(results: list[dict]) -> dict:
    """汇总错误原因 (前因用于诊断 API 失败)。"""
    reasons = defaultdict(int)
    for r in results:
        if r.get("error"):
            msg = str(r["error"])
            # 归一化: 取首词分类
            key = msg.split(":")[0].split(" ")[0] if msg else "unknown"
            if msg.startswith("HTTP 429"):
                key = "HTTP_429_rate_limit"
            elif msg.startswith("HTTP 5"):
                key = "HTTP_5xx_server"
            elif msg.startswith("HTTP 4"):
                key = "HTTP_4xx_client"
            elif "timeout" in msg:
                key = "timeout"
            reasons[key] += 1
    return dict(reasons)


def compute_confusion_matrix(results: list[dict]) -> dict:
    """类型级混淆矩阵: expected_type -> {detected_type: count}。"""
    matrix = defaultdict(lambda: defaultdict(int))
    for r in results:
        if r.get("error"):
            continue
        exp = r.get("expected_type", "未知")
        det = r.get("best_detected_type", "未识别")
        matrix[exp][det] += 1
    # 转为普通 dict
    return {exp: dict(dets) for exp, dets in sorted(matrix.items())}


def by_category_breakdown(results: list[dict]) -> dict:
    """按分类汇总结果。"""
    cats = defaultdict(lambda: {"total": 0, "correct": 0, "wrong_type": 0, "fn": 0, "fp": 0, "error": 0})
    for r in results:
        cat = r.get("category", "未知")
        cats[cat]["total"] += 1
        if r.get("error"):
            cats[cat]["error"] += 1
        elif r["match"] == "correct":
            cats[cat]["correct"] += 1
        elif r["match"] == "wrong_type":
            cats[cat]["wrong_type"] += 1
        elif r["match"] == "fn":
            cats[cat]["fn"] += 1
        elif r["match"] == "fp":
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


async def run_mode(client: httpx.AsyncClient, samples: list[dict], endpoint: str,
                   mode_name: str, max_samples: Optional[int] = None) -> tuple[list[dict], dict, dict]:
    """异步并发运行指定模式的评测。返回 (results, metrics, confusion_matrix)。"""
    subset = samples[:max_samples] if max_samples else samples
    total = len(subset)
    sem = asyncio.Semaphore(CONCURRENCY)
    results: list[dict] = [None] * total  # type: ignore

    async def worker(i: int, sample: dict):
        async with sem:
            raw_http = build_http_request(sample)
            api_result = await call_api_async(client, raw_http, endpoint)
            ev = evaluate_sample(api_result, sample)
            ev["mode"] = mode_name
            results[i] = ev

    t0 = time.time()
    print(f"\n{'='*64}")
    print(f"  [{mode_name}] 并发评测 — {total} 条样本 (并发={CONCURRENCY})")
    print(f"{'='*64}")

    await asyncio.gather(*(worker(i, s) for i, s in enumerate(subset)))

    metrics = compute_metrics(results, mode_name)
    matrix = compute_confusion_matrix(results)
    elapsed = round(time.time() - t0, 1)
    print(f"  [{mode_name}] 完成({elapsed}s): 检出率={metrics['detection_rate']}% "
          f"P={metrics['precision']}% R={metrics['recall']}% F1={metrics['f1']}% "
          f"误报率={metrics['fpr']}% 错误={metrics['errors']}")
    if metrics.get("error_reasons"):
        print(f"  [{mode_name}] 错误原因: {metrics['error_reasons']}")

    return results, metrics, matrix


def delta_metrics(a: dict, b: dict) -> dict:
    """计算 a 相对 b 的指标差值 (用于量化 CoT 增益)。"""
    keys = ["detection_rate", "strict_detection_rate", "fpr", "miss_rate",
            "precision", "recall", "f1", "accuracy"]
    return {k: round((a.get(k, 0) or 0) - (b.get(k, 0) or 0), 1) for k in keys}


def generate_comparison_report(
    mode_results: dict,            # mode_name -> (results, metrics, matrix)
    datasets: dict,                # ds_name -> samples
) -> dict:
    """生成以消融对比为核心的综合报告。"""
    # mode_results 的 key 形如 "cot/adversarial"; 解析出模式名与数据集名
    run_modes = sorted(set(k.split("/")[0] for k in mode_results))
    run_datasets = sorted(set(k.split("/")[1] for k in mode_results))
    report = {
        "meta": {
            "evaluation_version": "2.1",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "api_url": API_URL,
            "concurrency": CONCURRENCY,
            "datasets": {name: f"{len(s)} cases" for name, s in datasets.items()},
            "modes": run_modes,
            "research_question": "上下文增强 + CoT 推理是否提升 LLM 攻击载荷识别效果?",
        },
        "ablation": {},
        "per_mode": {},
        "per_category": {},
        "confusion_matrix": {},
    }

    # ---- 消融核心: 每个数据集上各模式对比 ----
    for ds_name in run_datasets:
        ds_modes = {}
        for m in run_modes:
            key = f"{m}/{ds_name}"
            if key in mode_results:
                ds_modes[m] = mode_results[key][1]
        if not ds_modes:
            continue
        entry = {"modes": ds_modes}
        # 以 cot 为基准的 delta
        if "cot" in ds_modes:
            if "standard" in ds_modes:
                entry["delta_cot_minus_standard"] = delta_metrics(ds_modes["cot"], ds_modes["standard"])
            if "no-context" in ds_modes:
                entry["delta_cot_minus_nocontext"] = delta_metrics(ds_modes["cot"], ds_modes["no-context"])
            if "standard" in ds_modes and "no-context" in ds_modes:
                entry["delta_standard_minus_nocontext"] = delta_metrics(ds_modes["standard"], ds_modes["no-context"])
        report["ablation"][ds_name] = entry

    # ---- 每模式完整指标 + 混淆矩阵 ----
    for m in run_modes:
        for ds_name in run_datasets:
            key = f"{m}/{ds_name}"
            if key not in mode_results:
                continue
            results, metrics, matrix = mode_results[key]
            report["per_mode"][key] = {
                "metrics": metrics,
                "by_category": by_category_breakdown(results),
            }
            report["confusion_matrix"][key] = matrix

    return report


def main():
    parser = argparse.ArgumentParser(description="LLM-VulnDetector v2.1 综合消融评测")
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
    print(f"[并发] {CONCURRENCY} | [超时] {REQUEST_TIMEOUT}s | [重试] {MAX_RETRIES}")

    # 测试连接
    try:
        resp = httpx.get(f"{API_URL}/health", timeout=10)
        if resp.status_code != 200:
            print(f"[警告] API 健康检查失败: {resp.status_code}")
        else:
            print("[API] 健康检查通过")
    except Exception as e:
        print(f"[错误] 无法连接到 API: {e}")
        print("[提示] 请先启动后端: cd backend && uvicorn app.main:app --reload --port 8000")
        sys.exit(1)

    async def _run():
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            mode_results = {}
            for mode_name in args.modes:
                if mode_name not in mode_endpoints:
                    print(f"[警告] 未知模式 {mode_name}, 跳过")
                    continue
                endpoint = mode_endpoints[mode_name]
                for ds_name, samples in datasets.items():
                    key = f"{mode_name}/{ds_name}"
                    results, metrics, matrix = await run_mode(
                        client, samples, endpoint, key, max_samples=args.max_samples)
                    mode_results[key] = (results, metrics, matrix)
            return mode_results

    mode_results = asyncio.run(_run())

    # 生成报告
    report = generate_comparison_report(mode_results, datasets)

    # 写入 JSON 报告
    output_path = Path(args.output) if args.output else (OUTPUT_DIR / "evaluation_v2_report.json")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"\n[报告] 已保存: {output_path}")

    # 写入详细结果
    detail_path = output_path.parent / f"{output_path.stem}_details.json"
    flat = []
    for key, (results, _, _) in mode_results.items():
        for r in results:
            r["_key"] = key
            flat.append(r)
    with open(detail_path, "w", encoding="utf-8") as f:
        json.dump(flat, f, indent=2, ensure_ascii=False, default=str)
    print(f"[详情] 已保存: {detail_path}")

    # 打印消融摘要
    print_ablation_summary(report)

    print("\n评测完成!")


def print_ablation_summary(report: dict):
    """打印消融对比摘要 (回答研究问题)。"""
    print("\n" + "=" * 78)
    print("  三模式消融对比摘要 (回答: 上下文增强 + CoT 是否提升检测效果)")
    print("=" * 78)
    for ds_name, entry in report.get("ablation", {}).items():
        print(f"\n  ▶ 数据集: {ds_name} ({report['meta']['datasets'].get(ds_name, '')})")
        modes = entry.get("modes", {})
        # 表头
        header = f"  {'模式':<14}{'检出率':>8}{'严格':>8}{'误报率':>8}{'P':>7}{'R':>7}{'F1':>7}{'Acc':>7}{'错误':>6}"
        print(header)
        print("  " + "-" * 72)
        for m, mt in modes.items():
            print(f"  {m:<14}{mt['detection_rate']:>7.1f}%{mt['strict_detection_rate']:>7.1f}%"
                  f"{mt['fpr']:>7.1f}%{mt['precision']:>7.1f}%{mt['recall']:>7.1f}%"
                  f"{mt['f1']:>7.1f}%{mt['accuracy']:>7.1f}%{mt['errors']:>6}")
        # delta
        for dk in ("delta_cot_minus_standard", "delta_cot_minus_nocontext", "delta_standard_minus_nocontext"):
            if dk in entry:
                d = entry[dk]
                print(f"  {dk}: 检出{d['detection_rate']:+.1f}pp | 严格{d['strict_detection_rate']:+.1f}pp | "
                      f"误报{d['fpr']:+.1f}pp | F1{d['f1']:+.1f}pp | Acc{d['accuracy']:+.1f}pp")
    print("\n" + "=" * 78)


if __name__ == "__main__":
    main()
