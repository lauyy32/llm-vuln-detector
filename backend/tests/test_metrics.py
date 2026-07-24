#!/usr/bin/env python
"""
指标计算单元测试 (离线, 不调用 API)。
验证 evaluate_v2 的 compute_metrics / compute_confusion_matrix 数学正确性。
"""
import sys
import os
from pathlib import Path

# 使脚本可作为模块导入
sys.path.insert(0, str(Path(__file__).parent))
import evaluate_v2 as ev  # noqa: E402


def _make(matches, expected_vuln=None):
    """构造合成 evaluate 结果。matches: list of (expected_vuln, match, detected, expected_type)。"""
    results = []
    for i, item in enumerate(matches):
        ev_v, match, det, etype = item
        # 复刻 evaluate_sample 的 is_vuln 逻辑
        if ev_v:
            is_vuln = match in ("correct", "wrong_type")
        else:
            is_vuln = (match == "fp")
        r = {
            "sample_id": f"s{i}",
            "category": etype if ev_v else "正常请求",
            "expected_vulnerable": ev_v,
            "expected_type": etype,
            "is_vuln": is_vuln,
            "detected_types": [det] if det else [],
            "best_detected_type": det if det else ("漏报/未识别" if ev_v else "正常"),
            "match": match,
        }
        results.append(r)
    return results


def test_perfect():
    # 10 攻击全对 + 10 良性全对
    m = [(_make if False else None)]  # placeholder
    matches = [(True, "correct", "SQL注入", "SQL注入")] * 10 + \
              [(False, "correct", "正常", "正常请求")] * 10
    res = _make(matches)
    metrics = ev.compute_metrics(res, "test")
    assert metrics["tp"] == 10 and metrics["tn"] == 10 and metrics["fp"] == 0 and metrics["fn"] == 0, metrics
    assert metrics["precision"] == 100.0
    assert metrics["recall"] == 100.0
    assert metrics["f1"] == 100.0
    assert metrics["accuracy"] == 100.0
    assert metrics["detection_rate"] == 100.0
    assert metrics["fpr"] == 0.0
    print("[OK] test_perfect")


def test_typical():
    # 攻击: 7 correct, 2 wrong_type(类型错但抓到), 1 fn(漏报) ; 良性: 8 correct, 2 fp
    matches = (
        [(True, "correct", "SQL注入", "SQL注入")] * 7 +
        [(True, "wrong_type", "SQL注入", "XSS")] * 2 +     # 检测到攻击但类型错 => 攻击级TP
        [(True, "fn", None, "SQL注入")] * 1 +               # 漏报 => FN
        [(False, "correct", "正常", "正常请求")] * 8 +
        [(False, "fp", "SQL注入", "正常请求")] * 2          # 误报 => FP
    )
    res = _make(matches)
    metrics = ev.compute_metrics(res, "test")
    # 攻击级二分类: 抓到的攻击(含类型错)=9 => tp_bin; 漏报=1 => fn; 误报=2 => fp; 正确放行=8 => tn
    assert metrics["tp"] == 9, metrics
    assert metrics["fn"] == 1, metrics
    assert metrics["fp"] == 2, metrics
    assert metrics["tn"] == 8, metrics
    assert metrics["type_correct"] == 7, metrics
    assert metrics["wrong_type"] == 2, metrics
    # precision = tp/(tp+fp) = 9/11 = 81.8
    assert metrics["precision"] == 81.8, metrics["precision"]
    # recall(攻击级) = tp/(tp+fn) = 9/10 = 90.0
    assert metrics["recall"] == 90.0, metrics["recall"]
    # f1 = 2*81.8*90/(81.8+90) = 85.7
    assert metrics["f1"] == 85.7, metrics["f1"]
    # accuracy = (9+8)/20 = 85.0
    assert metrics["accuracy"] == 85.0, metrics["accuracy"]
    # detection_rate(类型精确) = 7/10 = 70.0
    assert metrics["detection_rate"] == 70.0, metrics["detection_rate"]
    # strict_detection_rate(攻击级召回) = 9/10 = 90.0
    assert metrics["strict_detection_rate"] == 90.0, metrics["strict_detection_rate"]
    # type_accuracy = 7/9 = 77.8
    assert metrics["type_accuracy"] == 77.8, metrics["type_accuracy"]
    # fpr = fp/benign = 2/10 = 20.0
    assert metrics["fpr"] == 20.0, metrics["fpr"]
    print("[OK] test_typical")


def test_confusion_matrix():
    matches = (
        [(True, "correct", "SQL注入", "SQL注入")] * 3 +
        [(True, "wrong_type", "XSS", "SQL注入")] * 2 +   # 实际SQLi被判XSS
        [(False, "fp", "XSS", "正常请求")] * 1 +
        [(False, "correct", "正常", "正常请求")] * 4
    )
    res = _make(matches)
    cm = ev.compute_confusion_matrix(res)
    assert cm["SQL注入"]["SQL注入"] == 3, cm
    assert cm["SQL注入"]["XSS"] == 2, cm
    assert cm["正常请求"]["XSS"] == 1, cm
    assert cm["正常请求"]["正常"] == 4, cm
    print("[OK] test_confusion_matrix")


def test_error_handling():
    # 全错误样本不应崩溃, 应返回 errors 计数
    res = [{"sample_id": "e1", "error": "timeout", "match": None}] * 5
    metrics = ev.compute_metrics(res, "test")
    assert metrics["total"] == 5 and metrics["errors"] == 5 and metrics["valid"] == 0, metrics
    assert metrics["error_reasons"].get("timeout") == 5, metrics
    print("[OK] test_error_handling")


if __name__ == "__main__":
    test_perfect()
    test_typical()
    test_confusion_matrix()
    test_error_handling()
    print("\n所有指标单测通过 ✅")
