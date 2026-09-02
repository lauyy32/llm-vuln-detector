"""
泄漏消融自检（无 API，机器验证开关生效）。

回应 DeepSeek 锐评 §5「先告诉答案」指控：SYSTEM_PROMPT 逐签名特征清单 + 预扫描
正则结果喂给模型构成信息泄漏。本脚本验证：
- 默认（含特征）消息同时含逐签名清单（如 "UNION SELECT"）与预扫描块（risk_signals/pre_scan）
- 全关（无特征消融）消息两者均不出现

运行：cd backend && python -m pytest tests/selfcheck_leakage_ablation.py -v
      或 python tests/selfcheck_leakage_ablation.py
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.context_builder import parse_raw_request, build_detection_messages  # noqa: E402


RAW = (
    "GET /search?q=1%27%20OR%20%271%27%3D%271 HTTP/1.1\r\n"
    "Host: example.com\r\n\r\n"
)


def _sys_user(messages):
    sys = next(m["content"] for m in messages if m["role"] == "system")
    user = next(m["content"] for m in messages if m["role"] == "user")
    return sys, user


def test_default_contains_leakage_markers():
    parsed = parse_raw_request(RAW)
    sys_p, user_p = _sys_user(build_detection_messages(parsed, "test"))
    # 默认应含逐签名清单
    assert "UNION SELECT" in sys_p, "默认 System Prompt 应含逐签名特征清单"
    # 默认应含预扫描块
    assert "risk_signals" in user_p, "默认上下文应含预扫描 risk_signals"
    assert "pre_scan" in user_p, "默认上下文应含 pre_scan 块"


def test_clean_absent_leakage_markers():
    parsed = parse_raw_request(RAW)
    sys_p, user_p = _sys_user(build_detection_messages(
        parsed, "test",
        include_pre_scan=False,
        include_feature_list=False,
        include_fewshot=False,
    ))
    # 无特征消融不应含逐签名清单
    assert "UNION SELECT" not in sys_p, "无特征消融 System Prompt 不应含逐签名清单"
    # 不应含预扫描泄漏：逐参数风险信号与 pre_scan 块
    # （global_summary 中 high_risk_params:0 仅为无害计数，不泄漏攻击类别，无需断言）
    assert "risk_signals" not in user_p, "无特征消融上下文不应含 risk_signals"
    assert "pre_scan" not in user_p, "无特征消融上下文不应含 pre_scan 块"


if __name__ == "__main__":
    test_default_contains_leakage_markers()
    test_clean_absent_leakage_markers()
    print("PASS: 泄漏消融开关生效（默认含特征 / 全关无特征）")
