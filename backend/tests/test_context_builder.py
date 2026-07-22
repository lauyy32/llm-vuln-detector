"""
context_builder 单元测试 — HTTP 解析与上下文构造。
"""
import pytest
from app.core.context_builder import (
    parse_raw_request,
    build_structured_context,
    build_detection_messages,
    build_detection_messages_no_context,
    scan_risk_signals,
    RISK_PATTERNS,
)


class TestParseRawRequest:
    """测试原始 HTTP 请求解析。"""

    def test_get_with_query_params(self):
        raw = "GET /search?q=hello&page=2 HTTP/1.1\nHost: example.com"
        result = parse_raw_request(raw)
        assert result.method == "GET"
        assert result.path == "/search"
        assert result.host == "example.com"
        assert len(result.query_params) == 2
        assert result.query_params[0].name == "q"
        assert result.query_params[0].value == "hello"
        assert result.query_params[1].name == "page"
        assert result.query_params[1].value == "2"

    def test_post_form_body(self):
        raw = (
            "POST /login HTTP/1.1\n"
            "Host: example.com\n"
            "Content-Type: application/x-www-form-urlencoded\n"
            "\n"
            "username=admin&password=123456"
        )
        result = parse_raw_request(raw)
        assert result.method == "POST"
        assert result.body_type == "form"
        assert len(result.body_params) == 2
        assert result.body_params[0].name == "username"
        assert result.body_params[0].value == "admin"

    def test_post_json_body(self):
        raw = (
            "POST /api/user HTTP/1.1\n"
            "Host: api.test\n"
            "Content-Type: application/json\n"
            "\n"
            '{"name":"test","age":25}'
        )
        result = parse_raw_request(raw)
        assert result.method == "POST"
        assert result.body_type == "json"
        assert len(result.body_params) == 2
        assert result.body_params[0].name == "name"
        assert result.body_params[0].value == "test"

    def test_post_xml_body(self):
        raw = (
            "POST /api/xml HTTP/1.1\n"
            "Host: api.test\n"
            "Content-Type: application/xml\n"
            "\n"
            "<?xml version=\"1.0\"?><root>test</root>"
        )
        result = parse_raw_request(raw)
        assert result.body_type == "xml"
        assert len(result.body_params) == 1

    def test_empty_request(self):
        result = parse_raw_request("")
        assert result.method == ""
        assert result.path == ""

    def test_malformed_request_line(self):
        raw = "GARBAGE"
        result = parse_raw_request(raw)
        assert result.method == ""
        assert result.path == ""

    def test_crlf_normalization(self):
        raw = "GET /test HTTP/1.1\r\nHost: example.com\r\n"
        result = parse_raw_request(raw)
        assert result.method == "GET"
        assert result.host == "example.com"

    def test_headers_parsing(self):
        raw = (
            "GET /test HTTP/1.1\n"
            "Host: example.com\n"
            "Cookie: session=abc123\n"
            "Authorization: Bearer token123\n"
            "Content-Type: text/plain"
        )
        result = parse_raw_request(raw)
        assert result.headers["Host"] == "example.com"
        assert result.headers["Cookie"] == "session=abc123"
        assert result.headers["Authorization"] == "Bearer token123"

    def test_url_decoding(self):
        raw = "GET /search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E HTTP/1.1\nHost: test.com"
        result = parse_raw_request(raw)
        assert "<script>alert(1)</script>" in result.query_params[0].decoded


class TestRiskSignals:
    """测试正则预扫描。"""

    def test_sql_injection_signal(self):
        signals = scan_risk_signals("1' OR '1'='1")
        assert "sql_meta_char" in signals
        assert "sql_keyword" in signals

    def test_xss_signal(self):
        signals = scan_risk_signals("<script>alert(1)</script>")
        assert "xss_tag" in signals

    def test_command_injection_signal(self):
        signals = scan_risk_signals("127.0.0.1;cat /etc/passwd")
        assert "shell_meta" in signals
        assert "shell_keyword" in signals

    def test_path_traversal_signal(self):
        signals = scan_risk_signals("../../../etc/passwd")
        assert "path_traversal" in signals

    def test_ssrf_signal(self):
        signals = scan_risk_signals("http://127.0.0.1:8080/admin")
        assert "ssrf_internal" in signals

    def test_safe_value_no_signals(self):
        signals = scan_risk_signals("python tutorial")
        assert len(signals) == 0

    def test_all_patterns_are_valid_regex(self):
        """确保所有正则模式都能编译。"""
        import re
        for name, pattern in RISK_PATTERNS.items():
            try:
                re.compile(pattern)
            except re.error as e:
                pytest.fail(f"正则 {name} 编译失败: {e}")


class TestContextBuilder:
    """测试上下文构造。"""

    def test_build_structured_context(self):
        raw = "GET /search?q=test&page=1 HTTP/1.1\nHost: example.com"
        parsed = parse_raw_request(raw)
        ctx = build_structured_context(parsed, "test-001")
        import json
        ctx_dict = json.loads(ctx)
        assert ctx_dict["request_id"] == "test-001"
        assert ctx_dict["method"] == "GET"
        assert ctx_dict["path"] == "/search"
        assert len(ctx_dict["query_params"]) == 2

    def test_build_detection_messages(self):
        raw = "GET /search?q=test HTTP/1.1\nHost: example.com"
        parsed = parse_raw_request(raw)
        messages = build_detection_messages(parsed, "test-002")
        assert len(messages) == 2
        assert messages[0]["role"] == "system"
        assert messages[1]["role"] == "user"
        assert "test-002" in messages[1]["content"]
        assert "结构化上下文" in messages[1]["content"]

    def test_build_detection_messages_no_context(self):
        raw = "GET /search?q=test HTTP/1.1\nHost: example.com"
        messages = build_detection_messages_no_context(raw, "test-003")
        assert len(messages) == 2
        assert messages[0]["role"] == "system"
        assert messages[1]["role"] == "user"
        assert "test-003" in messages[1]["content"]
        assert "结构化上下文" not in messages[1]["content"]

    def test_context_includes_risk_signals(self):
        raw = "GET /search?q=1' OR '1'='1 HTTP/1.1\nHost: test.com"
        parsed = parse_raw_request(raw)
        ctx = build_structured_context(parsed, "test-004")
        import json
        ctx_dict = json.loads(ctx)
        assert len(ctx_dict["pre_scan"]["high_risk_params"]) > 0
        assert "q" in ctx_dict["pre_scan"]["high_risk_params"]

    def test_long_body_value_truncated(self):
        long_val = "A" * 500
        raw = f'POST /api HTTP/1.1\nHost: t.com\nContent-Type: application/json\n\n{{"data":"{long_val}"}}'
        parsed = parse_raw_request(raw)
        ctx = build_structured_context(parsed, "test-005")
        import json
        ctx_dict = json.loads(ctx)
        for p in ctx_dict["body_params"]:
            if p["name"] == "data":
                assert len(p["value"]) <= 200
