"""
llm_engine 单元测试 — JSON 解析容错（不实际调用 API）。
"""
import pytest
from app.core.llm_engine import LLMEngine, LLMEngineError


class TestJsonParsing:
    """测试 LLMEngine 的三级 JSON 容错解析。"""

    def _make_engine(self):
        """创建一个不实际调用的 engine（仅用于测试解析方法）。"""
        engine = LLMEngine.__new__(LLMEngine)
        engine.provider = "test"
        engine.api_key = "fake"
        engine.base_url = "http://fake"
        engine.model = "fake"
        engine.timeout = 60
        engine.max_retries = 3
        engine.temperature = 0.1
        engine._client = None
        return engine

    def test_direct_json(self):
        engine = self._make_engine()
        content = '{"is_vulnerable": true, "vulnerabilities": []}'
        result = engine._parse_json_response(content)
        assert result["is_vulnerable"] is True
        assert result["vulnerabilities"] == []

    def test_json_in_code_block(self):
        engine = self._make_engine()
        content = '```json\n{"is_vulnerable": false, "vulnerabilities": []}\n```'
        result = engine._parse_json_response(content)
        assert result["is_vulnerable"] is False

    def test_json_with_surrounding_text(self):
        engine = self._make_engine()
        content = 'Here is the analysis:\n{"is_vulnerable": true, "vulnerabilities": [{"type": "XSS"}]}\nDone.'
        result = engine._parse_json_response(content)
        assert result["is_vulnerable"] is True
        assert len(result["vulnerabilities"]) == 1

    def test_invalid_json_raises(self):
        engine = self._make_engine()
        content = "this is not json at all"
        with pytest.raises(LLMEngineError):
            engine._parse_json_response(content)

    def test_empty_content_raises(self):
        engine = self._make_engine()
        with pytest.raises(LLMEngineError):
            engine._parse_json_response("")

    def test_json_with_nested_braces(self):
        engine = self._make_engine()
        content = '{"is_vulnerable": true, "vulnerabilities": [{"type": "SQL注入", "payload": "1\' OR \'1\'=\'1"}]}'
        result = engine._parse_json_response(content)
        assert result["vulnerabilities"][0]["type"] == "SQL注入"

    def test_json_with_whitespace(self):
        engine = self._make_engine()
        content = '  \n  {"is_vulnerable": false}  \n  '
        result = engine._parse_json_response(content)
        assert result["is_vulnerable"] is False

    def test_json_with_chinese(self):
        engine = self._make_engine()
        content = '{"summary": "参数id存在SQL注入漏洞，高危", "risk_level": "high"}'
        result = engine._parse_json_response(content)
        assert "SQL注入" in result["summary"]


class TestLLMEngineInit:
    """测试 LLMEngine 初始化校验。"""

    def test_missing_api_key_raises(self):
        with pytest.raises(LLMEngineError, match="未配置"):
            LLMEngine({
                "provider": "deepseek",
                "api_key": "",
                "base_url": "http://fake",
                "model": "fake",
            })

    def test_valid_init(self):
        engine = LLMEngine({
            "provider": "deepseek",
            "api_key": "sk-test",
            "base_url": "http://fake",
            "model": "deepseek-chat",
            "timeout": 30,
            "max_retries": 2,
            "temperature": 0.2,
        })
        assert engine.provider == "deepseek"
        assert engine.api_key == "sk-test"
        assert engine.timeout == 30
        assert engine.temperature == 0.2
