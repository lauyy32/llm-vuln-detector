"""
schemas 单元测试 — Pydantic 数据模型校验。
"""
import pytest
from datetime import datetime
from pydantic import ValidationError

from app.models.schemas import (
    DetectRequest,
    DetectResponse,
    VulnerabilityItem,
    BatchDetectRequest,
    BatchDetectResponse,
    StatsResponse,
)


class TestDetectRequest:
    def test_valid_request(self):
        req = DetectRequest(raw_request="GET /test HTTP/1.1\nHost: example.com")
        assert req.raw_request == "GET /test HTTP/1.1\nHost: example.com"

    def test_too_short(self):
        with pytest.raises(ValidationError):
            DetectRequest(raw_request="short")

    def test_empty_after_strip(self):
        with pytest.raises(ValidationError):
            DetectRequest(raw_request="   \n  \n  ")

    def test_strips_whitespace(self):
        req = DetectRequest(raw_request="  GET /test HTTP/1.1\nHost: x.com  ")
        assert req.raw_request == "GET /test HTTP/1.1\nHost: x.com"


class TestVulnerabilityItem:
    def test_valid_item(self):
        v = VulnerabilityItem(
            type="SQL注入",
            severity="high",
            confidence=92,
            location="query.id",
            payload="1' OR '1'='1",
            description="test",
            remediation="use prepared statements",
        )
        assert v.type == "SQL注入"
        assert v.severity == "high"
        assert v.confidence == 92

    def test_invalid_severity(self):
        with pytest.raises(ValidationError):
            VulnerabilityItem(
                type="XSS",
                severity="critical",  # not in pattern
                confidence=80,
                description="x",
                remediation="y",
            )

    def test_confidence_out_of_range(self):
        with pytest.raises(ValidationError):
            VulnerabilityItem(
                type="XSS",
                severity="high",
                confidence=150,
                description="x",
                remediation="y",
            )

    def test_negative_confidence(self):
        with pytest.raises(ValidationError):
            VulnerabilityItem(
                type="XSS",
                severity="high",
                confidence=-1,
                description="x",
                remediation="y",
            )


class TestDetectResponse:
    def test_valid_response(self):
        resp = DetectResponse(
            success=True,
            method="GET",
            path="/test",
            host="example.com",
            is_vulnerable=True,
            risk_level="high",
            vulnerabilities=[],
            summary="test",
        )
        assert resp.is_vulnerable is True
        assert resp.risk_level == "high"
        assert isinstance(resp.timestamp, datetime)

    def test_invalid_risk_level(self):
        with pytest.raises(ValidationError):
            DetectResponse(
                success=True,
                is_vulnerable=False,
                risk_level="extreme",
            )

    def test_default_values(self):
        resp = DetectResponse(
            success=True,
            is_vulnerable=False,
        )
        assert resp.method == ""
        assert resp.path == ""
        assert resp.vulnerabilities == []
        assert resp.risk_level == "info"


class TestBatchDetectRequest:
    def test_valid_batch(self):
        req = BatchDetectRequest(requests=["GET /a HTTP/1.1\nHost: x", "GET /b HTTP/1.1\nHost: y"])
        assert len(req.requests) == 2

    def test_empty_list(self):
        with pytest.raises(ValidationError):
            BatchDetectRequest(requests=[])

    def test_too_many(self):
        with pytest.raises(ValidationError):
            BatchDetectRequest(requests=["x" * 10] * 51)


class TestStatsResponse:
    def test_default_values(self):
        s = StatsResponse(success=True)
        assert s.total == 0
        assert s.detection_rate == 0
        assert s.type_distribution == {}

    def test_with_data(self):
        s = StatsResponse(
            success=True,
            total=100,
            vulnerable=30,
            safe=70,
            detection_rate=30.0,
            type_distribution={"SQL注入": 10, "XSS": 15},
            risk_distribution={"high": 10, "medium": 15, "low": 5},
        )
        assert s.total == 100
        assert s.type_distribution["SQL注入"] == 10
