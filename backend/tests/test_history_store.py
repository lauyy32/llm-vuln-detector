"""
SQLiteHistoryStore 单元测试 — 数据持久化。
"""
import pytest
import tempfile
import os
from datetime import datetime
from app.utils.history_store import SQLiteHistoryStore
from app.models.schemas import DetectResponse, VulnerabilityItem


@pytest.fixture
def store(tmp_path):
    db_path = str(tmp_path / "test.db")
    return SQLiteHistoryStore(db_path=db_path)


@pytest.fixture
def sample_response():
    return DetectResponse(
        success=True,
        method="GET",
        path="/test",
        host="example.com",
        is_vulnerable=True,
        risk_level="high",
        vulnerabilities=[
            VulnerabilityItem(
                type="SQL注入",
                severity="high",
                confidence=92,
                location="query.id",
                payload="1' OR '1'='1",
                description="test vuln",
                remediation="use prepared statements",
            )
        ],
        summary="SQL injection detected",
    )


class TestSQLiteHistoryStore:

    @pytest.mark.asyncio
    async def test_save_and_get(self, store, sample_response):
        record_id = await store.save(sample_response)
        assert len(record_id) == 8

        retrieved = await store.get(record_id)
        assert retrieved is not None
        assert retrieved["is_vulnerable"] is True
        assert retrieved["method"] == "GET"

    @pytest.mark.asyncio
    async def test_get_nonexistent(self, store):
        result = await store.get("nonexistent")
        assert result is None

    @pytest.mark.asyncio
    async def test_list(self, store, sample_response):
        for i in range(5):
            await store.save(sample_response)

        items, total = await store.list(page=1, page_size=3)
        assert total == 5
        assert len(items) == 3

        items2, total2 = await store.list(page=2, page_size=3)
        assert total2 == 5
        assert len(items2) == 2

    @pytest.mark.asyncio
    async def test_stats(self, store, sample_response):
        safe_response = DetectResponse(
            success=True,
            method="GET",
            path="/safe",
            host="x.com",
            is_vulnerable=False,
            risk_level="info",
            vulnerabilities=[],
            summary="safe",
        )

        await store.save(sample_response)
        await store.save(sample_response)
        await store.save(safe_response)

        stats = await store.stats()
        assert stats["total"] == 3
        assert stats["vulnerable"] == 2
        assert stats["safe"] == 1
        assert stats["detection_rate"] == 66.7
        assert "SQL注入" in stats["type_distribution"]

    @pytest.mark.asyncio
    async def test_clear(self, store, sample_response):
        await store.save(sample_response)
        await store.save(sample_response)

        count = await store.clear()
        assert count == 2

        items, total = await store.list()
        assert total == 0

    @pytest.mark.asyncio
    async def test_empty_stats(self, store):
        stats = await store.stats()
        assert stats["total"] == 0
        assert stats["detection_rate"] == 0

    @pytest.mark.asyncio
    async def test_persistence_across_connections(self, store, sample_response, tmp_path):
        """测试数据在重新连接后仍然存在。"""
        record_id = await store.save(sample_response)

        # 用相同路径创建新实例
        new_store = SQLiteHistoryStore(db_path=store.db_path)
        retrieved = await new_store.get(record_id)
        assert retrieved is not None
        assert retrieved["is_vulnerable"] is True
