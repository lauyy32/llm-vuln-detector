"""
历史记录存储 — SQLite 持久化实现。

接口与 InMemoryHistoryStore 保持一致：
- save(response) -> record_id
- list(page, page_size) -> (items, total)
- get(record_id) -> dict | None
- stats() -> dict  (新增：统计信息)
- clear() -> int   (新增：清空所有记录)
"""
import json
import sqlite3
import uuid
import logging
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)


class SQLiteHistoryStore:
    """SQLite 持久化历史记录存储。"""

    def __init__(self, db_path: str = "data/vulndetector.db"):
        self.db_path = db_path
        self._init_db()
        logger.info("SQLiteHistoryStore 初始化完成: %s", db_path)

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """自动建表（如不存在）。"""
        import os
        db_dir = os.path.dirname(self.db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)

        conn = self._get_conn()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS detection_records (
                record_id        TEXT PRIMARY KEY,
                method           TEXT NOT NULL DEFAULT '',
                path             TEXT NOT NULL DEFAULT '',
                host             TEXT NOT NULL DEFAULT '',
                is_vulnerable    INTEGER NOT NULL DEFAULT 0,
                risk_level       TEXT NOT NULL DEFAULT 'info',
                vuln_count       INTEGER NOT NULL DEFAULT 0,
                vuln_types       TEXT NOT NULL DEFAULT '[]',
                summary          TEXT NOT NULL DEFAULT '',
                raw_request      TEXT NOT NULL DEFAULT '',
                full_response    TEXT NOT NULL DEFAULT '{}',
                timestamp        TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_timestamp
            ON detection_records(timestamp DESC)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_is_vulnerable
            ON detection_records(is_vulnerable)
        """)
        conn.commit()
        conn.close()

    async def save(self, response) -> str:
        """保存一条检测记录，返回 record_id。"""
        record_id = str(uuid.uuid4())[:8]
        vuln_types = list({v.type for v in response.vulnerabilities})
        ts = response.timestamp.isoformat() if isinstance(
            response.timestamp, datetime
        ) else str(response.timestamp)

        full_response = response.model_dump_json()

        conn = self._get_conn()
        conn.execute("""
            INSERT INTO detection_records
                (record_id, method, path, host, is_vulnerable,
                 risk_level, vuln_count, vuln_types, summary,
                 raw_request, full_response, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            record_id,
            response.method,
            response.path,
            response.host,
            int(response.is_vulnerable),
            response.risk_level,
            len(response.vulnerabilities),
            json.dumps(vuln_types, ensure_ascii=False),
            response.summary,
            response.raw_request if hasattr(response, 'raw_request') else '',
            full_response,
            ts,
        ))
        conn.commit()
        conn.close()
        logger.info("保存检测记录: id=%s, vulnerable=%s", record_id, response.is_vulnerable)
        return record_id

    async def list(self, page: int = 1, page_size: int = 20):
        """分页查询历史记录列表（摘要信息）。"""
        offset = (page - 1) * page_size
        conn = self._get_conn()
        total = conn.execute("SELECT COUNT(*) FROM detection_records").fetchone()[0]
        rows = conn.execute("""
            SELECT record_id, method, path, host, is_vulnerable,
                   risk_level, vuln_count, vuln_types, summary, timestamp
            FROM detection_records
            ORDER BY rowid DESC
            LIMIT ? OFFSET ?
        """, (page_size, offset)).fetchall()
        conn.close()

        items = []
        for r in rows:
            items.append({
                "record_id": r["record_id"],
                "method": r["method"],
                "path": r["path"],
                "host": r["host"],
                "is_vulnerable": bool(r["is_vulnerable"]),
                "risk_level": r["risk_level"],
                "vulnerability_count": r["vuln_count"],
                "vuln_types": json.loads(r["vuln_types"]),
                "summary": r["summary"],
                "timestamp": r["timestamp"],
            })
        return items, total

    async def get(self, record_id: str) -> Optional[dict]:
        """获取单条记录的完整响应。"""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT full_response FROM detection_records WHERE record_id = ?",
            (record_id,)
        ).fetchone()
        conn.close()
        if row is None:
            return None
        return json.loads(row["full_response"])

    async def stats(self) -> dict:
        """统计信息：总数、检出率、各类型分布、各风险等级分布。"""
        conn = self._get_conn()
        total = conn.execute("SELECT COUNT(*) FROM detection_records").fetchone()[0]
        vulnerable = conn.execute(
            "SELECT COUNT(*) FROM detection_records WHERE is_vulnerable = 1"
        ).fetchone()[0]

        type_rows = conn.execute("""
            SELECT vuln_types FROM detection_records WHERE is_vulnerable = 1
        """).fetchall()

        risk_rows = conn.execute("""
            SELECT risk_level, COUNT(*) as cnt
            FROM detection_records
            GROUP BY risk_level
        """).fetchall()

        conn.close()

        type_dist = {}
        for r in type_rows:
            for t in json.loads(r["vuln_types"]):
                type_dist[t] = type_dist.get(t, 0) + 1

        risk_dist = {r["risk_level"]: r["cnt"] for r in risk_rows}

        return {
            "total": total,
            "vulnerable": vulnerable,
            "safe": total - vulnerable,
            "detection_rate": round(vulnerable / total * 100, 1) if total else 0,
            "type_distribution": type_dist,
            "risk_distribution": risk_dist,
        }

    async def clear(self) -> int:
        """清空所有记录，返回删除条数。"""
        conn = self._get_conn()
        count = conn.execute("SELECT COUNT(*) FROM detection_records").fetchone()[0]
        conn.execute("DELETE FROM detection_records")
        conn.commit()
        conn.close()
        logger.info("清空历史记录: %d 条", count)
        return count
