"""
FastAPI 依赖注入 — 提供 LLMEngine 和 HistoryStore 的单例。
"""
from app.core.llm_engine import LLMEngine
from app.utils.history_store import SQLiteHistoryStore

_llm_engine: LLMEngine | None = None
_history_store: SQLiteHistoryStore | None = None


def set_llm_engine(engine: LLMEngine):
    global _llm_engine
    _llm_engine = engine


def set_history_store(store: SQLiteHistoryStore):
    global _history_store
    _history_store = store


def get_llm_engine() -> LLMEngine:
    if _llm_engine is None:
        raise RuntimeError("LLMEngine 未初始化")
    return _llm_engine


def get_history_store() -> SQLiteHistoryStore:
    if _history_store is None:
        raise RuntimeError("HistoryStore 未初始化")
    return _history_store
