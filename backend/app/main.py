"""
FastAPI 应用入口。
启动: uvicorn app.main:app --reload --port 8000
"""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.core.llm_engine import LLMEngine
from app.api.routes import router
from app.api.dependencies import set_llm_engine, set_history_store
from app.utils.logger import setup_logging
from app.utils.history_store import SQLiteHistoryStore

setup_logging()
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用生命周期管理。"""
    # --- 启动 ---
    logger.info(
        "启动 %s, LLM provider=%s, model=%s",
        settings.app_name, settings.llm_provider,
        settings.llm_model or settings.PROVIDER_DEFAULTS.get(settings.llm_provider, {}).get("model", ""),
    )
    llm_engine = LLMEngine(settings.get_llm_config())
    set_llm_engine(llm_engine)

    history_store = SQLiteHistoryStore(db_path="data/vulndetector.db")
    set_history_store(history_store)

    yield

    # --- 关闭 ---
    logger.info("正在关闭 %s ...", settings.app_name)
    await llm_engine.close()
    logger.info("已关闭")


app = FastAPI(
    title="LLM-VulnDetector",
    description="基于大语言模型的 HTTP 攻击载荷识别 API",
    version="2.0.0",
    lifespan=lifespan,
)

# CORS — 允许前端跨域访问
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 挂载路由
app.include_router(router)


@app.get("/health")
async def health_check():
    """健康检查。"""
    return {
        "status": "ok",
        "service": settings.app_name,
        "llm_provider": settings.llm_provider,
    }


@app.get("/")
async def root():
    """根路径 — 返回 API 信息。"""
    return {
        "name": "LLM-VulnDetector",
        "version": "2.0.0",
        "docs": "/docs",
        "health": "/health",
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.debug,
    )
