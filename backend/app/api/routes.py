"""
API 路由 — 漏洞检测 + 批量检测 + 历史记录 + 统计信息。
"""
import logging
from fastapi import APIRouter, Depends, HTTPException, Query

from app.core.llm_engine import LLMEngine, LLMEngineError
from app.core.context_builder import parse_raw_request, build_detection_messages, build_detection_messages_no_context
from app.models.schemas import (
    DetectRequest,
    DetectResponse,
    VulnerabilityItem,
    HistoryListResponse,
    HistoryDetailResponse,
    BatchDetectRequest,
    BatchDetectResponse,
    BatchDetectItem,
    StatsResponse,
)
from app.api.dependencies import get_llm_engine, get_history_store
import uuid

logger = logging.getLogger(__name__)
router = APIRouter()


async def _do_detect(
    raw_request: str,
    llm_engine: LLMEngine,
) -> DetectResponse:
    """内部：执行单次检测，返回 DetectResponse。"""
    parsed = parse_raw_request(raw_request)
    if not parsed.method:
        raise ValueError("无法解析 HTTP 请求行，请检查格式")

    request_id = str(uuid.uuid4())[:8]
    messages = build_detection_messages(parsed, request_id)
    detection_result = await llm_engine.detect(messages)

    vulns_raw = detection_result.get("vulnerabilities", [])
    vulnerabilities = []
    for v in vulns_raw:
        try:
            vulnerabilities.append(VulnerabilityItem(
                type=v.get("type", "未知"),
                severity=v.get("severity", "info"),
                confidence=int(v.get("confidence", 0)),
                location=v.get("location", ""),
                payload=v.get("payload", ""),
                description=v.get("description", ""),
                remediation=v.get("remediation", ""),
            ))
        except Exception as e:
            logger.warning("解析漏洞项失败: %s, raw=%s", e, v)

    risk_level = detection_result.get("risk_level", "info")
    is_vulnerable = detection_result.get("is_vulnerable", len(vulnerabilities) > 0)

    return DetectResponse(
        success=True,
        method=parsed.method,
        path=parsed.path,
        host=parsed.host,
        is_vulnerable=is_vulnerable,
        risk_level=risk_level,
        vulnerabilities=vulnerabilities,
        summary=detection_result.get("summary", ""),
    )


@router.post("/api/detect", response_model=DetectResponse)
async def detect_vulnerability(
    request: DetectRequest,
    llm_engine: LLMEngine = Depends(get_llm_engine),
    history_store=Depends(get_history_store),
):
    """漏洞检测接口。接收原始 HTTP 请求文本，解析后调用 LLM 分析，返回漏洞检测结果。"""
    try:
        response = await _do_detect(request.raw_request, llm_engine)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except LLMEngineError as e:
        logger.error("LLM 检测失败: %s", e)
        raise HTTPException(status_code=502, detail=f"LLM 检测失败: {e}")

    await history_store.save(response)
    return response


@router.post("/api/detect-no-context", response_model=DetectResponse)
async def detect_no_context(
    request: DetectRequest,
    llm_engine: LLMEngine = Depends(get_llm_engine),
):
    """
    消融实验对照接口 — 无上下文增强。
    直接发送原始 HTTP 请求给 LLM，不做结构化解析和预扫描。
    不保存历史记录。
    """
    try:
        parsed = parse_raw_request(request.raw_request)
        if not parsed.method:
            raise ValueError("无法解析 HTTP 请求行，请检查格式")
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    request_id = str(uuid.uuid4())[:8]
    messages = build_detection_messages_no_context(request.raw_request, request_id)

    try:
        detection_result = await llm_engine.detect(messages)
    except LLMEngineError as e:
        logger.error("LLM 检测失败(no-context): %s", e)
        raise HTTPException(status_code=502, detail=f"LLM 检测失败: {e}")

    vulns_raw = detection_result.get("vulnerabilities", [])
    vulnerabilities = []
    for v in vulns_raw:
        try:
            vulnerabilities.append(VulnerabilityItem(
                type=v.get("type", "未知"),
                severity=v.get("severity", "info"),
                confidence=int(v.get("confidence", 0)),
                location=v.get("location", ""),
                payload=v.get("payload", ""),
                description=v.get("description", ""),
                remediation=v.get("remediation", ""),
            ))
        except Exception as e:
            logger.warning("解析漏洞项失败: %s, raw=%s", e, v)

    risk_level = detection_result.get("risk_level", "info")
    is_vulnerable = detection_result.get("is_vulnerable", len(vulnerabilities) > 0)

    return DetectResponse(
        success=True,
        method=parsed.method,
        path=parsed.path,
        host=parsed.host,
        is_vulnerable=is_vulnerable,
        risk_level=risk_level,
        vulnerabilities=vulnerabilities,
        summary=detection_result.get("summary", ""),
    )


@router.post("/api/batch-detect", response_model=BatchDetectResponse)
async def batch_detect(
    request: BatchDetectRequest,
    llm_engine: LLMEngine = Depends(get_llm_engine),
    history_store=Depends(get_history_store),
):
    """批量检测接口。最多50条。"""
    results = []
    total_count = len(request.requests)
    for idx, raw_req in enumerate(request.requests):
        try:
            response = await _do_detect(raw_req, llm_engine)
            await history_store.save(response)
            results.append(BatchDetectItem(
                index=idx, success=True, result=response
            ))
        except ValueError as e:
            results.append(BatchDetectItem(
                index=idx, success=False, error=str(e)
            ))
        except LLMEngineError as e:
            results.append(BatchDetectItem(
                index=idx, success=False, error=f"LLM 错误: {e}"
            ))
        except Exception as e:
            results.append(BatchDetectItem(
                index=idx, success=False, error=f"未知错误: {e}"
            ))

    return BatchDetectResponse(
        success=True,
        total=total_count,
        results=results,
    )


@router.get("/api/history", response_model=HistoryListResponse)
async def get_history(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    history_store=Depends(get_history_store),
):
    """获取历史检测记录（分页）。"""
    items, total = await history_store.list(page=page, page_size=page_size)
    return HistoryListResponse(
        success=True,
        items=items,
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/api/history/{record_id}", response_model=HistoryDetailResponse)
async def get_history_detail(
    record_id: str,
    history_store=Depends(get_history_store),
):
    """获取单条历史检测详情。"""
    record = await history_store.get(record_id)
    if record is None:
        raise HTTPException(status_code=404, detail="记录不存在")
    return HistoryDetailResponse(success=True, data=record)


@router.get("/api/stats", response_model=StatsResponse)
async def get_stats(
    history_store=Depends(get_history_store),
):
    """获取检测统计信息。"""
    stats = await history_store.stats()
    return StatsResponse(success=True, **stats)


@router.delete("/api/history")
async def clear_history(
    history_store=Depends(get_history_store),
):
    """清空所有历史记录。"""
    count = await history_store.clear()
    return {"success": True, "deleted": count}
