"""
Pydantic 数据模型定义 — 前后端统一数据契约。
"""
from datetime import datetime
from pydantic import BaseModel, Field, field_validator


# ============================================================
#  请求模型
# ============================================================

class DetectRequest(BaseModel):
    """漏洞检测请求。"""
    raw_request: str = Field(
        ...,
        min_length=10,
        description="原始 HTTP 请求文本（包含请求行、请求头、请求体）",
    )

    @field_validator("raw_request")
    @classmethod
    def validate_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("请求内容不能为空")
        return v.strip()


# ============================================================
#  响应模型 — 检测结果
# ============================================================

class VulnerabilityItem(BaseModel):
    """单个漏洞详情。"""
    type: str = Field(..., description="漏洞类型，如 SQL注入、XSS 等")
    severity: str = Field(
        ...,
        description="严重程度: high / medium / low / info",
        pattern="^(high|medium|low|info)$",
    )
    confidence: int = Field(
        0, ge=0, le=100,
        description="置信度 0-100，反映 payload 危险度与漏洞模式匹配度",
    )
    location: str = Field("", description="漏洞所在位置（如 query.id、body.username）")
    payload: str = Field("", description="触发漏洞的具体 payload 片段")
    description: str = Field(..., description="成因分析：为什么判定为该漏洞")
    remediation: str = Field(..., description="修复建议")


class DetectResponse(BaseModel):
    """漏洞检测响应。"""
    success: bool = Field(..., description="请求是否成功")
    method: str = Field("", description="HTTP 请求方法")
    path: str = Field("", description="HTTP 请求路径")
    host: str = Field("", description="目标 Host")
    is_vulnerable: bool = Field(..., description="是否检测到漏洞")
    risk_level: str = Field(
        "info",
        description="整体风险等级: high / medium / low / info",
        pattern="^(high|medium|low|info)$",
    )
    vulnerabilities: list[VulnerabilityItem] = Field(
        default_factory=list,
        description="检测到的漏洞列表",
    )
    summary: str = Field("", description="整体分析摘要")
    timestamp: datetime = Field(default_factory=datetime.now, description="检测时间")


# ============================================================
#  响应模型 — 历史记录
# ============================================================

class HistoryListItem(BaseModel):
    """历史记录列表项（摘要）。"""
    record_id: str
    method: str
    path: str
    host: str
    is_vulnerable: bool
    risk_level: str
    vulnerability_count: int
    timestamp: datetime


class HistoryListResponse(BaseModel):
    """历史记录列表响应。"""
    success: bool
    items: list[HistoryListItem]
    total: int
    page: int
    page_size: int


class HistoryDetailResponse(BaseModel):
    """历史记录详情响应。"""
    success: bool
    data: DetectResponse | None = None


# ============================================================
#  请求/响应模型 — 批量检测
# ============================================================

class BatchDetectRequest(BaseModel):
    """批量检测请求。"""
    requests: list[str] = Field(
        ...,
        min_length=1,
        max_length=50,
        description="原始 HTTP 请求文本列表（最多50条）",
    )


class BatchDetectItem(BaseModel):
    """批量检测单项结果。"""
    index: int = Field(..., description="在批量请求中的序号")
    success: bool = Field(..., description="该条检测是否成功")
    error: str = Field("", description="失败原因（success=false 时）")
    result: DetectResponse | None = Field(None, description="检测结果（success=true 时）")


class BatchDetectResponse(BaseModel):
    """批量检测响应。"""
    success: bool
    total: int
    results: list[BatchDetectItem]


# ============================================================
#  响应模型 — 统计信息
# ============================================================

class StatsResponse(BaseModel):
    """检测统计信息。"""
    success: bool
    total: int = Field(0, description="总检测次数")
    vulnerable: int = Field(0, description="检出漏洞的请求数")
    safe: int = Field(0, description="未检出漏洞的请求数")
    detection_rate: float = Field(0, description="漏洞检出率(%)")
    type_distribution: dict = Field(default_factory=dict, description="各漏洞类型分布")
    risk_distribution: dict = Field(default_factory=dict, description="各风险等级分布")
