"""FastAPI 端点：三模式检测（SPEC §5）。

POST /api/v1/detect
请求体：{"mode":"request|code|both","sample_id":"...","code":"...","request":{...}}
响应体：{"verdict","confidence","cwe","mode","scorer","evidence"}

- mode 非法值由 Pydantic Literal 自动返回 422。
- request 模式：无 CPG 上下文 → StructuralHeuristicScorer 显式 abstain（SPEC §8）。
- code / both 模式：需提供 request.advisory.cwe 作为目标 CWE 才能定向；
  缺 CWE 时直接 abstain（不建库，快速返回）。有 CWE 时调 extract_taint 建库 +
  跑 taint，再交给 StructuralHeuristicScorer。

本期端点只用 StructuralHeuristicScorer（request 走 abstain，code/both 走结构化启发式）。
CodeQLBaselineScorer 主要在 run_ablation.py 的 harness 中使用；此处保留扩展位。
"""

from __future__ import annotations

import sys
from pathlib import Path

# 仓库根引导：保证 `import cpg.ablation.*` 在脚本直跑 / TestClient 下可用
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Literal, Optional

from . import config
from .context_build import build_context
from .cpg_eval import extract_taint
from .scorers import DetectionContext, StructuralHeuristicScorer, Verdict

app = FastAPI(
    title="LLM+CPG Vulnerability Detection - Ablation API",
    version="0.1.0",
    description="三模式（request/code/both）上下文消融实验后端骨架",
)

# 科研本地工具：放开 CORS 便于后续本地前端联调；非生产部署。
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)


class AdvisoryPayload(BaseModel):
    cve_id: Optional[str] = None
    cwe: Optional[str] = None
    summary: Optional[str] = None


class RequestPayload(BaseModel):
    poc: Optional[str] = None
    trigger_input: Optional[str] = None
    advisory: Optional[AdvisoryPayload] = None


class DetectRequest(BaseModel):
    mode: Literal["request", "code", "both"]
    sample_id: str
    code: Optional[str] = None
    request: Optional[RequestPayload] = None


def _respond(verdict: Verdict, mode: str, scorer_name: str) -> dict:
    body = verdict.to_dict()
    body["mode"] = mode
    body["scorer"] = scorer_name
    return body


@app.post("/api/v1/detect")
def detect(req: DetectRequest) -> dict:
    advisory = req.request.advisory if req.request else None
    cwe = (advisory.cwe if advisory else None)
    sample = {
        "sample_id": req.sample_id,
        "cwes": [cwe] if cwe else [],
        "cwe": cwe,
        "summary": (advisory.summary if advisory else None),
        "code_text": req.code,
        "request": (req.request.model_dump() if req.request else None),
    }

    # request 模式：无 CPG 上下文 → abstain（SPEC §8）
    if req.mode == "request":
        ctx = build_context("request", sample)
        verdict = StructuralHeuristicScorer().score(ctx)
        return _respond(verdict, req.mode, StructuralHeuristicScorer.name)

    # code / both 模式：必须有代码
    if req.code is None:
        verdict = Verdict(
            label="abstain", confidence=0.0, cwe=config.normalize_cwe(cwe),
            evidence=[{"reason": "code/both mode requires 'code' in request body"}],
        )
        return _respond(verdict, req.mode, StructuralHeuristicScorer.name)

    # 无目标 CWE：无法定向，直接 abstain（不建库，毫秒级返回）
    if cwe is None:
        verdict = Verdict(
            label="abstain", confidence=0.0, cwe=None,
            evidence=[{"reason": "code/both mode requires request.advisory.cwe to orient structural check"}],
        )
        return _respond(verdict, req.mode, StructuralHeuristicScorer.name)

    # 有代码 + 目标 CWE：建库 + 跑 taint，交给结构化启发式
    workdir = config.WORK_DIR / "api" / (req.sample_id or "sample")
    try:
        rows = extract_taint(req.code, cwe, workdir)
    except RuntimeError as exc:
        verdict = Verdict(
            label="abstain", confidence=0.0, cwe=config.normalize_cwe(cwe),
            evidence=[{"reason": f"extract_taint failed: {exc}"}],
        )
        return _respond(verdict, req.mode, StructuralHeuristicScorer.name)

    ctx = build_context(req.mode, sample, workdir=workdir, taint_rows=rows)
    verdict = StructuralHeuristicScorer(taint_rows=rows).score(ctx)
    return _respond(verdict, req.mode, StructuralHeuristicScorer.name)


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "codeql": str(config.codeql_binary()), "java_home": config.DEFAULT_JAVA_HOME}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8011)
