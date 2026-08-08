"""Scorer 抽象与三个具体评分器（SPEC §6）。

- ``DetectionContext``：一个样本在某个 mode 下的上下文（request_info / advisory_meta /
  code_text / cpg_slices）。
- ``Verdict``：判定结果（label / confidence / cwe / evidence）。
- ``Scorer``：统一接口 ``score(ctx) -> Verdict``。
- ``CodeQLBaselineScorer``：跑官方 ``python-code-scanning`` 套件得纯静态 baseline，不依赖 mode。
- ``StructuralHeuristicScorer``：吃 cpg_slices 与 taint 行，按「目标 CWE 是否存 source→sink
  流」判 vulnerable，无 LLM；request 模式（无 cpg_slices）→ 显式 abstain（SPEC §8）。
- ``LocalLLMScorer``：预留 stub，``score()`` 抛 ``NotImplementedError``。
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import config

# 注意：run_codeql_baseline 在 CodeQLBaselineScorer.score 内懒加载，避免与
# codeql_baseline（又 import 本模块的 Verdict）形成循环依赖。


# ---------------------------------------------------------------------------
# 数据类
# ---------------------------------------------------------------------------
@dataclass
class DetectionContext:
    request_info: dict | None   # poc / trigger_input
    advisory_meta: dict | None  # cve_id / cwe / summary
    code_text: str | None
    cpg_slices: str | None      # slice_builder / taint 文本


@dataclass
class Verdict:
    label: str                  # vulnerable | benign | abstain
    confidence: float
    cwe: str | None             # 判定（或目标）CWE；abstain 时为 None
    evidence: list = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "confidence": round(self.confidence, 4),
            "cwe": self.cwe,
            "evidence": self.evidence,
        }


# ---------------------------------------------------------------------------
# 抽象基类
# ---------------------------------------------------------------------------
class Scorer(ABC):
    name: str = "Scorer"

    @abstractmethod
    def score(self, ctx: DetectionContext) -> Verdict:
        ...


# ---------------------------------------------------------------------------
# 结构化启发式评分器（无 LLM）
# ---------------------------------------------------------------------------
class StructuralHeuristicScorer(Scorer):
    """按「目标 CWE 是否在 taint 行中存在 source→sink 流」判定。

    - request 模式：ctx.cpg_slices 为 None → 显式 abstain（SPEC §8）。
    - 无目标 CWE（advisory_meta 缺失 cwe）→ 无法定向，abstain。
    - 命中目标 CWE 的流 → vulnerable（confidence=1.0，确定性数据流证据）。
    - 未命中 → benign（confidence=0.7，结构化启发式无法证明不存在）。
    """

    name = "StructuralHeuristicScorer"

    def __init__(self, taint_rows: list[dict] | None = None):
        # 结构化 taint 证据（列 cwe/file/sourceLine/sourceNode/sinkLine/sinkNode）。
        # 由 harness/api 在 extract_taint 后注入；优先级高于从 cpg_slices 文本解析。
        self.taint_rows = taint_rows or []

    @staticmethod
    def _target_cwe(ctx: DetectionContext) -> str | None:
        cwe = (ctx.advisory_meta or {}).get("cwe")
        return config.normalize_cwe(cwe)

    def score(self, ctx: DetectionContext) -> Verdict:
        # request 模式：无 CPG 上下文，显式 abstain（SPEC §8）
        if ctx.cpg_slices is None:
            return Verdict(
                label="abstain",
                confidence=0.0,
                cwe=None,
                evidence=[{"reason": "no CPG context in request mode; ceiling for request-only detection"}],
            )

        target = self._target_cwe(ctx)
        if target is None:
            return Verdict(
                label="abstain",
                confidence=0.0,
                cwe=None,
                evidence=[{"reason": "no target CWE in advisory_meta; cannot orient structural check"}],
            )

        rows = self.taint_rows
        hits = [r for r in rows if config.normalize_cwe(r.get("cwe")) == target]
        if hits:
            evidence = [
                {
                    "type": "taint",
                    "cwe": target,
                    "sourceLine": int(h.get("sourceLine", 0) or 0),
                    "sinkLine": int(h.get("sinkLine", 0) or 0),
                    "file": h.get("file"),
                }
                for h in hits
            ]
            return Verdict(label="vulnerable", confidence=1.0, cwe=target, evidence=evidence)

        return Verdict(
            label="benign",
            confidence=0.7,
            cwe=target,
            evidence=[{"reason": f"no modelled source->sink flow for {target} in CPG slices"}],
        )


# ---------------------------------------------------------------------------
# CodeQL 官方基线评分器
# ---------------------------------------------------------------------------
class CodeQLBaselineScorer(Scorer):
    """调 ``codeql_baseline.run_codeql_baseline`` 得官方套件 verdict，不依赖 mode。

    构造时由 harness/api 注入 ``db_path`` 与 ``sample_file``（复用已建 DB，避免重复建库）。
    若未注入 db_path，则无代码可分析 → abstain。
    """

    name = "CodeQLBaselineScorer"

    def __init__(self, db_path: str | Path | None = None, sample_file: str | Path | None = None):
        self.db_path = Path(db_path) if db_path else None
        self.sample_file = Path(sample_file) if sample_file else None

    def score(self, ctx: DetectionContext) -> Verdict:
        from .codeql_baseline import run_codeql_baseline

        if self.db_path is None or self.sample_file is None:
            return Verdict(
                label="abstain",
                confidence=0.0,
                cwe=None,
                evidence=[{"reason": "CodeQLBaseline requires a built database path; none provided"}],
            )
        target = config.normalize_cwe((ctx.advisory_meta or {}).get("cwe"))
        return run_codeql_baseline(self.db_path, self.sample_file, target)


# ---------------------------------------------------------------------------
# 本地 LLM 评分器（预留 stub）
# ---------------------------------------------------------------------------
class LocalLLMScorer(Scorer):
    """预留：消费 context 文本调 Ollama Qwen2.5-Coder；本期不实现。"""

    name = "LocalLLMScorer"

    def __init__(self, model: str = "qwen2.5-coder"):
        self.model = model

    def score(self, ctx: DetectionContext) -> Verdict:
        raise NotImplementedError(
            "LocalLLMScorer is a stub for the ablation skeleton; wire Ollama Qwen2.5-Coder later."
        )


# 名称 -> 类 注册表（harness / api 用）
SCORER_REGISTRY: dict[str, type[Scorer]] = {
    "StructuralHeuristicScorer": StructuralHeuristicScorer,
    "CodeQLBaselineScorer": CodeQLBaselineScorer,
    "LocalLLMScorer": LocalLLMScorer,
}
