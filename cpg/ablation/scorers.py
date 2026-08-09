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

import json
import re
import urllib.error
import urllib.request
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
    """本地 LLM 评分器：消费 context 文本调本地 Ollama（默认 ``qwen2.5-coder``）。

    仅通过标准 HTTP 接口（``localhost:11434``）与本地模型通信，不依赖任何云端 API，
    以消除 API 漂移（ADR-001）。Ollama 未安装或目标模型未拉取时，``score()`` 不抛异常，
    而是返回 abstain verdict（reason 注明不可达），由消融 harness 计入 abstain 天花板。

    请求侧（request-only）模式无代码 / 无 CPG 上下文，本地 LLM 同样无法判别可利用性，
    直接 abstain（与 StructuralHeuristic 的 request 天花板保持一致）。

    纯标准库实现（urllib），不引入任何第三方依赖，满足「不下载不明来源软件」约束。
    """

    name = "LocalLLMScorer"
    DEFAULT_BASE = "http://localhost:11434"

    def __init__(self, model: str = "qwen2.5-coder:7b", base_url: str = DEFAULT_BASE,
                 timeout: float = 120.0):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._reachable: bool | None = None  # 懒检测缓存

    # ---- 可用性探测 ----
    def reachable(self) -> bool:
        if self._reachable is None:
            self._reachable = self._probe()
        return self._reachable

    def _probe(self) -> bool:
        """探测 Ollama 服务在线且目标模型已拉取（不触发生成）。"""
        try:
            req = urllib.request.Request(f"{self.base_url}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            models = [m.get("name") for m in data.get("models", [])]
            return any(
                self.model == mn
                or self.model.startswith(mn + ":")
                or mn.startswith(self.model)
                for mn in models
            )
        except Exception:
            return False

    # ---- prompt 构造 ----
    SYSTEM = (
        "你是一名资深代码安全审计助手。给定漏洞公告元数据与代码级上下文（CPG 污点切片），"
        "判断目标代码是否可被利用（vulnerable）、无可证伪利用路径（benign）或信息不足"
        "（abstain）。只输出严格 JSON，不要任何解释性文字。"
    )

    def _build_prompt(self, ctx: DetectionContext) -> str:
        meta = ctx.advisory_meta or {}
        cwe = meta.get("cwe")
        summary = meta.get("summary") or ""
        cve = meta.get("cve_id") or "unknown"
        parts = [
            "# 审计任务",
            f"- CVE: {cve}",
            f"- 目标 CWE: {cwe or '未指定'}",
            f"- 公告摘要: {summary}",
        ]
        if ctx.request_info:
            req_txt = json.dumps(ctx.request_info, ensure_ascii=False)
            parts.append(f"\n# 请求侧触发信息\n{req_txt[:2000]}")
        if ctx.code_text:
            parts.append(f"\n# 目标代码（节选）\n```\n{ctx.code_text[:6000]}\n```")
        if ctx.cpg_slices:
            parts.append(f"\n# 代码级上下文（CPG 污点切片）\n{ctx.cpg_slices[:4000]}")
        parts.append(
            "\n# 输出要求\n严格输出如下 JSON，不要任何额外文字：\n"
            '{"verdict":"vulnerable|benign|abstain","cwe":"CWE-xxx 或 null",'
            '"confidence":0.0到1.0的数字,"rationale":"一句话依据"}'
        )
        return "\n".join(parts)

    # ---- 调用 ----
    def _generate(self, prompt: str) -> str:
        payload = json.dumps(
            {
                "model": self.model,
                "prompt": prompt,
                "system": self.SYSTEM,
                "stream": False,
                "options": {"temperature": 0},
            }
        ).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return data.get("response", "")

    @staticmethod
    def _extract_json(text: str) -> dict | None:
        text = text.strip()
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(0))
            except json.JSONDecodeError:
                return None
        return None

    def score(self, ctx: DetectionContext) -> Verdict:
        target = config.normalize_cwe((ctx.advisory_meta or {}).get("cwe"))
        # request-only：无代码 / 无 CPG 上下文 → 本地 LLM 同样无法判别可利用性
        if ctx.cpg_slices is None and not ctx.code_text:
            return Verdict(
                label="abstain", confidence=0.0, cwe=target,
                evidence=[{"reason": "no code/CPG context in request-only mode"}],
            )
        if not self.reachable():
            return Verdict(
                label="abstain", confidence=0.0, cwe=target,
                evidence=[{
                    "reason": f"Ollama unreachable at {self.base_url} "
                              f"(model {self.model} not loaded); LocalLLMScorer disabled",
                }],
            )
        try:
            raw = self._generate(self._build_prompt(ctx))
        except Exception as exc:  # 网络 / 超时 / 生成前错误
            return Verdict(
                label="abstain", confidence=0.0, cwe=target,
                evidence=[{"reason": f"LocalLLM call failed: {exc}"}],
            )
        obj = self._extract_json(raw)
        if not obj:
            return Verdict(
                label="abstain", confidence=0.0, cwe=target,
                evidence=[{"reason": "LocalLLM returned non-JSON", "raw": raw[:500]}],
            )
        label = str(obj.get("verdict", "abstain")).lower()
        if label not in ("vulnerable", "benign", "abstain"):
            label = "abstain"
        cwe_out = config.normalize_cwe(obj.get("cwe")) if obj.get("cwe") else target
        try:
            conf = float(obj.get("confidence", 0.0))
        except (TypeError, ValueError):
            conf = 0.0
        conf = max(0.0, min(1.0, conf))
        return Verdict(
            label=label, confidence=conf, cwe=cwe_out,
            evidence=[{"type": "local-llm", "model": self.model,
                       "rationale": obj.get("rationale", "")}],
        )


# 名称 -> 类 注册表（harness / api 用）
SCORER_REGISTRY: dict[str, type[Scorer]] = {
    "StructuralHeuristicScorer": StructuralHeuristicScorer,
    "CodeQLBaselineScorer": CodeQLBaselineScorer,
    "LocalLLMScorer": LocalLLMScorer,
}
