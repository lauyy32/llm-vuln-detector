"""Scorer 抽象与四个具体评分器（SPEC §6）。

- ``DetectionContext``：一个样本在某个 mode 下的上下文（request_info / advisory_meta /
  code_text / cpg_slices）。
- ``Verdict``：判定结果（label / confidence / cwe / evidence）。
- ``Scorer``：统一接口 ``score(ctx) -> Verdict``。
- ``CodeQLBaselineScorer``：跑官方 python Security/CWE 定向查询得纯静态 baseline，不依赖 mode。
- ``StructuralHeuristicScorer``：吃 cpg_slices 与 taint 行，按「目标 CWE 是否存 source→sink
  流」判 vulnerable，无 LLM；request 模式（无 cpg_slices）→ 显式 abstain（SPEC §8）。
- ``ConfigSigScorer``：结构型/配置签名基线，按目标 CWE 在源码中匹配不安全配置签名
  （如 CWE-295 证书校验关闭、CWE-59 符号链接跟随、CWE-200 调试暴露）；对基于缺失的
  CWE（020/400/444/639/862/863）显式 abstain。纯正则/AST 扫描，无 LLM、无 CodeQL。
- ``LocalLLMScorer``：本地 Ollama HTTP 接口（urllib），模型不可达时自动 abstain。
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
    DEFAULT_BASE = config.OLLAMA_BASE  # 与 config.OLLAMA_BASE 同源（可环境变量覆盖）

    def __init__(self, model: str = "qwen2.5-coder:7b", base_url: str = DEFAULT_BASE,
                 timeout: float = 120.0, raw_log: str | Path | None = None,
                 seed: int | None = None):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.raw_log = Path(raw_log) if raw_log else None  # LLM 原始响应落盘（可复现性）
        self.seed = seed  # Ollama 采样 seed（temperature=0 时仍显式声明，满足可复现审计）
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
        "你是一名资深代码安全审计助手。给定目标 CWE 类型、目标源码节选与代码级上下文（CPG 污点切片），"
        "判断目标代码是否可被利用（vulnerable）、无可证伪利用路径（benign）或信息不足（abstain）。"
        "重要判断原则：污点切片只覆盖数据流型漏洞（路径穿越/SSRF/注入）；切片为空或标注 no flow 不代表目标"
        "安全——鉴权缺失、请求走私、符号链接跟随、信息泄露、输入校验缺失等逻辑型漏洞不产生数据流。"
        "请结合源码语义核查目标 CWE 对应的功能点是否缺失必要的安全控制（如越权检查、边界校验、"
        "协议约束）。只输出严格 JSON，不要任何解释性文字。"
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
        ]
        if summary:
            parts.append(f"- 公告摘要: {summary}")
        if ctx.request_info:
            req_txt = json.dumps(ctx.request_info, ensure_ascii=False)
            parts.append(f"\n# 请求侧触发信息\n{req_txt[:2000]}")
        if ctx.code_text:
            parts.append(f"\n# 目标代码（节选）\n```\n{ctx.code_text[:6000]}\n```")
        if ctx.cpg_slices:
            parts.append(f"\n# 代码级上下文（CPG 污点切片）\n{ctx.cpg_slices[:12000]}")
        parts.append(
            "\n# 输出要求\n严格输出如下 JSON，不要任何额外文字：\n"
            '{"verdict":"vulnerable|benign|abstain","cwe":"CWE-xxx 或 null",'
            '"confidence":0.0到1.0的数字,"rationale":"一句话依据"}'
        )
        return "\n".join(parts)

    # ---- 调用 ----
    def _generate(self, prompt: str) -> str:
        options: dict = {"temperature": 0}
        if self.seed is not None:
            options["seed"] = self.seed
        payload = json.dumps(
            {
                "model": self.model,
                "prompt": prompt,
                "system": self.SYSTEM,
                "stream": False,
                "options": options,
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

    def _log_raw(self, ctx: DetectionContext, prompt: str, raw: str) -> None:
        """把每次 LLM 调用的完整输入/输出落盘为 JSONL（可复现性审计）。

        ``ctx.advisory_meta`` 可能含 ``cve_id``；以该字段关联样本。写入失败静默忽略
        （日志文件不可写不阻断消融流程）。
        """
        if self.raw_log is None:
            return
        try:
            self.raw_log.parent.mkdir(parents=True, exist_ok=True)
            rec = {
                "cve_id": (ctx.advisory_meta or {}).get("cve_id"),
                "mode": "request" if (ctx.cpg_slices is None and not ctx.code_text) else
                        ("both" if ctx.request_info else "code"),
                "model": self.model,
                "seed": self.seed,
                "temperature": 0,
                "prompt": prompt,
                "raw_response": raw,
            }
            with self.raw_log.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        except Exception:
            pass

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
            prompt = self._build_prompt(ctx)
            raw = self._generate(prompt)
        except Exception as exc:  # 网络 / 超时 / 生成前错误
            return Verdict(
                label="abstain", confidence=0.0, cwe=target,
                evidence=[{"reason": f"LocalLLM call failed: {exc}"}],
            )
        self._log_raw(ctx, prompt, raw)
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


# ---------------------------------------------------------------------------
# 结构型 / 配置签名基线评分器（ConfigSig）
# ---------------------------------------------------------------------------
class ConfigSigScorer(Scorer):
    """结构型/配置签名基线：在源码中按目标 CWE 匹配「不安全配置/结构签名」。

    定位：与 CodeQLBaseline（官方污点/套件）、StructuralHeuristic（自建 taint）并列的
    **第三类静态基线**，专门覆盖 CodeQL Python 套件无成熟查询的逻辑型 CWE
    （如 CWE-295 证书校验、CWE-59 符号链接跟随、CWE-200 调试信息暴露）。
    纯正则/AST 扫描源码，无 LLM、无第三方依赖、不触发 CodeQL 建库，秒级。

    设计纪律（OPEN-DECISIONS #8）：
    - 仅对「**存在可检测正签名**」的 CWE（295/59/200）给出 vulnerable/benign 判定；
    - 对「**基于缺失（absence-based）**」或「**框架/循环级、无精确签名**」的 CWE
      （020/400/444/639/862/863）显式 abstain——签名法无法证明「某处缺少某个检查」，
      也易对通用模式（如 ``while True``）产生误报；这类恰好是 LLM+CPG 语义层要补的盲区，
      不以假阳性冒充覆盖。
    - request 模式（ctx.cpg_slices 为 None）无代码上下文，显式 abstain（与
      StructuralHeuristic 的 request 天花板保持一致）。

    信号来源：优先 ``source_root``（真实模式 staged 源码目录）；否则回退 ctx.code_text。
    """

    name = "ConfigSigScorer"

    # 基于缺失 / 无精确签名：签名法无法覆盖，显式 abstain
    ABSTAIN_CWES = {"CWE-020", "CWE-400", "CWE-444", "CWE-639", "CWE-862", "CWE-863"}

    # 各 CWE 的「不安全配置/结构签名」正则（行级匹配，file:line:snippet 作为证据）
    SIGNATURES: dict[str, list[re.Pattern[str]]] = {
        "CWE-295": [
            re.compile(r"verify\s*=\s*False", re.I),
            re.compile(r"check_hostname\s*=\s*False", re.I),
            re.compile(r"CERT_NONE"),
            re.compile(r"ssl\.CERT_NONE"),
        ],
        "CWE-59": [
            re.compile(r"os\.symlink\s*\("),
            re.compile(r"followlinks\s*=\s*True", re.I),
        ],
        "CWE-200": [
            re.compile(r"debug\s*=\s*True", re.I),
            re.compile(r"app\.debug"),
            re.compile(r"werkzeug\.debug", re.I),
            re.compile(r"traceback\.print_exc"),
        ],
    }

    def __init__(self, source_root: str | Path | None = None):
        self.source_root = Path(source_root) if source_root else None

    # ---- 源码收集 ----
    def _collect_sources(self, ctx: DetectionContext) -> list[tuple[str, str]]:
        """返回 [(file_label, text), ...]。优先 source_root 目录，否则回退 code_text。"""
        out: list[tuple[str, str]] = []
        if self.source_root and self.source_root.exists():
            for p in sorted(self.source_root.rglob("*.py")):
                try:
                    out.append((str(p), p.read_text(encoding="utf-8", errors="ignore")))
                except Exception:
                    continue
        if not out:
            ct = ctx.code_text
            if ct and ct.strip():
                out.append(("<code_text>", ct))
        return out

    # ---- CWE-295 通配符 DNS 专项（实战形态：SAN/host 中允许 ``*``）----
    @staticmethod
    def _wildcard_in_cert_context(line: str) -> bool:
        low = line.lower()
        if not any(k in low for k in
                   ("host", "san", "dns", "cert", "verify", "common_name", "cn")):
            return False
        return ("*" in line) or ("fnmatch" in low) or ("wildcard" in low)

    def _match(self, cwe: str, sources: list[tuple[str, str]]) -> list[dict]:
        pats = self.SIGNATURES.get(cwe, [])
        hits: list[dict] = []
        for fname, text in sources:
            for i, line in enumerate(text.splitlines(), 1):
                matched = any(p.search(line) for p in pats)
                if not matched and cwe == "CWE-295" and self._wildcard_in_cert_context(line):
                    matched = True
                if matched:
                    hits.append({"file": fname, "line": i, "snippet": line.strip()[:160]})
        return hits

    def score(self, ctx: DetectionContext) -> Verdict:
        # request 模式：无代码上下文
        if ctx.cpg_slices is None:
            return Verdict(
                label="abstain", confidence=0.0, cwe=None,
                evidence=[{"reason": "no code context in request mode; ConfigSig is code-based"}],
            )
        target = config.normalize_cwe((ctx.advisory_meta or {}).get("cwe"))
        if target is None:
            return Verdict(
                label="abstain", confidence=0.0, cwe=None,
                evidence=[{"reason": "no target CWE; cannot orient signature check"}],
            )
        # 基于缺失 / 无精确签名的 CWE：签名法无法覆盖
        if target in self.ABSTAIN_CWES:
            return Verdict(
                label="abstain", confidence=0.0, cwe=target,
                evidence=[{
                    "reason": f"{target} is absence-based / no precise source signature; "
                              f"out of ConfigSig scope (motivates LLM+CPG semantic layer)",
                }],
            )
        sources = self._collect_sources(ctx)
        if not sources:
            return Verdict(
                label="abstain", confidence=0.0, cwe=target,
                evidence=[{"reason": "no source available for ConfigSig scan"}],
            )
        hits = self._match(target, sources)
        if hits:
            return Verdict(
                label="vulnerable", confidence=0.8, cwe=target,
                evidence=[{
                    "type": "config-sig", "cwe": target,
                    "file": h["file"], "line": h["line"], "snippet": h["snippet"],
                } for h in hits[:5]],
            )
        return Verdict(
            label="benign", confidence=0.6, cwe=target,
            evidence=[{"reason": f"no config signature for {target} in source"}],
        )


class CPGEvidenceScorer(Scorer):
    """消费 CPG 污点切片文本（build_cpg_slices_text 渲染产物），做确定性判定。

    与 StructuralHeuristicScorer（吃注入的 taint_rows 结构化数据）不同，本评分器
    **直接解析 cpg_slices 文本**，模拟「规则/LLM 读取 CPG 切片」的最小形态：CPG
    切片文本本身即可作为独立判定输入，无需额外结构化注入。

    - request 模式（ctx.cpg_slices 为 None）→ abstain；
    - 切片声明「no untrusted input reaches a modelled sink」→ benign（CPG 已证明无 source→sink 连通）；
    - 切片含「reaches sink at L」污点流 → vulnerable（confidence=0.8）；
    - 切片非空但无结构化流信息（异常）→ abstain。

    无 LLM、无下载、无外部依赖。其意义在于为 LocalLLMScorer 提供「同吃 cpg_slices
    文本、但确定性解析」的对照基线，使③（LLM+CPG）的语义增量可被干净量化。
    """

    name = "CPGEvidenceScorer"

    _NO_FLOW_RE = re.compile(r"no untrusted input reaches a modelled sink", re.I)
    _FLOW_RE = re.compile(r"reaches sink at L\d+", re.I)
    _CWE_HEAD_RE = re.compile(r"^###\s+(CWE-\d+)", re.M)

    @staticmethod
    def _parse_flow_cwes(slices: str) -> list[str]:
        """按 `### CWE-XXX` 分段，返回含污点流的 CWE 列表。"""
        flows: list[str] = []
        parts = CPGEvidenceScorer._CWE_HEAD_RE.split(slices)
        # parts: ['', 'CWE-022', 'body...', 'CWE-918', 'body...', ...]
        for i in range(1, len(parts), 2):
            cwe = parts[i]
            body = parts[i + 1] if i + 1 < len(parts) else ""
            if CPGEvidenceScorer._FLOW_RE.search(body):
                flows.append(cwe)
        return flows

    def score(self, ctx: DetectionContext) -> Verdict:
        if ctx.cpg_slices is None:
            return Verdict(
                label="abstain", confidence=0.0, cwe=None,
                evidence=[{"reason": "no CPG slice in request mode; ceiling for request-only detection"}],
            )
        slices = ctx.cpg_slices
        target = config.normalize_cwe((ctx.advisory_meta or {}).get("cwe"))
        if self._NO_FLOW_RE.search(slices):
            return Verdict(
                label="benign", confidence=0.6, cwe=target,
                evidence=[{"type": "cpg-evidence", "reason": "CPG taint slice: no source->sink flow"}],
            )
        flow_cwes = self._parse_flow_cwes(slices)
        if flow_cwes:
            norm_flows = {config.normalize_cwe(c) for c in flow_cwes}
            # D5 门禁（OPEN #25，2026-09-02）：CPG 污点证据仅在「检测到的污点流 CWE
            # 与目标 CWE 一致」时才构成对本 CVE 的判定；否则该流属于越界证据
            # （如逻辑类 CVE 的切片里出现无关的 CWE-022/918 流，或 taint CWE 与目标
            # SSRF 不匹配），不能据此判定，显式 abstain。此门禁与
            # StructuralHeuristicScorer 的「目标 CWE 匹配」逻辑对齐，消除 §8.5 的
            # 双标误报，且不依赖任何 per-CVE 调参。
            if target is not None and target in norm_flows:
                return Verdict(
                    label="vulnerable", confidence=0.8, cwe=target,
                    evidence=[{"type": "cpg-evidence", "cwe": target, "flows": len(flow_cwes)}],
                )
            return Verdict(
                label="abstain", confidence=0.0, cwe=target,
                evidence=[{
                    "type": "cpg-evidence",
                    "reason": "taint flow(s) present but CWE mismatch with target; "
                              "out of CPG evidence scope for this CVE",
                    "flow_cwes": sorted(c for c in norm_flows if c),
                    "target": target,
                }],
            )
        # 切片非空但无结构化流信息（异常，如渲染格式变更）
        return Verdict(
            label="abstain", confidence=0.0, cwe=target,
            evidence=[{"reason": "CPG slice present but no flow info; format anomaly"}],
        )


# ---------------------------------------------------------------------------
# 已发表 LLM 方法风格基线（D3 head-to-head）
# ---------------------------------------------------------------------------
class PublishedLLMBaselineScorer(LocalLLMScorer):
    """D3 head-to-head 基线：复现已发表 LLM 漏洞检测器风格的**纯源码**判定。

    与 LocalLLMScorer（消费 CPG 污点切片增强上下文）同属本地 Ollama 调用，但本基线
    **只喂函数源码（code-only）**，不含任何 CPG 证据——对应文献中零样本 LLM 漏洞检测器
    （LineVul 风格 prompt 基线 / 通用 LLM-as-vuln-detector）的常见做法。两者同模型、同样本、
    仅上下文差异，构成干净对照，量化「CPG 证据上下文」对 LLM 判定的增量（D3 回应审稿『无 SOTA』）。

    复用 LocalLLMScorer 的 reachable/probe/generate/extract_json/_log_raw；仅重写 SYSTEM 与
    _build_prompt 为 code-only，并令 score() 在无源码时 abstain。纯标准库 urllib，无第三方依赖。
    """

    name = "PublishedLLMBaselineScorer"

    SYSTEM = (
        "你是一名代码漏洞审查助手。给定目标 CWE 类型与待审查的函数源码，"
        "判断该函数是否含有该类型漏洞（vulnerable）或无可证伪漏洞（benign）。"
        "只依据所给源码本身判断，不假设任何外部上下文或数据流分析结论。只输出严格 JSON，不要任何解释性文字。"
    )

    def _build_prompt(self, ctx: DetectionContext) -> str:
        meta = ctx.advisory_meta or {}
        cwe = meta.get("cwe")
        summary = meta.get("summary") or ""
        cve = meta.get("cve_id") or "unknown"
        parts = [
            "# 漏洞审查任务",
            f"- CVE: {cve}",
            f"- 目标 CWE: {cwe or '未指定'}",
        ]
        if summary:
            parts.append(f"- 公告摘要: {summary}")
        if ctx.code_text and ctx.code_text.strip():
            parts.append(f"\n# 待审查函数源码\n```\n{ctx.code_text[:6000]}\n```")
        else:
            # 无源码则无法审查，返回空串让 score() 判 abstain
            return ""
        parts.append(
            "\n# 输出要求\n严格输出如下 JSON，不要任何额外文字：\n"
            '{"verdict":"vulnerable|benign|abstain","cwe":"CWE-xxx 或 null",'
            '"confidence":0.0到1.0的数字,"rationale":"一句话依据"}'
        )
        return "\n".join(parts)

    def score(self, ctx: DetectionContext) -> Verdict:
        target = config.normalize_cwe((ctx.advisory_meta or {}).get("cwe"))
        if not ctx.code_text or not ctx.code_text.strip():
            return Verdict(
                label="abstain", confidence=0.0, cwe=target,
                evidence=[{"reason": "no source code provided; code-only LLM baseline cannot review"}],
            )
        if not self.reachable():
            return Verdict(
                label="abstain", confidence=0.0, cwe=target,
                evidence=[{"reason": f"Ollama unreachable at {self.base_url} (model {self.model})"}],
            )
        try:
            prompt = self._build_prompt(ctx)
            raw = self._generate(prompt)
        except Exception as exc:
            return Verdict(
                label="abstain", confidence=0.0, cwe=target,
                evidence=[{"reason": f"PublishedLLM call failed: {exc}"}],
            )
        self._log_raw(ctx, prompt, raw)
        obj = self._extract_json(raw)
        if not obj:
            return Verdict(
                label="abstain", confidence=0.0, cwe=target,
                evidence=[{"reason": "PublishedLLM returned non-JSON", "raw": raw[:500]}],
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
            evidence=[{"type": "published-llm-baseline", "model": self.model,
                       "rationale": obj.get("rationale", "")}],
        )


# 名称 -> 类 注册表（harness / api 用）
SCORER_REGISTRY: dict[str, type[Scorer]] = {
    "StructuralHeuristicScorer": StructuralHeuristicScorer,
    "CodeQLBaselineScorer": CodeQLBaselineScorer,
    "ConfigSigScorer": ConfigSigScorer,
    "CPGEvidenceScorer": CPGEvidenceScorer,
    "LocalLLMScorer": LocalLLMScorer,
    "PublishedLLMBaselineScorer": PublishedLLMBaselineScorer,
}
