"""按 mode 构造 DetectionContext（SPEC §5 / ARCHITECTURE §1）。

- ``request``：只填 request_info / advisory_meta；code_text / cpg_slices 为 None
  → Scorer 判 abstain（SPEC §8「无码检测天花板」）。
- ``code``：填 code_text，并调 extract_taint 得 cpg_slices（taint 文本）。
- ``both``：二者皆填（request_info 仅在 dataset 含请求数据时非空）。

协议修正（2026-08-28）：语料不含请求字段时，request 恒 abstain、both 退化为
code（request_info=None）。主消融默认 ``--modes code``；request/both 仅作天花板
对照点显式启用，不再宣称三模式为三个独立消融维度。

``build_context(mode, sample, ...)`` 保持核心签名；额外关键字参数（workdir / taint_rows /
cpg_slices / include_summary）供 harness 注入预计算产物，避免重复建库。``sample`` 兼容两种数据集形状：

* 实际 ``dataset.jsonl``：``cves``(list) / ``cwe`` / ``files`` / ``summary`` / ``cve_id``
* 文档约定形状：``vuln_code`` / ``fixed_code`` / ``sample_id`` / ``cwe``

并统一把 CWE 归一化为 3 位补零（``CWE-22`` -> ``CWE-022``）以对齐查询输出。
"""

from __future__ import annotations

from pathlib import Path

from . import config
from .cpg_eval import build_ast_section_from_source, build_cpg_slices_text, extract_taint
from .scorers import DetectionContext

VALID_MODES = ("request", "code", "both")


def _sample_id(sample: dict) -> str | None:
    return sample.get("sample_id") or sample.get("cve_id")


def _primary_cwe(sample: dict) -> str | None:
    cwes = sample.get("cwes")
    if not cwes:
        if sample.get("cwe"):
            cwes = [sample["cwe"]]
    if isinstance(cwes, str):
        cwes = [cwes]
    if cwes:
        return config.normalize_cwe(cwes[0])
    return None


def build_context(
    mode: str,
    sample: dict,
    *,
    workdir: str | Path | None = None,
    taint_rows: list[dict] | None = None,
    cpg_slices: str | None = None,
    include_summary: bool = False,
    include_ast: bool = False,
) -> DetectionContext:
    """构造 DetectionContext。

    ``include_summary``（默认 False）：是否把公告摘要写入 advisory_meta。摘要描述漏洞
    的具体位置与成因，直接注入 LLM prompt 构成标签泄漏（DeepSeek 评审确认）；CWE 为
    任务定向（CodeQL/结构启发式等基线共用同一目标 CWE），不属泄漏。主结果默认
    不含摘要，仅隔离实验（--with-summary）显式开启。
    """
    mode = (mode or "").lower()
    if mode not in VALID_MODES:
        raise ValueError(f"invalid mode {mode!r}; expected one of {VALID_MODES}")

    sid = _sample_id(sample)
    cwe = _primary_cwe(sample)
    summary = sample.get("summary") if include_summary else None
    advisory_meta = {"cve_id": sid, "cwe": cwe}
    if summary:
        advisory_meta["summary"] = summary

    if mode == "request":
        # 无代码可分析 → cpg_slices 为 None → Scorer 显式 abstain
        return DetectionContext(
            request_info=sample.get("request"),
            advisory_meta=advisory_meta,
            code_text=None,
            cpg_slices=None,
        )

    # code / both：需要代码文本
    code_text = sample.get("code_text")
    if code_text is None:
        # 缺代码（异常路径）：退化为 abstain 形态
        return DetectionContext(
            request_info=(sample.get("request") if mode == "both" else None),
            advisory_meta=advisory_meta,
            code_text=None,
            cpg_slices=None,
        )

    if taint_rows is None:
        wd = Path(workdir) if workdir else (config.WORK_DIR / "ctx" / (sid or "sample"))
        taint_rows = extract_taint(code_text, cwe, wd)
    if cpg_slices is None:
        ast_text = None
        if include_ast:
            # 优先用样本完整源码（语料库模式下按 prefix 读取真实 .py 文件）物化 AST——
            # 截断后的 code_text 片段常因半个语句而 ast.parse 失败，完整文件则必然合法，
            # 保证「含 AST」条件对所有样本都有有效 AST 边（与 LLM 看到的截断片段的微小
            # 错位可接受：AST 是结构总览，本就允许覆盖片段之外的结构）。
            ast_src = code_text or ""
            if not sample.get("reuse_db") and sample.get("prefix"):
                root = config.CORPUS_SRC / sample["prefix"]
                if root.is_dir():
                    blocks = []
                    for fp in sorted(root.rglob("*.py")):
                        try:
                            blocks.append(
                                f"# ===== FILE: {fp.name} =====\n"
                                + fp.read_text(encoding="utf-8", errors="replace")
                            )
                        except OSError:
                            continue
                    if blocks:
                        ast_src = "\n".join(blocks)
            if ast_src:
                ast_text = "\n".join(build_ast_section_from_source(ast_src))
        cpg_slices = build_cpg_slices_text(taint_rows, code_text, ast_text=ast_text)

    request_info = sample.get("request") if mode == "both" else None
    return DetectionContext(
        request_info=request_info,
        advisory_meta=advisory_meta,
        code_text=code_text,
        cpg_slices=cpg_slices,
    )
