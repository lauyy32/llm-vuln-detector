"""按 mode 构造 DetectionContext（SPEC §5 / ARCHITECTURE §1）。

- ``request``：只填 request_info / advisory_meta；code_text / cpg_slices 为 None
  → Scorer 判 abstain（SPEC §8「无码检测天花板」）。
- ``code``：填 code_text，并调 extract_taint 得 cpg_slices（taint 文本）。
- ``both``：二者皆填（request_info 仅在 dataset 含请求数据时非空）。

``build_context(mode, sample, ...)`` 保持核心签名；额外关键字参数（workdir / taint_rows /
cpg_slices）供 harness 注入预计算产物，避免重复建库。``sample`` 兼容两种数据集形状：

* 实际 ``dataset.jsonl``：``cves``(list) / ``cwe`` / ``files`` / ``summary`` / ``cve_id``
* 文档约定形状：``vuln_code`` / ``fixed_code`` / ``sample_id`` / ``cwe``

并统一把 CWE 归一化为 3 位补零（``CWE-22`` -> ``CWE-022``）以对齐查询输出。
"""

from __future__ import annotations

from pathlib import Path

from . import config
from .cpg_eval import build_cpg_slices_text, extract_taint
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
) -> DetectionContext:
    mode = (mode or "").lower()
    if mode not in VALID_MODES:
        raise ValueError(f"invalid mode {mode!r}; expected one of {VALID_MODES}")

    sid = _sample_id(sample)
    cwe = _primary_cwe(sample)
    summary = sample.get("summary")
    advisory_meta = {"cve_id": sid, "cwe": cwe, "summary": summary}

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
        cpg_slices = build_cpg_slices_text(taint_rows, code_text)

    request_info = sample.get("request") if mode == "both" else None
    return DetectionContext(
        request_info=request_info,
        advisory_meta=advisory_meta,
        code_text=code_text,
        cpg_slices=cpg_slices,
    )
