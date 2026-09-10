# -*- coding: utf-8 -*-
"""Prompt renderer（Code plan 第5阶段）——只负责渲染，不再截断。

- 接收已经过预算验证的 code_text / cpg_slices；
- 超预算直接抛异常（不再 code_text[:8000] / cpg_slices[:12000] 静默截半行）；
- SYSTEM 单一权威定义（其他脚本不得复制）；
- summary 由 protocol 控制，主实验显式 summary=False；
- 渲染确定性（无随机、无 dict 迭代序依赖）。
"""
from __future__ import annotations

import hashlib

# 单一权威 SYSTEM（其他模块 import 此处，不得复制）
SYSTEM = (
    "你是一名资深代码安全审计助手。给定目标 CWE 类型、目标源码节选与代码级上下文（CPG 污点切片），"
    "判断目标代码是否可被利用（vulnerable）、无可证伪利用路径（benign）或信息不足（abstain）。"
    "重要判断原则：污点切片只覆盖数据流型漏洞（路径穿越/SSRF/注入）；切片为空或标注 no flow 不代表目标"
    "安全——鉴权缺失、请求走私、符号链接跟随、信息泄露、输入校验缺失等逻辑型漏洞不产生数据流。"
    "请结合源码语义核查目标 CWE 对应的功能点是否缺失必要的安全控制（如越权检查、边界校验、"
    "协议约束）。只输出严格 JSON，不要任何解释性文字。"
)

OUTPUT_CONTRACT = (
    "\n# 输出要求\n严格输出如下 JSON，不要任何额外文字：\n"
    '{"verdict":"vulnerable|benign|abstain","cwe":"CWE-xxx 或 null",'
    '"confidence":0.0到1.0的数字,"rationale":"一句话依据"}'
)

DEFAULT_MAX_CODE_CHARS = 8000
DEFAULT_MAX_CPG_CHARS = 12000


def _sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def render_prompt(
    meta: dict | None,
    code_text: str | None,
    cpg_slices: str | None,
    *,
    summary: bool = False,
    max_code_chars: int = DEFAULT_MAX_CODE_CHARS,
    max_cpg_chars: int = DEFAULT_MAX_CPG_CHARS,
) -> str:
    """渲染 prompt。超预算抛 ValueError（不截断）。返回 (prompt_text)。"""
    meta = meta or {}
    cve = meta.get("cve_id") or meta.get("cve") or "unknown"
    cwe = meta.get("cwe") or "未指定"

    parts = ["# 审计任务", f"- CVE: {cve}", f"- 目标 CWE: {cwe}"]
    if summary and meta.get("summary"):
        parts.append(f"- 公告摘要: {meta['summary']}")
    if code_text:
        if len(code_text) > max_code_chars:
            raise ValueError(
                f"code_text 超预算 {len(code_text)} > {max_code_chars}，禁止截断")
        parts.append(f"\n# 目标代码（节选）\n```\n{code_text}\n```")
    if cpg_slices:
        if len(cpg_slices) > max_cpg_chars:
            raise ValueError(
                f"cpg_slices 超预算 {len(cpg_slices)} > {max_cpg_chars}，禁止截断")
        parts.append(f"\n# 代码级上下文（CPG 污点切片）\n{cpg_slices}")
    parts.append(OUTPUT_CONTRACT)
    return "\n".join(parts)


def prompt_sha256(prompt: str) -> str:
    return _sha256_text(prompt)


# ---------------------------------------------------------------------------
# V4（候选补丁充分性）：SYSTEM 与输出契约的 V4 权威定义（草案，待 reviewer 冻结）
# ---------------------------------------------------------------------------
SYSTEM_V4 = (
    "你是一名资深代码安全审计助手。给定一段存在漏洞的代码与一个**候选补丁**，"
    "判断：若把该候选补丁应用于给定的代码，是否足以消除目标漏洞。"
    "判据：补丁是否切断了漏洞路径或引入了必要的安全控制。"
    "只输出严格 JSON，不要任何解释性文字。"
)

OUTPUT_CONTRACT_V4 = (
    "\n# 输出要求\n严格输出如下 JSON，不要任何额外文字：\n"
    '{"verdict":"benign|vulnerable|abstain","confidence":0.0到1.0的数字,'
    '"rationale":"一句话依据"}\n'
    "（benign = 候选补丁足以消除目标漏洞；vulnerable = 不足以消除；"
    "abstain = 信息不足）"
)

# V4 表示预算（草案初值；冻结前须由真实 G0 renderer 的 token 测算校准）
DEFAULT_V4_MAX_CODE_CHARS = 24000
DEFAULT_V4_MAX_PATCH_CHARS = 60000


def render_v4_prompt(
    *,
    cve: str | None,
    cwe: str | None,
    code_text: str | None,
    candidate_patch: str | None,
    max_code_chars: int = DEFAULT_V4_MAX_CODE_CHARS,
    max_patch_chars: int = DEFAULT_V4_MAX_PATCH_CHARS,
) -> str:
    """V4 四臂 prompt 渲染（草案）。超预算抛 ValueError（不截断）。

    除 candidate_patch 外，四臂输入完全一致（A1 契约）。
    """
    parts = [SYSTEM_V4, "\n# 审计任务", f"- CVE: {cve or 'unknown'}",
             f"- 目标 CWE: {cwe or '未指定'}"]
    if code_text:
        if len(code_text) > max_code_chars:
            raise ValueError(f"code_text 超预算 {len(code_text)} > {max_code_chars}")
        parts.append(f"\n# 相关代码（vuln 状态）\n```\n{code_text}\n```")
    if candidate_patch:
        if len(candidate_patch) > max_patch_chars:
            raise ValueError(f"candidate_patch 超预算 {len(candidate_patch)} > {max_patch_chars}")
        parts.append(f"\n# 候选补丁\n```diff\n{candidate_patch}\n```")
    parts.append(OUTPUT_CONTRACT_V4)
    return "\n".join(parts)
