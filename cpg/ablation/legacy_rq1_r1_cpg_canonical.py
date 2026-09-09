# -*- coding: utf-8 -*-
"""legacy-rq1-r1-cpg-canonical 表示（确定性 CPG 行序，Experiment design §二.2 补正案）。

与 ``legacy-rq1-r0`` 的**唯一区别**：``cpg_slices`` 的 taint 行在渲染前按稳定键排序
（normalized CWE → 相对路径 → source/sink line → source/sink node → 行哈希），
消除 CodeQL 跨运行 flow 路径返回顺序非确定（实证 143/144 波动）。

``code_text`` 摘录复用 ``legacy_rq1_r0.load_legacy_code_text``（字节级一致），
preflight 与窗口常量也一致。因此本模块只冻结「表示名 + 行序策略」，不复制摘录逻辑，
避免与 r0 出现同源漂移。
"""
from __future__ import annotations

REPRESENTATION = "legacy-rq1-r1-cpg-canonical"

# 摘录逻辑与预算常量复用 r0（保证 code_text 字节级一致）
from cpg.ablation.legacy_rq1_r0 import (  # noqa: E402,F401
    MAX_CODE_CHARS, SUMMARY, load_legacy_code_text, preflight_legacy,
)
# 行序策略：渲染前 sort_taint_rows_canonical，再 build_cpg_slices_text
from cpg.ablation.cpg_eval import (  # noqa: E402,F401
    build_cpg_slices_text, sort_taint_rows_canonical,
)
