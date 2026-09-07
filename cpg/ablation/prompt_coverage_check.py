# -*- coding: utf-8 -*-
"""61539 源码侧 prompt 覆盖检查（Codex 门禁 2 的源码层，不依赖 CodeQL）。

对 v1（损坏）/v2（修复）的 vuln/fixed 两侧，判断安全关键修复区域是否可能进入
prompt 的 code_text 节选。三分类（补充裁决）：
    FULL    —— 关键修复文件/修改行在默认窗口内完整可见；
    PARTIAL —— 仅部分上下文可见；
    ABSENT  —— 关键区域未进入（representation failure，非模型判断失败）。

注意：这是源码层判断；完整 prompt 覆盖须在 CodeQL 污点锚点确定后复核（锚点会改变
命中文件的窗口优先级）。默认窗口参照 _load_sample_code：非命中文件取头部 100 行。
"""
import difflib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
V1 = ROOT / "cpg/corpus_pairs/CVE-2026-61539"
V2 = ROOT / "cpg/corpus-v2/CVE-2026-61539"

HEAD_WINDOW = 100  # 非 taint 命中文件的默认节选窗口（行）


def classify_file(v1_path, v2_path, side):
    """返回 (分类, 说明)。"""
    if not v2_path.exists():
        return "ABSENT", "v2 也无此文件"
    if not v1_path.exists():
        # v1 缺、v2 有（fixed 侧新增）——检查 v2 文件是否在头部窗口内
        lines = v2_path.read_text(encoding="utf-8", errors="replace").splitlines()
        if len(lines) <= HEAD_WINDOW:
            return "FULL", f"v2 新增 {len(lines)} 行 ≤ {HEAD_WINDOW} 窗口，完整可见"
        return "PARTIAL", f"v2 新增 {len(lines)} 行 > {HEAD_WINDOW} 窗口，仅头部可见"
    # 两侧都有但内容不同——diff 找修改行，判断是否在窗口内
    a = v1_path.read_text(encoding="utf-8", errors="replace").splitlines()
    b = v2_path.read_text(encoding="utf-8", errors="replace").splitlines()
    if a == b:
        return "FULL", "两侧内容相同（无修改）"
    changed = []
    sm = difflib.SequenceMatcher(None, a, b)
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag != "equal":
            changed.append((j1, j2))  # v2 侧行号区间
    max_changed_end = max((e for _, e in changed), default=0)
    if max_changed_end <= HEAD_WINDOW:
        return "FULL", f"修改行全部在窗口内（最末修改行 {max_changed_end} ≤ {HEAD_WINDOW}）"
    # 部分在窗口内
    min_changed_start = min((s for s, _ in changed), default=0)
    if min_changed_start <= HEAD_WINDOW:
        return "PARTIAL", f"修改行 {min_changed_start}..{max_changed_end}，部分超出窗口"
    return "ABSENT", f"修改行 {min_changed_start}..{max_changed_end} 全部在窗口外（> {HEAD_WINDOW}）"


def main():
    key_files = [
        "xinference/model/llm/tool_parsers/llama3_tool_parser.py",
        "xinference/model/llm/utils.py",
        "xinference/model/llm/tests/test_utils.py",
        "xinference/model/llm/tool_parsers/tests/test_llama3_tool_parser.py",
    ]
    print(f"61539 源码侧 prompt 覆盖检查（窗口={HEAD_WINDOW} 行）")
    for side in ("vuln", "fixed"):
        print(f"\n== {side} 侧 ==")
        for f in key_files:
            v1f = V1 / side / f
            v2f = V2 / side / f
            cls, note = classify_file(v1f, v2f, side)
            print(f"  [{cls:<7}] {f}")
            print(f"            {note}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
