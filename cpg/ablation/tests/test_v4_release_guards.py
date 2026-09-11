# -*- coding: utf-8 -*-
"""防复发：AST 扫描 `relative_to(ROOT)`，未包 try/except 且目标非常量即失败。

背景：`Path.relative_to(ROOT)` 在目标不在 ROOT 下时抛 ValueError。
该 bug 已在三个位置复发（`v4_gate_a._f` / `v4_release._f` / `v4_release."run_dir"`），
故改为**机器扫描**。判定用 AST，避免字符串解析的误报。
"""
import ast
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

# 仓库内常量 / 文件自身 → 必然在 ROOT 下，允许裸调用
SAFE_NAMES = {
    "CANONICAL_MANIFEST", "OLD_CANONICAL_MANIFEST", "TOKENIZER_PATH", "__file__",
}
# 明确已知安全的行（常量路径）；新增条目必须写明理由
KNOWN_SAFE_LINES = {
    "cpg/ablation/canonical_manifest_v2.py:123": "impl=__file__ 绝对路径（仓库内）",
    "cpg/ablation/run_experiment.py:453": "canonical=仓库内清单",
}


def _call_target_name(node: ast.Call) -> str:
    """提取 `X.relative_to(ROOT)` 中 X 的简单标识（不支持则返回 '<expr>'）。"""
    f = node.func
    if isinstance(f, ast.Attribute) and f.attr == "relative_to":
        v = f.value
        if isinstance(v, ast.Name):
            return v.id
        if isinstance(v, ast.Attribute):
            return v.attr
        if isinstance(v, ast.Call):
            inner = v.func
            if isinstance(inner, ast.Attribute):
                return inner.attr
            if isinstance(inner, ast.Name):
                return inner.id
    return "<expr>"


class TestNoUnguardedRelativeTo(unittest.TestCase):
    def test_scan(self):
        offenders = []
        for p in sorted((ROOT / "cpg" / "ablation").rglob("*.py")):
            if "tests" in p.parts:
                continue
            src = p.read_text(encoding="utf-8", errors="replace")
            rel = p.relative_to(ROOT).as_posix()
            try:
                tree = ast.parse(src)
            except SyntaxError:
                continue
            # 收集被 try/except 包裹的行号区间
            guarded_lines = set()
            for n in ast.walk(tree):
                if isinstance(n, ast.Try):
                    lo = n.lineno
                    hi = max(getattr(x, "end_lineno", x.lineno)
                             for x in n.body + n.handlers)
                    guarded_lines.update(range(lo, hi + 1))
            for n in ast.walk(tree):
                if not isinstance(n, ast.Call):
                    continue
                f = n.func
                if not (isinstance(f, ast.Attribute) and f.attr == "relative_to"):
                    continue
                if not (n.args and isinstance(n.args[0], ast.Name)
                        and n.args[0].id == "ROOT"):
                    continue
                tgt = _call_target_name(n)
                if tgt in SAFE_NAMES:
                    continue
                key = f"{rel}:{n.lineno}"
                if key in KNOWN_SAFE_LINES:
                    continue
                if n.lineno in guarded_lines:
                    continue
                offenders.append(f"{key} target={tgt!r}")
        self.assertEqual(
            offenders, [],
            "存在未保护的 relative_to(ROOT)：\n" + "\n".join(offenders)
            + "\n（若确实安全，请把该行加入 KNOWN_SAFE_LINES 并写明理由）")


if __name__ == "__main__":
    unittest.main()
