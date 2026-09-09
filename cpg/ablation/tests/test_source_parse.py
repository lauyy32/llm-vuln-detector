# -*- coding: utf-8 -*-
"""源码可解析门禁：遍历 cpg/ablation/*.py 用 ast.parse 验证语法。

排除 .venv / __pycache__ / tests 自身。Python 3.9 与运行 Python 都必须通过。
用法：python -m unittest cpg.ablation.tests.test_source_parse -v
"""
import ast
import sys
import unittest
from pathlib import Path

ABLATION = Path(__file__).resolve().parents[1]


def _py_files():
    out = []
    for p in sorted(ABLATION.rglob("*.py")):
        parts = p.parts
        if any(seg in (".venv", "__pycache__", "venv", ".work", "staging", "corpus_src") for seg in parts):
            continue
        if "site-packages" in parts:
            continue
        out.append(p)
    return out


class TestSourceParses(unittest.TestCase):
    def test_all_ablation_py_parse(self):
        files = _py_files()
        self.assertGreater(len(files), 0, "cpg/ablation 下应有 .py 文件")
        errors = []
        for p in files:
            try:
                ast.parse(p.read_text(encoding="utf-8"), filename=str(p))
            except SyntaxError as e:
                errors.append(f"{p}: {e}")
        self.assertEqual(errors, [], "存在语法错误文件:\n" + "\n".join(errors))


if __name__ == "__main__":
    unittest.main()
