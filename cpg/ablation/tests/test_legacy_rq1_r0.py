# -*- coding: utf-8 -*-
"""legacy-rq1-r0 适配器测试：字节级封存行为 + preflight fail-closed。"""
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from cpg.ablation.legacy_rq1_r0 import (  # noqa: E402
    REPRESENTATION, MAX_CODE_CHARS, load_legacy_code_text, preflight_legacy,
)


def _mk(root: Path, rel: str, n_lines: int, width: int = 8) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("".join(f"x{i:0{width}d}\n" for i in range(n_lines)), encoding="utf-8")
    return p


class TestLegacyBytes(unittest.TestCase):
    """原样封存：不优化历史行为（basename marker、按大小排序、截断）。"""

    def test_legacy_no_taint_exact_bytes(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            small = _mk(root, "a.py", 3)
            big = _mk(root, "b.py", 150)
            # 无 taint：按文件大小升序；每个取头 100 行；marker 用 basename
            out = load_legacy_code_text(root, [])
            first = out.splitlines()[0]
            self.assertEqual(first, f"# ===== FILE: {small.name} (L1-L3) =====",
                             "无 taint 时应按文件大小升序，marker 用 basename")
            self.assertIn(f"# ===== FILE: {big.name} (L1-L100) =====", out,
                          "大文件应只取头 100 行")

    def test_legacy_taint_window_exact_bytes(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            src = _mk(root, "c.py", 300)
            rows = [{"abs_path": str(src).replace("\\", "/"), "sourceLine": 200,
                     "sinkLine": 210}]
            out = load_legacy_code_text(root, rows)
            # sink±90 → [120, 300]；source−50/+80 → [150, 280]；合并 +20 阈值
            self.assertIn("(L120-L300)", out, "sink±90 窗口应展开并合并 source 窗口")
            self.assertNotIn("(L1-L100)", out, "命中文件不应退化为头 100 行")

    def test_legacy_truncation_exact_bytes(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            # 多个大文件，强制触发 8000 截断
            for i in range(6):
                _mk(root, f"f{i}.py", 400, width=40)
            out = load_legacy_code_text(root, [], max_chars=2000)
            self.assertIn("# (truncated)", out, "超预算应追加历史 truncated marker")

    def test_legacy_marker_is_basename_not_path(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _mk(root, "pkg/sub/deep.py", 5)
            out = load_legacy_code_text(root, [])
            self.assertIn("# ===== FILE: deep.py", out)
            self.assertNotIn("pkg/sub/deep.py", out,
                             "历史使用 basename，不得改为完整相对路径")


class TestPreflightFailClosed(unittest.TestCase):
    def test_missing_expected_tree_sha_fails(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(RuntimeError):
                preflight_legacy(Path(td), None)

    def test_missing_dir_fails(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(RuntimeError):
                preflight_legacy(Path(td) / "nope", "a" * 64)


class TestConstants(unittest.TestCase):
    def test_representation_name(self):
        self.assertEqual(REPRESENTATION, "legacy-rq1-r0")
        self.assertEqual(MAX_CODE_CHARS, 8000)


if __name__ == "__main__":
    unittest.main()
