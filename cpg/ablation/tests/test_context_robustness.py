# -*- coding: utf-8 -*-
"""context_robustness.py 测试：三模板 token 对齐、无敏感词、C0 原样、扰动块追加。

用法：python -m unittest cpg.ablation.tests.test_context_robustness -v
"""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from cpg.ablation import context_robustness as cr  # noqa: E402
from cpg.ablation.excerpt_plan import PairSelectionPlan  # noqa: E402


SENSITIVE = re.compile(r"CVE|CWE|vulnerable|benign|fixed|security|fix|漏洞|修复", re.IGNORECASE)


def _pad(c):
    return cr._pad_code_to_target(cr.TEMPLATES[c]) if c == "C3" else cr._pad_to_target(cr.TEMPLATES[c])


class TestTemplates(unittest.TestCase):
    def test_three_templates_aligned(self):
        padded = {c: _pad(c) for c in ("C1", "C2", "C3")}
        lengths = [len(v) for v in padded.values()]
        self.assertLessEqual(max(lengths) - min(lengths), 1, f"模板长度不对齐: {lengths}")

    def test_templates_no_sensitive_words(self):
        for c in ("C1", "C2", "C3"):
            t = _pad(c)
            self.assertIsNone(SENSITIVE.search(t), f"{c} 含敏感词")

    def test_templates_complete_lines(self):
        for c in ("C1", "C2", "C3"):
            t = _pad(c)
            self.assertTrue(t.endswith("\n"), f"{c} 未以换行结束")


class TestMakePerturbed(unittest.TestCase):
    def _base(self):
        p = PairSelectionPlan(sample_id="T")
        from cpg.ablation.excerpt_plan import BlockPlan, _sha256_bytes
        p.blocks = [
            BlockPlan(path="a.py", side="vuln", lo=1, hi=1, reason="head_window",
                      content="print('a')\n", content_sha=_sha256_bytes(b"print('a')\n"), token_estimate=2),
            BlockPlan(path="a.py", side="fixed", lo=1, hi=1, reason="head_window",
                      content="print('b')\n", content_sha=_sha256_bytes(b"print('b')\n"), token_estimate=2),
        ]
        return p

    def test_c0_returns_deepcopy(self):
        p = self._base()
        p2 = cr.make_perturbed_plan(p, "C0")
        self.assertEqual(p.blocks, p2.blocks)
        self.assertIsNot(p, p2, "C0 应返回深拷贝（非同一对象）")

    def test_c1_adds_two_blocks(self):
        p = self._base()
        n0 = len(p.blocks)
        p2 = cr.make_perturbed_plan(p, "C1")
        self.assertEqual(len(p2.blocks), n0 + 2, "C1 应追加 vuln+fixed 两个扰动块")
        # 扰动块无敏感词
        self.assertIsNone(SENSITIVE.search(p2.blocks[-1].content))

    def test_render_differs(self):
        from cpg.ablation.excerpt_plan import render_side
        p = self._base()
        c0 = render_side(cr.make_perturbed_plan(p, "C0"), "vuln")
        c1 = render_side(cr.make_perturbed_plan(p, "C1"), "vuln")
        self.assertNotEqual(c0, c1, "C0/C1 渲染应不同（扰动块真实可见）")
        self.assertIn("notice.txt", c1, "扰动块应出现在渲染结果")

    def test_no_cross_contamination(self):
        p = self._base()
        p_c1 = cr.make_perturbed_plan(p, "C1")
        p_c2 = cr.make_perturbed_plan(p, "C2")
        self.assertEqual(len(p.blocks), 2, "原始 plan 不应被修改")
        self.assertNotEqual(p_c1.blocks[-1].content, p_c2.blocks[-1].content,
                            "C1/C2 扰动内容应不同（无交叉污染）")


if __name__ == "__main__":
    unittest.main()
