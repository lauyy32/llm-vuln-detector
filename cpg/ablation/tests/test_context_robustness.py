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
        p.blocks = [BlockPlan(path="a.py", side="vuln", lo=1, hi=1,
                              reason="head_window", content="print('a')\n",
                              content_sha=_sha256_bytes(b"print('a')\n"), token_estimate=2)]
        return p

    def test_c0_returns_same(self):
        p = self._base()
        p2 = cr.make_perturbed_plan(p, "C0")
        self.assertIs(p, p2, "C0 应返回原 plan")

    def test_c1_adds_block(self):
        p = self._base()
        n0 = len(p.blocks)
        p2 = cr.make_perturbed_plan(p, "C1")
        self.assertEqual(len(p2.blocks), n0 + 1, "C1 应追加一个扰动块")
        # 扰动块无敏感词
        self.assertIsNone(SENSITIVE.search(p2.blocks[-1].content))


if __name__ == "__main__":
    unittest.main()
