# -*- coding: utf-8 -*-
"""prompt_renderer.py 测试：不截断、summary 关闭无泄漏、fence 正确、SHA 稳定。

用法：python -m unittest cpg.ablation.tests.test_prompt_renderer -v
"""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from cpg.ablation.prompt_renderer import (  # noqa: E402
    SYSTEM, render_prompt, prompt_sha256,
)


class TestRenderPrompt(unittest.TestCase):
    def test_summary_off_no_leak(self):
        meta = {"cve_id": "CVE-2026-61539", "cwe": "CWE-095",
                "summary": "unsafe eval() 导致 RCE"}
        p = render_prompt(meta, "print('x')\n", None, summary=False)
        self.assertNotIn("公告摘要", p)
        self.assertNotIn("unsafe eval", p)

    def test_summary_on_has_summary(self):
        meta = {"cve_id": "CVE-2026-61539", "cwe": "CWE-095",
                "summary": "unsafe eval() 导致 RCE"}
        p = render_prompt(meta, "print('x')\n", None, summary=True)
        self.assertIn("公告摘要", p)

    def test_fence_count(self):
        p = render_prompt({"cve_id": "X", "cwe": "CWE-095"},
                          "print('a')\nprint('b')\n", None)
        self.assertEqual(p.count("```"), 2, "code_text 应有一对 fence")

    def test_over_budget_fails(self):
        big = "x" * 9000
        with self.assertRaises(ValueError):
            render_prompt({"cve_id": "X", "cwe": "CWE-095"}, big, None)

    def test_cpg_over_budget_fails(self):
        big = "y" * 13000
        with self.assertRaises(ValueError):
            render_prompt({"cve_id": "X", "cwe": "CWE-095"}, None, big)

    def test_sha_stable(self):
        meta = {"cve_id": "X", "cwe": "CWE-095"}
        p1 = render_prompt(meta, "print('a')\n", None)
        p2 = render_prompt(meta, "print('a')\n", None)
        self.assertEqual(p1, p2)
        self.assertEqual(prompt_sha256(p1), prompt_sha256(p2))

    def test_snapshot(self):
        # 快照：固定输入 → 固定输出（防止渲染漂移）
        meta = {"cve_id": "CVE-2026-61539", "cwe": "CWE-095"}
        p = render_prompt(meta, "print('hello')\n", None, summary=False)
        self.assertTrue(p.startswith("# 审计任务\n- CVE: CVE-2026-61539\n- 目标 CWE: CWE-095"))
        self.assertIn("# 目标代码（节选）", p)
        self.assertIn("# 输出要求", p)


class TestSystemSingleSource(unittest.TestCase):
    def test_system_nonempty_and_stable(self):
        self.assertGreater(len(SYSTEM), 100)
        # SYSTEM 不随调用变化
        self.assertEqual(SYSTEM, SYSTEM)


if __name__ == "__main__":
    unittest.main()
