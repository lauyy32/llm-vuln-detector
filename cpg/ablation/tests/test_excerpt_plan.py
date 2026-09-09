# -*- coding: utf-8 -*-
"""excerpt_plan.py 测试：changed-hunk 定位、覆盖三态、完整行边界、文件顺序。

用法：python -m unittest cpg.ablation.tests.test_excerpt_plan -v
"""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from cpg.ablation.excerpt_plan import (  # noqa: E402
    ABSENT, FULL, PARTIAL, build_pair_selection_plan, get_changed_hunks, render_side,
)


def _run(args, cwd):
    return subprocess.run(args, cwd=str(cwd), capture_output=True, text=True)


class TestGetChangedHunks61539(unittest.TestCase):
    """真实 fixture：61539 utils.py 安全 hunk 在 L754-765，头 100 行窗口应漏掉。"""

    def test_utils_hunk_at_L754(self):
        repo = ROOT / "cpg/corpus_raw/xorbitsai__inference"
        if not repo.exists():
            self.skipTest("corpus_raw 未就绪")
        hunks = get_changed_hunks(repo, "1b3d220f34^", "1b3d220f34",
                                  "xinference/model/llm/utils.py")
        # 安全 hunk 在约 L754-765（Code plan 断言），不能只有 L1-15
        self.assertTrue(any(lo >= 700 for lo, hi in hunks),
                        f"安全 hunk 应出现在 L700+，实际 {hunks}")


class TestCoverage61539(unittest.TestCase):
    def test_head_window_misses_hunk(self):
        repo = ROOT / "cpg/corpus_raw/xorbitsai__inference"
        pm_path = ROOT / "cpg/corpus-v3/CVE-2026-61539/pair_manifest.json"
        if not repo.exists() or not pm_path.exists():
            self.skipTest("fixture 未就绪")
        pm = json.loads(pm_path.read_text(encoding="utf-8"))
        spec = type("S", (), {"sample_id": "CVE-2026-61539"})()
        # 用头 100 行窗口（hunk_window=None 禁用 hunk 窗口），安全 hunk L754 应 ABSENT
        plan = build_pair_selection_plan(spec, pm, repo, max_chars=8000,
                                         head_lines=100, hunk_window=None)
        cov = plan.hunk_coverage.get("xinference/model/llm/utils.py", {})
        self.assertIn(cov.get("fixed"), (ABSENT, PARTIAL),
                      f"头 100 行窗口应漏掉 L754 安全 hunk（fixed 侧），实际 {cov}")

    def test_hunk_window_covers_hunk(self):
        repo = ROOT / "cpg/corpus_raw/xorbitsai__inference"
        pm_path = ROOT / "cpg/corpus-v3/CVE-2026-61539/pair_manifest.json"
        if not repo.exists() or not pm_path.exists():
            self.skipTest("fixture 未就绪")
        pm = json.loads(pm_path.read_text(encoding="utf-8"))
        spec = type("S", (), {"sample_id": "CVE-2026-61539"})()
        # 预算足够大，hunk 中心窗口应 FULL 覆盖 L754（8000 预算下 PARTIAL 是预算挤占，非 bug）
        plan = build_pair_selection_plan(spec, pm, repo, max_chars=100000,
                                         head_lines=100, hunk_window=20)
        cov = plan.hunk_coverage.get("xinference/model/llm/utils.py", {})
        self.assertEqual(cov.get("fixed"), FULL,
                         f"hunk 中心窗口+大预算应 FULL 覆盖 L754（fixed 侧），实际 {cov}")


class TestBlockInvariants(unittest.TestCase):
    """合成 Git 仓库：块完整行、文件顺序按路径、同名 basename 唯一。"""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="excerpt_test_"))
        self.repo = self.tmp / "repo"
        self.repo.mkdir()
        _run(["git", "init", "-q"], self.repo)
        _run(["git", "config", "user.email", "t@t"], self.repo)
        _run(["git", "config", "user.name", "t"], self.repo)
        # 同名 basename 不同目录
        (self.repo / "a").mkdir(parents=True)
        (self.repo / "b").mkdir(parents=True)
        (self.repo / "a" / "x.py").write_text("print('a')\n" * 10)
        (self.repo / "b" / "x.py").write_text("print('b')\n" * 10)
        _run(["git", "add", "-A"], self.repo)
        _run(["git", "commit", "-q", "-m", "p"], self.repo)
        self.parent = _run(["git", "rev-parse", "HEAD"], self.repo).stdout.strip()
        # fix：改 a/x.py
        (self.repo / "a" / "x.py").write_text("print('a')\n" * 9 + "print('changed')\n")
        _run(["git", "add", "-A"], self.repo)
        _run(["git", "commit", "-q", "-m", "f"], self.repo)
        self.fix = _run(["git", "rev-parse", "HEAD"], self.repo).stdout.strip()

    def _pm(self):
        return {"parent_commit": self.parent, "fix_commit": self.fix,
                "files": [{"path": "a/x.py", "status": "M"},
                          {"path": "b/x.py", "status": "M"}]}

    def test_blocks_complete_lines(self):
        spec = type("S", (), {"sample_id": "T"})()
        plan = build_pair_selection_plan(spec, self._pm(), self.repo, max_chars=8000)
        for b in plan.blocks:
            self.assertTrue(b.content == "" or b.content.endswith("\n"),
                            f"块 {b.path} 未以换行结束")
            self.assertNotIn("\n# ===== FILE", b.content, "块内不应粘入 FILE marker")

    def test_render_side_full_path_unique(self):
        spec = type("S", (), {"sample_id": "T"})()
        plan = build_pair_selection_plan(spec, self._pm(), self.repo, max_chars=8000)
        text = render_side(plan, "vuln")
        self.assertIn("a/x.py", text)
        self.assertIn("b/x.py", text)
        # 完整相对路径唯一（不是 basename x.py）
        self.assertEqual(text.count("FILE: x.py"), 0, "不应只用 basename")

    def test_plan_sha_deterministic(self):
        spec = type("S", (), {"sample_id": "T"})()
        p1 = build_pair_selection_plan(spec, self._pm(), self.repo, max_chars=8000)
        p2 = build_pair_selection_plan(spec, self._pm(), self.repo, max_chars=8000)
        self.assertEqual(p1.plan_sha(), p2.plan_sha(), "相同输入 plan_sha 应一致")


if __name__ == "__main__":
    unittest.main()
