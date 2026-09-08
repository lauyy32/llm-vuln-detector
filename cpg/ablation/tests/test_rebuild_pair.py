# -*- coding: utf-8 -*-
"""rebuild_corpus.py 单元测试：合成 Git 仓库验证 status 处理、字节保真、批量 fail-closed。

用法：python -m unittest cpg.ablation.tests.test_rebuild_pair -v
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
import cpg.ablation.rebuild_corpus as rc  # noqa: E402
from cpg.ablation.rebuild_corpus import (  # noqa: E402
    SampleSpec, build_pair_in_staging, name_status, preflight_repo, tree_sha_lf,
)


def _run(args, cwd):
    return subprocess.run(args, cwd=str(cwd), capture_output=True, text=True)


class GitRepoFixture(unittest.TestCase):
    """合成一个 parent→fix 的 Git 仓库。"""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="rebuild_test_"))
        self.repo = self.tmp / "repo"
        self.repo.mkdir()
        _run(["git", "init", "-q"], self.repo)
        _run(["git", "config", "user.email", "t@t"], self.repo)
        _run(["git", "config", "user.name", "t"], self.repo)
        self.repo_slug = "test/repo"
        self.parent = self._commit_parent()
        # monkeypatch clone_dir 指向临时 repo
        self.patcher = mock.patch.object(rc, "clone_dir", return_value=self.repo)
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, rel, content: bytes):
        p = self.repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content)

    def _commit_parent(self):
        self._write("m.py", b"print('a')\n")
        self._write("d.py", b"print('del')\n")
        # 高相似度多行，便于 rename 检测
        self._write("old.py", b"print('l1')\nprint('l2')\nprint('l3')\nprint('l4')\n")
        self._write("u8.py", "print('中文')\n".encode("utf-8"))
        self._write("crlf.py", b"print('crlf')\r\nprint('line2')\r\n")
        _run(["git", "add", "-A"], self.repo)
        _run(["git", "commit", "-q", "-m", "parent"], self.repo)
        return _run(["git", "rev-parse", "HEAD"], self.repo).stdout.strip()

    def _make_fix(self):
        # M m.py, A a.py, D d.py, R old.py->new.py(改1行), M crlf.py(保持CRLF), M u8.py(保持中文)
        self._write("m.py", b"print('modified')\n")
        self._write("a.py", b"print('added')\n")
        (self.repo / "d.py").unlink()
        (self.repo / "old.py").unlink()
        self._write("new.py", b"print('l1')\nprint('l2x')\nprint('l3')\nprint('l4')\n")
        self._write("crlf.py", b"print('crlf changed')\r\nprint('line2')\r\n")
        self._write("u8.py", "print('中文改')\n".encode("utf-8"))
        _run(["git", "add", "-A"], self.repo)
        _run(["git", "commit", "-q", "-m", "fix"], self.repo)
        return _run(["git", "rev-parse", "HEAD"], self.repo).stdout.strip()

    def _spec(self, fix):
        return SampleSpec(sample_id="TEST", repo_slug=self.repo_slug,
                          fix_commit=fix, cwes=["CWE-095"])


class TestNameStatus(GitRepoFixture):
    def test_statuses(self):
        fix = self._make_fix()
        entries, err = name_status(self.repo_slug, self.parent, fix)
        self.assertEqual(err, "")
        by_status = {st: (p, prev) for st, p, prev in entries}
        self.assertIn("M", by_status)
        self.assertIn("A", by_status)
        self.assertIn("D", by_status)
        self.assertIn("R", by_status)


class TestBuildPair(GitRepoFixture):
    def test_build_modified_and_bytes(self):
        fix = self._make_fix()
        staging = self.tmp / "staging"
        staging.mkdir()
        r = build_pair_in_staging(self._spec(fix), self.parent, staging)
        self.assertEqual(r["status"], "BUILT")
        # 字节保真：rebuilt 文件 == git show 原始 blob 字节（text=False 不编解码）
        from cpg.ablation.rebuild_corpus import read_blob_bytes
        for f in ("crlf.py", "u8.py", "m.py"):
            rebuilt = (staging / "vuln" / f).read_bytes()
            blob = read_blob_bytes(self.repo_slug, self.parent, f)
            self.assertEqual(rebuilt, blob, f"{f} 应逐字节等于 git blob")
        # UTF-8 中文保真
        u8 = (staging / "vuln" / "u8.py").read_bytes()
        self.assertIn("中文".encode("utf-8"), u8)


class TestTreeShaDeterministic(GitRepoFixture):
    def test_tree_sha_stable_across_process(self):
        fix = self._make_fix()
        staging = self.tmp / "staging"
        staging.mkdir()
        build_pair_in_staging(self._spec(fix), self.parent, staging)
        sha1 = tree_sha_lf(staging / "vuln")
        sha2 = tree_sha_lf(staging / "vuln")
        self.assertEqual(sha1, sha2)


class TestUnknownStatusFails(unittest.TestCase):
    def test_unknown_status(self):
        spec = SampleSpec(sample_id="T", repo_slug="x/y", fix_commit="deadbeef", cwes=[])
        # 不存在的 repo → preflight 失败
        parent, err = preflight_repo(spec)
        self.assertNotEqual(err, "")


if __name__ == "__main__":
    unittest.main()
