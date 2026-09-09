# -*- coding: utf-8 -*-
"""build_historical_source_manifest 的备份取证测试（不依赖 git / 真实 17 例）。

聚焦两类 fail-closed 语义：
1. `load_backup` 只收录非空 side（空目录不得误报为可取证）；
2. `verify_backup_side` 对缺文件 / 多文件 / SHA 不符分别报错。
"""
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from cpg.ablation import build_historical_source_manifest as bsm  # noqa: E402


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


class TestVerifyBackupSide(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.side = Path(self._td.name) / "side"
        self.side.mkdir()
        (self.side / "a.py").write_bytes(b"aaa")
        (self.side / "sub").mkdir()
        (self.side / "sub" / "b.py").write_bytes(b"bbb")
        self.expected = {
            "a.py": _sha(b"aaa"),
            "sub/b.py": _sha(b"bbb"),
        }

    def tearDown(self):
        self._td.cleanup()

    def test_ok(self):
        self.assertEqual(bsm.verify_backup_side(self.side, self.expected), [])

    def test_missing_file(self):
        self.expected["missing.py"] = _sha(b"nope")
        errs = bsm.verify_backup_side(self.side, self.expected)
        self.assertTrue(any("缺文件" in e for e in errs))

    def test_extra_file(self):
        (self.side / "extra.py").write_bytes(b"extra")
        errs = bsm.verify_backup_side(self.side, self.expected)
        self.assertTrue(any("多出文件" in e for e in errs))

    def test_wrong_sha(self):
        self.expected["a.py"] = _sha(b"DIFFERENT")
        errs = bsm.verify_backup_side(self.side, self.expected)
        self.assertTrue(any("SHA 不符" in e for e in errs))


class TestLoadBackup(unittest.TestCase):
    def _mk_backup(self, td: Path, include_fixed: bool = True) -> Path:
        backup = td / "backup"
        corpus = backup / "corpus" / "CVE-2026-53500"
        (corpus / "vuln").mkdir(parents=True)
        (corpus / "vuln" / "mcp.py").write_bytes(b"vuln-code")
        if include_fixed:
            (corpus / "fixed").mkdir(parents=True)
            (corpus / "fixed" / "mcp.py").write_bytes(b"fixed-code")
        else:
            # 空 fixed 目录：无源码可取证
            (corpus / "fixed").mkdir(parents=True, exist_ok=True)
        files = [{"path": "CVE-2026-53500/vuln/mcp.py",
                  "sha256": _sha(b"vuln-code")}]
        if include_fixed:
            files.append({"path": "CVE-2026-53500/fixed/mcp.py",
                          "sha256": _sha(b"fixed-code")})
        (backup / "manifest-sha256.json").write_text(
            json.dumps({"files": files}), encoding="utf-8")
        return backup

    def test_parses_manifest_and_dirs(self):
        td = Path(self._enter())
        backup = self._mk_backup(td)
        dirs, sha_by_side, manifest_sha = bsm.load_backup(backup)
        self.assertEqual(set(dirs), {("CVE-2026-53500", "vuln"),
                                     ("CVE-2026-53500", "fixed")})
        self.assertEqual(sha_by_side["CVE-2026-53500/vuln"]["mcp.py"], _sha(b"vuln-code"))
        self.assertEqual(sha_by_side["CVE-2026-53500/fixed"]["mcp.py"], _sha(b"fixed-code"))
        self.assertEqual(len(manifest_sha), 64)

    def test_empty_side_is_unavailable(self):
        td = Path(self._enter())
        backup = self._mk_backup(td, include_fixed=False)
        dirs, sha_by_side, _ = bsm.load_backup(backup)
        self.assertIn(("CVE-2026-53500", "vuln"), dirs)
        self.assertNotIn(("CVE-2026-53500", "fixed"), dirs,
                         "空 fixed 目录不得被当作可取证证据")
        self.assertNotIn("CVE-2026-53500/fixed", sha_by_side)

    def test_missing_backup_returns_empty(self):
        dirs, sha_by_side, manifest_sha = bsm.load_backup(Path("/nonexistent/xyz"))
        self.assertEqual(dirs, {})
        self.assertEqual(sha_by_side, {})
        self.assertIsNone(manifest_sha)

    def _enter(self):
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        return self._td.name


if __name__ == "__main__":
    unittest.main()
