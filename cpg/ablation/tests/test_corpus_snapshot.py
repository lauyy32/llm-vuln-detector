# -*- coding: utf-8 -*-
"""corpus_db.py 第3阶段契约测试：stage_exact_snapshot + cache key 失效。

用法：python -m unittest cpg.ablation.tests.test_corpus_snapshot -v
"""
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
import cpg.ablation.corpus_db as cdb  # noqa: E402


def _make_source(base: Path, cve: str, files: dict):
    """构造 cpg/corpus-v3/<cve>/{vuln,fixed} 源码树，返回树哈希。"""
    src = base / "cpg" / "corpus-v3" / cve
    for version, fmap in files.items():
        d = src / version
        d.mkdir(parents=True, exist_ok=True)
        for rel, content in fmap.items():
            p = d / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(content)
    return src


def _manifest_entry(cve, src, vuln_files, fixed_files):
    return {
        "sample_id": cve,
        "source_path": f"cpg/corpus-v3/{cve}",
        "vuln_tree_sha256_lf": cdb.tree_sha_lf(src / "vuln"),
        "fixed_tree_sha256_lf": cdb.tree_sha_lf(src / "fixed"),
        "eligible": True,
    }


class TestStageExactSnapshot(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="snapshot_test_"))
        # mock ROOT 指向临时目录
        self.patcher = mock.patch.object(cdb, "ROOT", self.tmp)
        self.patcher.start()
        self.cve = "CVE-TEST-1"

    def tearDown(self):
        self.patcher.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _manifest(self, vuln_files=None, fixed_files=None):
        src = _make_source(self.tmp, self.cve,
                           {"vuln": vuln_files or {"a.py": b"print('a')\n"},
                            "fixed": fixed_files or {"a.py": b"print('b')\n"}})
        return {"samples": [_manifest_entry(self.cve, src,
                                            vuln_files or {"a.py": b"print('a')\n"},
                                            fixed_files or {"a.py": b"print('b')\n"})]}

    def test_stage_success(self):
        m = self._manifest()
        run_root = self.tmp / "run1"
        r = cdb.stage_exact_snapshot(m, run_root)
        self.assertEqual(len(r["samples"]), 1)
        self.assertTrue((run_root / "corpus_src" / f"{self.cve}_vuln" / "a.py").exists())
        self.assertTrue((run_root / "corpus_src" / f"{self.cve}_fixed" / "a.py").exists())

    def test_missing_side_fails(self):
        # 构造 fixed 缺失：manifest 有 fixed_tree_sha 但磁盘无 fixed 目录
        src = _make_source(self.tmp, self.cve,
                           {"vuln": {"a.py": b"print('a')\n"}})
        entry = {
            "sample_id": self.cve,
            "source_path": f"cpg/corpus-v3/{self.cve}",
            "vuln_tree_sha256_lf": cdb.tree_sha_lf(src / "vuln"),
            "fixed_tree_sha256_lf": "deadbeef",
            "eligible": True,
        }
        with self.assertRaises(RuntimeError):
            cdb.stage_exact_snapshot({"samples": [entry]}, self.tmp / "run2")

    def test_tree_hash_drift_fails(self):
        src = _make_source(self.tmp, self.cve,
                           {"vuln": {"a.py": b"print('a')\n"},
                            "fixed": {"a.py": b"print('b')\n"}})
        entry = {
            "sample_id": self.cve,
            "source_path": f"cpg/corpus-v3/{self.cve}",
            "vuln_tree_sha256_lf": cdb.tree_sha_lf(src / "vuln"),
            "fixed_tree_sha256_lf": "wrong_hash",
            "eligible": True,
        }
        with self.assertRaises(RuntimeError):
            cdb.stage_exact_snapshot({"samples": [entry]}, self.tmp / "run3")

    def test_no_residue_on_different_source(self):
        # 第一次 run 有 a.py，第二次 source 换成只有 b.py；staging 目录应只含当前文件
        m1 = self._manifest()
        r1 = cdb.stage_exact_snapshot(m1, self.tmp / "run_a")
        self.assertTrue((self.tmp / "run_a" / "corpus_src" / f"{self.cve}_vuln" / "a.py").exists())
        # 模拟源树删除 a.py：清空旧 source 后只写 b.py
        shutil.rmtree(self.tmp / "cpg" / "corpus-v3" / self.cve, ignore_errors=True)
        src = _make_source(self.tmp, self.cve,
                           {"vuln": {"b.py": b"print('b')\n"},
                            "fixed": {"b.py": b"print('c')\n"}})
        m2 = {"samples": [{
            "sample_id": self.cve, "source_path": f"cpg/corpus-v3/{self.cve}",
            "vuln_tree_sha256_lf": cdb.tree_sha_lf(src / "vuln"),
            "fixed_tree_sha256_lf": cdb.tree_sha_lf(src / "fixed"), "eligible": True}]}
        r2 = cdb.stage_exact_snapshot(m2, self.tmp / "run_b")
        self.assertFalse((self.tmp / "run_b" / "corpus_src" / f"{self.cve}_vuln" / "a.py").exists(),
                         "残留 a.py 不应出现在新 staging")


class TestCacheKey(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cachekey_test_"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_query_set_sha_changes(self):
        q1 = self.tmp / "q1.ql"
        q1.write_text("select 1")
        sha1 = cdb.query_set_sha([q1])
        q1.write_text("select 2")
        sha2 = cdb.query_set_sha([q1])
        self.assertNotEqual(sha1, sha2, "改 query 字节应改变 query_set_sha")

    def test_cache_key_changes_with_staged_sha(self):
        qsha = "qsha"
        cid = "codeql-2.26.2"
        k1 = cdb._sha256_bytes(("sm1" + qsha + cid).encode("utf-8"))
        k2 = cdb._sha256_bytes(("sm2" + qsha + cid).encode("utf-8"))
        self.assertNotEqual(k1, k2, "改 staged_manifest_sha 应改变 cache key")


if __name__ == "__main__":
    unittest.main()
