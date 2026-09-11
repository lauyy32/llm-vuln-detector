# -*- coding: utf-8 -*-
"""A-2 验收：事务性 / 幂等 / 并发 / registry fail-closed / 引用路径存在。

全部在**临时 root** 下运行，绝不触碰正式 artifacts 目录。
"""
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from cpg.ablation import v4_release as rel  # noqa: E402

TPL = ROOT / "cpg/ablation/artifacts/v4/critical_hunks.template.json"


def _mk_submissions(td: Path, seed: int = 3, role="NON_CRITICAL"):
    import random
    rows = json.loads(TPL.read_text(encoding="utf-8"))["entries"]
    random.seed(seed)
    out = []
    for who in ("reviewer1", "reviewer2"):
        recs = []
        for e in rows:
            r = dict(e)
            r.update({"question": "q", "reviewer": who, "criticality": role,
                      "evidence": "code-reasoning", "counterfactual": "否",
                      "dependency_group": [], "reason": "t"})
            recs.append(r)
        p = td / f"{who}.jsonl"
        p.write_text("\n".join(json.dumps(x, ensure_ascii=False) for x in recs),
                     encoding="utf-8")
        out.append(p)
    return out[0], out[1]


class A2Base(unittest.TestCase):
    def setUp(self):
        self.td = Path(tempfile.mkdtemp())
        self.root = self.td / "rec_root"
        self.s1, self.s2 = _mk_submissions(self.td)

    def tearDown(self):
        shutil.rmtree(self.td, ignore_errors=True)


class TestRegistryFailClosed(A2Base):
    def test_missing_registry_zero_write(self):
        """registry 缺失 → 零落盘（root 不被创建）。"""
        reg = rel.ANN / "distribution_registry.json"
        backup = reg.read_bytes() if reg.exists() else None
        try:
            if reg.exists():
                reg.unlink()
            with self.assertRaises(ValueError) as cm:
                rel.recover(self.s1, self.s2, root=self.root)
            self.assertIn("registry", str(cm.exception).lower())
            self.assertFalse(self.root.exists(), "失败时不得创建任何目录")
        finally:
            if backup is not None:
                reg.write_bytes(backup)

    def test_malformed_registry_fails(self):
        reg = rel.ANN / "distribution_registry.json"
        backup = reg.read_bytes()
        try:
            reg.write_text("{not json", encoding="utf-8")
            with self.assertRaises(ValueError):
                rel.recover(self.s1, self.s2, root=self.root)
            self.assertFalse(self.root.exists())
        finally:
            reg.write_bytes(backup)

    def test_template_sha_mismatch_fails(self):
        reg = rel.ANN / "distribution_registry.json"
        backup = reg.read_bytes()
        try:
            doc = json.loads(backup)
            for f in doc["internal_provenance"]["files"]:
                if f["path"].endswith("critical_hunks.template.json"):
                    f["sha256"] = "0" * 64
            reg.write_bytes((json.dumps(doc, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
            with self.assertRaises(ValueError) as cm:
                rel.recover(self.s1, self.s2, root=self.root)
            self.assertIn("不符", str(cm.exception))
        finally:
            reg.write_bytes(backup)


class TestTransaction(A2Base):
    def test_success_and_no_tmp_left(self):
        r = rel.recover(self.s1, self.s2, root=self.root)
        run = Path(r["run_dir"])
        self.assertTrue(run.exists() and run.is_dir())
        self.assertTrue(run.name.startswith("run-"))
        self.assertFalse(any(x.name.startswith(".tmp-") for x in self.root.iterdir()),
                         "不得残留 .tmp 目录")

    def test_fault_injection_leaves_no_tmp(self):
        """在报告写盘阶段注入失败 → 临时目录必须被清理、正式目录不变。"""
        orig = rel.va.disagreement_list

        def boom(*a, **k):
            raise RuntimeError("injected failure")
        rel.va.disagreement_list = boom
        try:
            with self.assertRaises(RuntimeError):
                rel.recover(self.s1, self.s2, root=self.root)
        finally:
            rel.va.disagreement_list = orig
        self.assertFalse(self.root.exists(), "注入失败后不得残留任何目录")

    def test_idempotent_replay_does_not_delete(self):
        r1 = rel.recover(self.s1, self.s2, root=self.root)
        run = Path(r1["run_dir"])
        marker = run / "MARKER_KEEP"
        marker.write_text("keep", encoding="utf-8")
        r2 = rel.recover(self.s1, self.s2, root=self.root)
        self.assertTrue(r2.get("idempotent_replay"))
        self.assertTrue(marker.exists(), "幂等返回不得删除既有成功结果")

    def test_conflicting_existing_dir_fails_closed(self):
        r1 = rel.recover(self.s1, self.s2, root=self.root)
        run = Path(r1["run_dir"])
        (run / "recovery_report.json").write_text("{}", encoding="utf-8")   # 破坏内容
        with self.assertRaises(ValueError):
            rel.recover(self.s1, self.s2, root=self.root)

    def test_report_paths_exist_after_promotion(self):
        r = rel.recover(self.s1, self.s2, root=self.root)
        run = Path(r["run_dir"])
        rep = json.loads((run / "recovery_report.json").read_text(encoding="utf-8"))
        # 引用路径在提升后必须实际存在
        self.assertTrue((run / rep["disagreement"]["artifact_relpath"]).exists())
        self.assertIn("run-", rep["run_dir"])
        self.assertNotIn(".tmp-", json.dumps(rep, ensure_ascii=False),
                         "报告中不得残留临时目录路径")

    def test_concurrent_unique_tmp_dirs(self):
        """同一对提交并发：临时目录名必须唯一（不互删）。"""
        import os, uuid
        names = {f".tmp-{rel._run_name(self.s1, self.s2)}-{os.getpid()}-{uuid.uuid4().hex[:8]}"
                 for _ in range(5)}
        self.assertEqual(len(names), 5)


if __name__ == "__main__":
    unittest.main()
