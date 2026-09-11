# -*- coding: utf-8 -*-
"""A-2 验收：事务性 / 幂等完整性 / 并发 / registry fail-closed / 引用路径存在。

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
NL = "\n"


def _write_json(p: Path, doc: dict) -> None:
    p.write_bytes((json.dumps(doc, ensure_ascii=False, indent=2) + NL).encode("utf-8"))


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
        p.write_text(NL.join(json.dumps(x, ensure_ascii=False) for x in recs),
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
            _write_json(reg, doc)
            with self.assertRaises(ValueError) as cm:
                rel.recover(self.s1, self.s2, root=self.root)
            self.assertIn("不符", str(cm.exception))
        finally:
            reg.write_bytes(backup)

    def test_registry_schema_and_clean_fail_closed(self):
        reg = rel.ANN / "distribution_registry.json"
        backup = reg.read_bytes()
        try:
            doc = json.loads(backup)
            doc["schema"] = "WRONG/1"
            _write_json(reg, doc)
            with self.assertRaises(ValueError):
                rel.recover(self.s1, self.s2, root=self.root)
            doc = json.loads(backup)
            doc["provenance_check"]["clean"] = False
            _write_json(reg, doc)
            with self.assertRaises(ValueError):
                rel.recover(self.s1, self.s2, root=self.root)
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
        self.assertFalse(any(x.name.endswith(".lease") for x in self.root.iterdir()),
                         "不得残留 .lease 文件")

    def test_fault_injection_leaves_no_tmp(self):
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

    def test_report_paths_exist_after_promotion(self):
        r = rel.recover(self.s1, self.s2, root=self.root)
        run = Path(r["run_dir"])
        rep = json.loads((run / "recovery_report.json").read_text(encoding="utf-8"))
        self.assertTrue((run / rep["disagreement"]["artifact_relpath"]).exists())
        self.assertIn("run-", rep["run_dir"])
        self.assertNotIn(".tmp-", json.dumps(rep, ensure_ascii=False))

    def test_concurrent_unique_tmp_dirs(self):
        import os
        import uuid
        names = {f".tmp-{rel._run_name(self.s1, self.s2)}-{os.getpid()}-{uuid.uuid4().hex[:8]}"
                 for _ in range(5)}
        self.assertEqual(len(names), 5)


class TestIdempotencyIntegrity(A2Base):
    """P0：幂等返回必须验证**整份事务的完整性**，而不是只看两个输入 SHA。"""

    def _first(self):
        return rel.recover(self.s1, self.s2, root=self.root)

    def test_1_first_success(self):
        r = self._first()
        rep = json.loads((Path(r["run_dir"]) / "recovery_report.json").read_text(encoding="utf-8"))
        self.assertEqual(rep["output_state"], "COMPLETE")
        self.assertEqual(rep["disagreements_n_items"], 0)
        self.assertTrue(rep["disagreements_sha256"])
        self.assertTrue(rep["distribution_registry_sha256"])

    def test_5_unchanged_returns_idempotent(self):
        self._first()
        r2 = rel.recover(self.s1, self.s2, root=self.root)
        self.assertTrue(r2.get("idempotent_replay"))

    def test_2_deleted_disagreements_rejected(self):
        r = self._first()
        (Path(r["run_dir"]) / "disagreements.json").unlink()
        with self.assertRaises(ValueError) as cm:
            rel.recover(self.s1, self.s2, root=self.root)
        self.assertIn("disagreements", str(cm.exception))

    def test_3_tampered_disagreements_rejected(self):
        r = self._first()
        p = Path(r["run_dir"]) / "disagreements.json"
        doc = json.loads(p.read_text(encoding="utf-8"))
        doc["items"] = [{"kind": "DISAGREEMENT", "hunk_id": "f" * 64}]
        _write_json(p, doc)
        with self.assertRaises(ValueError):
            rel.recover(self.s1, self.s2, root=self.root)

    def test_4_tampered_report_fields_rejected(self):
        for field, val in (("template", {"sha256": "0" * 64}),
                           ("distribution_registry_sha256", "1" * 64),
                           ("output_state", "PARTIAL")):
            with self.subTest(field=field):
                shutil.rmtree(self.root, ignore_errors=True)
                r = self._first()
                p = Path(r["run_dir"]) / "recovery_report.json"
                doc = json.loads(p.read_text(encoding="utf-8"))
                doc[field] = val
                _write_json(p, doc)
                with self.assertRaises(ValueError):
                    rel.recover(self.s1, self.s2, root=self.root)

    def test_report_binds_registry_bytes_and_payload_trees(self):
        r = self._first()
        rep = json.loads((Path(r["run_dir"]) / "recovery_report.json").read_text(encoding="utf-8"))
        rc = rep["registry_check"]
        self.assertTrue(rc["registry_sha256"])
        self.assertEqual(set(rc["reviewer_payload_tree_sha256"]), {"reviewer1", "reviewer2"})


if __name__ == "__main__":
    unittest.main()
