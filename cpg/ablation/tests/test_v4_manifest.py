# -*- coding: utf-8 -*-
"""V4 manifest 接线与 provenance 测试（对应 codex 必补 6 类）。"""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from cpg.ablation import v4_manifest as vm  # noqa: E402
from cpg.ablation import v4_patch_gen as v4g  # noqa: E402
from cpg.ablation import upstream_manifest as um  # noqa: E402
from cpg.ablation import v4_gate_a as ga  # noqa: E402
from cpg.ablation import canonical_manifest_v2 as v2mod  # noqa: E402


class TestManifestWiring(unittest.TestCase):
    def test_1_missing_cli_arg_rejected(self):
        """未传 --canonical-manifest 必须失败（退出非 0）。"""
        r = subprocess.run([sys.executable, str(ROOT / "cpg/ablation/v4_gate_a.py"),
                            "canonical"], capture_output=True, text=True, cwd=str(ROOT),
                           encoding="utf-8", errors="replace")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("--canonical-manifest", r.stdout + r.stderr)

    def test_1b_wrong_manifest_rejected(self):
        """传入与单一来源不符的 manifest 必须失败。"""
        r = subprocess.run([sys.executable, str(ROOT / "cpg/ablation/v4_gate_a.py"),
                            "canonical", "--canonical-manifest",
                            str(vm.LEGACY_CANONICAL_MANIFEST)],
                           capture_output=True, text=True, cwd=str(ROOT),
                           encoding="utf-8", errors="replace")
        self.assertNotEqual(r.returncode, 0)

    def test_2_three_modules_same_manifest(self):
        """三个模块读到的 manifest 路径必须完全一致（防 split-brain）。"""
        want = vm.manifest_path().resolve()
        self.assertEqual(v4g.CANONICAL_MANIFEST.resolve(), want)
        self.assertEqual(um.CANONICAL_MANIFEST.resolve(), want)
        self.assertEqual(ga.CANONICAL_MANIFEST.resolve(), want)

    def test_3_v4_output_pair_sha_equals_current(self):
        """V4 输出的 15 个 pair SHA 必须等于当前（v2 重算）值，而不是 legacy 值。"""
        v4 = json.loads((ROOT / "cpg/ablation/artifacts/v4/v4_canonical_manifest.json")
                        .read_text(encoding="utf-8"))
        v2 = json.loads(vm.manifest_path().read_text(encoding="utf-8"))
        by = {s["sample_id"]: s for s in v2["samples"]}
        for c in v4["candidates"]:
            s = by[c["sample_id"]]
            self.assertEqual(c["pair_manifest_sha256"], s["pair_manifest_sha256"])
            self.assertNotEqual(c["pair_manifest_sha256"], s.get("legacy_pair_manifest_sha256"))

    def test_6_registry_sha_matches(self):
        """registry 记录的 SHA 必须与磁盘实际 SHA 一致（漂移即失败）。"""
        reg = json.loads((ROOT / "cpg/ablation/artifacts/v4/manifest_registry.json")
                         .read_text(encoding="utf-8"))
        import hashlib
        for e in reg["entries"]:
            p = ROOT / e["manifest"]
            self.assertTrue(p.exists(), e["manifest"])
            self.assertEqual(hashlib.sha256(p.read_bytes()).hexdigest(), e["sha256"],
                             f"{e['consumer']} manifest SHA 漂移")


class TestV2FailClosed(unittest.TestCase):
    def _mk_old(self, samples, eligible_total=1):
        d = {"eligible_total": eligible_total, "samples": samples}
        return d

    def test_5a_duplicate_id_fails(self):
        """重复 sample_id 必须进入 errors。"""
        old = self._mk_old([{"sample_id": "CVE-X", "eligible": True},
                            {"sample_id": "CVE-X", "eligible": True}], 1)
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "old.json"
            p.write_text(json.dumps(old), encoding="utf-8")
            doc = v2mod.build_v2(p)
        self.assertTrue(any("重复" in e for e in doc["errors"]))

    def test_5b_eligible_missing_dir_fails(self):
        """eligible 但 corpus-v3 目录缺失必须进入 errors。"""
        old = self._mk_old([{"sample_id": "CVE-9999-1", "eligible": True}], 1)
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "old.json"
            p.write_text(json.dumps(old), encoding="utf-8")
            doc = v2mod.build_v2(p)
        self.assertTrue(any("目录缺失" in e for e in doc["errors"]))

    def test_5c_eligible_set_mismatch_fails(self):
        """eligible 集合/数量不符必须进入 errors。"""
        old = self._mk_old([{"sample_id": "CVE-9999-1", "eligible": True}], 99)
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "old.json"
            p.write_text(json.dumps(old), encoding="utf-8")
            doc = v2mod.build_v2(p)
        self.assertTrue(any("eligible 数量" in e for e in doc["errors"]))

    def test_5d_tree_drift_fails(self):
        """eligible 的 tree SHA 与旧 manifest 不一致（真漂移）必须进入 errors。"""
        # 用真实样本但伪造旧 tree SHA
        old = self._mk_old([{"sample_id": "CVE-2026-12482", "eligible": True,
                             "vuln_tree_sha256_lf": "0" * 64,
                             "fixed_tree_sha256_lf": "0" * 64,
                             "pair_manifest_sha256": "0" * 64,
                             "source_path": "cpg/corpus-v3/CVE-2026-12482"}], 1)
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "old.json"
            p.write_text(json.dumps(old), encoding="utf-8")
            doc = v2mod.build_v2(p)
        self.assertTrue(any("tree SHA" in e or "漂移" in e for e in doc["errors"]))


if __name__ == "__main__":
    unittest.main()
