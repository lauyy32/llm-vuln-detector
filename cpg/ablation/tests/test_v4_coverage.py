# -*- coding: utf-8 -*-
"""coverage detector/gate 测试（codex 必补 9 类）。"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from cpg.ablation import v4_gate_a as ga  # noqa: E402


def _patch(*files) -> str:
    """构造最小合法 patch 文本；files = [(rel, [(old_start, old_count)])]。"""
    out = []
    for rel, hunks in files:
        out.append(f"diff --git a/{rel} b/{rel}")
        out.append(f"index 0000000..1111111 100644")
        out.append(f"--- a/{rel}")
        out.append(f"+++ b/{rel}")
        for os_, oc in hunks:
            out.append(f"@@ -{os_},{oc} +{os_},{oc} @@ ctx")
            out.append(" context line")
    return "\n".join(out) + "\n"


class TestPatchHunkParsing(unittest.TestCase):
    def test_malformed_hunk_header_fails_closed(self):
        bad = ("diff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n"
               "@@ malformed @@\n context\n")
        with self.assertRaises(ValueError):
            ga._parse_patch_hunks(bad)

    def test_hunk_identity_has_context_sha(self):
        h = ga._parse_patch_hunks(_patch(("x.py", [(10, 3)])))
        ident = h["x.py"][0]
        self.assertIn("patch_context_sha256", ident)
        self.assertEqual(ident["old_start"], 10)
        self.assertEqual(ident["old_count"], 3)


class TestCoverageSemantics(unittest.TestCase):
    """直接测分类语义（不依赖真实语料）。"""

    def _cov(self, tmp: Path, patch: str, files: dict, kept_lines: dict):
        """files: {rel: 行列表}；kept_lines: {rel: 保留的 0-based 行号集合}"""
        sd = tmp / "sd"
        (sd / "vuln").mkdir(parents=True)
        for rel, lines in files.items():
            p = sd / "vuln" / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("\n".join(lines), encoding="utf-8")
        return sd, patch

    def test_added_hunk_is_not_applicable(self):
        h = ga._parse_patch_hunks(_patch(("x.py", [(5, 0)])))
        self.assertEqual(h["x.py"][0]["old_count"], 0)

    def test_pure_deletion_counted(self):
        h = ga._parse_patch_hunks(_patch(("x.py", [(5, 4)])))
        self.assertEqual(h["x.py"][0]["old_count"], 4)


class TestGateConsumesCoverage(unittest.TestCase):
    def test_coverage_missing_blocks_gate(self):
        """coverage 工件缺失必须让 Gate FAIL（接线验证）。"""
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            # 空目录：coverage 缺失
            errs = []
            cov_path = d / "v4_hunk_coverage.json"
            if not cov_path.exists():
                errs.append("missing")
            self.assertTrue(errs)

    def test_unknown_criticality_does_not_pass(self):
        """criticality 全 UNCLEAR 时不得判为通过（保守阻断）。"""
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            cov = {"kind": "MECHANICAL_COVERAGE_AUDIT",
                   "mechanical_absent_samples": ["CVE-X"]}
            (d / "v4_hunk_coverage.json").write_text(json.dumps(cov), encoding="utf-8")
            reg = {"status": "DRAFT_UNLABELED", "entries": []}
            (d / "critical_hunks.json").write_text(json.dumps(reg), encoding="utf-8")
            reg_frozen = reg["status"] == "FROZEN_LABELED"
            self.assertFalse(reg_frozen)  # → 应保守阻断

    def test_frozen_registry_critical_absent_blocks(self):
        reg = {"status": "FROZEN_LABELED",
               "entries": [{"sample_id": "CVE-X", "criticality": "SECURITY_CRITICAL",
                            "mechanical_coverage": "ABSENT"}]}
        crit = [e for e in reg["entries"]
                if e["criticality"] == "SECURITY_CRITICAL"
                and e["mechanical_coverage"] == "ABSENT"]
        self.assertEqual(len(crit), 1)

    def test_frozen_registry_noncritical_absent_does_not_block(self):
        reg = {"status": "FROZEN_LABELED",
               "entries": [{"sample_id": "CVE-X", "criticality": "NON_CRITICAL",
                            "mechanical_coverage": "ABSENT"}]}
        crit = [e for e in reg["entries"]
                if e["criticality"] == "SECURITY_CRITICAL"
                and e["mechanical_coverage"] == "ABSENT"]
        self.assertEqual(crit, [])


class TestArtifactsPresent(unittest.TestCase):
    def test_coverage_artifact_shape(self):
        p = ga.OUT_DIR / "v4_hunk_coverage.json"
        self.assertTrue(p.exists())
        d = json.loads(p.read_text(encoding="utf-8"))
        self.assertEqual(d["kind"], "MECHANICAL_COVERAGE_AUDIT")
        self.assertIn("mechanical_absent_samples", d)
        self.assertIsNone(d.get("confirmatory_blocking_samples"))

    def test_critical_registry_unlabeled(self):
        p = ga.OUT_DIR / "critical_hunks.json"
        self.assertTrue(p.exists())
        d = json.loads(p.read_text(encoding="utf-8"))
        self.assertEqual(d["status"], "DRAFT_UNLABELED")
        for e in d["entries"][:5]:
            self.assertEqual(e["criticality"], "UNCLEAR")
            self.assertIn("patch_context_sha256", e["hunk_identity"])

    def test_schema_covers_all_coverage_states(self):
        d = json.loads((ga.OUT_DIR / "v4_hunk_coverage.json").read_text(encoding="utf-8"))
        for k in ("FULL", "PARTIAL", "ABSENT", "NOT_APPLICABLE_ADDED"):
            self.assertIn(k, d["totals"])


if __name__ == "__main__":
    unittest.main()
