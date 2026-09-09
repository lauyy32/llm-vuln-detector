# -*- coding: utf-8 -*-
"""run_experiment 契约测试：representation 冻结、invoke schema、漂移阻断。

invoke 测试一律使用 fake ModelClient，不得实际调用模型。
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from cpg.ablation import run_experiment as rex  # noqa: E402


def _write_run_dir(rd: Path, n: int = 1, with_selection_plan: bool = False,
                   protocol: dict | None = None) -> None:
    (rd / "prompts").mkdir(parents=True, exist_ok=True)
    fp = rex.representation_fingerprints()
    prot = protocol if protocol is not None else {
        "representation": "legacy-rq1-r0", "summary": False, "max_code_chars": 8000,
        **fp,
    }
    (rd / "protocol.json").write_text(json.dumps(prot), encoding="utf-8")
    manifest = []
    for i in range(n):
        cve, side = f"CVE-T{i}", "vuln"
        p = rd / "prompts" / f"{cve}_{side}.prompt.txt"
        # 含 2 个 fence：使 verify-inputs 基础检查通过，得以走到完整性校验
        p.write_text("# 目标代码（节选）\n```\nx=1\n```\n", encoding="utf-8")
        rec = {
            "sample_id": cve, "side": side, "arm": "real",
            "prompt_path": str(p.relative_to(rd)),
            # 真实 SHA：不得用占位值（否则固化完整性缺口）
            "prompt_sha256": rex._sha256_text(p.read_text(encoding="utf-8")),
            "representation": "legacy-rq1-r0",
            "code_text_sha256": "b" * 64,
            "representation_sha256": fp["representation_sha256"],
            "prompt_renderer_sha256": fp["prompt_renderer_sha256"],
            "system_sha256": fp["system_sha256"],
            "source_tree_sha256": "c" * 64,
            "cpg_bundle_sha256": "e" * 64,
        }
        if with_selection_plan:
            rec["selection_plan_sha256"] = "d" * 64
        manifest.append(rec)
    (rd / "prompt_manifest.jsonl").write_text(
        "\n".join(json.dumps(m) for m in manifest) + "\n", encoding="utf-8")
    (rd / "run_schedule.json").write_text(json.dumps(
        [{"sample_id": m["sample_id"], "side": m["side"], "arm": "real"}
         for m in manifest]), encoding="utf-8")
    rex._write_state(rd, "INPUTS_VERIFIED")  # invoke 只接受该状态


class FakeClient:
    def __init__(self, *a, **k):
        pass

    def verify_digest(self):
        return None

    def call(self, prompt, system, **kw):
        return {"schema_version": "model-call/1", "verdict": "benign",
                "parse_status": "OK", "sample_id": kw.get("sample_id"),
                "side": kw.get("side"), "raw_response": {},
                "raw_response_sha256": "0" * 64}


class TestRepresentationGate(unittest.TestCase):
    def test_prepare_rejects_changed_hunk(self):
        # argparse 层即拒绝：changed-hunk-r0 不在 ALLOWED_REPRESENTATIONS
        self.assertNotIn("changed-hunk-r0", rex.ALLOWED_REPRESENTATIONS)
        self.assertEqual(rex.ALLOWED_REPRESENTATIONS,
                         {"legacy-rq1-r0", "legacy-rq1-r1-cpg-canonical"})

    def test_prepare_records_representation_hashes(self):
        fp = rex.representation_fingerprints()
        for k in ("representation_sha256", "prompt_renderer_sha256", "system_sha256"):
            self.assertIn(k, fp)
            self.assertEqual(len(fp[k]), 64, f"{k} 应是 64 位 hex")

    def test_canonical_fingerprint_includes_cpg_eval(self):
        fp = rex.representation_fingerprints("legacy-rq1-r1-cpg-canonical")
        for k in ("representation_sha256", "prompt_renderer_sha256",
                  "system_sha256", "cpg_eval_sha256"):
            self.assertIn(k, fp)
            self.assertEqual(len(fp[k]), 64, f"{k} 应是 64 位 hex")
        # canonical 的 representation_sha256 指向 r1 模块，r0 的指向 r0 模块
        fp0 = rex.representation_fingerprints("legacy-rq1-r0")
        self.assertNotEqual(fp["representation_sha256"],
                            fp0["representation_sha256"])


class TestInvokeSchema(unittest.TestCase):
    def test_invoke_accepts_legacy_manifest_without_selection_plan(self):
        with tempfile.TemporaryDirectory() as td:
            rd = Path(td)
            _write_run_dir(rd, n=2, with_selection_plan=False)
            with mock.patch.object(rex, "ModelClient", FakeClient):
                rc = rex.invoke(type("A", (), {"run_dir": rd})())
            self.assertEqual(rc, 0, "legacy manifest 无 selection_plan 时 invoke 应成功")
            lines = [json.loads(l) for l in
                     (rd / "results.jsonl").read_text(encoding="utf-8").splitlines()
                     if l.strip()]
            self.assertEqual(len(lines), 2)

    def test_invoke_rejects_prompt_sha_mismatch(self):
        """P0-1：磁盘 prompt 被改动后，冻结 SHA 不匹配必须阻断。"""
        with tempfile.TemporaryDirectory() as td:
            rd = Path(td)
            _write_run_dir(rd, n=1)
            # 改动磁盘 prompt，使实际 SHA 与冻结值不符
            (rd / "prompts" / "CVE-T0_vuln.prompt.txt").write_text("tampered",
                                                                  encoding="utf-8")
            with mock.patch.object(rex, "ModelClient", FakeClient):
                rc = rex.invoke(type("A", (), {"run_dir": rd})())
            self.assertNotEqual(rc, 0, "prompt SHA 漂移时 invoke 必须阻断")

    def test_invoke_result_contains_representation_provenance(self):
        """P0-2：结果必须落到 representation / 实现指纹 / cpg_bundle。"""
        with tempfile.TemporaryDirectory() as td:
            rd = Path(td)
            _write_run_dir(rd, n=1)
            fp = rex.representation_fingerprints()

            class ProvClient(FakeClient):
                def call(self, prompt, system, **kw):
                    rec = super().call(prompt, system, **kw)
                    ex = kw.get("extra") or {}
                    rec.update({
                        "representation": ex.get("representation"),
                        "code_text_sha256": ex.get("code_text_sha256"),
                        "representation_sha256": ex.get("representation_sha256"),
                        "prompt_renderer_sha256": ex.get("prompt_renderer_sha256"),
                        "cpg_bundle_sha256": ex.get("cpg_bundle_sha256"),
                    })
                    return rec

            with mock.patch.object(rex, "ModelClient", ProvClient):
                rc = rex.invoke(type("A", (), {"run_dir": rd})())
            self.assertEqual(rc, 0)
            rec = json.loads((rd / "results.jsonl").read_text(encoding="utf-8").splitlines()[0])
            self.assertEqual(rec["representation"], "legacy-rq1-r0")
            self.assertEqual(rec["representation_sha256"], fp["representation_sha256"])
            self.assertEqual(rec["prompt_renderer_sha256"], fp["prompt_renderer_sha256"])
            self.assertEqual(rec["cpg_bundle_sha256"], "e" * 64)

    def test_schedule_duplicate_blocked_before_any_call(self):
        """重复 schedule 必须在任何模型调用前阻断，且不留部分结果。"""
        with tempfile.TemporaryDirectory() as td:
            rd = Path(td)
            _write_run_dir(rd, n=2)
            sched = json.loads((rd / "run_schedule.json").read_text(encoding="utf-8"))
            sched.append(dict(sched[0]))  # 制造重复
            (rd / "run_schedule.json").write_text(json.dumps(sched), encoding="utf-8")
            with mock.patch.object(rex, "ModelClient", FakeClient):
                rc = rex.invoke(type("A", (), {"run_dir": rd})())
            self.assertNotEqual(rc, 0, "schedule 重复必须在调用前阻断")
            self.assertFalse((rd / "results.jsonl").exists(),
                             "阻断时不得已写入任何模型结果")

    def test_verify_inputs_requires_full_integrity(self):
        """verify-inputs 必须在完整校验通过后才写 INPUTS_VERIFIED。"""
        with tempfile.TemporaryDirectory() as td:
            rd = Path(td)
            _write_run_dir(rd, n=1)
            # 破坏：schedule 与 manifest 集合不一致
            sched = json.loads((rd / "run_schedule.json").read_text(encoding="utf-8"))
            sched[0]["sample_id"] = "CVE-GHOST"
            (rd / "run_schedule.json").write_text(json.dumps(sched), encoding="utf-8")
            rex._write_state(rd, "INPUTS_FROZEN")
            rc = rex.verify_inputs(type("A", (), {"run_dir": rd})())
            self.assertNotEqual(rc, 0, "集合不一致时 verify-inputs 必须失败")
            self.assertNotEqual(rex._read_state(rd), "INPUTS_VERIFIED",
                                "不得在未通过完整校验时标记为已验证")

    def test_representation_hash_drift_blocks_invoke(self):
        with tempfile.TemporaryDirectory() as td:
            rd = Path(td)
            _write_run_dir(rd, n=1)
            # 漂移：protocol 的 representation_sha256 与 manifest 记录不一致
            prot = json.loads((rd / "protocol.json").read_text(encoding="utf-8"))
            prot["representation_sha256"] = "f" * 64
            (rd / "protocol.json").write_text(json.dumps(prot), encoding="utf-8")
            with mock.patch.object(rex, "ModelClient", FakeClient):
                rc = rex.invoke(type("A", (), {"run_dir": rd})())
            # 当前实现应阻断（非 0）或至少不静默通过
            self.assertNotEqual(rc, 0,
                                "表示实现 SHA 漂移时 invoke 不得静默通过")


if __name__ == "__main__":
    unittest.main()
