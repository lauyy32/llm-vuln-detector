# -*- coding: utf-8 -*-
"""run_experiment 契约测试：representation 冻结、两阶段 RUN_LOCK、invoke schema、
结果门禁、resume。

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
from cpg.ablation import model_client as mc  # noqa: E402


def _write_run_dir(rd: Path, n: int = 1, with_selection_plan: bool = False,
                   protocol: dict | None = None, locked: bool = False) -> None:
    (rd / "prompts").mkdir(parents=True, exist_ok=True)
    fp = rex.representation_fingerprints()
    prot = protocol if protocol is not None else {
        "representation": "legacy-rq1-r0", "summary": False, "max_code_chars": 8000,
        "model": mc.MODEL, "model_digest": mc.MODEL_DIGEST,
        "num_ctx": mc.NUM_CTX, "num_predict": mc.NUM_PREDICT,
        "temperature": mc.TEMPERATURE, "top_p": mc.TOP_P, "seed": mc.SEED,
        "cpg_cache_key": "e" * 64, "canonical_cpg_rows_sha256": "f" * 64,
        **fp,
    }
    (rd / "protocol.json").write_text(json.dumps(prot), encoding="utf-8")
    manifest = []
    for i in range(n):
        cve, side = f"CVE-T{i}", "vuln"
        p = rd / "prompts" / f"{cve}_{side}.prompt.txt"
        p.write_text("# 目标代码（节选）\n```\nx=1\n```\n", encoding="utf-8")
        rec = {
            "sample_id": cve, "side": side, "arm": "real",
            "prompt_path": str(p.relative_to(rd)),
            "prompt_sha256": rex._sha256_text(p.read_text(encoding="utf-8")),
            "representation": "legacy-rq1-r0",
            "code_text_sha256": "b" * 64,
            "representation_sha256": fp["representation_sha256"],
            "prompt_renderer_sha256": fp["prompt_renderer_sha256"],
            "system_sha256": fp["system_sha256"],
            "source_tree_sha256": "c" * 64,
            "cpg_cache_key": "e" * 64,
            "canonical_cpg_rows_sha256": "f" * 64,
        }
        if with_selection_plan:
            rec["selection_plan_sha256"] = "d" * 64
        manifest.append(rec)
    (rd / "prompt_manifest.jsonl").write_text(
        "\n".join(json.dumps(m) for m in manifest) + "\n", encoding="utf-8")
    (rd / "run_schedule.json").write_text(json.dumps(
        [{"sample_id": m["sample_id"], "side": m["side"], "arm": "real"}
         for m in manifest]), encoding="utf-8")
    (rd / "cpg_bundle.json").write_text(json.dumps({"cpg_cache_key": "e" * 64}),
                                        encoding="utf-8")
    if locked:
        _write_lock_request(rd)
        _write_approval(rd)
    else:
        rex._write_state(rd, "INPUTS_VERIFIED")


def _write_lock_request(rd: Path) -> None:
    """写 lock_request.json（相对路径 + SHA）并置 INPUTS_LOCKED。"""
    canonical_real = ROOT / "cpg/ablation/artifacts/canonical_corpus_manifest.json"
    files = {
        "canonical_manifest": {"base": "repo",
                               "path": "cpg/ablation/artifacts/canonical_corpus_manifest.json",
                               "sha256": rex._file_sha256(canonical_real)},
        "protocol": {"base": "run", "path": "protocol.json",
                     "sha256": rex._file_sha256(rd / "protocol.json")},
        "prompt_manifest": {"base": "run", "path": "prompt_manifest.jsonl",
                            "sha256": rex._file_sha256(rd / "prompt_manifest.jsonl")},
        "run_schedule": {"base": "run", "path": "run_schedule.json",
                         "sha256": rex._file_sha256(rd / "run_schedule.json")},
        "cpg_bundle": {"base": "run", "path": "cpg_bundle.json",
                       "sha256": rex._file_sha256(rd / "cpg_bundle.json")},
    }
    lock = {"state": "INPUTS_LOCKED", "locked_at": "2026-09-09T00:00:00+00:00",
            "git_commit": rex._git_commit(), "files": files}
    lock_text = json.dumps(lock, ensure_ascii=False, indent=2)
    (rd / "lock_request.json").write_text(lock_text + "\n", encoding="utf-8")
    rex._write_state(rd, "INPUTS_LOCKED", {"lock_request_sha256": rex._lock_request_sha(rd)})


def _write_approval(rd: Path, reviewer: str = "codex") -> None:
    """写 review_approval.json 并置 REVIEW_LOCKED。"""
    approval = {"reviewer": reviewer, "decision": "APPROVED",
                "lock_request_sha256": rex._lock_request_sha(rd),
                "reviewed_git_commit": rex._git_commit(),
                "approved_at": "2026-09-09T00:00:00+00:00"}
    (rd / "review_approval.json").write_text(json.dumps(approval), encoding="utf-8")
    rex._write_state(rd, "REVIEW_LOCKED",
                     {"lock_request_sha256": approval["lock_request_sha256"],
                      "reviewer": reviewer})


class FakeClient:
    def __init__(self, *a, **k):
        pass

    def verify_digest(self):
        return None

    def call(self, prompt, system, **kw):
        ex = kw.get("extra") or {}
        request = {"model": mc.MODEL, "prompt": prompt, "system": system,
                   "stream": False,
                   "options": {"num_ctx": mc.NUM_CTX, "num_predict": mc.NUM_PREDICT,
                               "temperature": mc.TEMPERATURE, "top_p": mc.TOP_P,
                               "seed": mc.SEED}}
        raw_text = "{}"
        return {
            "schema_version": "model-call/1", "verdict": "benign",
            "parse_status": "OK", "sample_id": kw.get("sample_id"),
            "side": kw.get("side"), "arm": kw.get("arm"),
            "repeat": kw.get("repeat"), "run_error": None,
            "raw_response": {}, "raw_response_text": raw_text,
            "raw_response_sha256": rex._sha256_text(raw_text),
            "prompt_sha256": ex.get("prompt_sha256"),
            "prompt_path": ex.get("prompt_path"),
            "representation": ex.get("representation"),
            "code_text_sha256": ex.get("code_text_sha256"),
            "source_tree_sha256": ex.get("source_tree_sha256"),
            "cpg_cache_key": ex.get("cpg_cache_key"),
            "canonical_cpg_rows_sha256": ex.get("canonical_cpg_rows_sha256"),
            "representation_sha256": ex.get("representation_sha256"),
            "prompt_renderer_sha256": ex.get("prompt_renderer_sha256"),
            "cpg_eval_sha256": ex.get("cpg_eval_sha256"),
            "system_sha256": ex.get("system_sha256"),
            "model_name": mc.MODEL, "model_digest": mc.MODEL_DIGEST,
            "request": request,
            "request_sha256": rex._sha256_text(json.dumps(request, sort_keys=True)),
            "prompt_eval_count": 100,
        }


class TestRepresentationGate(unittest.TestCase):
    def test_prepare_rejects_changed_hunk(self):
        self.assertNotIn("changed-hunk-r0", rex.ALLOWED_REPRESENTATIONS)
        self.assertEqual(rex.ALLOWED_REPRESENTATIONS,
                         {"legacy-rq1-r0", "legacy-rq1-r1-cpg-canonical"})

    def test_prepare_records_representation_hashes(self):
        fp = rex.representation_fingerprints()
        for k in ("representation_sha256", "prompt_renderer_sha256", "system_sha256"):
            self.assertIn(k, fp)
            self.assertEqual(len(fp[k]), 64)

    def test_canonical_fingerprint_includes_cpg_eval(self):
        fp = rex.representation_fingerprints("legacy-rq1-r1-cpg-canonical")
        self.assertIn("cpg_eval_sha256", fp)
        fp0 = rex.representation_fingerprints("legacy-rq1-r0")
        self.assertNotEqual(fp["representation_sha256"], fp0["representation_sha256"])


class TestRunLock(unittest.TestCase):
    def test_invoke_rejects_unlocked(self):
        with tempfile.TemporaryDirectory() as td:
            rd = Path(td)
            _write_run_dir(rd, n=1, locked=False)
            with mock.patch.object(rex, "ModelClient", FakeClient):
                rc = rex.invoke(type("A", (), {"run_dir": rd})())
            self.assertNotEqual(rc, 0)

    def test_invoke_rejects_inputs_locked_without_approval(self):
        """有 lock_request 但无 reviewer approval 必须拒绝（P0-2）。"""
        with tempfile.TemporaryDirectory() as td:
            rd = Path(td)
            _write_run_dir(rd, n=1, locked=False)
            _write_lock_request(rd)  # INPUTS_LOCKED，无 approval
            rex._write_state(rd, "REVIEW_LOCKED")  # 伪造状态
            with mock.patch.object(rex, "ModelClient", FakeClient):
                rc = rex.invoke(type("A", (), {"run_dir": rd})())
            self.assertNotEqual(rc, 0, "无 reviewer approval 时 invoke 必须拒绝")

    def test_empty_lock_bypass_rejected(self):
        """P0-1：空锁（files={}）或错误 state 不得绕过。"""
        with tempfile.TemporaryDirectory() as td:
            rd = Path(td)
            _write_run_dir(rd, n=1, locked=False)
            (rd / "lock_request.json").write_text(
                json.dumps({"state": "NOT_LOCKED", "files": {}}), encoding="utf-8")
            (rd / "review_approval.json").write_text(
                json.dumps({"reviewer": "codex", "decision": "APPROVED",
                            "lock_request_sha256": "0" * 64,
                            "reviewed_git_commit": rex._git_commit()}), encoding="utf-8")
            rex._write_state(rd, "REVIEW_LOCKED")
            with mock.patch.object(rex, "ModelClient", FakeClient):
                rc = rex.invoke(type("A", (), {"run_dir": rd})())
            self.assertNotEqual(rc, 0, "空锁/错误 state 必须被拒绝")

    def test_lock_state_mismatch_rejected(self):
        """lock_request.state 非 INPUTS_LOCKED 必须被拒绝。"""
        with tempfile.TemporaryDirectory() as td:
            rd = Path(td)
            _write_run_dir(rd, n=1, locked=False)
            _write_lock_request(rd)
            lock = json.loads((rd / "lock_request.json").read_text(encoding="utf-8"))
            lock["state"] = "REVIEW_LOCKED"
            (rd / "lock_request.json").write_text(json.dumps(lock), encoding="utf-8")
            _write_approval(rd)
            with mock.patch.object(rex, "ModelClient", FakeClient):
                rc = rex.invoke(type("A", (), {"run_dir": rd})())
            self.assertNotEqual(rc, 0)

    def test_approve_lock_requires_inputs_locked(self):
        with tempfile.TemporaryDirectory() as td:
            rd = Path(td)
            rex._write_state(rd, "INPUTS_VERIFIED")
            rc = rex.approve_lock(type("A", (), {"run_dir": rd, "reviewer": "codex"})())
            self.assertNotEqual(rc, 0)

    def test_approve_lock_requires_reviewer(self):
        with tempfile.TemporaryDirectory() as td:
            rd = Path(td)
            _write_run_dir(rd, n=1, locked=False)
            _write_lock_request(rd)
            rc = rex.approve_lock(type("A", (), {"run_dir": rd, "reviewer": None})())
            self.assertNotEqual(rc, 0, "approve-lock 无 reviewer 必须拒绝")

    def test_invoke_rejects_lock_file_drift(self):
        with tempfile.TemporaryDirectory() as td:
            rd = Path(td)
            _write_run_dir(rd, n=1, locked=True)
            (rd / "protocol.json").write_text('{"tampered": true}', encoding="utf-8")
            with mock.patch.object(rex, "ModelClient", FakeClient):
                rc = rex.invoke(type("A", (), {"run_dir": rd})())
            self.assertNotEqual(rc, 0, "锁文件 SHA 漂移时 invoke 必须拒绝")

    def test_reject_does_not_change_state(self):
        """P0-1：状态机预条件拒绝不得污染状态（INPUTS_LOCKED 保持等待态）。"""
        with tempfile.TemporaryDirectory() as td:
            rd = Path(td)
            _write_run_dir(rd, n=1, locked=False)
            _write_lock_request(rd)  # INPUTS_LOCKED，无 approval
            rc = rex.invoke(type("A", (), {"run_dir": rd})())
            self.assertNotEqual(rc, 0)
            self.assertEqual(rex._read_state(rd), "INPUTS_LOCKED",
                             "预条件拒绝后状态不得被改成 FAILED")


class TestInvokeSchema(unittest.TestCase):
    def test_invoke_accepts_legacy_manifest_without_selection_plan(self):
        with tempfile.TemporaryDirectory() as td:
            rd = Path(td)
            _write_run_dir(rd, n=2, with_selection_plan=False, locked=True)
            with mock.patch.object(rex, "ModelClient", FakeClient):
                rc = rex.invoke(type("A", (), {"run_dir": rd})())
            self.assertEqual(rc, 0)
            lines = [json.loads(l) for l in
                     (rd / "results.jsonl").read_text(encoding="utf-8").splitlines()
                     if l.strip()]
            self.assertEqual(len(lines), 2)

    def test_invoke_rejects_prompt_sha_mismatch(self):
        with tempfile.TemporaryDirectory() as td:
            rd = Path(td)
            _write_run_dir(rd, n=1, locked=True)
            (rd / "prompts" / "CVE-T0_vuln.prompt.txt").write_text("tampered",
                                                                  encoding="utf-8")
            with mock.patch.object(rex, "ModelClient", FakeClient):
                rc = rex.invoke(type("A", (), {"run_dir": rd})())
            self.assertNotEqual(rc, 0)

    def test_invoke_result_contains_representation_provenance(self):
        with tempfile.TemporaryDirectory() as td:
            rd = Path(td)
            _write_run_dir(rd, n=1, locked=True)
            with mock.patch.object(rex, "ModelClient", FakeClient):
                rc = rex.invoke(type("A", (), {"run_dir": rd})())
            self.assertEqual(rc, 0)
            rec = json.loads((rd / "results.jsonl").read_text(encoding="utf-8").splitlines()[0])
            self.assertEqual(rec["representation"], "legacy-rq1-r0")
            self.assertEqual(rec["cpg_cache_key"], "e" * 64)
            self.assertEqual(rec["canonical_cpg_rows_sha256"], "f" * 64)

    def test_schedule_duplicate_blocked_before_any_call(self):
        with tempfile.TemporaryDirectory() as td:
            rd = Path(td)
            _write_run_dir(rd, n=2, locked=True)
            sched = json.loads((rd / "run_schedule.json").read_text(encoding="utf-8"))
            sched.append(dict(sched[0]))
            (rd / "run_schedule.json").write_text(json.dumps(sched), encoding="utf-8")
            _write_lock_request(rd)
            _write_approval(rd)
            with mock.patch.object(rex, "ModelClient", FakeClient):
                rc = rex.invoke(type("A", (), {"run_dir": rd})())
            self.assertNotEqual(rc, 0)
            self.assertFalse((rd / "results.jsonl").exists())

    def test_verify_inputs_requires_full_integrity(self):
        with tempfile.TemporaryDirectory() as td:
            rd = Path(td)
            _write_run_dir(rd, n=1, locked=False)
            sched = json.loads((rd / "run_schedule.json").read_text(encoding="utf-8"))
            sched[0]["sample_id"] = "CVE-GHOST"
            (rd / "run_schedule.json").write_text(json.dumps(sched), encoding="utf-8")
            rex._write_state(rd, "INPUTS_FROZEN")
            rc = rex.verify_inputs(type("A", (), {"run_dir": rd})())
            self.assertNotEqual(rc, 0)
            self.assertNotEqual(rex._read_state(rd), "INPUTS_VERIFIED")


class TestVerifyResults(unittest.TestCase):
    def _clean_record(self, rd: Path, sample_id: str, side: str, overrides: dict | None = None) -> dict:
        prot = json.loads((rd / "protocol.json").read_text(encoding="utf-8"))
        pm = None
        for line in (rd / "prompt_manifest.jsonl").read_text(encoding="utf-8").splitlines():
            if line.strip():
                r = json.loads(line)
                if r["sample_id"] == sample_id and r["side"] == side:
                    pm = r
                    break
        disk_prompt = (rd / pm["prompt_path"]).read_text(encoding="utf-8")
        request = {"model": prot["model"], "prompt": disk_prompt,
                   "system": rex.prompt_renderer.SYSTEM, "stream": False,
                   "options": {"num_ctx": prot["num_ctx"], "num_predict": prot["num_predict"],
                               "temperature": prot["temperature"], "top_p": prot["top_p"],
                               "seed": prot["seed"]}}
        raw_text = "{}"
        rec = {
            "schema_version": "model-call/1", "verdict": "benign",
            "parse_status": "OK", "sample_id": sample_id, "side": side,
            "arm": "real", "repeat": 0, "run_error": None,
            "raw_response": {}, "raw_response_text": raw_text,
            "raw_response_sha256": rex._sha256_text(raw_text),
            "prompt_sha256": pm["prompt_sha256"], "prompt_path": pm["prompt_path"],
            "representation": pm["representation"],
            "code_text_sha256": pm["code_text_sha256"],
            "source_tree_sha256": pm["source_tree_sha256"],
            "cpg_cache_key": pm["cpg_cache_key"],
            "canonical_cpg_rows_sha256": pm["canonical_cpg_rows_sha256"],
            "representation_sha256": pm["representation_sha256"],
            "prompt_renderer_sha256": pm["prompt_renderer_sha256"],
            "cpg_eval_sha256": pm.get("cpg_eval_sha256"),
            "system_sha256": pm["system_sha256"],
            "model_name": prot["model"], "model_digest": prot["model_digest"],
            "request": request,
            "request_sha256": rex._sha256_text(json.dumps(request, sort_keys=True)),
            "prompt_eval_count": 100,
        }
        if overrides:
            rec.update(overrides)
        return rec

    def _setup(self) -> Path:
        self._td = tempfile.TemporaryDirectory()
        rd = Path(self._td.name)
        _write_run_dir(rd, n=1, locked=True)  # verify-results 复核 RUN_LOCK，须已锁
        rex._write_state(rd, "COMPLETE")
        rec = self._clean_record(rd, "CVE-T0", "vuln")
        (rd / "results.jsonl").write_text(json.dumps(rec) + "\n", encoding="utf-8")
        self.addCleanup(self._td.cleanup)
        return rd

    def test_verify_accepts_clean_results(self):
        rd = self._setup()
        self.assertEqual(rex.verify_results(type("A", (), {"run_dir": rd})()), 0)

    def test_verify_rejects_parse_error(self):
        rd = self._setup()
        rec = self._clean_record(rd, "CVE-T0", "vuln",
                                 overrides={"parse_status": "ERROR", "verdict": None})
        (rd / "results.jsonl").write_text(json.dumps(rec) + "\n", encoding="utf-8")
        self.assertNotEqual(rex.verify_results(type("A", (), {"run_dir": rd})()), 0)

    def test_verify_rejects_run_error(self):
        rd = self._setup()
        rec = self._clean_record(rd, "CVE-T0", "vuln", overrides={"run_error": "网络错误"})
        (rd / "results.jsonl").write_text(json.dumps(rec) + "\n", encoding="utf-8")
        self.assertNotEqual(rex.verify_results(type("A", (), {"run_dir": rd})()), 0)

    def test_verify_rejects_invalid_verdict(self):
        rd = self._setup()
        rec = self._clean_record(rd, "CVE-T0", "vuln", overrides={"verdict": "maybe"})
        (rd / "results.jsonl").write_text(json.dumps(rec) + "\n", encoding="utf-8")
        self.assertNotEqual(rex.verify_results(type("A", (), {"run_dir": rd})()), 0)

    def test_verify_rejects_duplicate_key(self):
        rd = self._setup()
        rec = self._clean_record(rd, "CVE-T0", "vuln")
        with (rd / "results.jsonl").open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")
        self.assertNotEqual(rex.verify_results(type("A", (), {"run_dir": rd})()), 0)

    def test_verify_rejects_model_digest_drift(self):
        rd = self._setup()
        rec = self._clean_record(rd, "CVE-T0", "vuln", overrides={"model_digest": "f" * 64})
        (rd / "results.jsonl").write_text(json.dumps(rec) + "\n", encoding="utf-8")
        self.assertNotEqual(rex.verify_results(type("A", (), {"run_dir": rd})()), 0)

    def test_verify_rejects_forged_request_sha(self):
        """P0-3：伪造 request_sha256 必须被拒绝（重算与内容不符）。"""
        rd = self._setup()
        rec = self._clean_record(rd, "CVE-T0", "vuln", overrides={"request_sha256": "0" * 64})
        (rd / "results.jsonl").write_text(json.dumps(rec) + "\n", encoding="utf-8")
        self.assertNotEqual(rex.verify_results(type("A", (), {"run_dir": rd})()), 0)

    def test_verify_rejects_forged_raw_response_sha(self):
        """P0-3：伪造 raw_response_sha256 必须被拒绝。"""
        rd = self._setup()
        rec = self._clean_record(rd, "CVE-T0", "vuln",
                                 overrides={"raw_response_sha256": "0" * 64})
        (rd / "results.jsonl").write_text(json.dumps(rec) + "\n", encoding="utf-8")
        self.assertNotEqual(rex.verify_results(type("A", (), {"run_dir": rd})()), 0)

    def test_verify_rejects_tampered_raw_response_text(self):
        """P0-3：raw_response_text 被篡改但 hash 未随之更新，必须拒绝。"""
        rd = self._setup()
        rec = self._clean_record(rd, "CVE-T0", "vuln",
                                 overrides={"raw_response_text": "tampered"})
        (rd / "results.jsonl").write_text(json.dumps(rec) + "\n", encoding="utf-8")
        self.assertNotEqual(rex.verify_results(type("A", (), {"run_dir": rd})()), 0)


class TestResume(unittest.TestCase):
    def test_error_records_go_to_attempts_not_results(self):
        """错误尝试进 attempts.jsonl，不进 results.jsonl；resume 重试成功（P0-3）。"""
        with tempfile.TemporaryDirectory() as td:
            rd = Path(td)
            _write_run_dir(rd, n=1, locked=True)

            class FlakyClient(FakeClient):
                calls = 0

                def call(self, prompt, system, **kw):
                    type(self).calls += 1
                    rec = super().call(prompt, system, **kw)
                    if type(self).calls == 1:  # 仅第一次调用失败
                        rec.update({"parse_status": "ERROR", "verdict": None,
                                    "run_error": "网络错误"})
                    return rec

            with mock.patch.object(rex, "ModelClient", FlakyClient):
                rc = rex.invoke(type("A", (), {"run_dir": rd})())
                self.assertEqual(rex._read_state(rd), "RETRY_REQUIRED")
                # 错误尝试不得进入 results.jsonl（允许空文件，但 0 条成功记录）
                results_after_err = []
                if (rd / "results.jsonl").exists():
                    results_after_err = [l for l in
                                         (rd / "results.jsonl").read_text(encoding="utf-8").splitlines()
                                         if l.strip()]
                self.assertEqual(len(results_after_err), 0,
                                 "错误尝试不得写入 results.jsonl")
                attempts = [json.loads(l) for l in
                            (rd / "attempts.jsonl").read_text(encoding="utf-8").splitlines()
                            if l.strip()]
                self.assertEqual(len(attempts), 1, "错误尝试必须保留在 attempts.jsonl")
                self.assertEqual(attempts[0]["parse_status"], "ERROR")
                rc2 = rex.invoke(type("A", (), {"run_dir": rd})())
                self.assertEqual(rc2, 0)
                self.assertEqual(rex._read_state(rd), "COMPLETE")
                results = [json.loads(l) for l in
                           (rd / "results.jsonl").read_text(encoding="utf-8").splitlines()
                           if l.strip()]
                self.assertEqual(len(results), 1)
                self.assertEqual(results[0]["parse_status"], "OK")
                attempts2 = [json.loads(l) for l in
                             (rd / "attempts.jsonl").read_text(encoding="utf-8").splitlines()
                             if l.strip()]
                self.assertEqual(len(attempts2), 2, "attempts 保留全部尝试（审计不丢失）")

    def test_resume_after_keyboard_interrupt(self):
        """P0-2：进程在 RUNNING 被硬中断后，可再次 invoke 续跑（RUNNING 状态恢复）。"""
        with tempfile.TemporaryDirectory() as td:
            rd = Path(td)
            _write_run_dir(rd, n=1, locked=True)

            class InterruptClient(FakeClient):
                def call(self, prompt, system, **kw):
                    raise KeyboardInterrupt

            with mock.patch.object(rex, "ModelClient", InterruptClient):
                with self.assertRaises(KeyboardInterrupt):
                    rex.invoke(type("A", (), {"run_dir": rd})())
            self.assertEqual(rex._read_state(rd), "RUNNING",
                             "硬中断后状态应停在 RUNNING")
            # 再次 invoke（RUNNING 状态）应能 resume 续跑
            with mock.patch.object(rex, "ModelClient", FakeClient):
                rc = rex.invoke(type("A", (), {"run_dir": rd})())
            self.assertEqual(rc, 0)
            self.assertEqual(rex._read_state(rd), "COMPLETE")


class TestVerifyInputsFence(unittest.TestCase):
    def test_verify_inputs_accepts_markdown_fence_in_code(self):
        with tempfile.TemporaryDirectory() as td:
            rd = Path(td)
            _write_run_dir(rd, n=1, locked=False)
            p = rd / "prompts" / "CVE-T0_vuln.prompt.txt"
            code = "# code\n```python\nx=1\n```\n"
            prompt = (f"# 审计任务\n- CVE: CVE-T0\n- 目标 CWE: CWE-022\n"
                      + rex.CODE_START + code + "\n```\n"
                      + "\n# 代码级上下文（CPG 污点切片）\n# CPG TAINT SLICE\n\n"
                      + "\n# 输出要求\n{}")
            p.write_text(prompt, encoding="utf-8")
            pm = json.loads((rd / "prompt_manifest.jsonl").read_text(
                encoding="utf-8").splitlines()[0])
            pm["prompt_sha256"] = rex._sha256_text(prompt)
            (rd / "prompt_manifest.jsonl").write_text(json.dumps(pm) + "\n",
                                                      encoding="utf-8")
            rex._write_state(rd, "INPUTS_FROZEN")
            rc = rex.verify_inputs(type("A", (), {"run_dir": rd})())
            self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
