# -*- coding: utf-8 -*-
"""model_client.py 测试：digest fail-closed、infra/parse 错误不转 abstain、工件字段完整。

用法：python -m unittest cpg.ablation.tests.test_model_client -v
"""
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from cpg.ablation.model_client import ModelClient  # noqa: E402
from cpg.ablation.prompt_renderer import SYSTEM  # noqa: E402


class TestDigestFailClosed(unittest.TestCase):
    def test_digest_mismatch_raises(self):
        c = ModelClient()
        with mock.patch.object(c, "actual_digest", return_value="deadbeef"):
            with self.assertRaises(RuntimeError):
                c.verify_digest()

    def test_digest_match_ok(self):
        c = ModelClient()
        with mock.patch.object(c, "actual_digest", return_value=c.expected_digest):
            c.verify_digest()  # 不抛


class TestCallSchema(unittest.TestCase):
    def _mock_generate_ok(self, response_text):
        resp = json.dumps({"response": response_text, "prompt_eval_count": 100,
                           "done_reason": "stop"}).encode("utf-8")

        def fake_urlopen(req, timeout=None):
            m = mock.MagicMock()
            m.__enter__.return_value.read.return_value = resp
            return m
        return fake_urlopen

    def test_parse_ok(self):
        c = ModelClient()
        with mock.patch.object(c, "ollama_version", return_value="ollama 0.33.3"):
            with mock.patch("urllib.request.urlopen",
                            self._mock_generate_ok('{"verdict":"benign","cwe":null}')):
                rec = c.call("prompt", SYSTEM, sample_id="X", side="vuln", arm="real", repeat=0)
        self.assertEqual(rec["parse_status"], "OK")
        self.assertEqual(rec["verdict"], "benign")
        self.assertEqual(rec["schema_version"], "model-call/1")
        # 必需字段齐全
        for k in ("sample_id", "side", "arm", "repeat", "model_digest",
                  "raw_response_sha256", "request_sha256", "duration_ms"):
            self.assertIn(k, rec)

    def test_parse_error_not_abstain(self):
        c = ModelClient()
        with mock.patch.object(c, "ollama_version", return_value="ollama 0.33.3"):
            with mock.patch("urllib.request.urlopen",
                            self._mock_generate_ok("这不是 JSON")):
                rec = c.call("prompt", SYSTEM, sample_id="X", side="vuln", arm="real", repeat=0)
        self.assertEqual(rec["parse_status"], "ERROR")
        self.assertIsNone(rec["verdict"], "解析失败不得映射为 abstain")

    def test_run_error_not_abstain(self):
        import urllib.error
        c = ModelClient()
        with mock.patch.object(c, "ollama_version", return_value="ollama 0.33.3"):
            def boom(req, timeout=None):
                raise urllib.error.URLError("connection refused")
            with mock.patch("urllib.request.urlopen", boom):
                rec = c.call("prompt", SYSTEM, sample_id="X", side="vuln", arm="real", repeat=0)
        self.assertEqual(rec["parse_status"], "ERROR")
        self.assertIsNotNone(rec["run_error"])
        self.assertIsNone(rec["verdict"])


if __name__ == "__main__":
    unittest.main()
