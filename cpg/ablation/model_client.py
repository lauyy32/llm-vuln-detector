# -*- coding: utf-8 -*-
"""统一模型客户端（Code plan 第6阶段）。

- 调用前读取并校验完整 64 位 digest，不一致立即抛异常退出（不 WARN）；
- 记录 Ollama 后台版本（版本更新可能影响推理行为，即使 model 权重 digest 未变）；
- 完整冻结 model/digest/num_ctx/num_predict/temperature/top_p/seed；
- 网络错误/超时/非 JSON/schema 错误 → RUN_ERROR/PARSE_ERROR，**不得转成 abstain**；
- 原始响应落盘写失败即抛异常中止（不 except: pass）；
- 每次调用显式携带 sample_id/side/arm/repeat（不靠 getattr 兜底）；
- 唯一键 (run_id, sample_id, side, arm, repeat) 重复即失败（resume 安全）；
- API 密钥 / Authorization header 不落盘（本项目本地 Ollama 无鉴权）。
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

# 冻结模型契约（Experiment design 第6节）
MODEL = "qwen2.5-coder:7b"
MODEL_DIGEST = "dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364"
NUM_CTX = 32768
NUM_PREDICT = 1024
TEMPERATURE = 0
TOP_P = 1.0
SEED = 20260908
BASE_URL = "http://localhost:11434"
# 冻结 Ollama 运行时版本（P1）：digest 相同不保证不同 runtime 行为一致。
OLLAMA_VERSION = "0.33.3"

SCHEMA_VERSION = "model-call/1"


def _sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def ollama_version_number() -> str | None:
    """模块级：从 ``ollama --version`` 输出提取版本号（如 0.33.3）；无则 None。

    不依赖 ModelClient 实例，便于 invoke 前独立核对运行时版本（P1）。
    """
    import re
    try:
        r = subprocess.run(["ollama", "--version"], capture_output=True,
                           text=True, timeout=30)
        out = r.stdout.strip() if r.returncode == 0 else ""
    except Exception:
        out = ""
    m = re.search(r"(\d+\.\d+\.\d+)", out)
    return m.group(1) if m else None


class ModelClient:
    def __init__(self, base_url: str = BASE_URL, model: str = MODEL,
                 digest: str = MODEL_DIGEST, num_ctx: int = NUM_CTX,
                 num_predict: int = NUM_PREDICT, temperature: float = TEMPERATURE,
                 top_p: float = TOP_P, seed: int = SEED, timeout: float = 300.0):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.expected_digest = digest
        self.num_ctx = num_ctx
        self.num_predict = num_predict
        self.temperature = temperature
        self.top_p = top_p
        self.seed = seed
        self.timeout = timeout

    # ---- 运行时身份 ----
    def ollama_version(self) -> str:
        try:
            r = subprocess.run(["ollama", "--version"], capture_output=True, text=True, timeout=30)
            return r.stdout.strip() if r.returncode == 0 else f"unknown(rc={r.returncode})"
        except Exception:
            return "unknown"

    def ollama_version_number(self) -> str | None:
        """从 ollama --version 输出提取版本号（如 0.33.3）；无则 None。"""
        return ollama_version_number()

    def verify_ollama_version(self, expected: str = OLLAMA_VERSION) -> None:
        """核对实际 Ollama 版本与冻结值一致，不一致立即抛异常（fail-closed）。"""
        actual = self.ollama_version_number()
        if actual != expected:
            raise RuntimeError(
                f"[FATAL] Ollama 版本不一致: 实际 {actual} != 冻结 {expected}")

    def actual_digest(self) -> str:
        req = urllib.request.Request(f"{self.base_url}/api/tags", method="GET")
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        for m in data.get("models", []):
            if m["name"] == self.model:
                return m.get("digest", "")
        return ""

    def verify_digest(self) -> None:
        """校验实际 digest，不一致立即抛异常（fail-closed）。"""
        actual = self.actual_digest()
        if actual != self.expected_digest:
            raise RuntimeError(
                f"[FATAL] model digest 不一致: 实际 {actual} != 冻结 {self.expected_digest}")

    # ---- 底层调用 ----
    def generate(self, prompt: str, system: str) -> dict:
        """调 /api/generate，返回 Ollama 原始响应 dict。网络/超时抛异常。"""
        payload = {
            "model": self.model,
            "prompt": prompt,
            "system": system,
            "stream": False,
            "options": {
                "temperature": self.temperature,
                "num_ctx": self.num_ctx,
                "num_predict": self.num_predict,
                "top_p": self.top_p,
                "seed": self.seed,
            },
        }
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}/api/generate", data=body,
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"HTTP {e.code}: {e.read()[:200]}") from e
        except urllib.error.URLError as e:
            raise RuntimeError(f"网络错误: {e.reason}") from e
        return {"request": payload, "raw": raw}

    # ---- 一次调用（含 parse 状态）----
    def call(self, prompt: str, system: str, *, sample_id: str, side: str,
             arm: str, repeat: int, extra: dict | None = None) -> dict:
        """执行一次调用，返回完整工件（schema model-call/1）。

        infra/parse 错误在 result 里标记 parse_status=ERROR / run_error，绝不映射为 abstain。
        """
        t0 = time.time()
        try:
            g = self.generate(prompt, system)
            raw_text = g["raw"].decode("utf-8", errors="replace")
            try:
                resp_obj = json.loads(raw_text)
            except json.JSONDecodeError:
                resp_obj = {"_raw": raw_text}
            verdict = self._extract_verdict(resp_obj.get("response", ""))
            # parse_status 反映 verdict 能否解析（非 abstain 兜底），而非 HTTP 是否 JSON
            parse_status = "OK" if verdict is not None else "ERROR"
            run_error = None
        except Exception as e:
            g = {"request": {}, "raw": b""}
            resp_obj = {}
            verdict = None
            parse_status = "ERROR"
            run_error = str(e)

        raw_text = g["raw"].decode("utf-8", errors="replace") if g["raw"] else ""
        duration_ms = int((time.time() - t0) * 1000)
        request_sha = _sha256_bytes(json.dumps(g["request"], sort_keys=True).encode("utf-8"))

        record = {
            "schema_version": SCHEMA_VERSION,
            "sample_id": sample_id,
            "side": side,
            "arm": arm,
            "repeat": repeat,
            "prompt_path": extra.get("prompt_path") if extra else None,
            "prompt_sha256": extra.get("prompt_sha256") if extra else None,
            "system_sha256": _sha256_bytes(system.encode("utf-8")),
            "selection_plan_sha256": extra.get("selection_plan_sha256") if extra else None,
            # 表示版本与实现指纹（P0-2：必须落盘，否则结果无法追溯所用表示）
            "representation": (extra or {}).get("representation"),
            "code_text_sha256": (extra or {}).get("code_text_sha256"),
            "representation_sha256": (extra or {}).get("representation_sha256"),
            "prompt_renderer_sha256": (extra or {}).get("prompt_renderer_sha256"),
            "cpg_eval_sha256": (extra or {}).get("cpg_eval_sha256"),
            "source_tree_sha256": extra.get("source_tree_sha256") if extra else None,
            "cpg_cache_key": extra.get("cpg_cache_key") if extra else None,
            "canonical_cpg_rows_sha256": extra.get("canonical_cpg_rows_sha256") if extra else None,
            "model_name": self.model,
            "model_digest": self.expected_digest,
            "ollama_version": self.ollama_version(),
            "ollama_version_number": self.ollama_version_number(),
            "request": g["request"],
            "request_sha256": request_sha,
            "raw_response": resp_obj,
            "raw_response_text": raw_text,
            "raw_response_sha256": _sha256_bytes(raw_text.encode("utf-8")),
            "parse_status": parse_status,
            "verdict": verdict,
            "prompt_eval_count": resp_obj.get("prompt_eval_count") if isinstance(resp_obj, dict) else None,
            "done_reason": resp_obj.get("done_reason") if isinstance(resp_obj, dict) else None,
            "duration_ms": duration_ms,
            "run_error": run_error,
        }
        return record

    @staticmethod
    def _extract_verdict(text: str):
        """解析模型输出 JSON，返回 verdict 字符串或 None（非 abstain 兜底）。"""
        import re
        text = text.strip()
        try:
            return json.loads(text).get("verdict")
        except json.JSONDecodeError:
            pass
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(0)).get("verdict")
            except json.JSONDecodeError:
                return None
        return None
