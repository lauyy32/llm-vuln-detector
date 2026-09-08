# -*- coding: utf-8 -*-
"""61539 复验——四份 prompt 统一调用模型（qwen2.5-coder:7b）。

遵循 Codex P0-2：显式冻结全部推理参数，验证不截断，保存 prompt_eval_count。
四份请求一次性提交、固定顺序，不提前查看单个输出。

用法：python cpg/ablation/invoke_61539.py
"""
import json
import re
import sys
import time
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PROMPT_ROOT = REPO / "cpg/ablation/.work/rerun_61539"
OUT = REPO / "cpg/ablation/.work/rerun_61539/llm_results.json"

SYSTEM = (
    "你是一名资深代码安全审计助手。给定目标 CWE 类型、目标源码节选与代码级上下文（CPG 污点切片），"
    "判断目标代码是否可被利用（vulnerable）、无可证伪利用路径（benign）或信息不足（abstain）。"
    "重要判断原则：污点切片只覆盖数据流型漏洞（路径穿越/SSRF/注入）；切片为空或标注 no flow 不代表目标"
    "安全——鉴权缺失、请求走私、符号链接跟随、信息泄露、输入校验缺失等逻辑型漏洞不产生数据流。"
    "请结合源码语义核查目标 CWE 对应的功能点是否缺失必要的安全控制（如越权检查、边界校验、"
    "协议约束）。只输出严格 JSON，不要任何解释性文字。"
)

# 冻结推理参数（Codex P0-2）
MODEL = "qwen2.5-coder:7b"
MODEL_DIGEST = "dae161e27b0e90dd1856"  # ollama /api/tags 实测
NUM_CTX = 32768
NUM_PREDICT = 1024
TEMPERATURE = 0
SEED = None
TOP_P = 1.0
BASE_URL = "http://localhost:11434"


def call(prompt: str) -> dict:
    payload = json.dumps({
        "model": MODEL,
        "prompt": prompt,
        "system": SYSTEM,
        "stream": False,
        "options": {
            "temperature": TEMPERATURE,
            "num_ctx": NUM_CTX,
            "num_predict": NUM_PREDICT,
            "top_p": TOP_P,
        },
    }).encode("utf-8")
    req = urllib.request.Request(
        f"{BASE_URL}/api/generate", data=payload,
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=180) as resp:
        return json.loads(resp.read().decode("utf-8"))


def extract_verdict(text: str) -> dict:
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            return {"verdict": "abstain", "raw": text[:120]}
    return {"verdict": "abstain", "raw": text[:120]}


def main():
    order = [("v1", "vuln"), ("v1", "fixed"), ("v2", "vuln"), ("v2", "fixed")]
    results = {"model": MODEL, "model_digest": MODEL_DIGEST,
               "num_ctx": NUM_CTX, "num_predict": NUM_PREDICT,
               "temperature": TEMPERATURE, "seed": SEED, "top_p": TOP_P,
               "runs": []}
    for version, side in order:
        prompt = (PROMPT_ROOT / version / f"{side}.prompt.txt").read_text(encoding="utf-8")
        t0 = time.time()
        resp = call(prompt)
        dt = round(time.time() - t0, 1)
        raw = resp.get("response", "")
        verdict = extract_verdict(raw)
        results["runs"].append({
            "version": version, "side": side,
            "prompt_sha256": None,  # 由下方回填
            "prompt_eval_count": resp.get("prompt_eval_count"),
            "eval_count": resp.get("eval_count"),
            "done_reason": resp.get("done_reason"),
            "secs": dt,
            "verdict": verdict.get("verdict"),
            "cwe": verdict.get("cwe"),
            "confidence": verdict.get("confidence"),
            "rationale": (verdict.get("rationale") or "")[:150],
        })
        # 回填 prompt sha
        results["runs"][-1]["prompt_sha256"] = \
            __import__("hashlib").sha256(prompt.encode("utf-8")).hexdigest()
        print(f"[{version}-{side}] verdict={verdict.get('verdict')} "
              f"prompt_eval={resp.get('prompt_eval_count')} eval={resp.get('eval_count')} "
              f"{dt}s")

    OUT.write_text(json.dumps(results, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"\n[written] {OUT}")
    # 四层变化小结
    print("\n=== 四层变化（source→cpg→prompt→prediction）===")
    for r in results["runs"]:
        print(f"  {r['version']}-{r['side']}: verdict={r['verdict']} "
              f"(prompt_eval={r['prompt_eval_count']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
