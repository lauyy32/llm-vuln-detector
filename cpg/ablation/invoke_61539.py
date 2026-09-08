# -*- coding: utf-8 -*-
"""61539 复验——四份 prompt 统一调用模型（qwen2.5-coder:7b）。

修正（Codex 核验后）：
- 保存完整 64 位模型 digest，调用前校验 Ollama 实际 digest；
- 保存完整请求体 + 原始响应全文；
- 不逐次打印 verdict（全部收集后统一输出）；
- 重复运行 N 次测稳定性（temperature=0 下应确定）。

用法：python cpg/ablation/invoke_61539.py [--repeat 2]
"""
import argparse
import hashlib
import json
import re
import sys
import time
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PROMPT_ROOT = REPO / "cpg/ablation/.work/rerun_61539"
OUT = REPO / "cpg/ablation/.work/rerun_61539/llm_results.json"

from cpg.ablation.prompt_renderer import SYSTEM  # 单一权威定义，不在此复制

MODEL = "qwen2.5-coder:7b"
MODEL_DIGEST = "dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364"  # 完整 64 位
NUM_CTX = 32768
NUM_PREDICT = 1024
TEMPERATURE = 0
SEED = None
TOP_P = 1.0
BASE_URL = "http://localhost:11434"


def get_actual_digest() -> str:
    req = urllib.request.Request(f"{BASE_URL}/api/tags", method="GET")
    with urllib.request.urlopen(req, timeout=15) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    for m in data.get("models", []):
        if m["name"] == MODEL:
            return m.get("digest", "")
    return ""


def call(prompt: str) -> dict:
    payload = {
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
    }
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        f"{BASE_URL}/api/generate", data=body,
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=180) as resp:
        return {"request": payload, "response": json.loads(resp.read().decode("utf-8"))}


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
    ap = argparse.ArgumentParser()
    ap.add_argument("--repeat", type=int, default=2, help="每份 prompt 重复运行次数（测稳定性）")
    args = ap.parse_args()

    actual_digest = get_actual_digest()
    digest_ok = actual_digest == MODEL_DIGEST
    if not digest_ok:
        print(f"[WARN] 实际 digest {actual_digest} != 冻结 {MODEL_DIGEST}")

    order = [("v1", "vuln"), ("v1", "fixed"), ("v2", "vuln"), ("v2", "fixed")]
    # 先收集全部结果（不打印 verdict）
    collected = []
    for version, side in order:
        prompt = (PROMPT_ROOT / version / f"{side}.prompt.txt").read_text(encoding="utf-8")
        prompt_sha = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
        for rep in range(args.repeat):
            t0 = time.time()
            result = call(prompt)
            dt = round(time.time() - t0, 1)
            resp = result["response"]
            raw = resp.get("response", "")
            verdict = extract_verdict(raw)
            collected.append({
                "version": version, "side": side, "rep": rep,
                "prompt_sha256": prompt_sha,
                "prompt_eval_count": resp.get("prompt_eval_count"),
                "eval_count": resp.get("eval_count"),
                "done_reason": resp.get("done_reason"),
                "secs": dt,
                "verdict": verdict.get("verdict"),
                "cwe": verdict.get("cwe"),
                "confidence": verdict.get("confidence"),
                "rationale": (verdict.get("rationale") or "")[:150],
                "raw_response": raw,          # 原始响应全文
                "request": result["request"],  # 完整请求体
            })

    results = {
        "model": MODEL, "model_digest": MODEL_DIGEST,
        "actual_digest": actual_digest, "digest_verified": digest_ok,
        "num_ctx": NUM_CTX, "num_predict": NUM_PREDICT,
        "temperature": TEMPERATURE, "seed": SEED, "top_p": TOP_P,
        "repeat": args.repeat,
        "runs": collected,
    }
    OUT.write_text(json.dumps(results, ensure_ascii=False, indent=1), encoding="utf-8")

    # 全部完成后统一打印
    print(f"模型 {MODEL} digest_verified={digest_ok} repeat={args.repeat}\n")
    print("=== 四份结果（统一输出）===")
    for r in collected:
        print(f"  [{r['version']}-{r['side']} rep{r['rep']}] verdict={r['verdict']} "
              f"(prompt_eval={r['prompt_eval_count']}, {r['secs']}s)")
    # 稳定性检查
    print("\n=== 稳定性（每组合多轮 verdict 一致性）===")
    by_key = {}
    for r in collected:
        by_key.setdefault((r["version"], r["side"]), []).append(r["verdict"])
    for k in sorted(by_key):
        vs = by_key[k]
        print(f"  {k[0]}-{k[1]}: {vs} 稳定={'✓' if len(set(vs))==1 else '✗'}")
    print(f"\n[written] {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
