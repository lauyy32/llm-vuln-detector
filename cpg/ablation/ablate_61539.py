# -*- coding: utf-8 -*-
"""61539 消融（重做）：测试"utils.py 前 100 行块"对判定的影响。

上一版 ablate_61539.py 的 rebuild() 丢失了"# 目标代码（节选）"标题与 Markdown 代码围栏，
导致 B/C 的 prompt 格式被破坏，结果作废（Codex 核验）。本版修正：
- split 保留 head（标题+开围栏）/ blocks / tail（闭围栏+之后），rebuild 原样拼回；
- 4 变体完整：v1_orig / v1_add_utils / v2_orig / v2_no_utils；
- 保存每份 prompt 的 SHA-256、完整请求、原始响应、完整 64 位 digest；
- digest 不一致立即退出（fail-closed）；
- 自动断言：增删 utils 块时，非目标区域（head/tail/其他块）逐字节相同；
- repeat=3（措辞仍只称"稳定性抽查"）。

用法：python cpg/ablation/ablate_61539.py
"""
import hashlib
import json
import re
import sys
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PROMPT_ROOT = REPO / "cpg/ablation/.work/rerun_61539"
OUT = REPO / "cpg/ablation/.work/rerun_61539/ablation_results.json"
OUT_PROMPTS = REPO / "cpg/ablation/.work/rerun_61539/ablation_prompts"

sys.path.insert(0, str(REPO))
from cpg.ablation.invoke_61539 import (  # noqa: E402
    SYSTEM, MODEL, MODEL_DIGEST, NUM_CTX, NUM_PREDICT, TEMPERATURE, TOP_P,
    BASE_URL, get_actual_digest, extract_verdict,
)

REPEAT = 3


def split_file_blocks(prompt: str):
    """切成 (prefix, head, blocks, tail)：
    prefix = "# 审计任务" 等头部；head = "# 目标代码（节选）\n```\n"；tail = "\n```" 及之后。"""
    m = re.search(r"(# 目标代码（节选）\n```\n)(.*?)(\n```)", prompt, re.DOTALL)
    if not m:
        return None, None, None, None
    prefix = prompt[:m.start()]
    head = m.group(1)
    code_block = m.group(2)
    tail = m.group(3) + prompt[m.end():]
    parts = re.split(r"(# ===== FILE: [^\n]+ =====\n)", code_block)
    blocks = []
    for i in range(1, len(parts), 2):
        header = parts[i]
        body = parts[i + 1] if i + 1 < len(parts) else ""
        blocks.append((header, body))
    return prefix, head, blocks, tail


def rebuild(prefix, head, blocks, tail):
    return prefix + head + "".join(h + b for h, b in blocks) + tail


def call(prompt: str) -> dict:
    payload = {
        "model": MODEL, "prompt": prompt, "system": SYSTEM, "stream": False,
        "options": {"temperature": TEMPERATURE, "num_ctx": NUM_CTX,
                    "num_predict": NUM_PREDICT, "top_p": TOP_P},
    }
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(f"{BASE_URL}/api/generate", data=body,
                                 headers={"Content-Type": "application/json"},
                                 method="POST")
    with urllib.request.urlopen(req, timeout=180) as resp:
        return {"request": payload, "response": json.loads(resp.read().decode("utf-8"))}


def main():
    actual_digest = get_actual_digest()
    if actual_digest != MODEL_DIGEST:
        print(f"[FATAL] 实际 digest {actual_digest} != 冻结 {MODEL_DIGEST}，终止")
        return 1
    print(f"digest_verified=True\n")

    v1 = (PROMPT_ROOT / "v1/vuln.prompt.txt").read_text(encoding="utf-8")
    v2 = (PROMPT_ROOT / "v2/vuln.prompt.txt").read_text(encoding="utf-8")

    prefix1, head1, blocks1, tail1 = split_file_blocks(v1)
    prefix2, head2, blocks2, tail2 = split_file_blocks(v2)
    if blocks1 is None or blocks2 is None:
        print("[FAIL] 无法切分 FILE 块"); return 1

    def find_utils(blocks):
        for i, (h, b) in enumerate(blocks):
            if "utils.py" in h:
                return i
        return None

    utils_idx2 = find_utils(blocks2)
    utils_block2 = blocks2[utils_idx2] if utils_idx2 is not None else None

    # 4 变体（增删 utils 块，其余 prefix/head/tail/块 逐字节保留）。
    # 注意：v2 顺序为 [parser, utils, test_utils]，v1_add 是"末尾追加"[parser, test_utils, utils]，
    # 故跨对(v1_add vs v2)不同序，只可作 v1_orig vs v1_add 与 v2_orig vs v2_no 两组同序对照。
    v1_orig = rebuild(prefix1, head1, blocks1, tail1)
    v1_add = rebuild(prefix1, head1, blocks1 + [utils_block2], tail1)
    v2_orig = rebuild(prefix2, head2, blocks2, tail2)
    v2_no = rebuild(prefix2, head2, [b for i, b in enumerate(blocks2) if i != utils_idx2], tail2)

    # 断言：v1_orig 应与原始 v1 逐字节相同；v2_orig 与原始 v2 相同
    assert v1_orig == v1, "v1_orig != v1"
    assert v2_orig == v2, "v2_orig != v2"
    # 断言：v1_add 的非 utils 区域与 v1 相同；v2_no 的非 utils 区域与 v2 相同
    assert v1_add.startswith(prefix1 + head1) and v1_add.endswith(tail1), "v1_add 破坏"
    assert v2_no.startswith(prefix2 + head2) and v2_no.endswith(tail2), "v2_no 破坏"

    variants = {
        "v1_orig": v1_orig,
        "v1_add_utils": v1_add,
        "v2_orig": v2_orig,
        "v2_no_utils": v2_no,
    }

    # 落盘每份 prompt + SHA
    OUT_PROMPTS.mkdir(parents=True, exist_ok=True)
    prompt_sha = {}
    for name, p in variants.items():
        sha = hashlib.sha256(p.encode("utf-8")).hexdigest()
        prompt_sha[name] = sha
        (OUT_PROMPTS / f"{name}.prompt.txt").write_text(p, encoding="utf-8")

    results = {
        "model": MODEL, "model_digest": MODEL_DIGEST,
        "actual_digest": actual_digest, "digest_verified": True,
        "num_ctx": NUM_CTX, "num_predict": NUM_PREDICT,
        "temperature": TEMPERATURE, "top_p": TOP_P,
        "repeat": REPEAT,
        "prompt_sha256": prompt_sha,
        "format_check": {
            "v1_orig_has_fence": v1_orig.count("```") == 2,
            "v1_add_has_fence": v1_add.count("```") == 2,
            "v2_orig_has_fence": v2_orig.count("```") == 2,
            "v2_no_has_fence": v2_no.count("```") == 2,
        },
        "variants": {},
    }

    # 先收集全部结果（不逐次打印 verdict）
    for name, prompt in variants.items():
        for rep in range(REPEAT):
            result = call(prompt)
            resp = result["response"]
            raw = resp.get("response", "")
            v = extract_verdict(raw)
            results["variants"].setdefault(name, []).append({
                "rep": rep,
                "verdict": v.get("verdict"),
                "confidence": v.get("confidence"),
                "rationale": (v.get("rationale") or "")[:150],
                "prompt_eval_count": resp.get("prompt_eval_count"),
                "eval_count": resp.get("eval_count"),
                "raw_response": raw,
                "request": result["request"],
            })

    OUT.write_text(json.dumps(results, ensure_ascii=False, indent=1), encoding="utf-8")

    # 全部完成后统一输出
    print("=== 4 变体判定（repeat=3）===")
    for name in variants:
        vs = [r["verdict"] for r in results["variants"][name]]
        print(f"  {name}: {vs}")
    print(f"\n格式检查（围栏数=2）: {results['format_check']}")
    print(f"\n[written] {OUT}")
    print(f"[prompts] {OUT_PROMPTS}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
