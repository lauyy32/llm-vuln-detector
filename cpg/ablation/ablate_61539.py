# -*- coding: utf-8 -*-
"""61539 上下文不鲁棒性消融（2×2，隔离"语料修复"vs"摘录构成"混淆）。

Hy4 实测：eval( 在 v1-vuln/v2-vuln 位置(951)与上下文逐字相同，唯一差别是 v2 其后
追加了 utils.py L1-100（约 1859 字符 license 样板），模型就从 vulnerable 翻成 benign。
本消融验证"后缀构成"是否为因果：
    A = v2-vuln 原样           （已知 benign，基线）
    B = v2-vuln 去掉 utils.py   （若回 vulnerable → 证明"后缀构成"是因果）
    C = v1-vuln 追加 utils.py   （若翻 benign → 复证）

复用 invoke_61539 的冻结 digest + 调用；各 repeat=2。

用法：python cpg/ablation/ablate_61539.py
"""
import json
import re
import sys
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PROMPT_ROOT = REPO / "cpg/ablation/.work/rerun_61539"
OUT = REPO / "cpg/ablation/.work/rerun_61539/ablation_results.json"

sys.path.insert(0, str(REPO))
from cpg.ablation.invoke_61539 import (  # noqa: E402
    SYSTEM, MODEL, MODEL_DIGEST, NUM_CTX, NUM_PREDICT, TEMPERATURE, TOP_P,
    BASE_URL, get_actual_digest, extract_verdict,
)

FILE_SEP = re.compile(r"(# ===== FILE: [^\n]+ =====\n)(.*?)(?=# ===== FILE: |```)", re.DOTALL)


def split_file_blocks(prompt: str):
    """把 prompt 的 code_text 切成 [(header, body), ...]，非 FILE 部分（头部/尾部）单独保留。"""
    # 找 code_text 的 ``` 包裹区间
    m = re.search(r"# 目标代码（节选）\n```\n(.*?)\n```", prompt, re.DOTALL)
    if not m:
        return None, None, None
    code_block = m.group(1)
    before = prompt[:m.start()]
    after = prompt[m.end():]
    blocks = []
    last = 0
    for mm in re.finditer(r"# ===== FILE: ([^\n]+) =====\n", code_block):
        if last < mm.start():
            pass  # 块间无残留
        blocks.append(mm.group(0))
        last = mm.end()
    # 更简单：按 FILE 头切
    parts = re.split(r"(# ===== FILE: [^\n]+ =====\n)", code_block)
    # parts = [前置, header1, body1, header2, body2, ...]
    blocks = []
    for i in range(1, len(parts), 2):
        header = parts[i]
        body = parts[i + 1] if i + 1 < len(parts) else ""
        blocks.append((header, body))
    return before, blocks, after


def rebuild(before, blocks, after):
    code = "".join(h + b for h, b in blocks)
    return before + code + after


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
        return json.loads(resp.read().decode("utf-8"))


def main():
    digest_ok = get_actual_digest() == MODEL_DIGEST
    print(f"digest_verified={digest_ok}\n")

    v1 = (PROMPT_ROOT / "v1/vuln.prompt.txt").read_text(encoding="utf-8")
    v2 = (PROMPT_ROOT / "v2/vuln.prompt.txt").read_text(encoding="utf-8")

    before1, blocks1, after1 = split_file_blocks(v1)
    before2, blocks2, after2 = split_file_blocks(v2)
    if blocks1 is None or blocks2 is None:
        print("[FAIL] 无法切分 FILE 块"); return 1

    def find_utils(blocks):
        for i, (h, b) in enumerate(blocks):
            if "utils.py" in h:
                return i
        return None

    utils_idx2 = find_utils(blocks2)
    utils_block2 = blocks2[utils_idx2] if utils_idx2 is not None else None

    # 构造 A/B/C
    A = v2  # 原样
    B_blocks = [b for i, b in enumerate(blocks2) if i != utils_idx2]
    B = rebuild(before2, B_blocks, after2)
    C = rebuild(before1, blocks1 + [utils_block2], after1)

    variants = {"A_v2_orig": A, "B_v2_no_utils": B, "C_v1_add_utils": C}
    results = {"digest_verified": digest_ok, "variants": {}}
    for name, prompt in variants.items():
        verdicts = []
        for rep in range(2):
            resp = call(prompt)
            v = extract_verdict(resp.get("response", ""))
            verdicts.append(v.get("verdict"))
            results["variants"].setdefault(name, []).append({
                "rep": rep, "verdict": v.get("verdict"),
                "confidence": v.get("confidence"),
                "rationale": (v.get("rationale") or "")[:120],
                "prompt_eval_count": resp.get("prompt_eval_count"),
            })
        print(f"[{name}] verdicts={verdicts}")

    OUT.write_text(json.dumps(results, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"\n[written] {OUT}")
    print("\n=== 消融结论 ===")
    print(f"  A(v2 原样)     = {results['variants']['A_v2_orig'][0]['verdict']}")
    print(f"  B(v2 去 utils) = {results['variants']['B_v2_no_utils'][0]['verdict']}")
    print(f"  C(v1 加 utils) = {results['variants']['C_v1_add_utils'][0]['verdict']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
