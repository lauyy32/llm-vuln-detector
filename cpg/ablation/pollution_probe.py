"""污染探测脚本（第 0 步 B，2026-09-04）。

目的：检验目标模型是否"记忆化"了 GitHub Advisory 2026 段的 CVE 细节——
只给 CVE 编号、不给任何代码/摘要，让模型描述漏洞位置/成因。
若模型能说出**具体且准确**的细节 = 训练数据污染实锤（标签泄漏的记忆化通道）。
qwen2.5-coder（2024 截止）是阴性对照：应输出 UNKNOWN / 泛泛而谈（说不出具体细节）。

用法：
    # 本地阴性对照（Ollama）
    python pollution_probe.py --backend ollama --model qwen2.5-coder:7b \
        --dataset ../../cpg/dataset.jsonl --out .work/pollution_qwen7b.jsonl

    # API 目标（OpenAI 兼容）
    python pollution_probe.py --backend openai --model deepseek-v4-flash \
        --base-url https://api.deepseek.com/v1 --key "$DEEPSEEK_API_KEY" \
        --out .work/pollution_deepseek.jsonl

纯标准库（urllib），输出每行 JSON：{cve, backend, model, raw}。
"""
from __future__ import annotations

import argparse
import json
import random
import urllib.request


PROMPT = (
    "You are given a CVE identifier. Do NOT search, do NOT guess, do NOT invent.\n"
    "If you have no memorized knowledge about this exact CVE, answer with exactly: UNKNOWN\n"
    "Otherwise, state (1) the vulnerability class, (2) the affected component or file, "
    "(3) the root cause, and (4) the fix, ONLY from your memorized knowledge.\n"
    "CVE: {cve}\nAnswer:"
)


def load_cves(dataset_path: str, n: int, seed: int) -> list[str]:
    cves = set()
    with open(dataset_path, encoding="utf-8") as fh:
        for line in fh:
            s = json.loads(line)
            cve = s.get("cve_id") or s.get("cve")
            if cve:
                cves.add(cve)
    rng = random.Random(seed)
    return rng.sample(sorted(cves), min(n, len(cves)))


def call_ollama(model: str, cve: str) -> str:
    req = urllib.request.Request(
        "http://localhost:11434/api/generate",
        data=json.dumps({
            "model": model,
            "prompt": PROMPT.format(cve=cve),
            "stream": False,
            "options": {"temperature": 0},
        }).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=180) as r:
        return json.loads(r.read().decode())["response"].strip()


def call_openai(model: str, base_url: str, key: str, cve: str) -> str:
    req = urllib.request.Request(
        base_url.rstrip("/") + "/chat/completions",
        data=json.dumps({
            "model": model,
            "messages": [
                {"role": "system", "content": "Answer factually. Reply UNKNOWN when you do not know."},
                {"role": "user", "content": PROMPT.format(cve=cve)},
            ],
            "temperature": 0,
            "max_tokens": 400,
        }).encode(),
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {key}"},
    )
    with urllib.request.urlopen(req, timeout=180) as r:
        return json.loads(r.read().decode())["choices"][0]["message"]["content"].strip()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--backend", choices=["ollama", "openai"], required=True)
    ap.add_argument("--model", required=True)
    ap.add_argument("--base-url", default="https://api.deepseek.com/v1")
    ap.add_argument("--key", default="")
    ap.add_argument("--dataset", default="../../cpg/dataset.jsonl")
    ap.add_argument("--out", required=True)
    ap.add_argument("--n", type=int, default=15)
    ap.add_argument("--seed", type=int, default=20260904)
    ap.add_argument(
        "--cves",
        nargs="*",
        default=None,
        help="显式指定 CVE 列表（优先级高于 --dataset 抽样）；用于 P1-7 阳性对照——"
        "对训练截止前的知名 CVE 提问，探测应能'说出'，以证明探测具备灵敏度。",
    )
    args = ap.parse_args()

    cves = args.cves if args.cves else load_cves(args.dataset, args.n, args.seed)
    rows = []
    for cve in cves:
        if args.backend == "ollama":
            raw = call_ollama(args.model, cve)
        else:
            raw = call_openai(args.model, args.base_url, args.key, cve)
        row = {"cve": cve, "backend": args.backend, "model": args.model, "raw": raw}
        rows.append(row)
        tag = "UNKNOWN" if raw.strip().upper().startswith("UNKNOWN") else f"{len(raw)}字"
        print(f"[{len(rows):02d}/{len(cves)}] {cve} -> {tag} | {raw[:120]!r}")
        with open(args.out, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"\nwritten: {args.out} ({len(rows)} rows)")


if __name__ == "__main__":
    main()
