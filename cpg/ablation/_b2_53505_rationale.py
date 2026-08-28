"""深挖 53505：LLM 对 vuln/fixed 的 rationale（B-2 正面样本证据）。"""
import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from cpg.ablation.run_ablation import _load_sample_code
from cpg.ablation.cpg_eval import build_cpg_slices_text
from cpg.ablation.context_build import build_context
from cpg.ablation.scorers import LocalLLMScorer

summary = ("Thumbor proportion filter allows unbounded post-transform resize leading to remote DoS")
for version in ("vuln", "fixed"):
    prefix = f"CVE-2026-53505_{version}"
    rows = []
    with open("cpg/ablation/.work/taint.csv", newline="", encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            ap = (r.get("abs_path") or "").replace("\\", "/")
            if f"/{prefix}/" in ap:
                rows.append(r)
    code = _load_sample_code(prefix, rows)
    slices = build_cpg_slices_text(rows, code)
    sample = {
        "sample_id": "CVE-2026-53505", "version": version, "cwes": ["CWE-400"],
        "cwe": "CWE-400", "truth": "vulnerable" if version == "vuln" else "benign",
        "prefix": prefix, "summary": summary, "code_text": code,
    }
    ctx = build_context("code", sample, taint_rows=rows, cpg_slices=slices)
    llm = LocalLLMScorer(timeout=600)
    verdict = llm.score(ctx)
    print(f"=== {prefix} ===")
    print(f"verdict: {verdict.label} (truth={sample['truth']})  cwe={verdict.cwe}")
    print(f"rationale: {verdict.rationale}")
    print(f"code_text 前 800 字符：")
    print(code[:800])
    print()
