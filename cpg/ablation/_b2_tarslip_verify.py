"""验证 TarSlip 证据注入后 LLM 对 50558 vuln/fixed 的语义判定（B-2 关键证据）。"""
import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from cpg.ablation.run_ablation import _load_sample_code
from cpg.ablation.cpg_eval import build_cpg_slices_text
from cpg.ablation.context_build import build_context
from cpg.ablation.scorers import CPGEvidenceScorer, LocalLLMScorer


def load_rows(prefix: str) -> list[dict]:
    rows = []
    for f in ("cpg/ablation/.work/taint.csv", "cpg/ablation/.work/tarslip.csv"):
        if not Path(f).exists():
            continue
        with open(f, newline="", encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                ap = (r.get("abs_path") or "").replace("\\", "/")
                if f"/{prefix}/" in ap:
                    rows.append(r)
    return rows


summary = ("Penelope unsafe tar extraction allows arbitrary local file write via crafted session archive")
for version, truth in (("vuln", "vulnerable"), ("fixed", "benign")):
    prefix = f"CVE-2026-50558_{version}"
    rows = load_rows(prefix)
    code = _load_sample_code(prefix, rows)
    slices = build_cpg_slices_text(rows, code)
    sample = {
        "sample_id": "CVE-2026-50558", "version": version, "cwes": ["CWE-022"],
        "cwe": "CWE-022", "truth": truth, "prefix": prefix, "summary": summary,
        "code_text": code,
    }
    ctx = build_context("code", sample, taint_rows=rows, cpg_slices=slices)
    cpg = CPGEvidenceScorer().score(ctx).label
    llm = LocalLLMScorer(timeout=600)
    v = llm.score(ctx)
    print(f"=== {prefix} (truth={truth}) ===")
    print(f"taint rows: {len(rows)} | code_text: {len(code)} chars")
    print(f"CPGEvidence: {cpg} | LocalLLM: {v.label} (cwe={v.cwe}, conf={v.confidence:.2f})")
    print(f"slices 摘要:\n{slices[:400]}")
    print()
