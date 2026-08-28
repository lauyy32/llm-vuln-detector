"""验证 B-2 锚点截断：50558_fixed 的 code_text 是否含 safe_tar_extractall，以及 LLM 判定。"""
import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from cpg.ablation.run_ablation import _load_sample_code
from cpg.ablation.cpg_eval import build_cpg_slices_text
from cpg.ablation.context_build import build_context
from cpg.ablation.scorers import CPGEvidenceScorer, LocalLLMScorer

prefix = "CVE-2026-50558_fixed"
rows = []
with open("cpg/ablation/.work/taint.csv", newline="", encoding="utf-8") as fh:
    for r in csv.DictReader(fh):
        ap = (r.get("abs_path") or "").replace("\\", "/")
        if f"/{prefix}/" in ap:
            rows.append(r)

code = _load_sample_code(prefix, rows)
print(f"=== code_text: {len(code)} chars ===")
print(f"含 safe_tar_extractall 定义: {'safe_tar_extractall' in code}")
print(f"含 _is_within_directory guard: {'_is_within_directory' in code}")
print(f"含 _extract_member 调用: {'_extract_member' in code}")
# 打印含 safe 的行上下文
for i, line in enumerate(code.splitlines()):
    if "safe_tar_extractall" in line or "_is_within_directory" in line:
        print(f"  >> {line.strip()[:100]}")

sample = {
    "sample_id": "CVE-2026-50558", "version": "fixed", "cwes": ["CWE-022"],
    "cwe": "CWE-022", "truth": "benign", "prefix": prefix, "summary": (
        "Penelope unsafe tar extraction allows arbitrary local file write via crafted session archive"),
    "code_text": code,
}
slices = build_cpg_slices_text(rows, code)
print(f"\n=== cpg_slices ({len(slices)} chars) ===")
print(slices[:600])

ctx = build_context("code", sample, taint_rows=rows, cpg_slices=slices)
print(f"\n=== 评分 ===")
print(f"CPGEvidence: {CPGEvidenceScorer().score(ctx).label}")
llm = LocalLLMScorer(timeout=600)
print(f"LocalLLM:    {llm.score(ctx).label}  (truth=benign)")
