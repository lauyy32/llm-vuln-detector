"""B-2 基准：收集关键样本的 LLM rationale（漏报盲区 + 独对样本 + 独错样本）。"""
import csv
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from cpg.ablation.run_ablation import _load_sample_code
from cpg.ablation.cpg_eval import build_cpg_slices_text
from cpg.ablation.context_build import build_context
from cpg.ablation.scorers import LocalLLMScorer

# 读 dataset 拿真实 summary
summaries = {}
with open("cpg/dataset.jsonl", encoding="utf-8") as fh:
    for line in fh:
        d = json.loads(line)
        summaries[d["cve_id"]] = d.get("summary") or ""

# 目标样本：独对 1 + 漏报盲区 7 + 独错 fixed 6（abstain 2 个也纳入）
targets = [
    ("CVE-2026-53505", "vuln", "独对"),
    ("CVE-2026-54785", "vuln", "漏报"),
    ("CVE-2026-59881", "vuln", "漏报"),
    ("CVE-2026-69243", "vuln", "漏报"),
    ("CVE-2026-70487", "vuln", "漏报"),
    ("CVE-2026-70488", "vuln", "漏报"),
    ("CVE-2026-71433", "vuln", "漏报"),
    ("CVE-2026-71554", "vuln", "漏报"),
    ("CVE-2026-53502", "fixed", "独错误报"),
    ("CVE-2026-54706", "fixed", "独错误报"),
    ("CVE-2026-54707", "fixed", "独错误报"),
    ("CVE-2026-67424", "fixed", "独错误报"),
    ("CVE-2026-67435", "fixed", "独错误报"),
    ("CVE-2026-70488", "fixed", "独错abstain"),
    ("CVE-2026-71554", "fixed", "独错abstain"),
]

llm = LocalLLMScorer(timeout=600)
out = []
for sid, version, cat in targets:
    prefix = f"{sid}_{version}"
    trows = []
    for f in ("cpg/ablation/.work/taint.csv", "cpg/ablation/.work/tarslip.csv"):
        with open(f, newline="", encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                if f"/{prefix}/" in (r.get("abs_path") or ""):
                    trows.append(r)
    code = _load_sample_code(prefix, trows)
    slices = build_cpg_slices_text(trows, code)
    sample = {
        "sample_id": sid, "version": version, "cwes": ["CWE-022"], "cwe": "CWE-022",
        "truth": "vulnerable" if version == "vuln" else "benign", "prefix": prefix,
        "summary": summaries.get(sid, ""), "code_text": code,
    }
    ctx = build_context("code", sample, taint_rows=trows, cpg_slices=slices)
    v = llm.score(ctx)
    raw = llm._generate(llm._build_prompt(ctx))
    parsed = llm._extract_json(raw) or {}
    out.append({"sample": f"{sid}_{version}", "cat": cat, "truth": sample["truth"],
                "verdict": v.label, "confidence": v.confidence, "cwe": v.cwe,
                "taint_rows": len(trows), "code_chars": len(code),
                "summary": summaries.get(sid, "")[:120],
                "rationale": parsed.get("rationale", "?")})
    print(f"[{cat}] {sid}_{version}: LLM={v.label} (truth={sample['truth']}, taint={len(trows)})")

with open("cpg/ablation/b2_rationales.json", "w", encoding="utf-8") as fh:
    json.dump(out, fh, ensure_ascii=False, indent=2)
print(f"\n[ok] wrote cpg/ablation/b2_rationales.json ({len(out)} 样本)")
