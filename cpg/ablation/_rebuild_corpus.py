"""T3：重建 corpus DB（含新样本）+ 重跑 taint + analyze。"""
import sys

sys.path.insert(0, "C:/Users/lenovo/WorkBuddy/2026-07-21-16-16-43/llm-vuln-detector")

from cpg.ablation.corpus_db import build_corpus_db
from cpg.ablation.run_ablation import _load_dataset_rows

rows = _load_dataset_rows(None)
print(f"[t3] loading {len(rows)} dataset rows")
db, staged, taint, sarif = build_corpus_db(rows, skip_baseline=False, force_rebuild=True)
print(f"[t3] DB={db}")
print(f"[t3] staged={len(staged)} samples")
print(f"[t3] taint rows={len(taint)}")
print(f"[t3] sarif={sarif}")
print("[t3] REBUILD_DONE")
