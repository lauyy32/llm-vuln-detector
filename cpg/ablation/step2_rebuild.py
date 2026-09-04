"""第二步：语料库级 corpus_db 重建（含 D1 全部样本，force_rebuild）。

背景：现有 corpus_db（C:/Users/lenovo/cpg_db/corpus_db）早于 D1 语料建成，
src.zip 不含 D1 新增 5 个零污点 CVE（62677/70479/70485/70486/70492）的源 →
其 taint 查询零行 = 建库缺口（非建模盲区）。重建取 dataset.jsonl(74) ∪
dataset_d1.jsonl(D1) 的 CVE 并集做 staging 元数据，force 重建 DB + 重跑 7 个
taint 查询 + baseline analyze；顺带刷新 74-set 全部污点证据（多管线鲁棒性）。

用法：python cpg/ablation/step2_rebuild.py
产物：corpus_db/ 重建 + cpg/ablation/.work/{taint,tarslip,cwe-*.csv} 重写
"""
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from cpg.ablation.corpus_db import build_corpus_db  # noqa: E402

rows_by_cve: dict[str, dict] = {}
for rel in ("cpg/dataset.jsonl", "cpg/dataset_d1.jsonl"):
    p = ROOT / rel
    if not p.exists():
        continue
    for line in p.open(encoding="utf-8"):
        s = json.loads(line)
        c = s.get("cve_id")
        if c and c not in rows_by_cve:
            rows_by_cve[c] = s
rows = list(rows_by_cve.values())
print(f"[step2] union rows = {len(rows)} CVEs ({time.strftime('%H:%M:%S')})", flush=True)

t0 = time.time()
db, staged, taint, sarif = build_corpus_db(rows, skip_baseline=False, force_rebuild=True)
elapsed = (time.time() - t0) / 60
print(f"[step2] DONE db={db}\n  staged={len(staged)} taint_rows={len(taint)} "
      f"sarif={sarif} elapsed={elapsed:.1f}min", flush=True)
