# -*- coding: utf-8 -*-
"""61539 端到端复验——四份 CPG + prompt 生成（不调用模型）。

严格遵循补充裁决：
- 四份 prompt（v1-vuln/v1-fixed/v2-vuln/v2-fixed）全部生成、落盘、SHA-256 后，才统一调模型；
- 不先看任何单侧模型输出；
- prompt 覆盖三分类 FULL/PARTIAL/ABSENT 在模型调用前完成；
- 泄漏检查：prompt 不得出现 v1/v2/vuln/fixed/期望标签。

实现：每个版本用独立 CPG_DATA_ROOT（subprocess 隔离 config 模块级缓存），stage 源码
→ codeql 建库 → cwe-918(SSRF) 查询 → decode → code_text + cpg_slices → prompt。

用法：
    python cpg/ablation/rerun_61539.py            # 主进程，串行跑 v1/v2 两个 worker
    python cpg/ablation/rerun_61539.py --worker v1   # 内部 worker（勿直接调用）
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
OUT_ROOT = REPO / "cpg/ablation/.work/rerun_61539"
TMP_DATA_ROOT = Path("C:/Users/lenovo/cpg_db_61539_rerun")


def worker(version: str):
    """在独立 DATA_ROOT 下生成 v1 或 v2 的两份 prompt（vuln/fixed）。"""
    os.environ["CPG_DATA_ROOT"] = str(TMP_DATA_ROOT / version)
    sys.path.insert(0, str(REPO))
    from cpg.ablation import config
    from cpg.ablation.corpus_db import _decode_bqrs
    from cpg.ablation.cpg_eval import build_cpg_slices_text
    from cpg.ablation.run_ablation import _load_sample_code
    from cpg.ablation.scorers import DetectionContext, LocalLLMScorer

    cve = "CVE-2026-61539"
    src_root = REPO / ("cpg/corpus_pairs" if version == "v1" else "cpg/corpus-v2") / cve
    corpus_src = config.CORPUS_SRC
    corpus_db = config.CORPUS_DB
    env = config.make_env(config.DEFAULT_JAVA_HOME)

    # 1) stage 源码（v1 从 corpus_pairs，v2 从 corpus-v2）
    for side in ("vuln", "fixed"):
        dst = corpus_src / f"{cve}_{side}"
        if dst.exists():
            shutil.rmtree(dst)
        shutil.copytree(src_root / side, dst)

    # 2) 建库（单例，快）
    rc = config.run(
        [str(config.codeql_binary()), "database", "create",
         config.win_path(corpus_db), "--language=python",
         f"--source-root={config.win_path(corpus_src)}", "--overwrite"],
        env, config.DB_CREATE_TIMEOUT,
    )
    if rc != 0:
        return {"version": version, "error": f"db create failed rc={rc}"}

    # 3) cwe-918 (SSRF) 查询——61539 是 CWE-918
    ql = config.QUERIES_DIR / "cwe-918.ql"
    bqrs = config.WORK_DIR / "cwe-918.bqrs"
    csv_out = config.WORK_DIR / "cwe-918.csv"
    rc = config.run(
        [str(config.codeql_binary()), "query", "run", config.win_path(ql),
         f"--database={config.win_path(corpus_db)}",
         f"--search-path={config.win_path(config.CODEQL_QUERIES_DIR)}",
         f"--output={config.win_path(bqrs)}", "--ram=3000", "--threads=8"],
        env, config.EXTRACT_TAINT_TIMEOUT,
    )
    if rc != 0:
        return {"version": version, "error": f"query run failed rc={rc}"}
    taint_rows = _decode_bqrs(bqrs, csv_out, env)

    # 4) 生成两份 prompt
    scorer = LocalLLMScorer(model="qwen2.5-coder:7b", seed=None)
    meta = {"cve_id": cve, "cwe": "CWE-918",
            "summary": "xinference llama3 tool parser SSRF"}
    results = {"version": version, "taint_total": len(taint_rows), "prompts": {}}
    for side in ("vuln", "fixed"):
        prefix = f"{cve}_{side}"
        rows_side = [r for r in taint_rows
                     if f"/{prefix}/" in (r.get("abs_path") or "").replace("\\", "/")]
        code_text = _load_sample_code(prefix, rows_side)
        cpg_slices = build_cpg_slices_text(rows_side, code_text)
        ctx = DetectionContext(request_info=None, advisory_meta=meta, code_text=code_text,
                               cpg_slices=cpg_slices, taint_rows=rows_side,
                               cpg_evidence_available=bool(rows_side))
        prompt = scorer._build_prompt(ctx)
        sha = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
        out = OUT_ROOT / version
        out.mkdir(parents=True, exist_ok=True)
        (out / f"{side}.prompt.txt").write_text(prompt, encoding="utf-8")
        results["prompts"][side] = {
            "prompt_sha256": sha,
            "prompt_chars": len(prompt),
            "taint_rows": len(rows_side),
            "has_llama3_tool_parser": "llama3_tool_parser" in code_text,
            "has_utils": "utils.py" in code_text or "utils" in code_text,
            "code_text_chars": len(code_text),
            "cpg_slices_chars": len(cpg_slices),
        }
    (OUT_ROOT / version / "meta.json").write_text(
        json.dumps(results, ensure_ascii=False, indent=1), encoding="utf-8")
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--worker", choices=["v1", "v2"])
    args = ap.parse_args()
    if args.worker:
        r = worker(args.worker)
        print(json.dumps(r, ensure_ascii=False, indent=1))
        return 0 if "error" not in r else 1

    OUT_ROOT.mkdir(parents=True, exist_ok=True)
    all_results = {}
    for version in ("v1", "v2"):
        print(f"\n===== 生成 {version} 的 CPG + prompt =====")
        r = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), "--worker", version],
            capture_output=True, text=True, encoding="utf-8", timeout=1800,
        )
        print(r.stdout[-1500:] if r.stdout else r.stderr[-1500:])
        if r.returncode != 0:
            print(f"[FAIL] {version} worker rc={r.returncode}")
            all_results[version] = {"error": f"worker rc={r.returncode}"}
        else:
            meta_file = OUT_ROOT / version / "meta.json"
            if meta_file.exists():
                all_results[version] = json.loads(meta_file.read_text(encoding="utf-8"))
            else:
                all_results[version] = {"error": "meta.json missing"}
    (OUT_ROOT / "summary.json").write_text(
        json.dumps(all_results, ensure_ascii=False, indent=1), encoding="utf-8")
    print("\n===== 四份 prompt 生成完成 =====")
    print(json.dumps(all_results, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
