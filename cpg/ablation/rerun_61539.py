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
import re
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
    from cpg.ablation.upstream_manifest import read_meta

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

    # 2) meta 从 read_meta 读真实 CWE（61539 = CWE-95 Eval Injection，非 SSRF）。
    #    ⚠️ summary 必须置空：历史主结果默认 --with-summary 不注入（摘要描述漏洞位置/成因，
    #    构成标签泄漏）。上轮错误注入摘要导致 prompt 与历史不等价、模型判 abstain。
    meta_full = read_meta(cve)
    cwe = config.normalize_cwe((meta_full.get("cwes") or [None])[0])
    meta = {"cve_id": cve, "cwe": cwe, "summary": ""}

    # 3) 建库（单例，快；DB 已存在则复用，避免重复重建）
    if not corpus_db.exists():
        rc = config.run(
            [str(config.codeql_binary()), "database", "create",
             config.win_path(corpus_db), "--language=python",
             f"--source-root={config.win_path(corpus_src)}", "--overwrite"],
            env, config.DB_CREATE_TIMEOUT,
        )
        if rc != 0:
            return {"version": version, "error": f"db create failed rc={rc}"}

    # 4) 跑全部 6 个 taint 查询（原协议，不写死 taint=[]；v2 的 DB 内容已变须真查），
    #    记录每个查询的 rc/耗时/行数
    import time
    all_taint = []
    query_log = []
    for _cwe, qbase in config.CWE_TAINT_QUERIES:
        ql = config.QUERIES_DIR / f"{qbase}.ql"
        if not ql.exists():
            continue
        bqrs = config.WORK_DIR / f"{qbase}.bqrs"
        csv_out = config.WORK_DIR / f"{qbase}.csv"
        t0 = time.time()
        rc = config.run(
            [str(config.codeql_binary()), "query", "run", config.win_path(ql),
             f"--database={config.win_path(corpus_db)}",
             f"--search-path={config.win_path(config.CODEQL_QUERIES_DIR)}",
             f"--output={config.win_path(bqrs)}", "--ram=3000", "--threads=8"],
            env, config.EXTRACT_TAINT_TIMEOUT,
        )
        dt = round(time.time() - t0, 1)
        rows = []
        if rc == 0:
            rows = _decode_bqrs(bqrs, csv_out, env)
            all_taint.extend(rows)
        query_log.append({"query": qbase, "cwe": _cwe, "rc": rc,
                          "secs": dt, "rows": len(rows)})
    taint_rows = all_taint

    # 4) 生成两份 prompt
    scorer = LocalLLMScorer(model="qwen2.5-coder:7b", seed=None)
    results = {"version": version, "cwe": cwe, "taint_total": len(taint_rows),
               "query_log": query_log, "prompts": {}}
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
            # 关键 hunk 是否进入 prompt（Codex：不能只凭文件名判 FULL）。
            # 危险 eval 用负向后行断言排除属性调用，避免把 ast.literal_eval( 误判成 eval(。
            "hunk_eval_call": bool(re.search(r"(?<![\w.])eval\s*\(", code_text)),
            "hunk_json_loads": "json.loads" in code_text,
            "hunk_ast_literal_eval": "ast.literal_eval" in code_text,
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
