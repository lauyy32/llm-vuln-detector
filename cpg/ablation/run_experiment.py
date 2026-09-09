# -*- coding: utf-8 -*-
"""通用批量实验 runner（Code plan 第7阶段）。

状态机：CREATED → INPUTS_FROZEN → RUNNING → COMPLETE → VERIFIED；任何失败 → FAILED。
子命令：prepare / verify-inputs / invoke / verify-results / summarize。

- 只接受 --protocol / --canonical-manifest / --run-dir（不接受人工 --exclude-cves）；
- prepare 生成全部 prompt 并冻结 SHA + 固定 seed 打乱调用顺序写入 run_schedule；
- 全部 prompt 冻结后才可 invoke；运行期间不打印单项 verdict；
- resume 支持，但唯一键 (sample_id, side, arm, repeat) 重复即失败；
- 结果完成后再 summarize，不边看结果边改。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from cpg.ablation import excerpt_plan  # noqa: E402
from cpg.ablation import prompt_renderer  # noqa: E402
from cpg.ablation import config  # noqa: E402
from cpg.ablation import corpus_db  # noqa: E402
from cpg.ablation.cpg_eval import build_cpg_slices_text  # noqa: E402
from cpg.ablation import legacy_rq1_r0  # noqa: E402
from cpg.ablation.legacy_rq1_r0 import (  # noqa: E402
    REPRESENTATION as LEGACY_REPR, MAX_CODE_CHARS, SUMMARY,
    load_legacy_code_text, preflight_legacy,
)
from cpg.ablation.excerpt_plan import REPRESENTATION as CHANGED_HUNK_REPR  # noqa: E402
from cpg.ablation.model_client import ModelClient, MODEL, MODEL_DIGEST, NUM_CTX, NUM_PREDICT, TEMPERATURE, TOP_P, SEED  # noqa: E402

# 允许用于 RQ1-R prompt 生成的表示（选 C 裁决）：
# changed-hunk-r0 是改进摘录器，按 Experiment design §二.2 不得混入 RQ1-R，
# 因此不列入允许集（它仅用于独立覆盖审计 / future V4）。
ALLOWED_REPRESENTATIONS = {LEGACY_REPR}
assert CHANGED_HUNK_REPR not in ALLOWED_REPRESENTATIONS

STATES = ("CREATED", "INPUTS_FROZEN", "RUNNING", "COMPLETE", "VERIFIED", "FAILED")


def _sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def representation_fingerprints() -> dict:
    """表示实现的指纹：同一 representation 名称下改代码会被检出。

    至少冻结 legacy_rq1_r0.py、prompt_renderer.py 与 SYSTEM 文本。
    """
    return {
        "representation_sha256": _file_sha256(Path(legacy_rq1_r0.__file__)),
        "prompt_renderer_sha256": _file_sha256(Path(prompt_renderer.__file__)),
        "system_sha256": _sha256_text(prompt_renderer.SYSTEM),
    }


def _read_state(run_dir: Path) -> str:
    p = run_dir / "state.json"
    if not p.exists():
        return "CREATED"
    return json.loads(p.read_text(encoding="utf-8")).get("state", "CREATED")


def _write_state(run_dir: Path, state: str, extra: dict | None = None):
    run_dir.mkdir(parents=True, exist_ok=True)
    d = {"state": state}
    if extra:
        d.update(extra)
    (run_dir / "state.json").write_text(json.dumps(d, ensure_ascii=False, indent=2), encoding="utf-8")


def _fail(run_dir: Path, msg: str):
    _write_state(run_dir, "FAILED", {"error": msg})
    print(f"[FAIL] {msg}")
    return 1


def load_canonical(manifest_path: Path) -> dict:
    return json.loads(manifest_path.read_text(encoding="utf-8"))


def prepare(args) -> int:
    """生成 82×2 prompt + 冻结 SHA + run_schedule。CREATED → INPUTS_FROZEN。"""
    run_dir = args.run_dir
    if _read_state(run_dir) not in ("CREATED", "FAILED"):
        return _fail(run_dir, f"prepare 要求 CREATED，当前 {_read_state(run_dir)}")
    manifest = load_canonical(args.canonical_manifest)
    if manifest.get("errors"):
        return _fail(run_dir, f"canonical manifest 有验证错误: {manifest['errors'][:3]}")
    eligible = [s for s in manifest["samples"] if s.get("eligible")]
    if len(eligible) != manifest.get("eligible_total"):
        return _fail(run_dir, f"eligible 计数不符 {len(eligible)} != {manifest['eligible_total']}")

    # 协议：冻结摘录表示 + 模型参数。
    # representation 必须显式指定；changed-hunk-r0 不得作为默认值，
    # 且不得用于 RQ1-R prompt 生成（仅覆盖审计 / future V4）。
    representation = getattr(args, "representation", None)
    if representation not in ALLOWED_REPRESENTATIONS:
        return _fail(run_dir, f"必须显式指定 representation，取值 "
                              f"{sorted(ALLOWED_REPRESENTATIONS)}，实际 {representation!r}")
    protocol = {
        "model": MODEL, "model_digest": MODEL_DIGEST,
        "num_ctx": NUM_CTX, "num_predict": NUM_PREDICT,
        "temperature": TEMPERATURE, "top_p": TOP_P, "seed": SEED,
        "representation": representation,
        "summary": SUMMARY,
        "max_code_chars": MAX_CODE_CHARS,
    }
    protocol.update(representation_fingerprints())  # 绑实现 SHA，改代码即漂移

    prompts_dir = run_dir / "prompts"
    prompts_dir.mkdir(parents=True, exist_ok=True)

    # 接 CPG 链：stage 82 例 → 建库 → 跑 7 个 taint 查询（P0-2 修复，不再是纯源码）
    staging_dir = run_dir / "staging"
    staged = corpus_db.stage_exact_snapshot(manifest, staging_dir)
    query_files = [config.QUERIES_DIR / f"{qbase}.ql"
                   for _cwe, qbase in config.CWE_TAINT_QUERIES
                   if (config.QUERIES_DIR / f"{qbase}.ql").exists()]
    qsha = corpus_db.query_set_sha(query_files)
    cid = corpus_db.codeql_identity()
    db_path = staging_dir / "corpus_db"
    bundle = corpus_db.build_or_reuse_db(
        staged["staged_manifest_sha256"], qsha, cid, staging_dir, query_files, db_path)
    taint_rows = bundle.get("taint_rows", [])
    cpg_bundle_sha = bundle["cache_key"]
    (run_dir / "cpg_bundle.json").write_text(
        json.dumps({"cache_key": cpg_bundle_sha,
                    "codeql_version": cid,
                    "queries": bundle.get("queries", []),
                    "n_taint_rows": len(taint_rows)},
                   ensure_ascii=False, indent=2), encoding="utf-8")

    prompt_manifest = []
    for s in eligible:
        cve = s["sample_id"]
        for side in ("vuln", "fixed"):
            # legacy-rq1-r0：用 staging 源（taint_rows 的 abs_path 指向 staging，
            # 与 legacy 的 hit_paths 前缀匹配一致）；staging 由 canonical manifest
            # 复制而来，树哈希需与 canonical 一致（preflight fail-closed）。
            side_root = staging_dir / "corpus_src" / f"{cve}_{side}"
            preflight_legacy(side_root, s.get(f"{side}_tree_sha256_lf"))
            rows_side = [r for r in taint_rows
                         if f"/{cve}_{side}/" in (r.get("abs_path") or "").replace("\\", "/")]
            code_text = load_legacy_code_text(side_root, rows_side)
            # 复刻历史 LocalLLMScorer._build_prompt 的 code_text[:8000] 二次截断
            code_text = code_text[:protocol["max_code_chars"]]
            # 按 prefix 过滤该样本该侧的 taint 行，生成 cpg_slices（空则显式 success-zero）
            cpg_slices = build_cpg_slices_text(rows_side, code_text)
            prompt = prompt_renderer.render_prompt(
                {"cve_id": cve, "cwe": (s.get("cwes") or [None])[0] if isinstance(s.get("cwes"), list) else None},
                code_text, cpg_slices, summary=protocol["summary"],
                max_code_chars=protocol["max_code_chars"],
            )
            sha = _sha256_text(prompt)
            pout = prompts_dir / f"{cve}_{side}.prompt.txt"
            pout.write_text(prompt, encoding="utf-8")
            prompt_manifest.append({
                "sample_id": cve, "side": side, "arm": "real",
                "prompt_path": str(pout.relative_to(run_dir)),
                "prompt_sha256": sha,
                # legacy-rq1-r0 无结构化 selection plan，记录摘录内容 SHA 与表示版本
                "representation": protocol["representation"],
                "code_text_sha256": _sha256_text(code_text),
                "representation_sha256": protocol["representation_sha256"],
                "prompt_renderer_sha256": protocol["prompt_renderer_sha256"],
                "system_sha256": protocol["system_sha256"],
                "source_tree_sha256": s.get(f"{side}_tree_sha256_lf"),
                "cpg_bundle_sha256": cpg_bundle_sha,
                "cpg_taint_rows": len(rows_side),
                "cpg_slices_chars": len(cpg_slices),
            })

    # 固定 seed 打乱调用顺序（vuln/fixed 交错）
    rng = random.Random(SEED)
    order = prompt_manifest[:]
    rng.shuffle(order)
    run_schedule = [{"sample_id": p["sample_id"], "side": p["side"], "arm": p["arm"]}
                    for p in order]

    (run_dir / "prompt_manifest.jsonl").write_text(
        "\n".join(json.dumps(p, ensure_ascii=False) for p in prompt_manifest) + "\n",
        encoding="utf-8")
    (run_dir / "run_schedule.json").write_text(
        json.dumps(run_schedule, ensure_ascii=False, indent=2), encoding="utf-8")
    (run_dir / "protocol.json").write_text(
        json.dumps(protocol, ensure_ascii=False, indent=2), encoding="utf-8")

    _write_state(run_dir, "INPUTS_FROZEN", {"n_prompts": len(prompt_manifest)})
    print(f"[prepare] {len(prompt_manifest)} 份 prompt 冻结，schedule 已写入")
    return 0


def verify_inputs(args) -> int:
    """验证输入工件：prompt SHA 一致 + 无摘要泄漏 + fence 正确。"""
    run_dir = args.run_dir
    if _read_state(run_dir) != "INPUTS_FROZEN":
        return _fail(run_dir, f"verify-inputs 要求 INPUTS_FROZEN，当前 {_read_state(run_dir)}")
    manifest = []
    for line in (run_dir / "prompt_manifest.jsonl").read_text(encoding="utf-8").splitlines():
        if line.strip():
            manifest.append(json.loads(line))
    errors = []
    for p in manifest:
        prompt = (run_dir / p["prompt_path"]).read_text(encoding="utf-8")
        if _sha256_text(prompt) != p["prompt_sha256"]:
            errors.append(f"{p['sample_id']}/{p['side']} prompt SHA 漂移")
        if "公告摘要" in prompt:
            errors.append(f"{p['sample_id']}/{p['side']} 含公告摘要泄漏")
        if prompt.count("```") != 2:
            errors.append(f"{p['sample_id']}/{p['side']} fence 数 != 2")
    if errors:
        return _fail(run_dir, f"verify-inputs {len(errors)} 错误: {errors[:3]}")
    print(f"[verify-inputs] PASS {len(manifest)} 份 prompt 验证通过")
    return 0


def invoke(args) -> int:
    """调用模型。INPUTS_FROZEN → RUNNING → COMPLETE。"""
    run_dir = args.run_dir
    if _read_state(run_dir) != "INPUTS_FROZEN":
        return _fail(run_dir, f"invoke 要求 INPUTS_FROZEN，当前 {_read_state(run_dir)}")

    # 复核表示实现指纹：同一 representation 名称下改代码必须被检出
    prot = json.loads((run_dir / "protocol.json").read_text(encoding="utf-8"))
    fp_now = representation_fingerprints()
    for k, v in fp_now.items():
        if prot.get(k) != v:
            return _fail(run_dir, f"表示实现指纹漂移: {k} "
                                  f"协议={prot.get(k)} 当前={v}")

    client = ModelClient()
    client.verify_digest()  # 不一致抛异常

    schedule = json.loads((run_dir / "run_schedule.json").read_text(encoding="utf-8"))
    # 索引 prompt_manifest
    pmap = {}
    for line in (run_dir / "prompt_manifest.jsonl").read_text(encoding="utf-8").splitlines():
        if line.strip():
            p = json.loads(line)
            pmap[(p["sample_id"], p["side"])] = p

    _write_state(run_dir, "RUNNING")
    results_path = run_dir / "results.jsonl"
    seen = set()
    # 支持 resume：跳过已存在的唯一键；重复（非跳过）则失败
    done = set()
    if results_path.exists():
        for line in results_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                r = json.loads(line)
                done.add((r["sample_id"], r["side"], r["arm"], r["repeat"]))

    with open(results_path, "a", encoding="utf-8") as f:
        for item in schedule:
            key = (item["sample_id"], item["side"], item["arm"], 0)
            if key in done:
                continue
            if key in seen:
                return _fail(run_dir, f"唯一键重复: {key}")
            seen.add(key)
            p = pmap[(item["sample_id"], item["side"])]
            prompt = (run_dir / p["prompt_path"]).read_text(encoding="utf-8")
            rec = client.call(prompt, prompt_renderer.SYSTEM,
                              sample_id=item["sample_id"], side=item["side"],
                              arm=item["arm"], repeat=0, extra={
                                  "prompt_path": p["prompt_path"],
                                  "prompt_sha256": p["prompt_sha256"],
                                  # legacy-rq1-r0 无 selection plan；改用实现指纹
                                  "representation": p.get("representation"),
                                  "code_text_sha256": p.get("code_text_sha256"),
                                  "representation_sha256": p.get("representation_sha256"),
                                  "prompt_renderer_sha256": p.get("prompt_renderer_sha256"),
                                  "system_sha256": p.get("system_sha256"),
                                  "source_tree_sha256": p["source_tree_sha256"],
                              })
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            f.flush()  # 写失败会抛异常中止

    _write_state(run_dir, "COMPLETE")
    print(f"[invoke] 完成 {len(seen)} 次调用")
    return 0


def verify_results(args) -> int:
    """验证结果完整性。COMPLETE → VERIFIED。"""
    run_dir = args.run_dir
    if _read_state(run_dir) != "COMPLETE":
        return _fail(run_dir, f"verify-results 要求 COMPLETE，当前 {_read_state(run_dir)}")
    schedule = json.loads((run_dir / "run_schedule.json").read_text(encoding="utf-8"))
    results = []
    for line in (run_dir / "results.jsonl").read_text(encoding="utf-8").splitlines():
        if line.strip():
            results.append(json.loads(line))
    got = {(r["sample_id"], r["side"]) for r in results}
    expected = {(s["sample_id"], s["side"]) for s in schedule}
    if got != expected:
        missing = expected - got
        return _fail(run_dir, f"结果不完整，缺 {len(missing)} 项: {list(missing)[:3]}")
    _write_state(run_dir, "VERIFIED", {"n_results": len(results)})
    print(f"[verify-results] PASS {len(results)} 项结果完整")
    return 0


def summarize(args) -> int:
    """聚合统计（只读，不改状态）。"""
    run_dir = args.run_dir
    if _read_state(run_dir) not in ("COMPLETE", "VERIFIED"):
        return _fail(run_dir, f"summarize 要求 COMPLETE/VERIFIED，当前 {_read_state(run_dir)}")
    results = []
    for line in (run_dir / "results.jsonl").read_text(encoding="utf-8").splitlines():
        if line.strip():
            results.append(json.loads(line))
    by_pair = {}
    for r in results:
        by_pair.setdefault(r["sample_id"], {})[r["side"]] = r["verdict"]
    strict = sum(1 for cve, d in by_pair.items()
                 if d.get("vuln") == "vulnerable" and d.get("fixed") == "benign")
    n = len(by_pair)
    summary = {"n_pairs": n, "strict_success": strict,
               "rate": round(strict / n, 4) if n else None}
    (run_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[summarize] strict_success={strict}/{n}")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("command", choices=["prepare", "verify-inputs", "invoke", "verify-results", "summarize"])
    ap.add_argument("--protocol", type=Path)
    ap.add_argument("--representation", default=None,
                    choices=sorted(ALLOWED_REPRESENTATIONS),
                    help="摘录表示版本，必须显式指定（不允许 changed-hunk-r0）")
    ap.add_argument("--canonical-manifest", type=Path,
                    default=ROOT / "cpg/ablation/artifacts/canonical_corpus_manifest.json")
    ap.add_argument("--run-dir", required=True, type=Path)
    args = ap.parse_args()

    fn = {"prepare": prepare, "verify-inputs": verify_inputs, "invoke": invoke,
          "verify-results": verify_results, "summarize": summarize}[args.command]
    try:
        return fn(args)
    except Exception as e:
        return _fail(args.run_dir, f"{args.command} 异常: {e}")


if __name__ == "__main__":
    sys.exit(main())
