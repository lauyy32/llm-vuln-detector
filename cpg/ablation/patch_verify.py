"""补丁验证基准（第二研究问题）：对 fixed 样本注入 vuln→fixed 修复 diff，评估 LLM 补丁验证能力。

与单版本检测（run_ablation）互补的独立任务设定：
- 单版本检测：给定单个版本源码，判断是否可被利用；
- 补丁验证：给定漏洞公告 + 修复补丁，判断补丁是否完整消除漏洞（fixed 样本 truth=benign）。

用法：
  python cpg/ablation/patch_verify.py [--out cpg/ablation/patch_verify_results.json]
"""
from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from cpg.ablation.run_ablation import _load_dataset_rows, _load_sample_code
from cpg.ablation.cpg_eval import build_cpg_slices_text
from cpg.ablation.context_build import build_context
from cpg.ablation.scorers import LocalLLMScorer

PAIRS = ROOT / "cpg/corpus_pairs"

DIFF_SYSTEM = (
    "你是一名资深代码安全审计助手。给定漏洞公告元数据、目标源码节选、CPG 污点切片"
    "与【修复补丁】（vulnerable 版本到 fixed 版本的差异）。"
    "任务：验证该补丁是否完整消除了公告所述漏洞。"
    "判断原则：若补丁对漏洞点施加了有效防护（路径校验/白名单/守卫/消毒/限流），判定补丁完整（benign）；"
    "若漏洞路径仍可被利用或补丁与漏洞无关（如只改文档/版本号），判定仍有风险（vulnerable）。"
    "污点切片只是线索，以补丁与源码语义为准。只输出严格 JSON。"
)


def _smart_truncate(lines: list[str], max_lines: int = 90) -> list[str]:
    """取变更行（+/-）最密集的连续窗口，避免从头截断丢掉核心修复。"""
    change_idx = [i for i, l in enumerate(lines)
                  if l.startswith(("+", "-")) and not l.startswith(("+++", "---"))]
    if not change_idx:
        return lines[:max_lines]
    mid = change_idx[len(change_idx) // 2]
    start = max(0, mid - max_lines // 2)
    return lines[start:start + max_lines]


def make_diff(cve: str, max_files: int = 3) -> str:
    """构造 vuln→fixed 的 unified diff（每文件变更行密集窗口，最多 max_files 文件）。"""
    v, f = PAIRS / cve / "vuln", PAIRS / cve / "fixed"
    if not v.is_dir() or not f.is_dir():
        return ""
    vfiles = {p.relative_to(v).as_posix() for p in v.rglob("*") if p.is_file()}
    ffiles = {p.relative_to(f).as_posix() for p in f.rglob("*") if p.is_file()}
    changed = sorted(vfiles & ffiles)
    parts, n = [], 0
    for rel in changed:
        if n >= max_files:
            break
        r = subprocess.run(["diff", "-u", str(v / rel), str(f / rel)],
                           capture_output=True, text=True)
        if r.returncode not in (0, 1) or not r.stdout:
            continue
        lines = r.stdout.splitlines()
        if any(l.startswith(("+", "-")) and not l.startswith(("+++", "---")) for l in lines):
            parts.append(f"--- {rel}\n" + "\n".join(_smart_truncate(lines)))
            n += 1
    return "\n".join(parts)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=str, default="cpg/ablation/patch_verify_results.json")
    args = ap.parse_args()

    # 全部 fixed 样本（来自权威 dataset，36 版本）
    rows = _load_dataset_rows(None)
    summaries = {r["cve_id"]: (r.get("summary") or "") for r in rows}

    # 无 diff 基线：从权威消融 results.csv 取 code 模式 LLM 判定
    base_pred = {}
    with (ROOT / "cpg/ablation/results.csv").open(newline="", encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            if r["mode"] == "code" and r["version"] == "fixed" and r["scorer"] == "LocalLLMScorer":
                base_pred[r["sample_id"]] = r["predicted"]

    llm = LocalLLMScorer(timeout=600)
    import urllib.request
    out = []
    for row in rows:
        sid = row["cve_id"]
        prefix = f"{sid}_fixed"
        trows = []
        for f in ("cpg/ablation/.work/taint.csv", "cpg/ablation/.work/tarslip.csv"):
            if Path(f).exists():
                with open(f, newline="", encoding="utf-8") as fh:
                    for r in csv.DictReader(fh):
                        if f"/{prefix}/" in (r.get("abs_path") or ""):
                            trows.append(r)
        code = _load_sample_code(prefix, trows)
        slices = build_cpg_slices_text(trows, code)
        diff = make_diff(sid)
        sample = {"sample_id": sid, "version": "fixed", "cwes": ["CWE-022"], "cwe": "CWE-022",
                  "truth": "benign", "prefix": prefix, "summary": summaries.get(sid, ""),
                  "code_text": code}
        ctx = build_context("code", sample, taint_rows=trows, cpg_slices=slices)
        prompt = llm._build_prompt(ctx)
        if diff:
            prompt += f"\n# 修复补丁（vuln→fixed diff）\n```diff\n{diff[:4000]}\n```"
        payload = json.dumps({"model": llm.model, "system": DIFF_SYSTEM, "prompt": prompt,
                              "stream": False, "options": {"temperature": 0}}).encode("utf-8")
        req = urllib.request.Request("http://localhost:11434/api/generate", data=payload,
                                     headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=600) as resp:
            raw = json.loads(resp.read().decode("utf-8"))["response"]
        parsed = llm._extract_json(raw) or {}
        verdict = parsed.get("verdict", "?")
        b = base_pred.get(sid, "?")
        improved = (verdict == "benign" and b != "benign")
        out.append({"sample": sid, "base_pred": b, "patch_verdict": verdict,
                    "diff_chars": len(diff), "rationale": str(parsed.get("rationale", ""))[:140],
                    "improved": improved})
        print(f"{sid}_fixed: 无diff={b:<10} 有diff={verdict:<10} {'✅修复' if improved else ''} | {str(parsed.get('rationale',''))[:70]}")

    n_imp = sum(1 for r in out if r["improved"])
    n_fp_fixed = sum(1 for r in out if r["base_pred"] == "vulnerable" and r["patch_verdict"] == "benign")
    n_tot = len(out)
    print(f"\n=== 补丁验证汇总 ===")
    print(f"样本数: {n_tot}；误报修复: {n_fp_fixed}；判定改善: {n_imp}；"
          f"误报修复率: {n_fp_fixed}/{sum(1 for r in out if r['base_pred']=='vulnerable')}")

    out_path = ROOT / args.out
    out_path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    # markdown 报告
    md = ["# 补丁验证基准（第二研究问题）", "",
          f"> {n_tot} 个 fixed 样本 · diff 注入（vuln→fixed）· qwen2.5-coder:7b temperature=0", "",
          "| 样本 | 无diff判定 | 有diff判定 | 结果 | LLM 依据 |", "| --- | --- | --- | --- | --- |"]
    for r in sorted(out, key=lambda x: x["sample"]):
        md.append(f"| {r['sample']}_fixed | {r['base_pred']} | {r['patch_verdict']} "
                  f"| {'✅ 误报修复' if r['improved'] else ''} | {r['rationale'][:70]} |")
    md += ["", f"**汇总：误报修复 {n_fp_fixed} 个（判定改善 {n_imp}/{n_tot}）**"]
    (ROOT / "cpg/ablation/patch_verify_report.md").write_text("\n".join(md), encoding="utf-8")
    print(f"[ok] wrote {out_path} + patch_verify_report.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
