"""T2：版本对比 diff 注入实验——LLM 补丁验证能力。

对 14 个 fixed 样本注入 vuln→fixed 修复 diff（unified diff，限量），
评估 LLM 能否据补丁判断「修复是否完整消除漏洞」：
- 修复完整（safe wrapper/guard 到位）→ benign（修复 50558_fixed 等误报）
- 修复不完整 → vulnerable

独立实验设置：明确告知 LLM 这是修复补丁（补丁验证任务），不混入主消融。
"""
import csv
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from cpg.ablation.run_ablation import _load_sample_code
from cpg.ablation.cpg_eval import build_cpg_slices_text
from cpg.ablation.context_build import build_context
from cpg.ablation.scorers import LocalLLMScorer

PAIRS = Path("cpg/corpus_pairs")
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


def make_diff(cve: str) -> str:
    """vuln vs fixed 的 unified diff（限量：每文件 90 行窗口、最多 3 文件）。"""
    v, f = PAIRS / cve / "vuln", PAIRS / cve / "fixed"
    if not v.is_dir() or not f.is_dir():
        return ""
    parts = []
    # 找变更文件（vuln 有 fixed 无 / 都有但内容不同 / 新增）
    vfiles = {p.relative_to(v).as_posix() for p in v.rglob("*") if p.is_file()}
    ffiles = {p.relative_to(f).as_posix() for p in f.rglob("*") if p.is_file()}
    changed = sorted(vfiles & ffiles)
    n = 0
    for rel in changed:
        if n >= 3:
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


def main():
    # fixed 样本清单（28 样本的 fixed 版本）
    fixed_samples = []
    with open("cpg/ablation/results.csv", newline="", encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            if r["mode"] == "code" and r["version"] == "fixed" and r["scorer"] == "LocalLLMScorer":
                fixed_samples.append((r["sample_id"], r["predicted"], r["truth"]))
    fixed_samples = sorted(set(fixed_samples))

    summaries = {}
    with open("cpg/dataset.jsonl", encoding="utf-8") as fh:
        for line in fh:
            d = json.loads(line)
            summaries[d["cve_id"]] = d.get("summary") or ""

    llm = LocalLLMScorer(timeout=600)
    rows_out = []
    for sid, base_pred, truth in fixed_samples:
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
        sample = {
            "sample_id": sid, "version": "fixed", "cwes": ["CWE-022"], "cwe": "CWE-022",
            "truth": "benign", "prefix": prefix, "summary": summaries.get(sid, ""),
            "code_text": code,
        }
        ctx = build_context("code", sample, taint_rows=trows, cpg_slices=slices)
        prompt = llm._build_prompt(ctx)
        # 注入 diff 段
        if diff:
            prompt += f"\n# 修复补丁（vuln→fixed diff）\n```diff\n{diff[:4000]}\n```"
        payload = json.dumps({"model": llm.model, "system": DIFF_SYSTEM, "prompt": prompt,
                              "stream": False, "options": {"temperature": 0}}).encode("utf-8")
        import urllib.request
        req = urllib.request.Request("http://localhost:11434/api/generate", data=payload,
                                     headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=600) as resp:
            raw = json.loads(resp.read().decode("utf-8"))["response"]
        parsed = llm._extract_json(raw) or {}
        verdict = parsed.get("verdict", "?")
        improved = (verdict == "benign" and base_pred != "benign")
        rows_out.append({
            "sample": sid, "base_pred": base_pred, "diff_verdict": verdict,
            "diff_chars": len(diff), "rationale": str(parsed.get("rationale", ""))[:120],
            "improved": improved,
        })
        print(f"{sid}_fixed: 无diff={base_pred:<10} 有diff={verdict:<10} (diff={len(diff)}ch)"
              f" {'✅修复误报' if improved else ''} | {str(parsed.get('rationale',''))[:80]}")

    n_improved = sum(1 for r in rows_out if r["improved"])
    print(f"\n=== 汇总：fixed 误报修复 {n_improved}/{len(rows_out)} ===")
    with open("cpg/ablation/t2_diff_results.json", "w", encoding="utf-8") as fh:
        json.dump(rows_out, fh, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    main()
