"""补丁验证的阴性对照：区分"读懂补丁"与"看见补丁就说没事"。

问题
----
`patch_verify.py` 只对 fixed 样本注入真实 vuln→fixed diff，且系统提示直接说
"验证该补丁是否完整消除了公告所述漏洞"。这一设定**预设补丁存在**，模型的先验
答案就是"补丁有效"（benign）。因此原报告"误报修复 7 个 / 判定改善 11/18"无法
区分两种机制：

  H1（真能力）模型读懂补丁内容，确认净化器覆盖了污点路径 → 判 benign；
  H2（提示先验）模型只要看到 diff 就倾向判 benign，与补丁内容无关。

本脚本用两个阴性对照把 H1 与 H2 分开。三个实验臂共用**同一套系统提示、同一份
源码与污点切片、同一温度（0）**，只替换注入的 diff：

| 臂 | 注入内容 | 补丁是否真的修复漏洞 | 正确判定 |
|----|----------|----------------------|----------|
| `real` | 该 CVE 真实 vuln→fixed diff | 是 | benign |
| `placebo` | 仅注释/空行/版本号的装饰性 diff（在真实 fixed 文件上合成） | **否** | **vulnerable** |
| `shuffled` | **另一个 CVE** 的真实 diff（结构像补丁但与本代码无关） | **否** | **vulnerable** |

判读规则：
- 若 placebo / shuffled 的 benign 率接近 real → H2 成立，原补丁验证结论是提示
  先验的产物，必须撤回；
- 若 placebo / shuffled 显著低于 real（模型对无效补丁判 vulnerable）→ H1 成立，
  补丁验证能力为真，且该能力正是纯静态污点分析所不具备的（污点流在打补丁前后
  都存在，见 `paired_metrics.py` 的双标记统计）。

样本范围
--------
默认取"CPG 对补丁失明"的 CVE 子集，即 CPGEvidence 在 vuln 与 fixed 两个版本
**都判 vulnerable** 的 CVE（双标记）。选择理由是预先设定的：补丁验证只在静态
证据无法区分补丁前后时才有意义，这些正是该子集。子集由 `b2_74_7b.json` 的
`cpg_full` 字段确定性导出，不做人工挑选。

用法
----
    python cpg/ablation/patch_verify_control.py --arms real placebo shuffled
    python cpg/ablation/patch_verify_control.py --arms placebo --model qwen2.5-coder:14b
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from cpg.ablation.context_build import build_context
from cpg.ablation.cpg_eval import build_cpg_slices_text
from cpg.ablation.patch_verify import DIFF_SYSTEM, make_diff
from cpg.ablation.run_ablation import _load_dataset_rows, _load_sample_code
from cpg.ablation.scorers import LocalLLMScorer

WORK = ROOT / "cpg/ablation/.work"
B2_JSON = ROOT / "cpg/ablation/b2_74_7b.json"
MAIN_CSV = ROOT / "cpg/ablation/seeds/v8_74/results.csv"


# --------------------------------------------------------------------------
# 样本子集：CPG 双标记（对补丁失明）
# --------------------------------------------------------------------------
def cpg_patch_blind_cves(path: Path = B2_JSON) -> list[str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    by = {s["sample"]: s for s in data["samples"]}
    out = []
    for name in by:
        if not name.endswith("_vuln"):
            continue
        cve = name[: -len("_vuln")]
        v, f = by.get(f"{cve}_vuln"), by.get(f"{cve}_fixed")
        if v and f and v.get("cpg_full") == "vulnerable" and f.get("cpg_full") == "vulnerable":
            out.append(cve)
    return sorted(out)


# --------------------------------------------------------------------------
# 三个实验臂的 diff 构造
# --------------------------------------------------------------------------
COSMETIC_HEADER = "维护性整理：补充模块注释、统一空行、同步版本号（无功能变更）"


def make_placebo_diff(cve: str, real_diff: str) -> str:
    """在真实 diff 的文件头与行号上下文之上，合成仅注释/空行/版本号的装饰性变更。

    做法：沿用真实 diff 的 `--- <相对路径>` 文件头（保证路径真实），但把变更体
    替换为注释插入与版本号自增。长度与真实 diff 同量级，避免"篇幅"成为混淆变量。
    """
    files = [l[4:].strip() for l in real_diff.splitlines() if l.startswith("--- ")]
    if not files:
        files = ["src/module.py"]
    parts = []
    for i, rel in enumerate(files):
        parts.append(
            f"--- {rel}\n"
            f"@@ -1,4 +1,8 @@\n"
            f" # -*- coding: utf-8 -*-\n"
            f"+#\n"
            f"+# {COSMETIC_HEADER}\n"
            f"+#\n"
            f"+\n"
            f" import os\n"
            f" import sys\n"
            f"@@ -12,7 +16,7 @@\n"
            f"-__version__ = \"1.{i}.0\"\n"
            f"+__version__ = \"1.{i}.1\"\n"
            f" \n"
            f"-# TODO: 清理历史遗留分支\n"
            f"+# NOTE: 历史遗留分支保留待后续评估\n"
        )
    return "\n".join(parts)


def make_shuffled_diff(cve: str, all_cves: list[str], cache: dict[str, str]) -> tuple[str, str]:
    """取列表中下一个 CVE 的真实 diff（循环配对，确定性、无随机）。"""
    if cve not in all_cves or len(all_cves) < 2:
        return "", ""
    donor = all_cves[(all_cves.index(cve) + 1) % len(all_cves)]
    if donor not in cache:
        cache[donor] = make_diff(donor)
    return cache[donor], donor


# --------------------------------------------------------------------------
# 主流程
# --------------------------------------------------------------------------
def load_taint_rows(prefix: str) -> list[dict]:
    rows: list[dict] = []
    for name in ("taint.csv", "tarslip.csv"):
        p = WORK / name
        if not p.exists():
            continue
        with p.open(newline="", encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                if f"/{prefix}/" in (r.get("abs_path") or ""):
                    rows.append(r)
    return rows


def load_main_baseline() -> dict[str, str]:
    """无 diff 基线取自权威主协议产物 seeds/v8_74（而非历史 results.csv）。"""
    base: dict[str, str] = {}
    if not MAIN_CSV.exists():
        return base
    with MAIN_CSV.open(newline="", encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            if (
                r["mode"] == "code"
                and r["version"] == "fixed"
                and r["scorer"] == "LocalLLMScorer"
            ):
                base[r["sample_id"]] = r["predicted"]
    return base


def ask_llm(llm: LocalLLMScorer, prompt: str, model: str, timeout: int = 600) -> dict:
    payload = json.dumps(
        {
            "model": model,
            "system": DIFF_SYSTEM,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0, "num_predict": 512},
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        "http://localhost:11434/api/generate",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = json.loads(resp.read().decode("utf-8"))["response"]
    return {"raw": raw, "parsed": llm._extract_json(raw) or {}}


def ask_llm_openai(llm: LocalLLMScorer, prompt: str, model: str,
                   base_url: str, key: str, timeout: int = 600) -> dict:
    """OpenAI 兼容后端（frontier spot-check 用）。与 Ollama 臂同 system prompt、
    同 temperature=0；API 残余非确定性通过 --repeats 多轮观测并全量落 raw。"""
    import os
    key = key or os.environ.get("DEEPSEEK_API_KEY", "")
    if not key:
        raise SystemExit("openai 后端需要 --key 或环境变量 DEEPSEEK_API_KEY")
    payload = json.dumps(
        {
            "model": model,
            "messages": [
                {"role": "system", "content": DIFF_SYSTEM},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0,
            "max_tokens": 1024,
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        base_url.rstrip("/") + "/chat/completions",
        data=payload,
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {key}"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = json.loads(resp.read().decode("utf-8"))["choices"][0]["message"]["content"]
    return {"raw": raw, "parsed": llm._extract_json(raw) or {}}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--arms", nargs="+", default=["real", "placebo", "shuffled"],
                    choices=["real", "placebo", "shuffled"])
    ap.add_argument("--model", default="qwen2.5-coder:7b")
    ap.add_argument("--cves", nargs="*", help="显式指定 CVE（默认取 CPG 双标记子集）")
    ap.add_argument("--dataset", type=Path, default=None,
                    help="指定语料集路径（默认 DATASET_JSONL；扩到全量 D1 用 dataset_d1.jsonl）")
    ap.add_argument("--out", default="cpg/ablation/patch_verify_control.json")
    ap.add_argument("--raw-out", default="cpg/ablation/patch_verify_control_raw.jsonl")
    ap.add_argument("--backend", choices=["ollama", "openai"], default="ollama",
                    help="openai 用于 frontier spot-check（DeepSeek 等 API 模型）")
    ap.add_argument("--base-url", default="https://api.deepseek.com/v1")
    ap.add_argument("--key", default="",
                    help="缺省读环境变量 DEEPSEEK_API_KEY，避免进 shell 历史")
    args = ap.parse_args()

    cves = args.cves or cpg_patch_blind_cves()
    print(f"[subset] CPG 双标记（对补丁失明）CVE {len(cves)} 个：{', '.join(cves)}\n")

    rows = {r["cve_id"]: r for r in _load_dataset_rows(None, args.dataset)}
    base_pred = load_main_baseline()
    llm = LocalLLMScorer(timeout=600)
    donor_cache: dict[str, str] = {}

    results = []
    raw_fh = (ROOT / args.raw_out).open("w", encoding="utf-8")
    for cve in cves:
        row = rows.get(cve)
        if row is None:
            print(f"[skip] {cve}: 不在 dataset 中")
            continue
        prefix = f"{cve}_fixed"
        trows = load_taint_rows(prefix)
        code = _load_sample_code(prefix, trows)
        if not code:
            print(f"[skip] {cve}: 无源码")
            continue
        slices = build_cpg_slices_text(trows, code)
        # CWE 取自 dataset 真实字段（原 patch_verify 硬编码 CWE-022，此处修正）
        cwes = row.get("cwes") or ([row["cwe"]] if row.get("cwe") else [])
        sample = {
            "sample_id": cve, "version": "fixed", "cwes": cwes,
            "cwe": (cwes[0] if cwes else None), "truth": "benign",
            "prefix": prefix, "code_text": code,
        }
        ctx = build_context("code", sample, taint_rows=trows, cpg_slices=slices)
        base_prompt = llm._build_prompt(ctx)
        real_diff = make_diff(cve)

        rec = {"cve": cve, "cwe": (cwes[0] if cwes else "?"),
               "base_pred_no_diff": base_pred.get(cve, "?"), "arms": {}}
        for arm in args.arms:
            if arm == "real":
                diff, donor, expect = real_diff, "", "benign"
            elif arm == "placebo":
                diff, donor, expect = make_placebo_diff(cve, real_diff), "", "vulnerable"
            else:
                diff, donor = make_shuffled_diff(cve, cves, donor_cache)
                expect = "vulnerable"
            if not diff:
                rec["arms"][arm] = {"verdict": "no_diff", "correct": None}
                continue
            prompt = base_prompt + f"\n# 修复补丁（vuln→fixed diff）\n```diff\n{diff[:4000]}\n```"
            if args.backend == "ollama":
                got = ask_llm(llm, prompt, args.model)
            else:
                got = ask_llm_openai(llm, prompt, args.model, args.base_url, args.key)
            verdict = got["parsed"].get("verdict", "?")
            rec["arms"][arm] = {
                "verdict": verdict,
                "expect": expect,
                "correct": (verdict == expect),
                "donor": donor,
                "diff_chars": len(diff),
                "rationale": str(got["parsed"].get("rationale", ""))[:200],
            }
            raw_fh.write(json.dumps(
                {"cve": cve, "arm": arm, "model": args.model,
                 "verdict": verdict, "raw": got["raw"]}, ensure_ascii=False) + "\n")
            raw_fh.flush()
            print(f"  {cve} [{arm:8s}] verdict={verdict:<11s} 期望={expect:<11s}"
                  f" {'✓' if verdict == expect else '✗'}"
                  f" | {str(got['parsed'].get('rationale',''))[:60]}")
        results.append(rec)
        print()

    raw_fh.close()

    # 汇总：各臂 benign 率（H2 的判据）
    print("=== 阴性对照汇总 ===")
    summary = {}
    for arm in args.arms:
        vs = [r["arms"][arm]["verdict"] for r in results if arm in r["arms"]]
        vs = [v for v in vs if v != "no_diff"]
        n = len(vs)
        n_benign = sum(1 for v in vs if v == "benign")
        n_vuln = sum(1 for v in vs if v == "vulnerable")
        summary[arm] = {"n": n, "benign": n_benign, "vulnerable": n_vuln,
                        "benign_rate": (n_benign / n if n else 0.0)}
        print(f"  {arm:9s} n={n:2d} benign={n_benign:2d} vulnerable={n_vuln:2d} "
              f"benign率={summary[arm]['benign_rate']:.3f}")

    if "real" in summary and ("placebo" in summary or "shuffled" in summary):
        r = summary["real"]["benign_rate"]
        for ctrl in ("placebo", "shuffled"):
            if ctrl in summary:
                gap = r - summary[ctrl]["benign_rate"]
                verdict = ("H1（真读补丁）" if gap >= 0.30
                           else "H2（提示先验主导）" if gap <= 0.10
                           else "不确定")
                print(f"  real − {ctrl}: benign率差 {gap:+.3f} → {verdict}")

    out = {"model": args.model, "subset": cves, "summary": summary, "results": results}
    (ROOT / args.out).write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"\n[ok] wrote {args.out} + {args.raw_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
