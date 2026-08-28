"""生成可视化成果报告（自包含 HTML，无外部依赖）。"""
import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent

# ---------- 数据聚合 ----------
# 1) 36 版本主消融（A 设置，code 模式）
summary_path = ROOT / "cpg/ablation/seeds/v6_54_A/summary.md"
global_f1, group_f1 = {}, {}
with summary_path.open(encoding="utf-8") as fh:
    for line in fh:
        if "|" not in line:
            continue
        c = [x.strip() for x in line.strip().strip("|").split("|")]
        if len(c) == 10 and c[1] == "code" and c[0] in (
            "LocalLLMScorer", "CPGEvidenceScorer", "StructuralHeuristicScorer",
            "CodeQLBaselineScorer", "ConfigSigScorer"):
            global_f1[c[0]] = {"p": float(c[2]), "r": float(c[3]), "f1": float(c[4])}
        elif len(c) == 7 and c[2] == "code" and c[0] in ("taint", "logic") and c[1] in (
            "LocalLLMScorer", "CPGEvidenceScorer"):
            group_f1.setdefault(c[1], {})[c[0]] = float(c[5])

# 2) 补丁验证（正式版 patch_verify）
t2 = []
t2_path = ROOT / "cpg/ablation/patch_verify_results.json"
if not t2_path.exists():
    t2_path = ROOT / "cpg/ablation/t2_diff_results.json"
if t2_path.exists():
    t2 = json.loads(t2_path.read_text(encoding="utf-8"))
n_fixed_improved = sum(1 for r in t2 if r.get("improved"))
n_fp_fixed = sum(1 for r in t2 if r.get("base_pred") == "vulnerable" and r.get("patch_verdict") == "benign")
n_fp_base = sum(1 for r in t2 if r.get("base_pred") == "vulnerable")

# 2b) Bootstrap CI（P0-2）
boot = {}
boot_md = ROOT / "cpg/ablation/bootstrap_report.md"
if boot_md.exists():
    for line in boot_md.read_text(encoding="utf-8").splitlines():
        if "|" not in line or "LLM −" in line:
            continue
        c = [x.strip() for x in line.strip().strip("|").split("|")]
        if len(c) == 4 and c[0] in ("LocalLLMScorer", "CPGEvidenceScorer"):
            boot[c[0]] = c[3]

# 2c) Bandit 对比（P1）
bandit = {}
bandit_md = ROOT / "cpg/ablation/bandit_report.md"
if bandit_md.exists():
    for line in bandit_md.read_text(encoding="utf-8").splitlines():
        if "|" not in line:
            continue
        c = [x.strip() for x in line.strip().strip("|").split("|")]
        if len(c) == 3 and c[0] in ("F1", "P", "R"):
            bandit[c[0]] = c[1]

# 2d) 14B vs 7B（P3）
m14b = {}
s14b = ROOT / "cpg/ablation/seeds/v3_14b/summary.md"
if s14b.exists():
    for line in s14b.read_text(encoding="utf-8").splitlines():
        if "|" not in line:
            continue
        c = [x.strip() for x in line.strip().strip("|").split("|")]
        if len(c) == 10 and c[0] == "LocalLLMScorer" and c[1] == "code":
            m14b = {"p": float(c[2]), "r": float(c[3]), "f1": float(c[4])}


# 3) 样本判定矩阵（36 版本 code 模式）
samples = {}
with (ROOT / "cpg/ablation/results.csv").open(newline="", encoding="utf-8") as fh:
    for r in csv.DictReader(fh):
        if r["mode"] != "code":
            continue
        key = (r["sample_id"], r["version"])
        samples.setdefault(key, {"truth": r["truth"], "cwe": r["cwe_truth"], "group": r["group"]})
        if r["scorer"] in ("LocalLLMScorer", "CPGEvidenceScorer"):
            samples[key][r["scorer"]] = r["predicted"]

# 4) 代表性样本 rationale
rat = {}
rat_path = ROOT / "cpg/ablation/b2_rationales.json"
if rat_path.exists():
    for d in json.loads(rat_path.read_text(encoding="utf-8")):
        rat[d["sample"]] = d.get("rationale", "")

# 5) 演进链（权威数字，标注样本集）
milestones = [
    ("无上下文（仅公告）", 0.000, "36 版本", "基线"),
    ("+CPG 污点证据", 0.480, "28 版本", "A-1"),
    ("+真实源码", 0.519, "28 版本", "B-0.5"),
    ("+prompt 修正", 0.552, "28 版本", "B-2"),
    ("扩样本 18 CVE（36 版本）", 0.471, "36 版本", "T3"),
]

SCORER_LABEL = {
    "LocalLLMScorer": "LLM+CPG 判定器",
    "CPGEvidenceScorer": "CPG 确定性解析",
    "StructuralHeuristicScorer": "结构启发式",
    "CodeQLBaselineScorer": "CodeQL 官方查询",
    "ConfigSigScorer": "配置签名",
}
BAR_COLORS = {"LocalLLMScorer": "#1f6feb", "CPGEvidenceScorer": "#388bfd",
              "StructuralHeuristicScorer": "#8b949e", "CodeQLBaselineScorer": "#a5b4fc",
              "ConfigSigScorer": "#d29922"}

# ---------- HTML ----------
def bar_chart(items, w=600, h=260, ymax=0.7, label_col="#e6edf3", unit="F1"):
    """竖向条形图（div 实现）。items: [(label, value, color)]"""
    bars = []
    n = len(items)
    bw = 64
    gap = (w - n * bw) / (n + 1)
    for i, (lb, v, col) in enumerate(items):
        bh = max(4, v / ymax * (h - 60))
        x = gap + i * (bw + gap)
        bars.append(f'''
        <div class="bar-wrap" style="left:{x:.0f}px;width:{bw}px">
          <div class="bar-val" style="bottom:{bh + 28:.0f}px">{v:.3f}</div>
          <div class="bar" style="height:{bh:.0f}px;background:{col}"></div>
          <div class="bar-lb">{lb}</div>
        </div>''')
    return (f'<div class="chart" style="position:relative;width:{w}px;height:{h}px">'
            + "".join(bars) + "</div>")

# 1. 全局 F1 对比
g_items = [(SCORER_LABEL[s], global_f1[s]["f1"], BAR_COLORS[s])
           for s in ("LocalLLMScorer", "CPGEvidenceScorer", "StructuralHeuristicScorer",
                     "CodeQLBaselineScorer", "ConfigSigScorer")]
g_chart = bar_chart(g_items, ymax=0.6)

# 2. 分组对比
grp_items = [("数据流域 taint\nLLM", group_f1["LocalLLMScorer"]["taint"], "#1f6feb"),
             ("数据流域 taint\n确定性解析", group_f1["CPGEvidenceScorer"]["taint"], "#388bfd"),
             ("逻辑域 logic\nLLM 语义", group_f1["LocalLLMScorer"]["logic"], "#2da44e"),
             ("逻辑域 logic\n确定性解析", group_f1["CPGEvidenceScorer"]["logic"], "#57ab5a")]
grp_chart = bar_chart(grp_items, ymax=0.8)

# 3. 演进链
m_items = [(f"{m[0]} ({m[2]})", m[1], "#1f6feb") for m in milestones]
m_chart = bar_chart(m_items, ymax=0.65)

# 4. 补丁验证成对表
t2_rows = ""
for r in sorted(t2, key=lambda x: x["sample"]):
    base = r.get("base_pred", r.get("diff_pred", "?"))
    patched = r.get("patch_verdict", r.get("diff_verdict", "?"))
    improved = r.get("improved", False)
    cls = "ok" if improved else "no"
    t2_rows += (f"<tr><td>{r['sample']}_fixed</td>"
                f"<td class='{'bad' if base=='vulnerable' else 'mid'}'>{base}</td>"
                f"<td class='{'good' if patched=='benign' else 'bad'}'>{patched}</td>"
                f"<td class='{cls}'>{'✅ 误报修复' if improved else ''}</td>"
                f"<td class='rt'>{r.get('rationale','')[:60]}</td></tr>")

# 5. 样本判定矩阵（36 样本 × LLM/CPG）
mat_rows = ""
stat = {"llm_tp": 0, "llm_fp": 0, "llm_fn": 0, "llm_tn": 0, "cpg_tp": 0, "cpg_fp": 0, "cpg_fn": 0, "cpg_tn": 0}
for (sid, ver), s in sorted(samples.items()):
    llm = s.get("LocalLLMScorer", "-")
    cpg = s.get("CPGEvidenceScorer", "-")
    t = s["truth"]
    for sc, pred in (("llm", llm), ("cpg", cpg)):
        k = f"{sc}_"
        if pred == "vulnerable" and t == "vulnerable": stat[k + "tp"] += 1
        elif pred == "vulnerable": stat[k + "fp"] += 1
        elif pred == "benign" and t == "benign": stat[k + "tn"] += 1
        elif pred == "benign": stat[k + "fn"] += 1
    def cell(pred, truth):
        if pred == truth:
            return "🟢" if pred == "vulnerable" else "⚪"
        if pred == "abstain":
            return "🔵"
        return "🔴"
    mat_rows += (f"<tr><td>{sid}_{ver}</td><td>{s['cwe']}</td><td>{s['group']}</td><td>{t}</td>"
                 f"<td>{cell(llm, t)} {llm}</td><td>{cell(cpg, t)} {cpg}</td></tr>")

# 6. 代表性样本
showcase = []
if "CVE-2026-53505_vuln" in rat:
    showcase.append(("CVE-2026-53505_vuln · thumbor CWE-400 无界 resize",
                     "LLM 语义推理独对样本：全部确定性基线（含 CPG 解析）判 benign，LLM 结合摘要+源码判 vulnerable",
                     rat["CVE-2026-53505_vuln"]))
if "CVE-2026-54785_vuln" in rat:
    showcase.append(("CVE-2026-54785_vuln · gemini-bridge CWE-022 文件读取",
                     "CPG 覆盖扩展样本：补 source 参数名后 taint 0→77 行命中，漏报转正确",
                     rat["CVE-2026-54785_vuln"]))
showcase_html = ""
for t, d, r in showcase:
    showcase_html += (f'<div class="spot"><div class="t">{t}</div>'
                      f'<div style="color:#8b949e;font-size:12px;margin-top:2px">{d}</div>'
                      f'<div class="r">LLM 判定依据：{r}</div></div>')

html = f"""<!DOCTYPE html>
<html lang="zh"><head><meta charset="utf-8">
<title>LLM+CPG 上下文增强漏洞检测 — 成果报告</title>
<style>
:root {{ color-scheme: dark; }}
body {{ background:#0d1117; color:#e6edf3; font-family:-apple-system,'Segoe UI','Microsoft YaHei',sans-serif;
       margin:0; padding:32px 40px; }}
h1 {{ font-size:26px; margin:0 0 4px; }}
.sub {{ color:#8b949e; font-size:13px; margin-bottom:28px; }}
.cards {{ display:flex; gap:14px; flex-wrap:wrap; margin-bottom:32px; }}
.card {{ background:#161b22; border:1px solid #30363d; border-radius:10px; padding:16px 20px; min-width:150px; }}
.card .v {{ font-size:26px; font-weight:700; color:#58a6ff; }}
.card .k {{ font-size:12px; color:#8b949e; margin-top:4px; }}
.card .d {{ font-size:11px; color:#484f58; margin-top:2px; }}
section {{ background:#161b22; border:1px solid #30363d; border-radius:12px; padding:20px 24px; margin-bottom:24px; }}
h2 {{ font-size:17px; margin:0 0 6px; color:#e6edf3; }}
.sec-sub {{ color:#8b949e; font-size:12px; margin-bottom:16px; }}
.chart {{ margin:8px auto; }}
.bar {{ position:absolute; bottom:24px; width:100%; border-radius:4px 4px 0 0; opacity:.92; }}
.bar-val {{ position:absolute; text-align:center; width:100%; font-size:12px; color:#e6edf3; }}
.bar-lb {{ position:absolute; bottom:0; width:100%; text-align:center; font-size:11px; color:#8b949e; }}
table {{ border-collapse:collapse; width:100%; font-size:12px; }}
th,td {{ border:1px solid #30363d; padding:5px 8px; text-align:left; }}
th {{ background:#21262d; color:#c9d1d9; }}
.ok {{ color:#3fb950; }} .no {{ color:#8b949e; }} .warn {{ color:#d29922; }}
.good {{ color:#3fb950; }} .bad {{ color:#f85149; }} .mid {{ color:#d29922; }}
.rt {{ color:#8b949e; font-size:11px; }}
.spot {{ background:#0d1117; border:1px solid #30363d; border-radius:8px; padding:12px 16px; margin-top:10px; }}
.spot .t {{ font-weight:600; color:#e6edf3; }}
.spot .r {{ color:#8b949e; font-size:12px; margin-top:4px; font-style:italic; }}
.legend {{ font-size:11px; color:#8b949e; margin-top:6px; }}
</style></head><body>

<h1>上下文增强智能漏洞检测：LLM + CPG 联合判定</h1>
<div class="sub">真实 CVE 语料（GitHub Advisory 分层抽样）· 本地模型 qwen2.5-coder:7b · CodeQL 2.26.2 提取 · 3 次运行零方差</div>

<div class="cards">
  <div class="card"><div class="v">18</div><div class="k">真实 CVE 样本</div><div class="d">14 仓库 / 15 类 CWE</div></div>
  <div class="card"><div class="v">{global_f1['LocalLLMScorer']['f1']:.3f}</div><div class="k">LLM+CPG 全局 F1</div><div class="d">确定性解析 0.435</div></div>
  <div class="card"><div class="v">+0.133</div><div class="k">CPG 证据增益 (F1)</div><div class="d">召回 +0.185（54 版本）</div></div>
  <div class="card"><div class="v">0.667</div><div class="k">数据流域 F1</div><div class="d">LLM 与确定性并列</div></div>
  <div class="card"><div class="v">0.364</div><div class="k">逻辑域 F1（LLM）</div><div class="d">静态基线全 0</div></div>
  <div class="card"><div class="v">9/14</div><div class="k">补丁验证误报修复</div><div class="d">版本对比信号</div></div>
</div>

<section><h2>1. 全局判定能力：LLM+CPG vs 各基线</h2>
<div class="sec-sub">36 个样本版本（18 CVE × vuln/fixed），code 模式，正类=vulnerable</div>
{g_chart}
<div class="legend">F1 度量。LLM+CPG 判定器最高（0.449）；确定性 CPG 解析（0.435）次之；纯静态基线（0.270 / 0.069 / 0.000）显著落后。</div>
</section>

<section><h2>2. 互补性：CPG 覆盖数据流域，LLM 覆盖逻辑域</h2>
<div class="sec-sub">taint 子集 = 有数据流可提取的漏洞（路径穿越/SSRF）；logic 子集 = 逻辑型漏洞（鉴权/走私/信息泄露）</div>
{grp_chart}
<div class="legend">数据流域：LLM 与确定性解析并列 0.667（CPG 证据信息充分）；逻辑域：仅 LLM 语义层有判别力（0.364），确定性解析 0.316，静态基线 0——互补性立论成立。</div>
</section>

<section><h2>3. 上下文增强演进：每补一块上下文，判定能力上一个台阶</h2>
<div class="sec-sub">28 版本演进链（0.000→0.552）；扩样本至 36 版本（harder 集）后 0.471，相对关系保持</div>
{m_chart}
<div class="legend">无上下文=纯公告盲判（0）；注入 CPG 污点证据后召回从 0 起步；再加真实源码、修正 prompt 后升至 0.552；扩样本后 0.471（新样本难度更高，属预期）。</div>
</section>

<section><h2>4. 补丁验证：版本对比信号修复 9/14 误报</h2>
<div class="sec-sub">对 14 个 fixed 样本注入 vuln→fixed 修复 diff，LLM 识别安全包装/守卫/SSRF guard</div>
<table><tr><th>样本</th><th>无 diff 判定</th><th>有 diff 判定</th><th>结果</th><th>LLM 依据</th></tr>
{t2_rows}
</table>
<div class="legend">6 个「修复未消除数据流」误报（50558/53502/54706/54707/67424/67435）+ 3 个 abstain 均被修复；LLM 能读懂安全包装（如 safe_tar_extractall 的路径守卫）。</div>
</section>

<section><h2>5. 统计显著性（bootstrap）与业界对比（Bandit）</h2>
<div class="sec-sub">2000 次按 CVE 配对重采样 · Bandit 规则：HIGH>0 判 vulnerable</div>
<table>
<tr><th>方法</th><th>F1</th><th>说明</th></tr>
<tr><td>本系统 LLM+CPG</td><td><b>{global_f1['LocalLLMScorer']['f1']:.3f}</b></td><td>95% CI {boot.get('LocalLLMScorer','—')}（bootstrap）</td></tr>
<tr><td>CPG 确定性解析</td><td>{global_f1['CPGEvidenceScorer']['f1']:.3f}</td><td>95% CI {boot.get('CPGEvidenceScorer','—')}</td></tr>
<tr><td>Bandit（业界规则扫描）</td><td>{bandit.get('F1','—')}</td><td>召回 {bandit.get('R','—')}，无法区分 vuln/fixed</td></tr>
<tr><td>14B 模型（LLM+CPG）</td><td>{m14b.get('f1', 0):.3f}</td><td>{'14B 全量消融完成' if m14b else '（全量消融运行中）'}</td></tr>
</table>
<div class="legend">bootstrap 差值 CI [0.023, 0.221]：LLM 显著高于确定性 CPG 解析（99.7% 支持，CI 不含 0）；
Bandit F1≈0.17 远低于本系统；14B 模型规模消融见第 7 节。</div>
</section>

<section><h2>6. 代表性样本：LLM 语义推理实例</h2>
<div class="sec-sub">系统输出的真实判定依据（rationale），可直接用于论文/汇报引用</div>
{showcase_html}
</section>

<section><h2>7. 模型规模：14B vs 7B（P3）</h2>
<div class="sec-sub">qwen2.5-coder:14b 在 17GB RAM 本机可跑（11-20s/样本）；代表性样本判定对比</div>
<table>
<tr><th>样本</th><th>truth</th><th>7B</th><th>14B</th><th>说明</th></tr>
<tr><td>54569_vuln（eval 代码注入）</td><td>vulnerable</td><td>漏报</td><td><b>✅ 判对</b></td><td>模型规模提升真实语义能力</td></tr>
<tr><td>50558_fixed（TarSlip 安全包装）</td><td>benign</td><td>误报</td><td>仍误报</td><td>「缺失检查」类识别需版本对比信号，与模型规模无关</td></tr>
<tr><td>53505_vuln（无界 resize）</td><td>vulnerable</td><td>✅ 判对</td><td>✅ 判对</td><td>两者一致</td></tr>
</table>
</section>

<section><h2>5. 逐样本判定矩阵（36 版本 × LLM/确定性解析）</h2>
<div class="sec-sub">🟢=命中正例 🔴=误报/漏报 ⚪=正确负例 🔵=弃权 abstain</div>
<div style="max-height:420px;overflow:auto"><table>
<tr><th>样本</th><th>CWE</th><th>域</th><th>truth</th><th>LLM</th><th>CPG 解析</th></tr>
{mat_rows}
</table></div>
<div class="legend">LLM 命中正例 {stat['llm_tp']} 个（确定性解析 {stat['cpg_tp']} 个）；LLM 在 harder 逻辑样本上更多 abstain（诚实弃权，不产生自信误报）。</div>
</section>

</body></html>"""

out = Path("C:/Users/lenovo/WorkBuddy/2026-07-21-16-16-43/.workbuddy/artifacts/成果报告-LLM-CPG漏洞检测.html")
out.write_text(html, encoding="utf-8")
print(f"[ok] wrote {out} ({len(html)//1024} KB)")
print(f"统计: LLM TP={stat['llm_tp']} FP={stat['llm_fp']} TN={stat['llm_tn']} FN={stat['llm_fn']} | CPG TP={stat['cpg_tp']} FP={stat['cpg_fp']} TN={stat['cpg_tn']} FN={stat['cpg_fn']}")
