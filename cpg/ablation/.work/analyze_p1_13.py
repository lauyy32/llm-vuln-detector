# -*- coding: utf-8 -*-
"""P1-13 RQ1 前沿臂分析：合并 4 个分片结果，按预注册 A/B/C 分支判读。
用法：python cpg/ablation/.work/analyze_p1_13.py
口径：配对分析在完整对 n=82（剔除 53500/59224/70485，与冻结主协议一致）；
abstain 不计入判别对错（与本地口径一致），单独申报；判别=同 CVE vuln 判
vulnerable 且 fixed 判 benign。统计契约：BA/MCC/平凡基线/单侧精确 McNemar。"""
import csv, json, math, os
from collections import Counter, defaultdict

ROOT = os.path.dirname(os.path.abspath(__file__))
SEEDS = os.path.join(ROOT, "..", "seeds")
INCOMPLETE = {"CVE-2026-53500", "CVE-2026-59224", "CVE-2026-70485"}  # frozen n=82 gate
LOCAL_DISC = {"CVE-2026-54574", "CVE-2026-61539", "CVE-2026-67435"}  # 本地 3/82 判别集


def load_round(tag_a, tag_b):
    rows = []
    for tag in (tag_a, tag_b):
        with open(os.path.join(SEEDS, tag, "results.csv"), encoding="utf-8") as fh:
            rows += [r for r in csv.DictReader(fh) if r["scorer"] == "APILLMScorer"
                     and r["mode"] == "code"]
    return rows


def abstain_breakdown(tag_a, tag_b):
    out = {}
    for tag in (tag_a, tag_b):
        p = os.path.join(SEEDS, tag, "raw_api_llm_responses.jsonl")
        raws = [json.loads(l) for l in open(p, encoding="utf-8")]
        empty = sum(1 for r in raws if not r["raw_response"].strip())
        out[tag] = {"raw": len(raws), "empty": empty}
    return out


def analyze(rows, label):
    by_cve = defaultdict(dict)
    for r in rows:
        if r["sample_id"] in INCOMPLETE:
            continue
        by_cve[r["sample_id"]][r["version"]] = r["predicted"]
    pairs = {c: v for c, v in by_cve.items() if "vuln" in v and "fixed" in v}
    disc, both_abst, partial = [], [], []
    for c, v in pairs.items():
        vv, vf = v["vuln"], v["fixed"]
        if vv == "vulnerable" and vf == "benign":
            disc.append(c)
        if "abstain" in (vv, vf):
            partial.append(c)
    # 单端指标（answered only）
    ans = [(v["vuln"], "vulnerable") for c, v in pairs.items() if v["vuln"] != "abstain"] + \
          [(v["fixed"], "benign") for c, v in pairs.items() if v["fixed"] != "abstain"]
    tp = sum(1 for p, t in ans if p == "vulnerable" and t == "vulnerable")
    fn = sum(1 for p, t in ans if p != "vulnerable" and t == "vulnerable")
    tn = sum(1 for p, t in ans if p == "benign" and t == "benign")
    fp = sum(1 for p, t in ans if p != "benign" and t == "benign")
    tpr = tp / (tp + fn) if tp + fn else 0
    tnr = tn / (tn + fp) if tn + fp else 0
    ba = (tpr + tnr) / 2
    num = tp * tn - fp * fn
    den = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)) or 1
    mcc = num / den
    n_disc = len(disc)
    p_one = sum(math.comb(len(pairs), k) for k in range(n_disc, len(pairs) + 1)) * 0.5 ** len(pairs) \
        if pairs else 1.0
    print(f"\n=== {label} ===")
    print(f"完整对 n={len(pairs)}  判别正确 {n_disc}（{sorted(x[-5:] for x in disc)}）")
    print(f"含弃权对 {len(partial)}  单端 answered {len(ans)}: TP={tp} FN={fn} TN={tn} FP={fp}")
    print(f"BA={ba:.3f} MCC={mcc:+.3f}（平凡基线 F1=0.667 不适用此任务；参考本地 7B 判别 3/82、BA=0.512）")
    print(f"判别 ≥ 观察值的单侧精确二项 p={p_one:.2e}（H0: 判别率=0.5×？仅作描述）")
    inter = set(x[-5:] for x in disc) & set(x[-5:] for x in LOCAL_DISC)
    print(f"与本地判别集交集: {sorted(inter)}")
    return n_disc, p_one


r1 = load_round("v13_85_ds_r1a", "v13_85_ds_r1b")
print("round1 API 行数:", len(r1), "| raw 覆盖:", abstain_breakdown("v13_85_ds_r1a", "v13_85_ds_r1b"))
n1, p1 = analyze(r1, "Round 1")

try:
    r2 = load_round("v13_85_ds_r2a", "v13_85_ds_r2b")
    print("\nround2 API 行数:", len(r2), "| raw 覆盖:", abstain_breakdown("v13_85_ds_r2a", "v13_85_ds_r2b"))
    n2, p2 = analyze(r2, "Round 2")
except FileNotFoundError:
    print("\nround2 尚未完成")
    n2 = None

print("\n=== A/B/C 判读（预注册阈值：A ≤5 或不显著 / B ≥10 且 p<0.05 / C 6-9）===")
for tag, n in [("r1", n1), ("r2", n2)]:
    if n is None:
        continue
    verdict = "A" if n <= 5 else ("B" if n >= 10 else "C")
    print(f"{tag}: 判别 {n}/82 → 分支 {verdict}")
