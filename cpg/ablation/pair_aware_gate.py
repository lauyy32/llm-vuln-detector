"""第一步 · pair-aware 判别门禁（2026-09-04，终版计划第①步）。

背景：CPGEvidence（v9 门禁）逐版本判定——target CWE 流存在 → vulnerable，否则
abstain/benign。它**不比较同一 CVE 的 vuln/fixed 两侧**：当 fixed 版本的目标 CWE 流
被补丁切断但仍残留非目标流（或恰好 target 流仍在）时，会两端判 vulnerable（双标），
浪费补丁边界的判别信号。D5-B 已证明 5 个 CVE 的流集确实不同（cut），但 CPGEvidence
非 pair-aware 未能利用。

本脚本实现 pair-aware 门禁（PA，确定性，复用 v9 流集，无需 Ollama）：
  对每个 CVE，t = target CWE：
    vuln_t  = (cve,'vuln')  侧存在 cwe==t 的语义流  (file, sourceNode, sinkNode)
    fixed_t = (cve,'fixed') 侧同理
    判定：
      1. vuln_t ∧ ¬fixed_t  → (vulnerable, benign)   # 补丁切断了 target 流 → 判别成功
      2. vuln_t ∧  fixed_t  → (abstain, abstain)      # fixed 仍有 target 流 → 无法确证已修（双标→中性）
      3. ¬vuln_t            → (abstain, abstain)      # vuln 侧无 target 流 → 无法断言（v9 无假良性纪律）
  规则 3 隐含：fixed-only target 流（vuln 侧无）不产生"反向"判别（噪声不判反），
  判别仅来自规则 1 的右侧方向 → inverted 恒为 0，n_disc = #rule1，p = 0.5^n_disc。

输出：逐 CVE 判定 + 配对判别表 + BA/MCC（PA 恒无 FP 恒高 TN? 见注释）+ McNemar p，
交叉对照 D5-B cut 清单与 GT 复核（17/17 真修复）验证规则 1 的方向假设。

用法：
  python cpg/ablation/pair_aware_gate.py \
      --taint-dir cpg/ablation/.work --dataset cpg/dataset.jsonl \
      --out cpg/ablation/.work/pair_aware_gate.json
"""
from __future__ import annotations

import argparse
import json
import math
from collections import defaultdict
from pathlib import Path

from d5_flowcut_baserate import load_dataset, load_taint_flows, CVE_RE, TAINT_CWES

ABSTAIN = "abstain"


def pair_aware_predict(sem: dict, cwe_by_key: dict, ds: dict) -> dict:
    """返回 {cve: {'vuln': pred, 'fixed': pred, 'rule': int, 'flows': (n_v, n_f)}}。"""
    out = {}
    for cid in sorted(ds):
        target = ds[cid]["cwe"]
        vuln_flows = sem.get((cid, "vuln"), set())
        fixed_flows = sem.get((cid, "fixed"), set())
        vuln_t = {f for f in vuln_flows if f[0] == target}
        fixed_t = {f for f in fixed_flows if f[0] == target}
        if vuln_t and not fixed_t:
            preds, rule = {"vuln": "vulnerable", "fixed": "benign"}, 1
        elif vuln_t and fixed_t:
            preds, rule = {"vuln": ABSTAIN, "fixed": ABSTAIN}, 2
        else:
            preds, rule = {"vuln": ABSTAIN, "fixed": ABSTAIN}, 3
        out[cid] = {
            "vuln": preds["vuln"], "fixed": preds["fixed"], "rule": rule,
            "n_vuln_t": len(vuln_t), "n_fixed_t": len(fixed_t),
        }
    return out


def binom_sf(k: int, n: int) -> float:
    if n == 0:
        return 1.0
    return sum(math.comb(n, i) * 0.5 ** n for i in range(k, n + 1))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--taint-dir", required=True)
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    ds = load_dataset(Path(args.dataset))
    sem, strict, cwe_by_key = load_taint_flows(Path(args.taint_dir))

    pa = pair_aware_predict(sem, cwe_by_key, ds)

    correct, inverted, both, neither, abstain2 = [], [], [], [], []
    for cid, p in pa.items():
        if p["rule"] == 1:
            correct.append(cid)
        elif p["rule"] == 2:
            both.append(cid)
        else:
            neither.append(cid)
    n_disc = len(correct) + len(inverted)
    p_val = binom_sf(len(correct), n_disc)
    disc_rate = len(correct) / len(ds) if ds else 0.0

    # 与 D5-B cut 交叉（同 loader 重算）
    cut_cves = []
    for cid in ds:
        v, f = sem.get((cid, "vuln"), set()), sem.get((cid, "fixed"), set())
        if (v or f) and v != f:
            cut_cves.append(cid)

    out = {
        "corpus_n": len(ds),
        "pair_aware": {
            "rule1_discriminated": sorted(correct),
            "rule2_double_to_abstain": sorted(both),
            "rule3_no_evidence_abstain": sorted(neither),
            "n_discordant": n_disc,
            "discrimination_rate": round(disc_rate, 4),
            "p_value_exact_onesided": round(p_val, 6),
            "correct_n": len(correct), "inverted_n": len(inverted),
        },
        "d5b_cut_cves": sorted(cut_cves),
        "cross_check": {
            "pa_rule1_in_d5b_cut": sorted(set(correct) & set(cut_cves)),
            "pa_rule1_not_in_d5b_cut": sorted(set(correct) - set(cut_cves)),
        },
    }
    Path(args.out).write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"corpus: {len(ds)} CVE")
    print(f"  PA 判别成功 (rule1, vuln→vulnerable/fixed→benign): {len(correct)} → {sorted(correct)}")
    print(f"  PA 双标→双abstain (rule2): {len(both)} → {sorted(both)}")
    print(f"  PA 无证据 abstain (rule3): {len(neither)}")
    print(f"  配对: correct={len(correct)} inverted={len(inverted)} n_disc={n_disc} "
          f"判别率={disc_rate:.3f} McNemar 单侧精确 p={p_val:.4f}")
    print(f"  D5-B cut 清单: {len(cut_cves)}")
    print(f"  cross: rule1∩cut={len(set(correct)&set(cut_cves))}  rule1∖cut={sorted(set(correct)-set(cut_cves))}")
    print(f"[ok] wrote {args.out}")


if __name__ == "__main__":
    main()
