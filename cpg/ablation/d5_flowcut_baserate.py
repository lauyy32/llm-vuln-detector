"""D5 · 流程切断基础率（flow-cut baserate）+ CPGEvidence 复用复算（OPEN #25, 2026-09-03）。

目的（用户显式要求「检验引入 CPG 能否突破随机」）：
  1. D5-B（流程切断基础率）：量化 CPG 在补丁边界上的「判别上限」。
     解析全部污点 CSV，按 (CVE, version) 构建污点流集合，逐 CVE 比较 vuln 与
     fixed 的流集合：若两端流集合相同 → CPG 在该 CVE 上零判别信号（结构性失明）；
     若不同 → CPG 至少存在潜在判别信号。flow-cut baserate = 有证据 CVE 中「流集不同」
     的占比 = CPG 判别力的理论上限。
  2. D5-A（isSanitizer 复用复算）：CPGEvidence 是污点流 CWE 的确定性函数（v9 门禁下），
     故可直接由污点 CSV 复算其 2x2 / BA / MCC，无需重跑 Ollama。先把本脚本跑在现有
     v9 CSV 上做自检（须与已报 v9：BA≈0.500 / MCC≈0.000 一致），再把 isSanitizer
     重跑产出的新 CSV 喂入，对比 isSanitizer 是否改变随机结论。

流签名设计（严谨性）：patch 会平移行号，但 source→sink 的污点关系不变。故判别比较用
  semantic = (cwe, file, sourceNode, sinkNode)  （忽略行号，避免把「行号平移」误判为「流被切断」）
同时报告 strict = (cwe, file, sourceLine, sinkLine, sourceNode, sinkNode) 作为上界灵敏度。

CPGEvidence 复算规则（严格对齐 scorers.py v9 门禁）：
  对某 (CVE, version)，target = norm(truth CWE)：
    - 若流集中存在 cwe == target 的流            → vulnerable
    - 若流集非空但 target 不在其中（CWE 越界）    → abstain（v9 门禁）
    - 若流集为空（该 repo 查询跑过、无流）         → benign（NO_FLOW_RE，v9 缺证据→abstain 修复后
                                                    对「跑过无流」仍判 benign，与 scorers.py L561 一致）
  truth：vuln 版本 = vulnerable，fixed 版本 = benign（corpus 设计）。
  2x2 排除 abstain；双标 CVE = 两端均 vulnerable。

用法：
  python cpg/ablation/d5_flowcut_baserate.py \
      --taint-dir cpg/ablation/.work \
      --dataset   cpg/dataset.jsonl \
      --out       cpg/ablation/.work/d5_flowcut_baserate.json
"""
from __future__ import annotations
import csv, json, math, re, sys
from pathlib import Path
from collections import defaultdict

HERE = Path(__file__).resolve().parent
WORK = HERE / ".work"
DATASET = HERE.parent.parent / "dataset.jsonl"

CVE_RE = re.compile(r"(CVE-[\d-]+)_(vuln|fixed)")
ABSTAIN = "abstain"

# 污点组覆盖的 CWE（与 config.CWE_TAINT_QUERIES / d5_doublelabel_analysis.TAINT_CWES 对齐）
TAINT_CWES = {"CWE-022", "CWE-078", "CWE-079", "CWE-089", "CWE-094", "CWE-918"}


def norm(cwe):
    if not cwe:
        return None
    s = str(cwe).strip().upper().lstrip("CWE-").strip("-")
    if s.isdigit():
        return "CWE-" + s.zfill(3)
    return "CWE-" + s.upper()


def load_dataset(path: Path) -> dict:
    out = {}
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            cid = d.get("cve_id")
            cwes = d.get("cwes") or []
            out[cid] = {
                "cwe": norm(cwes[0]) if cwes else None,
                "label": d.get("label"),
                "repo": d.get("repo_slug"),
            }
    return out


def load_taint_flows(taint_dir: Path) -> dict:
    """返回 {(cve_id, version): set_of_semantic_flows, ...} 与 strict 版本。"""
    sem: dict = defaultdict(set)
    strict: dict = defaultdict(set)
    cwe_by_key: dict = defaultdict(set)
    for csv_path in sorted(taint_dir.glob("*.csv")):
        if csv_path.stat().st_size == 0:
            continue
        with csv_path.open(newline="", encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                ap = r.get("abs_path") or ""
                m = CVE_RE.search(ap)
                if not m:
                    continue
                cid, ver = m.group(1), m.group(2)
                cwe = norm(r.get("cwe"))
                if cwe is None:
                    continue
                file = r.get("file") or ""
                sl = r.get("sourceLine") or ""
                kl = r.get("sinkLine") or ""
                sn = r.get("sourceNode") or ""
                kn = r.get("sinkNode") or ""
                key = (cid, ver)
                sem[key].add((cwe, file, sn, kn))
                strict[key].add((cwe, file, sl, kl, sn, kn))
                cwe_by_key[key].add(cwe)
    return sem, strict, cwe_by_key


def confusion(rows):
    tp = fp = tn = fn = ab = 0
    for truth, pred in rows:
        if pred == ABSTAIN:
            ab += 1
            continue
        if pred == "vulnerable" and truth == "vulnerable":
            tp += 1
        elif pred == "vulnerable" and truth == "benign":
            fp += 1
        elif pred == "benign" and truth == "benign":
            tn += 1
        elif pred == "benign" and truth == "vulnerable":
            fn += 1
    return dict(tp=tp, fp=fp, tn=tn, fn=fn, abstain=ab)


def ba_mcc(c):
    tp, fp, tn, fn = c["tp"], c["fp"], c["tn"], c["fn"]
    tpr = tp / (tp + fn) if (tp + fn) else 0.0
    tnr = tn / (tn + fp) if (tn + fp) else 0.0
    ba = (tpr + tnr) / 2
    denom = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = (tp * tn - fp * fn) / denom if denom else 0.0
    return dict(tpr=round(tpr, 4), tnr=round(tnr, 4), ba=round(ba, 4), mcc=round(mcc, 4))


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--taint-dir", default=str(WORK))
    ap.add_argument("--dataset", default=str(DATASET))
    ap.add_argument("--out", default=str(WORK / "d5_flowcut_baserate.json"))
    args = ap.parse_args()

    ds = load_dataset(Path(args.dataset))
    sem, strict, cwe_by_key = load_taint_flows(Path(args.taint_dir))

    # ---- 全集 CVE（数据集 74） ----
    cves = sorted(ds.keys())

    # ---- D5-B：流程切断基础率 ----
    cut, identical, no_ev, asym = [], [], [], []
    cut_cwe = defaultdict(lambda: [0, 0])  # cwe -> [has_evidence, cut]
    for cid in cves:
        target = ds[cid]["cwe"]
        vuln = sem.get((cid, "vuln"), set())
        fixed = sem.get((cid, "fixed"), set())
        has_ev = bool(vuln) or bool(fixed)
        if not has_ev:
            no_ev.append(cid)
        elif vuln == fixed:
            identical.append(cid)
        else:
            cut.append(cid)
            if vuln and not fixed:
                asym.append((cid, "vuln-only→fixed-cut"))
            elif fixed and not vuln:
                asym.append((cid, "fixed-only→vuln-cut"))
        if has_ev:
            cut_cwe[target][0] += 1
            if vuln != fixed:
                cut_cwe[target][1] += 1

    n = len(cves)
    has_ev_n = len(cut) + len(identical)
    flowcut_baserate = (len(cut) / has_ev_n) if has_ev_n else 0.0
    cpg_coverage = has_ev_n / n if n else 0.0

    # ---- D5-A：CPGEvidence 复用复算（v9 门禁） ----
    rows = []          # (truth, pred)
    double = []
    per_cve_pred = {}
    for cid in cves:
        target = ds[cid]["cwe"]
        preds = {}
        for ver, truth in (("vuln", "vulnerable"), ("fixed", "benign")):
            flows_cwes = cwe_by_key.get((cid, ver), set())
            if target is not None and target in flows_cwes:
                pred = "vulnerable"
            elif flows_cwes:
                pred = ABSTAIN          # CWE 越界（v9 门禁）
            else:
                pred = "benign"         # 跑过无流（NO_FLOW_RE）
            rows.append((truth, pred))
            preds[ver] = pred
        per_cve_pred[cid] = preds
        if preds.get("vuln") == "vulnerable" and preds.get("fixed") == "vulnerable":
            double.append(cid)

    c = confusion(rows)
    m = ba_mcc(c)

    out = {
        "taint_dir": args.taint_dir,
        "corpus_n": n,
        "d5b_flowcut": {
            "cpg_coverage": round(cpg_coverage, 4),
            "has_evidence_n": has_ev_n,
            "no_evidence_n": len(no_ev),
            "flowcut_baserate": round(flowcut_baserate, 4),
            "cut_n": len(cut),
            "identical_n": len(identical),
            "by_target_cwe": {k: {"has_evidence": v[0], "cut": v[1],
                                  "baserate": round(v[1] / v[0], 4) if v[0] else 0.0}
                              for k, v in sorted(cut_cwe.items())},
            "identical_cves": sorted(identical),
            "no_evidence_cves": sorted(no_ev),
            "cut_cves": sorted(cut),
            "asymmetric": asym,
        },
        "d5a_cpgevidence": {
            "confusion": c,
            "metrics": m,
            "double_label_n": len(double),
            "double_label_cves": sorted(double),
        },
    }

    Path(args.out).write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(out, ensure_ascii=False, indent=2))

    print("\n=== D5-B 流程切断基础率（CPG 判别上限）===")
    print(f"  语料 CVE 数: {n}")
    print(f"  CPG 有证据 CVE: {has_ev_n} ({cpg_coverage:.1%})  |  CPG 结构性失明(两端无流): {len(no_ev)}")
    print(f"  flow-cut baserate = {flowcut_baserate:.1%}  "
          f"（有证据 CVE 中 vuln≠fixed 流集 = CPG 潜在可判别占比）")
    print(f"  两端流集相同(非判别): {len(identical)}  |  流集不同(可判别): {len(cut)}")
    print("  按目标 CWE 的 flow-cut baserate:")
    for k, v in sorted(cut_cwe.items()):
        br = (v[1] / v[0]) if v[0] else 0.0
        print(f"    {k}: 有证据 {v[0]}, 可判别 {v[1]} → {br:.1%}")
    print("\n=== D5-A CPGEvidence 复用复算（v9 门禁，须与已报 BA≈0.500/MCC≈0.000 对齐）===")
    print(f"  混淆: {c}")
    print(f"  指标: {m}")
    print(f"  双标 CVE 数: {len(double)}  → {sorted(double)}")
    print(f"\n[ok] wrote {args.out}")


if __name__ == "__main__":
    main()
