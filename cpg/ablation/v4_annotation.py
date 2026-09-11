# -*- coding: utf-8 -*-
"""V4 标注基础设施：提交校验 / 一致性统计 / 分歧检测 / 仲裁 / frozen 编译。

**不含任何研究判断**，只做机械校验、汇总与状态机推进。

关键纪律（均来自外部验收）：
  - 依赖引用只用**完整 hunk_id**，禁止前缀（P0-4）；
  - 分歧检测覆盖 **role / dependency_group / counterfactual / evidence**（P0-3），
    任一字段不一致即进入仲裁；
  - 仲裁件必须绑定 template SHA **与两份 submission SHA**（P0-2）；
  - 排除是 **sample/CVE 级**（整例删除），并冻结 active/excluded 样本集合（P0-1）；
  - 所有入口强制先 `validate_submission`（P1）。
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path

ROLE_DIRECT = "DIRECT_SECURITY"
ROLE_SUPPORTING = "SUPPORTING_REQUIRED"
ROLE_NONCRIT = "NON_CRITICAL"
ROLE_UNCERTAIN = "UNCERTAIN"
VALID_ROLES = {ROLE_DIRECT, ROLE_SUPPORTING, ROLE_NONCRIT, ROLE_UNCERTAIN}
SAFE_ROLES = {ROLE_DIRECT, ROLE_SUPPORTING}
VALID_EVIDENCE = {"PoC", "regression-test", "code-reasoning", "insufficient"}
VALID_COUNTERFACTUAL = {"是", "否", "不确定"}
FINAL_FIELDS = ("final_role", "final_dependency_group", "final_counterfactual",
                "final_evidence", "final_reason", "adjudicator")


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _hid(ident: dict) -> str:
    """hunk_id：必须存在于 identity（由 v4_selector.hunk_id 生成）。"""
    h = ident.get("hunk_id")
    if not h:
        raise ValueError("hunk_identity 缺 hunk_id")
    return h


def _load_rows(p: Path) -> list:
    """优先整体 JSON 对象（doc.entries/items），失败再按 JSONL 逐行。"""
    txt = p.read_text(encoding="utf-8")
    try:
        doc = json.loads(txt)
        if isinstance(doc, list):
            return doc
        if isinstance(doc, dict):
            for k in ("entries", "items"):
                if isinstance(doc.get(k), list):
                    return doc[k]
            return [doc]
    except json.JSONDecodeError:
        pass
    return [json.loads(l) for l in txt.splitlines() if l.strip()]


def _template_index(template_path: Path) -> dict:
    """template 索引：**重复 hunk_id 必须失败**（P1）。"""
    tpl = json.loads(template_path.read_text(encoding="utf-8"))
    idx, dup = {}, []
    for e in tpl["entries"]:
        k = _hid(e["hunk_identity"])
        if k in idx:
            dup.append(k)
        idx[k] = e
    if dup:
        raise ValueError(f"template 存在重复 hunk_id {len(dup)} 条")
    return idx


def validate_submission(path: Path, template_path: Path) -> dict:
    """校验一份提交（fail-closed）：集合精确一致、字段合法、依赖精确唯一、P1 各项。"""
    errs = []
    tpl = _template_index(template_path)
    rows = _load_rows(path)
    got, dup, by_key = set(), [], {}
    for r in rows:
        ident = r.get("hunk_identity") or {}
        try:
            k = _hid(ident)
        except ValueError as e:
            errs.append(f"{r.get('sample_id')}: {e}")
            continue
        if k in got:
            dup.append(k)
        got.add(k)
        by_key[k] = r
        # P1：三处 sample_id 必须一致
        if not (r.get("sample_id") == ident.get("sample_id")
                == (tpl.get(k, {}).get("sample_id"))):
            errs.append(f"{r.get('sample_id')}: sample_id 三处不一致")
        if r.get("criticality") not in VALID_ROLES:
            errs.append(f"{r.get('sample_id')}: 非法 criticality={r.get('criticality')}")
        ev = r.get("evidence")
        if ev is not None and ev not in VALID_EVIDENCE:
            errs.append(f"{r.get('sample_id')}: 非法 evidence={ev}")
        cf = r.get("counterfactual")
        if cf is not None and cf not in VALID_COUNTERFACTUAL:
            errs.append(f"{r.get('sample_id')}: 非法 counterfactual={cf}")
        if not r.get("reason"):
            errs.append(f"{r.get('sample_id')}: reason 为空")
        # P1：UNCERTAIN 必须 insufficient + 有理由
        if r.get("criticality") == ROLE_UNCERTAIN and ev != "insufficient":
            errs.append(f"{r.get('sample_id')}: UNCERTAIN 必须 evidence=insufficient")
    if dup:
        errs.append(f"重复 hunk_id {len(dup)} 条")
    if got != set(tpl):
        errs.append(f"hunk_id 集合不符: 缺 {len(set(tpl) - got)}，多 {len(got - set(tpl))}")
    # 依赖：完整 hunk_id、存在、同 CVE、不得自引用（P0-4）
    for k, r in by_key.items():
        deps = r.get("dependency_group") or []
        if not isinstance(deps, list):
            errs.append(f"{r.get('sample_id')}: dependency_group 非列表")
            continue
        for d in deps:
            if not isinstance(d, str) or len(d) != 64 or any(c not in "0123456789abcdef" for c in d):
                errs.append(f"{r.get('sample_id')}: 依赖项非完整 hunk_id（禁前缀）: {str(d)[:16]}")
                continue
            if d == k:
                errs.append(f"{r.get('sample_id')}: 依赖自引用")
                continue
            if d not in tpl:
                errs.append(f"{r.get('sample_id')}: 依赖不存在 {d[:12]}")
                continue
            if tpl[d]["sample_id"] != r["sample_id"]:
                errs.append(f"{r.get('sample_id')}: 依赖跨 CVE（{tpl[d]['sample_id']}）")
    return {"path": str(path), "n_rows": len(rows), "bytes": path.stat().st_size,
            "sha256": _sha(path.read_bytes()), "errors": errs, "ok": not errs}


def _index_checked(path: Path, template_path: Path, who: str) -> dict:
    v = validate_submission(path, template_path)
    if not v["ok"]:
        raise ValueError(f"提交校验失败 {path.name}: {v['errors'][:5]}")
    idx = {}
    for r in _load_rows(path):
        if r.get("reviewer") != who:
            raise ValueError(f"{path.name}: reviewer={r.get('reviewer')} != {who}")
        idx[_hid(r["hunk_identity"])] = r
    return idx


def _cohen_kappa(a: list, b: list, labels: list) -> float:
    n = len(a)
    if n == 0:
        return 0.0
    po = sum(1 for x, y in zip(a, b) if x == y) / n
    ca, cb = Counter(a), Counter(b)
    pe = sum((ca.get(l, 0) / n) * (cb.get(l, 0) / n) for l in labels)
    return 0.0 if pe == 1 else (po - pe) / (1 - pe)


def _raw_agreement(r1: dict, r2: dict, keys: list, field: str, default=None) -> float:
    if not keys:
        return 0.0
    same = 0
    for k in keys:
        a = r1[k].get(field)
        b = r2[k].get(field)
        if field == "dependency_group":
            a, b = sorted(a or []), sorted(b or [])
        if a == b:
            same += 1
    return round(same / len(keys), 4)


def agreement_report(sub1: Path, sub2: Path, template_path: Path) -> dict:
    """角色 κ + **各科学字段一致率**（P1：不能用一个 role κ 概括全部标注质量）。"""
    r1 = _index_checked(sub1, template_path, "reviewer1")
    r2 = _index_checked(sub2, template_path, "reviewer2")
    keys = sorted(set(r1) & set(r2))
    a = [r1[k]["criticality"] for k in keys]
    b = [r2[k]["criticality"] for k in keys]
    return {
        "n_common": len(keys), "n_template": len(_template_index(template_path)),
        "raw_agreement_role": _raw_agreement(r1, r2, keys, "criticality"),
        "cohen_kappa_role": round(_cohen_kappa(a, b, sorted(VALID_ROLES)), 4),
        "raw_agreement_dependency": _raw_agreement(r1, r2, keys, "dependency_group"),
        "raw_agreement_counterfactual": _raw_agreement(r1, r2, keys, "counterfactual"),
        "raw_agreement_evidence": _raw_agreement(r1, r2, keys, "evidence"),
        "uncertain_ratio_r1": round(sum(1 for x in a if x == ROLE_UNCERTAIN) / len(a), 4) if a else None,
        "uncertain_ratio_r2": round(sum(1 for x in b if x == ROLE_UNCERTAIN) / len(b), 4) if b else None,
        "submission_sha256": {"reviewer1": _sha(sub1.read_bytes()),
                              "reviewer2": _sha(sub2.read_bytes())},
    }


_FIELD_LABELS = {"criticality": "role"}


def disagreement_list(sub1: Path, sub2: Path, template_path: Path, out: Path) -> dict:
    """分歧清单（JSON 对象）：**role / dependency / counterfactual / evidence 任一不一致**
    都要进入仲裁（P0-3）。每项分别给出四类分歧标志。
    """
    r1 = _index_checked(sub1, template_path, "reviewer1")
    r2 = _index_checked(sub2, template_path, "reviewer2")
    items = []
    for k in sorted(set(r1) & set(r2)):
        x, y = r1[k], r2[k]
        flags = {
            "role": x["criticality"] != y["criticality"],
            "dependency": sorted(x.get("dependency_group") or []) != sorted(y.get("dependency_group") or []),
            "counterfactual": x.get("counterfactual") != y.get("counterfactual"),
            "evidence": x.get("evidence") != y.get("evidence"),
        }
        if not any(flags.values()):
            continue
        unc = ROLE_UNCERTAIN in (x["criticality"], y["criticality"])
        if unc and x["criticality"] == y["criticality"]:
            kind = "UNANIMOUS_UNCERTAIN"
        elif unc:
            kind = "PARTIAL_UNCERTAIN"
        else:
            kind = "DISAGREEMENT"
        items.append({
            "kind": kind, "sample_id": x["sample_id"], "hunk_id": k,
            "hunk_identity": x["hunk_identity"], "fields_in_dispute": flags,
            "reviewer1": {f: x.get(f) for f in
                          ("criticality", "dependency_group", "counterfactual",
                           "evidence", "reason")},
            "reviewer2": {f: y.get(f) for f in
                          ("criticality", "dependency_group", "counterfactual",
                           "evidence", "reason")},
            **{f: None for f in FINAL_FIELDS},
        })
    doc = {"schema": "v4-adjudication/2",
           "template_sha256": _sha(template_path.read_bytes()),
           "submission_sha256": {"reviewer1": _sha(sub1.read_bytes()),
                                 "reviewer2": _sha(sub2.read_bytes())},
           "n_items": len(items),
           "note": ("第三人须对每个 item 给出 final_role / final_dependency_group / "
                    "final_counterfactual / final_evidence / final_reason / adjudicator；"
                    "编译器只消费这些 final_* 字段，不得取任一 reviewer 版本"),
           "items": items}
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes((json.dumps(doc, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
    return doc


def adjudicate(disagreements: Path, out: Path, template_path: Path,
               sub1: Path, sub2: Path) -> dict:
    """校验并在同一 JSON 对象上仲裁（P0-2：template + 两份 submission SHA 全核对）。"""
    doc = json.loads(disagreements.read_text(encoding="utf-8"))
    if doc.get("template_sha256") != _sha(template_path.read_bytes()):
        raise ValueError("分歧清单 template_sha256 与当前 template 不符")
    if doc.get("submission_sha256") != {"reviewer1": _sha(sub1.read_bytes()),
                                        "reviewer2": _sha(sub2.read_bytes())}:
        raise ValueError("分歧清单 submission SHA 与当前提交不符")
    # item 集合必须与当前检测一致（防缺/多/重复）
    fresh = disagreement_list(sub1, sub2, template_path, out)
    if [i["hunk_id"] for i in fresh["items"]] != [i["hunk_id"] for i in doc.get("items", [])]:
        raise ValueError("仲裁件 item 集合与当前分歧检测不一致")
    out.write_bytes((json.dumps(doc, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
    return doc


def compile_frozen(template_path: Path, sub1: Path, sub2: Path, adjudicated: Path,
                   out: Path, exclusions: dict | None = None) -> dict:
    """编译 frozen registry（**sample 级排除** + 完整 SHA/schema 校验）。

    P0-1：排除是**整例（CVE）删除**——某 hunk 未处置即排除该 CVE 的全部 hunk；
    冻结 `active_sample_ids` / `excluded_sample_ids` / `universe_sha256`。
    P0-2：核对 template SHA、两份 submission SHA、仲裁 item 集合与字段完整性。
    """
    tpl = _template_index(template_path)
    r1 = _index_checked(sub1, template_path, "reviewer1")
    r2 = _index_checked(sub2, template_path, "reviewer2")
    if exclusions is None:
        exclusions = {}
    adj_doc = json.loads(adjudicated.read_text(encoding="utf-8"))
    if adj_doc.get("template_sha256") != _sha(template_path.read_bytes()):
        raise ValueError("仲裁件 template_sha256 不符")
    if adj_doc.get("submission_sha256") != {"reviewer1": _sha(sub1.read_bytes()),
                                            "reviewer2": _sha(sub2.read_bytes())}:
        raise ValueError("仲裁件 submission SHA 与当前提交不符")
    adj = {}
    for it in adj_doc.get("items", []):
        k = it.get("hunk_id")
        if k in adj:
            raise ValueError(f"仲裁件存在重复 item: {str(k)[:12]}")
        if it.get("kind") not in ("DISAGREEMENT", "UNANIMOUS_UNCERTAIN", "PARTIAL_UNCERTAIN"):
            raise ValueError(f"仲裁件含未知 kind: {it.get('kind')}")
        adj[k] = it

    # ---- 逐 hunk 判定（先不落地，先发现待排除 CVE）----
    entries, pending_cve = [], set()
    for k, t in tpl.items():
        x, y = r1[k], r2[k]
        same_all = (x["criticality"] == y["criticality"]
                    and sorted(x.get("dependency_group") or []) == sorted(y.get("dependency_group") or [])
                    and x.get("counterfactual") == y.get("counterfactual")
                    and x.get("evidence") == y.get("evidence"))
        if same_all and x["criticality"] != ROLE_UNCERTAIN:
            role, src, dep = x["criticality"], "unanimous", x.get("dependency_group") or []
            cf, ev, rs = x.get("counterfactual"), x.get("evidence"), x.get("reason")
        else:
            a = adj.get(k)
            if not a or a.get("final_role") not in VALID_ROLES or not a.get("adjudicator"):
                pending_cve.add(t["sample_id"])
                continue
            # evidence/uncertain 语义
            if a["final_role"] == ROLE_UNCERTAIN:
                pending_cve.add(t["sample_id"])
                continue
            if a.get("final_evidence") is not None and a["final_evidence"] not in VALID_EVIDENCE:
                raise ValueError(f"仲裁 final_evidence 非法: {a.get('final_evidence')}")
            role, src = a["final_role"], "adjudicated"
            dep = a.get("final_dependency_group") or []
            cf, ev, rs = (a.get("final_counterfactual"), a.get("final_evidence"),
                          a.get("final_reason"))
            # 依赖必须是完整 hunk_id 且存在
            for d in dep:
                if d not in tpl:
                    raise ValueError(f"仲裁 final_dependency_group 含未知 id {str(d)[:12]}")
        entries.append({
            "sample_id": t["sample_id"], "hunk_id": k, "hunk_identity": t["hunk_identity"],
            "role": role, "source": src,
            "criticality": ("SECURITY_CRITICAL" if role in SAFE_ROLES
                            else "NON_CRITICAL" if role == ROLE_NONCRIT else role),
            "dependency_group": dep, "counterfactual": cf,
            "evidence": ev, "reason": rs,
        })
    # 未处置 UNCERTAIN：须整例排除
    unhandled = sorted(pending_cve - set(exclusions))
    if unhandled:
        raise ValueError(f"存在未处置 UNCERTAIN（须复审或整例列入 exclusions）: {unhandled}")
    excluded = set(exclusions)
    if excluded:
        entries = [e for e in entries if e["sample_id"] not in excluded]
    all_samples = sorted({t["sample_id"] for t in tpl.values()})
    active = sorted(set(all_samples) - excluded)
    universe = {"active_sample_ids": active, "excluded_sample_ids": sorted(excluded),
                "exclusions": {k: exclusions[k] for k in sorted(excluded)}}
    doc = {"schema": "v4-critical-hunks-frozen/3",
           "status": "FROZEN_LABELED" if not excluded else "FROZEN_WITH_EXCLUSIONS",
           "template_sha256": _sha(template_path.read_bytes()),
           "submission_sha256": {"reviewer1": _sha(sub1.read_bytes()),
                                 "reviewer2": _sha(sub2.read_bytes())},
           "adjudication_sha256": _sha(adjudicated.read_bytes()),
           "universe_sha256": _sha(json.dumps(universe, sort_keys=True).encode("utf-8")),
           "stale_universe_guard": {"active_sample_ids": active, "excluded_sample_ids": sorted(excluded)},
           "n_entries": len(entries), "n_excluded_samples": len(excluded),
           "role_counts": {r: sum(1 for e in entries if e["role"] == r)
                           for r in sorted(VALID_ROLES)},
           "entries": entries}
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes((json.dumps(doc, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
    return doc
