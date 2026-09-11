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
        # P1-1：hunk_id 必须是 64 位 hex 且可由其余字段重算
        from cpg.ablation.v4_selector import is_hex64 as _hx, recompute_hunk_id as _rh, \
            identity_matches as _im, IDENTITY_FIELDS as _IF
        if not _hx(k):
            errs.append(f"{r.get('sample_id')}: hunk_id 非 64 位 hex")
        elif _rh(ident) != k:
            errs.append(f"{r.get('sample_id')}: hunk_id 无法由 identity 重算（被篡改）")
        elif k in tpl and not _im(ident, tpl[k]["hunk_identity"]):
            errs.append(f"{r.get('sample_id')}: identity 与 template 逐字段不符")
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
        # P1-2：科学字段必填，不得留 null
        if r.get("dependency_group") is None:
            errs.append(f"{r.get('sample_id')}: dependency_group 不得为空（空依赖请填 []）")
        if cf is None:
            errs.append(f"{r.get('sample_id')}: counterfactual 必填")
        if ev is None:
            errs.append(f"{r.get('sample_id')}: evidence 必填")
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


def _reviewer_projection(row: dict) -> dict:
    """reviewer 侧的**规范化投影**（缺口2：用于比对仲裁件内嵌内容是否被篡改）。"""
    return {"criticality": row.get("criticality"),
            "dependency_group": sorted(row.get("dependency_group") or []),
            "counterfactual": row.get("counterfactual"),
            "evidence": row.get("evidence"),
            "reason": row.get("reason")}


def expected_disagreements(sub1: Path, sub2: Path, template_path: Path) -> dict:
    """**纯函数**：重算当前预期的分歧映射（不写盘）。

    返回 {hunk_id: item}；item 含 kind / sample_id / hunk_identity / fields_in_dispute
    以及两侧 reviewer 的规范化投影，供编译器逐字段比对。
    """
    r1 = _index_checked(sub1, template_path, "reviewer1")
    r2 = _index_checked(sub2, template_path, "reviewer2")
    out = {}
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
        out[k] = {"kind": kind, "sample_id": x["sample_id"], "hunk_id": k,
                  "hunk_identity": x["hunk_identity"], "fields_in_dispute": flags,
                  "reviewer1": _reviewer_projection(x),
                  "reviewer2": _reviewer_projection(y)}
    return out


def _write_disagreements(sub1: Path, sub2: Path, template_path: Path, out: Path) -> dict:
    """落盘分歧清单（JSON 对象），供第三人仲裁。"""
    items = list(expected_disagreements(sub1, sub2, template_path).values())
    for it in items:
        it.update({f: None for f in FINAL_FIELDS})
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


def disagreement_list(sub1: Path, sub2: Path, template_path: Path, out: Path) -> dict:
    """分歧清单（JSON 对象）：role / dependency / counterfactual / evidence 任一不一致
    都要进入仲裁（P0-3）。每项分别给出四类分歧标志。
    """
    return _write_disagreements(sub1, sub2, template_path, out)


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
    # 施工单3 + 缺口2：编译器**自行重算**（纯函数，不写盘）并逐字段比对，
    # 含两侧 reviewer 的规范化投影（防仲裁件内嵌内容被替换而顶部 SHA 不变）。
    if adj_doc.get("n_items") != len(adj_doc.get("items", [])):
        raise ValueError("仲裁件 n_items 与 items 长度不符")
    expected = expected_disagreements(sub1, sub2, template_path)
    if set(adj) != set(expected):
        raise ValueError(f"仲裁件与当前预期分歧集合不符: 缺 {sorted(set(expected) - set(adj))[:2]}，"
                         f"多 {sorted(set(adj) - set(expected))[:2]}")
    for k, e in expected.items():
        a = adj[k]
        for f in ("kind", "sample_id", "hunk_identity", "fields_in_dispute"):
            if a.get(f) != e[f]:
                raise ValueError(f"仲裁件 {f} 被篡改: {str(k)[:12]}")
        for rv in ("reviewer1", "reviewer2"):
            got = a.get(rv) or {}
            if _reviewer_projection(got) != e[rv]:
                raise ValueError(f"仲裁件内嵌 {rv} 内容与提交不符（被篡改）: {str(k)[:12]}")

    # ---- 逐 hunk 判定 ----
    # P0：直接维护 pending_uncertain_ids（**不再用 `k not in adj` 推导**——一致 UNCERTAIN
    #     若因其他字段分歧而进入 adjudication，其 final_role 为 null，推导会漏掉）
    entries = []
    missing_adjudication = set()
    pending_uncertain_ids: dict = {}      # {sample_id: {hunk_id, ...}}

    def _mark_uncertain(sid: str, hid: str) -> None:
        pending_uncertain_ids.setdefault(sid, set()).add(hid)

    for k, t in tpl.items():
        x, y = r1[k], r2[k]
        sid = t["sample_id"]
        same_all = (x["criticality"] == y["criticality"]
                    and sorted(x.get("dependency_group") or []) == sorted(y.get("dependency_group") or [])
                    and x.get("counterfactual") == y.get("counterfactual")
                    and x.get("evidence") == y.get("evidence"))
        if same_all and x["criticality"] != ROLE_UNCERTAIN:
            role, src, dep = x["criticality"], "unanimous", x.get("dependency_group") or []
            cf, ev, rs = x.get("counterfactual"), x.get("evidence"), x.get("reason")
        else:
            a = adj.get(k)
            # 缺口1修复：先区分"未仲裁"与"已仲裁"。**凡有 adjudicator，必须先统一校验
            # 全部 final_* 字段**，之后才按 final_role 决定确定标签或 pending UNCERTAIN。
            if a is None or not a.get("adjudicator"):
                # 未仲裁：一致 UNCERTAIN → pending；否则记 missing_adjudication
                if x["criticality"] == ROLE_UNCERTAIN and y["criticality"] == ROLE_UNCERTAIN:
                    _mark_uncertain(sid, k)
                else:
                    missing_adjudication.add(sid)
                continue
            need = ("final_role", "final_dependency_group", "final_counterfactual",
                    "final_evidence", "final_reason")
            miss = [f for f in need if a.get(f) is None]
            if miss:
                raise ValueError(f"仲裁项缺 final 字段 {miss}: {str(k)[:12]}")
            if a["final_role"] not in VALID_ROLES:
                raise ValueError(f"仲裁 final_role 非法: {a.get('final_role')}")
            if a["final_evidence"] not in VALID_EVIDENCE:
                raise ValueError(f"仲裁 final_evidence 非法: {a.get('final_evidence')}")
            if a["final_counterfactual"] not in VALID_COUNTERFACTUAL:
                raise ValueError(f"仲裁 final_counterfactual 非法: {a.get('final_counterfactual')}")
            if not isinstance(a["final_dependency_group"], list):
                raise ValueError("仲裁 final_dependency_group 必须为列表")
            # 校验通过后再按 final_role 分支
            if a["final_role"] == ROLE_UNCERTAIN:
                _mark_uncertain(sid, k)
                continue
            role, src = a["final_role"], "adjudicated"
            dep = a["final_dependency_group"]
            cf, ev, rs = (a["final_counterfactual"], a["final_evidence"],
                          a["final_reason"])
            from cpg.ablation.v4_selector import is_hex64 as _hx3
            for d in dep:
                if not _hx3(d):
                    raise ValueError(f"仲裁依赖非完整 hunk_id: {str(d)[:16]}")
                if d == k:
                    raise ValueError("仲裁依赖自引用")
                if d not in tpl:
                    raise ValueError(f"仲裁依赖不存在 {d[:12]}")
                if tpl[d]["sample_id"] != sid:
                    raise ValueError(f"仲裁依赖跨 CVE: {tpl[d]['sample_id']}")
        entries.append({
            "sample_id": sid, "hunk_id": k, "hunk_identity": t["hunk_identity"],
            "role": role, "source": src,
            "criticality": ("SECURITY_CRITICAL" if role in SAFE_ROLES
                            else "NON_CRITICAL" if role == ROLE_NONCRIT else role),
            "dependency_group": dep, "counterfactual": cf,
            "evidence": ev, "reason": rs,
        })
    # P0-3：普通分歧**不得**靠 exclusions 绕过
    if missing_adjudication:
        raise ValueError(f"存在未仲裁的普通分歧（不得以 exclusions 绕过）: "
                         f"{sorted(missing_adjudication)}")
    pending_uncertain = {k for s in pending_uncertain_ids.values() for k in s}
    # UNCERTAIN：须复审，或**结构化整例排除**（source_item_ids 必须==该样本的 pending 全集）
    structured = {}
    if exclusions and not set(exclusions) <= pending_uncertain_ids.keys():
        raise ValueError(f"exclusions 含非 UNCERTAIN 样本（不得主动删除确定样本）: "
                         f"{sorted(set(exclusions) - set(pending_uncertain_ids))}")
    for sid, rec in (exclusions or {}).items():
        if isinstance(rec, str):
            raise ValueError(f"exclusions[{sid}] 必须是结构化记录")
        miss = [f for f in ("reason", "adjudicator", "evidence", "source_item_ids")
                if not rec.get(f)]
        if miss:
            raise ValueError(f"exclusions[{sid}] 缺字段 {miss}")
        if rec.get("evidence") != "insufficient":
            raise ValueError(f"exclusions[{sid}] evidence 必须为 insufficient")
        from cpg.ablation.v4_selector import is_hex64 as _hx2
        want_here = set(pending_uncertain_ids.get(sid) or set())
        got = set(rec["source_item_ids"])
        for it in got:
            if not _hx2(it):
                raise ValueError(f"exclusions[{sid}] source_item_ids 含非完整 hunk_id")
        # 必须**完整覆盖**该样本的全部 pending hunk（不得只引用子集）
        if got != want_here:
            raise ValueError(f"exclusions[{sid}] source_item_ids 必须等于该样本全部 pending "
                             f"UNCERTAIN（缺 {sorted(want_here - got)[:2]}，多 {sorted(got - want_here)[:2]}）")
        structured[sid] = rec
    unhandled = sorted(set(pending_uncertain_ids) - set(structured))
    if unhandled:
        raise ValueError(f"存在未复审 UNCERTAIN（须复审或结构化整例排除）: {unhandled}")
    excluded = set(structured)
    if excluded:
        entries = [e for e in entries if e["sample_id"] not in excluded]
    all_samples = sorted({t["sample_id"] for t in tpl.values()})
    active = sorted(set(all_samples) - excluded)
    universe = {"all_sample_ids": all_samples,
                "active_sample_ids": active,
                "excluded_sample_ids": sorted(excluded),
                "exclusions": {k: structured[k] for k in sorted(excluded)}}
    doc = {"schema": "v4-critical-hunks-frozen/4",
           "status": "FROZEN_LABELED" if not excluded else "FROZEN_WITH_EXCLUSIONS",
           "template_sha256": _sha(template_path.read_bytes()),
           "submission_sha256": {"reviewer1": _sha(sub1.read_bytes()),
                                 "reviewer2": _sha(sub2.read_bytes())},
           "adjudication_sha256": _sha(adjudicated.read_bytes()),
           "universe_sha256": _sha(json.dumps(universe, sort_keys=True).encode("utf-8")),
           "stale_universe_guard": universe,
           "n_entries": len(entries), "n_excluded_samples": len(excluded),
           "role_counts": {r: sum(1 for e in entries if e["role"] == r)
                           for r in sorted(VALID_ROLES)},
           "entries": entries}
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes((json.dumps(doc, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
    return doc
