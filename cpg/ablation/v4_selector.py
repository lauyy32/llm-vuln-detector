# -*- coding: utf-8 -*-
"""V4 source selector：由冻结的 real patch 决定"给模型看哪些源码行"。

独立成模块的目的（codex P0-1）：selection 的**生成实现**必须可被单独指纹化
（此前 coverage 记的是 prompt_renderer.py 的 SHA，指纹对象错了——selection 实际
由本模块生成）。冻结本文件 SHA 后，selection 才可跨运行/跨机器复算一致。

表示策略（**草案，待 freeze**）：
  - 对 real patch 触及的每个文件，取每个 hunk 的 vulnerable 行范围 ±window 行；
  - 按文件名字典序累积，超出 max_chars 的文件整体丢弃（并在 note 中计数）。

⚠️ 本策略是"预注册表示"，不是研究结论；其正确性由 critical-hunk coverage 门禁检验。
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

WINDOW = 20
MAX_CHARS = 24000


def selector_impl_sha256() -> str:
    """本 selector 实现的 SHA-256（供 provenance 冻结）。"""
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def hunk_id(ident: dict) -> str:
    """**完整唯一 hunk 身份**（P0-4）：对复合 identity 做 SHA-256。

    依赖引用只接受该完整 id，禁止前缀匹配（相同 body 可能出现在不同文件/位置，
    前缀可能命中多个 hunk）。依赖图由此获得精确、唯一、可校验的引用目标。
    """
    payload = "|".join([
        str(ident.get("sample_id")), str(ident.get("file")),
        str(ident.get("file_status")), str(ident.get("old_start")),
        str(ident.get("old_count")), str(ident.get("new_start")),
        str(ident.get("new_count")), str(ident.get("body_lf_sha256")),
    ])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def attach_hunk_ids(coverage: dict) -> dict:
    """给 coverage 里每条 hunk_identity 补写 `hunk_id`（供 template/标注/依赖使用）。"""
    for s in coverage["samples"].values():
        for h in s.get("hunks", []):
            h["hunk_identity"]["hunk_id"] = hunk_id(h["hunk_identity"])
    return coverage


# hunk_id 的组成字段（重算时必须完全一致）
IDENTITY_FIELDS = ("sample_id", "file", "file_status", "old_start", "old_count",
                   "new_start", "new_count", "body_lf_sha256")


def recompute_hunk_id(ident: dict) -> str:
    """由 identity 的**其余字段**重算 hunk_id（P1-1：防篡改）。"""
    return hunk_id({k: ident.get(k) for k in IDENTITY_FIELDS})


def is_hex64(s) -> bool:
    return isinstance(s, str) and len(s) == 64 and all(c in "0123456789abcdef" for c in s)


def identity_matches(a: dict, b: dict, fields=IDENTITY_FIELDS) -> bool:
    """逐字段比对两个 identity（忽略 hunk_id 之外的附加键）。"""
    return all(a.get(k) == b.get(k) for k in fields)


def parse_patch_hunks(patch_text: str) -> dict:
    """解析 patch → {file: [{old_start, old_count, new_start, new_count, header, _body}]}。

    `_body` 为**完整单个 hunk body**（结束边界 = 全局下一个 `@@ ` 或 `diff --git `）。
    malformed hunk header → 抛 ValueError（fail-closed）。
    """
    out: dict = {}
    cur = None
    buf = patch_text.split("\n")
    for i, ln in enumerate(buf):
        if ln.startswith("diff --git ") and " b/" in ln:
            cur = ln.split(" b/", 1)[1].strip()
            out.setdefault(cur, [])
        elif ln.startswith("@@ ") and cur is not None:
            m = re.match(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)", ln)
            if not m:
                raise ValueError(f"malformed hunk header: {ln[:80]}")
            out[cur].append({
                "old_start": int(m.group(1)), "old_count": int(m.group(2) or 1),
                "new_start": int(m.group(3)), "new_count": int(m.group(4) or 1),
                "header": ln, "_start_idx": i,
                "patch_context_sha256": hashlib.sha256(
                    "\n".join(buf[i:i + 4]).encode("utf-8")).hexdigest(),
            })
    for rel, hs in out.items():
        for h in hs:
            i = h["_start_idx"]
            stop = len(buf)
            for j in range(i + 1, len(buf)):
                if buf[j].startswith("@@ ") or buf[j].startswith("diff --git "):
                    stop = j
                    break
            h["_body"] = "\n".join(buf[i + 1:stop])
    return out


def file_status(patch_text: str) -> dict:
    """由**文件状态**判定 added（`new file mode` / `--- /dev/null`），非 old_count==0。"""
    status, cur = {}, None
    for ln in patch_text.split("\n"):
        if ln.startswith("diff --git ") and " b/" in ln:
            cur = ln.split(" b/", 1)[1].strip()
            status.setdefault(cur, "M")
        elif cur is not None:
            if ln.startswith("new file mode") or ln.startswith("--- /dev/null"):
                status[cur] = "A"
            elif ln.startswith("deleted file mode"):
                status[cur] = "D"
    return status


def excerpt(sample_vuln_dir: Path, patch_text: str, window: int = WINDOW,
            max_chars: int = MAX_CHARS) -> tuple:
    """返回 (code_text, selection_manifest)。

    selection_manifest = {"files": {rel: [1-based 行号...]}, "dropped_file_count": int}
    """
    hunks: dict = {}
    cur = None
    for ln in patch_text.split("\n"):
        if ln.startswith("diff --git ") and " b/" in ln:
            cur = ln.split(" b/", 1)[1].strip()
            hunks.setdefault(cur, [])
        elif ln.startswith("@@ ") and cur is not None:
            m = re.match(r"@@ -(\d+)(?:,(\d+))?", ln)
            if m:
                hunks[cur].append((int(m.group(1)), int(m.group(2) or 1)))
    chunks, selection, total, dropped = [], {}, 0, 0
    for rel in sorted(hunks):
        p = sample_vuln_dir / rel
        if not p.exists():
            continue
        lines = p.read_text(encoding="utf-8", errors="replace").split("\n")
        keep: set = set()
        for start, count in hunks[rel]:
            lo = max(0, start - 1 - window)
            hi = min(len(lines), start - 1 + count + window)
            keep.update(range(lo, hi))
        if not keep:
            continue
        body = "\n".join(lines[i] for i in sorted(keep))
        chunk = f"// ---- {rel} ----\n{body}"
        if total + len(chunk) > max_chars:
            dropped += 1
            continue
        chunks.append(chunk)
        total += len(chunk)
        selection[rel] = sorted(keep)
    out = "\n\n".join(chunks)
    if dropped:
        out += f"\n\n// [excerpt note] 另有 {dropped} 个触及文件因预算未纳入本摘录"
    return out, {"files": selection, "dropped_file_count": dropped,
                 "window": window, "max_chars": max_chars}
