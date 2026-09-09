# -*- coding: utf-8 -*-
"""legacy-rq1-r0 摘录适配器（Experiment design §二.2 冻结表示）。

```text
representation = legacy-rq1-r0
summary        = false
max_code_chars = 8000
role           = RQ1-R 主重跑（历史基线重跑）
```

**本模块原样封存历史 `run_ablation._load_sample_code()` 的行为，不做任何优化**，
包括那些已知不完美的部分：

- 文件按 `(是否 taint 命中, 文件大小)` 排序（**不是**完整相对路径）；
- taint 命中文件：`sink±90`、`source−50/+80`，重叠合并（阈值 +20），按命中行数降序；
- 未命中文件：头 100 行；
- `max_chars=8000` 约束下会在语句中间截断并追加 `# (truncated)`；
- FILE marker 使用 **basename**（同名文件不可区分）。

依据 Experiment design：RQ1-R 是把历史基线在修复语料、统一 digest 下重新跑清，
"改进后的摘录器必须另立版本，不能混进本轮"。因此这些行为即使不完美也必须保留。

同时提供 `preflight_legacy()`：合法输入下不改动生成字节，只在调用前用 canonical
manifest 校验 source tree 与文件路径，异常即阻断（避免继承旧函数的 fail-open：
root 缺失返回空串、读文件失败 continue）。
"""
from __future__ import annotations

import hashlib
from pathlib import Path

REPRESENTATION = "legacy-rq1-r0"
MAX_CODE_CHARS = 8000
SUMMARY = False

# 历史窗口常量（原样封存，不得优化）
SINK_WINDOW = 90
SOURCE_LO_WINDOW = 50
SOURCE_HI_WINDOW = 80
MERGE_GAP = 20
HEAD_LINES = 100
TRUNC_MIN_REMAIN = 200


def tree_sha_lf(dirpath: Path) -> str:
    """目录树哈希（LF 规范化内容），跨平台可复算。"""
    parts = []
    for p in sorted(dirpath.rglob("*")):
        if p.is_file():
            rel = p.relative_to(dirpath).as_posix()
            data = p.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
            parts.append(rel + ":" + hashlib.sha256(data).hexdigest())
    return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()


def preflight_legacy(side_root: Path, expected_tree_sha: str | None) -> None:
    """调用 legacy 摘录前的门禁：source tree 必须存在且哈希匹配。

    合法输入下不改变任何生成字节；异常即阻断（fail-closed）。
    """
    if not side_root.is_dir():
        raise RuntimeError(f"[legacy preflight] 源目录不存在: {side_root}")
    if not expected_tree_sha:
        # 严格 fail-closed：canonical manifest 漏字段不得放行
        raise RuntimeError(
            f"[legacy preflight] expected_tree_sha 缺失（fail-closed）: {side_root}")
    actual = tree_sha_lf(side_root)
    if actual != expected_tree_sha:
        raise RuntimeError(
            f"[legacy preflight] 源树哈希漂移: {side_root} "
            f"实际 {actual[:12]} != 期望 {expected_tree_sha[:12]}")


def load_legacy_code_text(side_root: Path, taint_rows: list[dict],
                          max_chars: int = MAX_CODE_CHARS) -> str:
    """原样复刻历史 `_load_sample_code()` 的字节输出。

    `side_root`：该侧源码根目录（如 `cpg/corpus-v3/<CVE>/vuln`）。
    `taint_rows`：该侧 taint 命中行（含 abs_path/sourceLine/sinkLine）。
    """
    root = Path(side_root).resolve()
    hit_paths: dict[str, list[tuple[int, int]]] = {}
    root_str = str(root).replace("\\", "/") + "/"
    for r in taint_rows:
        ap = (r.get("abs_path") or "").replace("\\", "/")
        if ap.startswith(root_str):
            try:
                a = int(r.get("sourceLine") or 0)
                b = int(r.get("sinkLine") or 0)
            except (TypeError, ValueError):
                a = b = 0
            hit_paths.setdefault(ap, []).append((a, b))

    py_files = sorted(
        (p for p in root.rglob("*.py") if p.is_file()),
        key=lambda p: (p.resolve().as_posix() not in hit_paths, p.stat().st_size),
    )
    blocks: list[tuple[int, int, int, Path, list[str]]] = []
    for p in py_files:
        try:
            lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        if not lines:
            continue
        ap = p.resolve().as_posix()
        ab = [x for x in hit_paths.get(ap, []) if x[0] and x[1]]
        if ab:
            spans: list[tuple[int, int]] = []
            for a, b in ab:
                spans.append((max(1, b - SINK_WINDOW), min(len(lines), b + SINK_WINDOW)))
                spans.append((max(1, a - SOURCE_LO_WINDOW),
                              min(len(lines), a + SOURCE_HI_WINDOW)))
            spans.sort()
            merged: list[list[int]] = []
            for lo, hi in spans:
                if merged and lo <= merged[-1][1] + MERGE_GAP:
                    merged[-1][1] = max(merged[-1][1], hi)
                else:
                    merged.append([lo, hi])
            scored = []
            for lo, hi in merged:
                n_hit = sum(1 for (a, b) in ab if (lo <= a <= hi) or (lo <= b <= hi))
                scored.append((n_hit, lo, hi))
            scored.sort(key=lambda x: (-x[0], x[1]))
            for n_hit, lo, hi in scored:
                blocks.append((0, lo, hi, p, lines))
        else:
            blocks.append((1, 1, min(HEAD_LINES, len(lines)), p, lines))

    blocks.sort(key=lambda b: b[0])
    parts: list[str] = []
    used = 0
    for _prio, lo, hi, p, lines in blocks:
        text = (f"# ===== FILE: {p.name} (L{lo}-L{hi}) =====\n"
                + "\n".join(lines[lo - 1:hi]))
        if used + len(text) > max_chars:
            remain = max_chars - used
            if remain > TRUNC_MIN_REMAIN:
                parts.append(text[:remain] + "\n# (truncated)")
            break
        parts.append(text)
        used += len(text) + 1
    return "\n".join(parts)
