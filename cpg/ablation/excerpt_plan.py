# -*- coding: utf-8 -*-
"""配对摘录计划（Code plan 第4阶段）——先建结构化计划，再渲染文本。

替代 run_ablation._load_sample_code 的"按文件大小排序 + 头 100 行 + text[:remain] 截半行"。

核心不变量：
- 文件顺序依据**完整相对路径**（不依据各侧文件大小），vuln/fixed 两侧一致；
- 同一逻辑文件在两侧使用配对窗口；
- added/deleted 显式记录 side absence；
- 只在完整行边界截取，绝不截半行；
- 文件标记使用完整相对路径；
- 达预算时缩小窗口或舍弃完整低优先块，绝不截半行；
- 对所有上游 changed hunk 输出 FULL/PARTIAL/ABSENT；
- 相同输入跨进程 SHA 一致（不依赖 dict 迭代序、PYTHONHASHSEED）。
"""
from __future__ import annotations

import hashlib
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

# changed-hunk 覆盖三态
FULL = "FULL"
PARTIAL = "PARTIAL"
ABSENT = "ABSENT"


def _sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


@dataclass
class BlockPlan:
    path: str            # 完整相对路径（含目录）
    side: str            # vuln / fixed
    lo: int              # 1-based 起始行
    hi: int              # 1-based 结束行（含）
    reason: str          # 选择原因
    content: str         # 块内容（完整行）
    content_sha: str
    token_estimate: int


@dataclass
class PairSelectionPlan:
    sample_id: str
    blocks: list[BlockPlan] = field(default_factory=list)
    hunk_coverage: dict = field(default_factory=dict)  # path -> FULL/PARTIAL/ABSENT
    changed_hunks: dict = field(default_factory=dict)  # path -> [(lo,hi), ...]
    max_chars: int = 8000

    def plan_sha(self) -> str:
        keys = sorted(
            f"{b.path}|{b.side}|{b.lo}|{b.hi}|{b.content_sha}" for b in self.blocks
        )
        return _sha256_bytes("\n".join(keys).encode("utf-8"))


def get_changed_hunks(repo_dir: Path, parent: str, fix: str, path: str) -> list[tuple[int, int]]:
    """git diff -U0 获取该文件 fix 侧相对 parent 的 added 行区间 [(lo, hi), ...]（1-based 含）。"""
    r = subprocess.run(
        ["git", "diff", "-U0", parent, fix, "--", path],
        cwd=str(repo_dir), capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    if r.returncode != 0:
        return []
    hunks = []
    cur_lo = None
    for line in r.stdout.splitlines():
        if line.startswith("@@"):
            # 解析 @@ -a,b +c,d @@ 里的 +c,d
            try:
                plus = line.split("+", 1)[1].split(" ")[0]
                c = int(plus.split(",")[0])
            except (IndexError, ValueError):
                cur_lo = None
                continue
            cur_lo = c
        elif line.startswith("+") and not line.startswith("+++"):
            if cur_lo is not None:
                if hunks and hunks[-1][1] == cur_lo - 1:
                    hunks[-1] = (hunks[-1][0], cur_lo)
                else:
                    hunks.append((cur_lo, cur_lo))
                cur_lo += 1
        elif line.startswith("-") and not line.startswith("---"):
            pass
        else:
            if cur_lo is not None:
                cur_lo += 1
    return hunks


def _read_lines(repo_dir: Path, commit: str, path: str) -> list[str]:
    r = subprocess.run(
        ["git", "show", f"{commit}:{path}"],
        cwd=str(repo_dir), capture_output=True,
    )
    if r.returncode != 0:
        return []
    return r.stdout.decode("utf-8", errors="replace").splitlines()


def _is_complete_line(content: str) -> bool:
    return content == "" or content.endswith("\n")


def build_pair_selection_plan(
    sample_spec,
    pair_manifest: dict,
    repo_dir: Path,
    max_chars: int = 8000,
    head_lines: int = 100,
    hunk_window: int = 20,
) -> PairSelectionPlan:
    """生成 vuln/fixed 共享的摘录计划。

    - 文件顺序按完整相对路径排序；
    - 优先 changed-hunk 中心窗口（FULL 覆盖），剩余预算给文件头部（head_lines）；
    - 只在完整行边界截取；达预算时缩小窗口/舍弃低优先块，绝不截半行。
    """
    plan = PairSelectionPlan(sample_id=sample_spec.sample_id, max_chars=max_chars)
    parent = pair_manifest["parent_commit"]
    fix = pair_manifest["fix_commit"]

    # 收集所有 .py 改动文件（按完整相对路径排序）
    files = sorted(pair_manifest.get("files", []), key=lambda f: f["path"])

    # 1) 计算每个文件的 changed hunks（fix 侧）
    changed_hunks = {}
    for f in files:
        hunks = get_changed_hunks(repo_dir, parent, fix, f["path"])
        changed_hunks[f["path"]] = hunks

    # 2) 为每个文件生成候选块（vuln/fixed 两侧配对窗口）
    #    逻辑：对每个文件，取 vuln(parent) 和 fixed(fix) 的对应行区间
    blocks: list[BlockPlan] = []
    for f in files:
        path = f["path"]
        status = f.get("status")
        hunks = changed_hunks[path]

        # changed-hunk 中心窗口：每个 hunk 单独 ±window，只合并重叠区间（不把远处的
        # hunk 连成一个超大窗口，避免超预算被截断后丢掉真正的安全 hunk）。
        # hunk_window=None 表示禁用 hunk 窗口（退化为头 100 行旧策略）。
        if hunk_window is not None and status in ("M", "T") and hunks:
            windows = []
            for h_lo, h_hi in sorted(hunks):
                w_lo = max(1, h_lo - hunk_window)
                w_hi = h_hi + hunk_window
                if windows and w_lo <= windows[-1][1] + 1:
                    windows[-1] = (windows[-1][0], max(windows[-1][1], w_hi))
                else:
                    windows.append((w_lo, w_hi))
            for w_lo, w_hi in windows:
                for side, commit in (("vuln", parent), ("fixed", fix)):
                    lines = _read_lines(repo_dir, commit, path)
                    lo_c = max(1, w_lo)
                    hi_c = min(len(lines), w_hi)
                    content = "\n".join(lines[lo_c - 1:hi_c]) + ("\n" if lines else "")
                    blocks.append(BlockPlan(
                        path=path, side=side, lo=lo_c, hi=hi_c,
                        reason=f"changed_hunk_window:{w_lo}-{w_hi}",
                        content=content, content_sha=_sha256_bytes(content.encode("utf-8")),
                        token_estimate=len(content) // 4,
                    ))
            continue

        # 头部窗口（无 changed hunk 的 modified，或 added/deleted 的现有侧）
        if status in ("M", "T"):
            for side, commit in (("vuln", parent), ("fixed", fix)):
                lines = _read_lines(repo_dir, commit, path)
                hi_c = min(len(lines), head_lines)
                content = "\n".join(lines[:hi_c]) + ("\n" if lines else "")
                blocks.append(BlockPlan(
                    path=path, side=side, lo=1, hi=hi_c, reason="head_window",
                    content=content, content_sha=_sha256_bytes(content.encode("utf-8")),
                    token_estimate=len(content) // 4,
                ))
        elif status == "A":
            lines = _read_lines(repo_dir, fix, path)
            hi_c = min(len(lines), head_lines)
            content = "\n".join(lines[:hi_c]) + ("\n" if lines else "")
            blocks.append(BlockPlan(
                path=path, side="fixed", lo=1, hi=hi_c, reason="added_head",
                content=content, content_sha=_sha256_bytes(content.encode("utf-8")),
                token_estimate=len(content) // 4,
            ))
        elif status == "D":
            lines = _read_lines(repo_dir, parent, path)
            hi_c = min(len(lines), head_lines)
            content = "\n".join(lines[:hi_c]) + ("\n" if lines else "")
            blocks.append(BlockPlan(
                path=path, side="vuln", lo=1, hi=hi_c, reason="deleted_head",
                content=content, content_sha=_sha256_bytes(content.encode("utf-8")),
                token_estimate=len(content) // 4,
            ))
        # R/C：renamed/copied 也按现有侧取头部（简化，pair_manifest 已有 prev）
        elif status in ("R", "C"):
            lines = _read_lines(repo_dir, fix, path)
            hi_c = min(len(lines), head_lines)
            content = "\n".join(lines[:hi_c]) + ("\n" if lines else "")
            blocks.append(BlockPlan(
                path=path, side="fixed", lo=1, hi=hi_c, reason=f"{status}_head",
                content=content, content_sha=_sha256_bytes(content.encode("utf-8")),
                token_estimate=len(content) // 4,
            ))
            if f.get("prev"):
                lines = _read_lines(repo_dir, parent, f["prev"])
                hi_c = min(len(lines), head_lines)
                content = "\n".join(lines[:hi_c]) + ("\n" if lines else "")
                blocks.append(BlockPlan(
                    path=f["prev"], side="vuln", lo=1, hi=hi_c, reason=f"{status}_prev_head",
                    content=content, content_sha=_sha256_bytes(content.encode("utf-8")),
                    token_estimate=len(content) // 4,
                ))

    # 3) 预算分配：按 (有 changed hunk 优先, 完整相对路径) 排序，累计到 max_chars
    #    每块只取完整行；达预算后舍弃剩余块（不截半行）
    def block_priority(b: BlockPlan) -> tuple:
        is_hunk = b.reason.startswith("changed_hunk_window")
        return (0 if is_hunk else 1, b.path, b.side)

    sorted_blocks = sorted(blocks, key=block_priority)
    selected: list[BlockPlan] = []
    total = 0
    for b in sorted_blocks:
        if not _is_complete_line(b.content):
            # 不完整行块（不应发生，防御）
            continue
        if total + len(b.content) > max_chars and selected:
            # 达预算，舍弃剩余块（不截半行）
            continue
        if len(b.content) > max_chars and not selected:
            # 单块超预算：截到完整行边界
            lines = b.content.splitlines(keepends=True)
            acc = ""
            for ln in lines:
                if total + len(ln) > max_chars:
                    break
                acc += ln
                total += len(ln)
            if acc:
                b.content = acc
                b.hi = b.lo + acc.count("\n") - 1
                b.content_sha = _sha256_bytes(acc.encode("utf-8"))
                b.token_estimate = len(acc) // 4
                selected.append(b)
            continue
        selected.append(b)
        total += len(b.content)

    plan.blocks = selected
    plan.changed_hunks = changed_hunks
    plan.hunk_coverage = _compute_coverage(files, changed_hunks, selected, head_lines, hunk_window)
    return plan


def _compute_coverage(files, changed_hunks, blocks, head_lines, hunk_window) -> dict:
    """对每个有 changed hunk 的文件，判断 hunk 是否进入摘录 → FULL/PARTIAL/ABSENT。"""
    coverage = {}
    for f in files:
        path = f["path"]
        hunks = changed_hunks.get(path, [])
        if not hunks:
            continue
        # 该文件的块（两侧都要看）
        file_blocks = [b for b in blocks if b.path == path]
        covered = 0
        for lo, hi in hunks:
            in_any = any(b.lo <= lo and hi <= b.hi for b in file_blocks)
            if in_any:
                covered += 1
        if covered == len(hunks):
            coverage[path] = FULL
        elif covered > 0:
            coverage[path] = PARTIAL
        else:
            coverage[path] = ABSENT
    return coverage


def render_side(plan: PairSelectionPlan, side: str) -> str:
    """渲染单侧代码文本，块间用完整相对路径 FILE marker 分隔。"""
    side_blocks = [b for b in plan.blocks if b.side == side]
    # 按完整相对路径排序
    side_blocks = sorted(side_blocks, key=lambda b: b.path)
    parts = []
    for b in side_blocks:
        parts.append(f"# ===== FILE: {b.path} (L{b.lo}-L{b.hi}) =====\n")
        parts.append(b.content)
    return "".join(parts)
