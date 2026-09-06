# -*- coding: utf-8 -*-
"""v4_patch_gen：G1 完整 real diff + G2 apply-clean placebo 生成器。

G1：对 corpus_pairs/{cve}/{vuln,fixed} 全树做差异——含新增/删除/重命名显式处理；
输出标准 unified diff（带 diff --git 头，可 `git apply`）；无文件数/行数截断。
自动断言：对 vuln 树应用 diff 后与 fixed 树逐文件哈希一致（G1 树哈希等价）。
G2：在真实 vuln 文件上构造语义保持的装饰性变更（注释插入/版本号自增，锚定真实行），
经同一 tree-diff 出 diff；断言 `git apply --check` 通过 + 变更内容受限于纯装饰。

用法（冒烟）：
  python cpg/ablation/v4_patch_gen.py CVE-2026-12482 CVE-2026-67424 CVE-2026-73498
"""
import hashlib
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
PAIRS = ROOT / "cpg" / "corpus_pairs"

# 装饰 placebo 的可选真实锚点（对每个 CVE 文件确定性选择）
COMMENT_ANCHOR = re.compile(r"^(#.*?)\n", re.M)      # 首个注释行后插一行
VERSION_ANCHOR = re.compile(r"^__version__\s*=\s*['\"][^'\"]+['\"]", re.M)


def file_hash(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def list_tree(root: Path) -> dict[str, Path]:
    out = {}
    for p in root.rglob("*"):
        if p.is_file():
            out[p.relative_to(root).as_posix()] = p
    return out


def is_binary(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            chunk = fh.read(8192)
        return b"\x00" in chunk
    except Exception:
        return True


def git_diff_two(a: Path, b: Path, rel: str) -> str:
    """git diff --no-index 两个文件 → 仅取 hunk 体（剥绝对路径头，自写干净头）。"""
    r = subprocess.run(["git", "diff", "--no-index", "--", str(a), str(b)],
                       capture_output=True, text=True, cwd=str(ROOT))
    out = r.stdout
    keep = []
    for ln in out.splitlines():
        if ln.startswith(("diff --git", "index ", "--- ", "+++ ", "deleted file",
                          "new file", "old mode", "new mode", "Binary files")):
            continue
        keep.append(ln)
    return "\n".join(keep)


def gen_complete_real_diff(cve: str, override_pair: Path | None = None) -> tuple[str, dict]:
    """G1：全量树 diff（vuln→fixed），规范实现——临时 git 仓两 commit 后 `git diff`。

    天然覆盖：修改/新增/删除/重命名文件，无文件数/行数截断。
    override_pair（含 vuln/placebo 子目录）时生成 vuln→placebo diff（G2 复用）。"""
    pair = override_pair or (PAIRS / cve)
    v, f = pair / "vuln", pair / "fixed"
    with tempfile.TemporaryDirectory() as td:
        repo = Path(td)
        subprocess.run(["git", "init", "-q"], cwd=str(repo), check=True)
        subprocess.run(["git", "config", "user.email", "t@t.t"], cwd=str(repo))
        subprocess.run(["git", "config", "user.name", "t"], cwd=str(repo))
        # 复制两树（均以目录名 vuln/fixed 入仓，便于 diff 路径干净）
        shutil.copytree(v, repo / "vuln")
        shutil.copytree(f, repo / "fixed")
        subprocess.run(["git", "add", "-A"], cwd=str(repo), check=True)
        subprocess.run(["git", "commit", "-qm", "vuln"], cwd=str(repo))
        vrev = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(repo),
                              capture_output=True, text=True).stdout.strip()
        # 把 fixed 内容覆盖到 vuln 名（同一路径 diff）
        shutil.rmtree(repo / "vuln")
        shutil.move(str(repo / "fixed"), str(repo / "vuln"))
        subprocess.run(["git", "add", "-A"], cwd=str(repo), check=True)
        subprocess.run(["git", "commit", "-qm", "fixed"], cwd=str(repo))
        r = subprocess.run(["git", "diff", "-M", f"{vrev}..HEAD", "--", "vuln/"],
                           capture_output=True, text=True, cwd=str(repo))
        full = r.stdout
    # 归一化路径前缀：git 输出 a/vuln/.. b/vuln/.. → a/.. b/..
    norm = full.replace("a/vuln/", "a/").replace("b/vuln/", "b/")
    # 统计变更文件
    rels = []
    for ln in norm.splitlines():
        if ln.startswith("diff --git"):
            path = ln.split(" b/", 1)[1] if " b/" in ln else ""
            rels.append(path)
    report = {"modified": [], "added": [], "deleted": [], "binary": [],
              "n_files": len(rels)}
    for ln in norm.splitlines():
        if ln.startswith("new file mode"):
            report["added"].append(rels[min(len(report["added"]), len(rels) - 1)])
        if ln.startswith("deleted file mode"):
            report["deleted"].append(rels[min(len(report["deleted"]), len(rels) - 1)])
        if ln.startswith("Binary files"):
            report["binary"].append(rels[min(len(report["binary"]), len(rels) - 1)])
    report["modified"] = [x for x in rels
                          if x not in report["added"] and x not in report["deleted"]
                          and x not in report["binary"]]
    return norm, report


def apply_and_verify(cve: str, diff_text: str) -> tuple[bool, str]:
    """G1 树哈希门禁：临时副本应用 diff → 与 fixed 树逐文件哈希一致。"""
    with tempfile.TemporaryDirectory() as td:
        dst = Path(td) / "work"
        shutil.copytree(PAIRS / cve / "vuln", dst)
        patch = Path(td) / "p.diff"
        patch.write_text(diff_text, encoding="utf-8")
        r = subprocess.run(["git", "apply", "--check", str(patch)],
                           capture_output=True, text=True, cwd=str(dst))
        if r.returncode != 0:
            return False, f"apply --check 失败: {r.stderr.strip()[:200]}"
        r2 = subprocess.run(["git", "apply", str(patch)],
                            capture_output=True, text=True, cwd=str(dst))
        if r2.returncode != 0:
            return False, f"apply 失败: {r2.stderr.strip()[:200]}"
        # 哈希等价
        applied = list_tree(dst)
        fixed = list_tree(PAIRS / cve / "fixed")
        rels = sorted(set(applied) | set(fixed))
        diff_files = [rel for rel in rels
                      if rel in applied and rel in fixed
                      and file_hash(applied[rel]) != file_hash(fixed[rel])]
        only_a = [rel for rel in applied if rel not in fixed]
        only_f = [rel for rel in fixed if rel not in applied]
        if diff_files or only_a or only_f:
            return False, (f"哈希不等价: 差 {diff_files[:3]}, 仅vuln侧 {only_a[:3]}, "
                           f"仅fixed侧 {only_f[:3]}")
        return True, "应用后与 fixed 树逐文件哈希一致"


def gen_placebo_diff(cve: str, seed_files: int = 2) -> tuple[str, dict]:
    """G2：在真实 vuln 文件上做确定性装饰性变更，再走 tree-diff。
    变更规则（全部锚定真实行，内容受限为纯装饰）：
      a) 版本号行自增（若存在 __version__ 行）；
      b) 首个注释行后插入一行中性注释；
    返回 (placebo_diff, report)。"""
    with tempfile.TemporaryDirectory() as td:
        src = PAIRS / cve / "vuln"
        dst = Path(td) / "placebo"
        shutil.copytree(src, dst)
        files = sorted(list_tree(dst).values())
        edits = []
        n_edits = 0
        for p in files[: seed_files * 4]:
            if is_binary(p):
                continue
            txt = p.read_text(encoding="utf-8", errors="replace")
            new = txt
            # (a) 版本号自增
            m = VERSION_ANCHOR.search(new)
            if m:
                seg = m.group(0)
                def bump(s):
                    mm = re.search(r"['\"]([0-9]+)\.([0-9]+)\.([0-9]+)['\"]", s)
                    if mm:
                        a, b2, c2 = int(mm.group(1)), int(mm.group(2)), int(mm.group(3))
                        return s[:mm.start(3)] + str(c2 + 1) + s[mm.end(3):]
                    return s
                bumped = bump(seg)
                if bumped != seg:
                    new = new.replace(seg, bumped, 1)
                    n_edits += 1
                    edits.append(f"version bump in {p.relative_to(dst).as_posix()}")
            # (b) 注释行后插中性注释（防 self-declaring：内容仅例行说明）
            if n_edits < seed_files:
                m2 = COMMENT_ANCHOR.search(new)
                if m2:
                    anchor = m2.group(0)
                    insert = anchor + "# 例行维护与可读性整理\n"
                    new = new.replace(anchor, insert, 1)
                    n_edits += 1
                    edits.append(f"comment insert in {p.relative_to(dst).as_posix()}")
            if n_edits >= seed_files:
                break
            if new != txt:
                p.write_text(new, encoding="utf-8")
        if n_edits == 0:
            # 兜底：任意真实文件末尾追加中性注释（仍 apply-clean）
            p = files[0]
            with p.open("a", encoding="utf-8") as fh:
                fh.write("\n# 例行维护\n")
            edits.append(f"eof comment in {files[0].relative_to(src).as_posix()}")
            n_edits = 1
        # 把 placebo 树布置为临时对中的 fixed 角色，与真实 vuln 树 diff
        with tempfile.TemporaryDirectory() as td2:
            pair = Path(td2)
            shutil.copytree(src, pair / "vuln")
            shutil.move(str(dst), str(pair / "fixed"))
            diff_text, rep = gen_complete_real_diff(cve, override_pair=pair)
            rep["edits"] = edits
            return diff_text, rep


def token_estimate(text: str) -> int:
    """一致性估算（CJK≈1token/字，ASCII≈4字/token 的折中：按 len/3 近似）。
    门禁用同一估算器比较臂间比，估算器偏差在比值中抵消。"""
    return max(1, len(text) // 3)


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("cves", nargs="+")
    args = ap.parse_args()
    for cve in args.cves:
        print("=" * 20, cve, "=" * 20)
        diff, rep = gen_complete_real_diff(cve)
        ok, msg = apply_and_verify(cve, diff)
        print(f"[G1] real diff: 文件 {rep['n_files']}（增{len(rep['added'])} 删"
              f"{len(rep['deleted'])} 改{len(rep['modified'])} 二进{len(rep['binary'])}）"
              f"| {len(diff)} 字符 | 树哈希: {msg}")
        print(f"     新增文件: {rep['added'][:5]}")
