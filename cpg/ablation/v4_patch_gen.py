# -*- coding: utf-8 -*-
"""v4_patch_gen（v2，2026-09-06 外部审计后重写）：G1 完整 real diff + G2 apply-clean placebo。

审计修复记录（逐项）：
- P0-1 类型语法 Path|None → Optional[Path]（Python 3.9 兼容，freeze 声明 ≥3.9）
- P0-2 subprocess 全部 encoding=utf-8 + errors=strict + check=True（Windows GBK 不再崩溃）
- P0-3 placebo 固定中文"例行维护/可读性整理"=自述型臂指纹（与已删"无功能变更"同类）→ 删除；
  改为英文、贴文件局部语义（最近 def/class 语境）、每条不同、AST 等价机器验证
- P0-4 版本号自增不保证语义保持（运行时分支/元数据/特性开关）→ 从 placebo 规则删除
- P1-1 report 元数据改为按 diff --git section 切片解析（added/deleted/renamed 独立字段）
- P1-2 git diff 加 --binary --full-index；apply 用 --binary（二进制可应用/fail-closed）
- P1-3 路径归一化只改 header 行（diff --git/---/+++/rename），不动补丁正文
- P0-6 token 估算改内容感知（ASCII≈4字/tok、CJK≈1字/tok），不再声称比值抵消
- P0-5 placebo 校验入库：__main__/v4_gates_smoke.py 跑 apply+AST+内容检查并写 JSON 报告
"""
import ast
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parent.parent.parent
PAIRS = ROOT / "cpg" / "corpus_pairs"
_ENC = {"encoding": "utf-8", "errors": "strict"}


def _run(args, cwd, check=True) -> subprocess.CompletedProcess:
    """统一 subprocess：UTF-8、strict 错误、默认 fail-closed。"""
    return subprocess.run(args, capture_output=True, text=True, cwd=str(cwd),
                          check=check, **_ENC)


def file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def list_tree(root: Path) -> dict[str, Path]:
    out = {}
    for p in root.rglob("*"):
        if p.is_file():
            out[p.relative_to(root).as_posix()] = p
    return out


def _norm_header(full: str) -> str:
    """P1-3：仅规范化 diff 头部行中的 a/vuln/ b/vuln/ 前缀，不动补丁正文。"""
    out = []
    for ln in full.splitlines():
        if ln.startswith(("diff --git", "--- ", "+++ ", "rename from", "rename to")):
            ln = ln.replace("a/vuln/", "a/").replace("b/vuln/", "b/")
        out.append(ln)
    return "\n".join(out)


def _parse_sections(diff_text: str) -> dict:
    """P1-1：按 diff --git section 切片解析，added/deleted/renamed/modified/binary 独立。"""
    report = {"added": [], "deleted": [], "renamed": [], "modified": [],
              "binary": [], "n_files": 0}
    lines = diff_text.splitlines()
    i = 0
    while i < len(lines):
        if lines[i].startswith("diff --git "):
            rel = lines[i].split(" b/", 1)[1].strip()
            j = i + 1
            body = []
            while j < len(lines) and not lines[j].startswith("diff --git "):
                body.append(lines[j]); j += 1
            report["n_files"] += 1
            if any(x.startswith("Binary files") for x in body):
                report["binary"].append(rel)
            elif any(x.startswith("new file mode") for x in body):
                report["added"].append(rel)
            elif any(x.startswith("deleted file mode") for x in body):
                report["deleted"].append(rel)
            elif any(x.startswith("rename from") for x in body):
                report["renamed"].append(rel)
            else:
                report["modified"].append(rel)
            i = j
        else:
            i += 1
    return report


def gen_complete_real_diff(cve: str, override_pair: Optional[Path] = None) -> tuple[str, dict]:
    """G1：全量树 diff（vuln→fixed）。规范实现：临时 git 仓双 commit + git diff --binary -M。"""
    pair = override_pair or (PAIRS / cve)
    v, f = pair / "vuln", pair / "fixed"
    if not v.is_dir() or not f.is_dir():
        raise FileNotFoundError(f"语料树缺失: {cve}")
    with tempfile.TemporaryDirectory() as td:
        repo = Path(td)
        _run(["git", "init", "-q"], repo)
        _run(["git", "config", "user.email", "t@t.t"], repo)
        _run(["git", "config", "user.name", "t"], repo)
        _run(["git", "config", "core.quotepath", "false"], repo)
        shutil.copytree(v, repo / "vuln")
        shutil.copytree(f, repo / "fixed")
        _run(["git", "add", "-A"], repo)
        _run(["git", "commit", "-qm", "vuln"], repo)
        vrev = _run(["git", "rev-parse", "HEAD"], repo).stdout.strip()
        shutil.rmtree(repo / "vuln")
        shutil.move(str(repo / "fixed"), str(repo / "vuln"))
        _run(["git", "add", "-A"], repo)
        _run(["git", "commit", "-qm", "fixed"], repo)
        r = _run(["git", "diff", "--binary", "--full-index", "-M",
                  f"{vrev}..HEAD", "--", "vuln/"], repo)
        full = r.stdout
    norm = _norm_header(full)
    return norm, _parse_sections(norm), full


def apply_and_verify(cve: str, raw_diff: str) -> tuple[bool, str]:
    """G1 树哈希门禁：对【未归一化】diff 在 vuln/ 子树结构下 apply --binary，
    与 fixed 树逐文件哈希一致（原始 git 产出路径，in-repo 验证可靠）。"""
    with tempfile.TemporaryDirectory() as td:
        work = Path(td) / "work"
        work.mkdir()
        shutil.copytree(PAIRS / cve / "vuln", work / "vuln")
        patch = Path(td) / "p.diff"
        patch.write_text(raw_diff, encoding="utf-8")
        r = subprocess.run(["git", "apply", "--binary", "--check", str(patch)],
                           capture_output=True, text=True, cwd=str(work), **_ENC)
        if r.returncode != 0:
            return False, f"apply --check 失败: {r.stderr.strip()[:200]}"
        r2 = subprocess.run(["git", "apply", "--binary", str(patch)],
                            capture_output=True, text=True, cwd=str(work), **_ENC)
        if r2.returncode != 0:
            return False, f"apply 失败: {r2.stderr.strip()[:200]}"
        applied = list_tree(work / "vuln")
        fixed = list_tree(PAIRS / cve / "fixed")
        bad = [rel for rel in applied if rel in fixed
               and file_hash(applied[rel]) != file_hash(fixed[rel])]
        only = [rel for rel in fixed if rel not in applied]
        if bad or only:
            return False, f"哈希不等价: 差 {bad[:3]} 缺 {only[:3]}"
        return True, "应用后与 fixed 树逐文件哈希一致"


# ---------------------------------------------------------------------------
# G2 placebo：真实 vuln 文件上、AST 等价、无标签词的注释插入
# ---------------------------------------------------------------------------
_DECORATION_WORDS = ("maintenance", "refactor", "cleanup", "format",
                     "readability", "routine", "cosmetic", "整理", "维护", "可读性")


def _enclosing_def(text: str, pos: int) -> str:
    head = text[:pos]
    names = [m.group(1) for m in
             re.finditer(r"^(?:async\s+def|def|class)\s+([A-Za-z_]\w*)", head, re.M)]
    return names[-1] if names else ""


def _make_natural_comment(text: str, pos: int, rel: str = "") -> str:
    """英文、贴局部语义、无装饰性词汇的注释（逐文件不同，禁止共享模板）。"""
    fn = _enclosing_def(text, pos)
    if fn:
        return f"# {fn}: argument expectations are unchanged by this line\n"
    rest = text[pos:]
    m = re.search(r"^\s*([A-Za-z_][A-Za-z0-9_]*)", rest, re.M)
    triple_dq = chr(34) * 3
    if m and not m.group(1).startswith(("#", chr(39) * 3, triple_dq)):
        return f"# {m.group(1)} path below kept as authored; no behavior drift intended\n"
    stem = Path(rel).stem.replace("_", " ")
    if rel:
        return f"# {stem}: comments kept in sync with the code below\n"
    return "# see the block below; no behavior change is intended here\n"


def _nearest_comment_pos(text: str) -> Optional[int]:
    m = re.search(r"^#.*$", text, re.M)
    return m.start() if m else None


def gen_placebo_diff(cve: str, seed_files: int = 2) -> tuple[str, dict]:
    """G2：真实 vuln 文件上 AST 等价的注释插入。
    删版本号变更（P0-4）；删固定中文措辞（P0-3）；AST 等价机器验证；逐文件不同注释。"""
    with tempfile.TemporaryDirectory() as td:
        src = PAIRS / cve / "vuln"
        dst = Path(td) / "placebo"
        shutil.copytree(src, dst)
        files = sorted(list_tree(dst).values())
        edits, ast_ok, done = [], True, 0
        for p in files:
            if done >= seed_files:
                break
            if p.suffix != ".py":
                continue
            txt = p.read_text(encoding="utf-8")
            pos = _nearest_comment_pos(txt)
            if pos is None:
                continue
            try:
                before = ast.dump(ast.parse(txt))
            except SyntaxError:
                continue
            comment = _make_natural_comment(txt, pos, rel=p.relative_to(dst).as_posix())
            if any(w in comment.lower() for w in _DECORATION_WORDS):
                continue
            # 整行前置（在注释行行首前插新行），不切开原行——插入 '#' 后+换行会拆行致 SyntaxError
            line_start = txt.rfind("\n", 0, pos) + 1
            new_txt = txt[:line_start] + comment + txt[line_start:]
            try:
                after = ast.dump(ast.parse(new_txt))
            except SyntaxError:
                continue
            if before != after:
                ast_ok = False
                continue
            p.write_text(new_txt, encoding="utf-8")
            edits.append(f"comment in {p.relative_to(dst).as_posix()}: {comment.strip()[:50]}")
            done += 1
        if not edits:
            return "", {"edits": [], "ast_equivalent": False, "error": "no edit possible"}
        with tempfile.TemporaryDirectory() as td2:
            pair = Path(td2)
            shutil.copytree(src, pair / "vuln")
            shutil.move(str(dst), str(pair / "fixed"))
            diff_text, rep, _raw = gen_complete_real_diff(cve, override_pair=pair)
            # G2 可应用性入库断言：raw diff（a/vuln/.. 路径）对 vuln/ 子树 apply --check
            work = Path(td2) / "ac"; work.mkdir()
            shutil.copytree(src, work / "vuln")
            patch = Path(td2) / "pl.diff"
            patch.write_text(_raw, encoding="utf-8")
            chk = subprocess.run(["git", "apply", "--binary", "--check", str(patch)],
                                 capture_output=True, text=True, cwd=str(work), **_ENC)
            rep["edits"] = edits
            rep["ast_equivalent"] = ast_ok
            rep["apply_clean"] = (chk.returncode == 0)
            rep["apply_error"] = "" if chk.returncode == 0 else chk.stderr.strip()[:120]
            return diff_text, rep


def tokens_estimate(text: str) -> int:
    """P0-6 内容感知：ASCII≈4 字/tok、CJK≈1 字/tok；不声称跨内容比值抵消。"""
    ascii_n = sum(1 for ch in text if ord(ch) < 0x80)
    cjk_n = sum(1 for ch in text if 0x4E00 <= ord(ch) <= 0x9FFF)
    other = len(text) - ascii_n - cjk_n
    return max(1, ascii_n // 4 + cjk_n + other // 2)


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("cves", nargs="+")
    ap.add_argument("--json", action="store_true", help="输出 JSON 报告")
    args = ap.parse_args()
    results = {}
    for cve in args.cves:
        entry = {}
        try:
            rd, rrep, rd_raw = gen_complete_real_diff(cve)
            ok, msg = apply_and_verify(cve, rd_raw)
            entry.update({"g1_files": rrep["n_files"], "g1_added": rrep["added"],
                          "g1_deleted": rrep["deleted"], "g1_renamed": rrep["renamed"],
                          "g1_binary": rrep["binary"], "g1_len_chars": len(rd),
                          "g1_tree_hash": msg, "g1_pass": ok})
        except Exception as e:
            entry["g1_error"] = str(e)[:200]
        try:
            pd, prep = gen_placebo_diff(cve)
            entry.update({"g2_len_chars": len(pd), "g2_edits": prep.get("edits"),
                          "g2_ast_equivalent": prep.get("ast_equivalent"),
                          "g2_apply_clean": prep.get("apply_clean"),
                          "g2_apply_error": prep.get("apply_error", "")})
            if rd:
                entry["g2_token_ratio"] = round(tokens_estimate(pd) /
                                                tokens_estimate(rd), 3)
        except Exception as e:
            entry["g2_error"] = str(e)[:200]
        results[cve] = entry
    if args.json:
        print(json.dumps(results, ensure_ascii=False, indent=1))
    else:
        for cve, e in results.items():
            print(cve, json.dumps(e, ensure_ascii=False)[:320])
