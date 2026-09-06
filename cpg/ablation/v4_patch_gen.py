# -*- coding: utf-8 -*-
"""v4_patch_gen（v2.1，2026-09-06 第三轮审计后重写）。

v2.1 修复（逐项对应第三轮审计 P0/P1）：
- P0-1 display diff 补回末尾换行；canonical=display 单一份，且该精确文本必须 apply-clean+树等价
- P0-3 racy-clean：每次 git add 前 `git rm -r --cached .` 强制全量重哈希（同长度/同时间戳修改不再漏检，
  以 CVE-2026-54785 的 __version__ 1.3.0→1.3.1 为回归锚点）
- P0-2 placebo 删除一切"行为不变"自述（unchanged/behavior drift/no behavior change/as authored/preserve）；
  注释改"# see also: <identifier>"式交叉引用 + "(in <stem>)" 消歧，禁跨文件同模板；
  黑名单含 unchanged/behavior/drift/change/no-op/preserve
- P0-4 补齐 v4_gates_smoke.py（真实测试脚本 + 持久化 JSON 报告 + display-diff SHA-256 + 失败记录）
- P1 树等价：路径集合双向相等 + 逐文件字节 + 文件类型(文件/符号链接)比较
- P1 AST 等价但语义：跳过 shebang/coding/noqa/type/coverage 等特殊注释，绝不在文件首行前插入
- P1 tokens_estimate 明确标注为 PROXY（真实 token 门禁在 prompt 组装后由实际 tokenizer 计，见 freeze §2）
- P1 stdout 强制 UTF-8（Python 3.9 下 JSON 中文不再乱码）
"""
import ast
import hashlib
import io
import tokenize
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
    return subprocess.run(args, capture_output=True, text=True, cwd=str(cwd),
                          check=check, **_ENC)


def file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def file_kind(path: Path) -> str:
    return "symlink" if path.is_symlink() else "file"


def list_tree(root: Path) -> dict[str, Path]:
    out = {}
    for p in root.rglob("*"):
        if p.is_file() or p.is_symlink():
            out[p.relative_to(root).as_posix()] = p
    return out


def _norm_header(full: str) -> str:
    """P1-3：仅规范化 header 行前缀；保留末尾换行（P0-1）。"""
    out = []
    for ln in full.splitlines():
        if ln.startswith(("diff --git", "--- ", "+++ ", "rename from", "rename to")):
            ln = (ln.replace("a/vuln/", "a/").replace("b/vuln/", "b/")
                    .replace("vuln/", "", 1))
        out.append(ln)
    text = "\n".join(out)
    return text + "\n" if full.endswith("\n") else text + "\n"


def _parse_sections(diff_text: str) -> dict:
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


def _git_index_add(repo: Path):
    """P0-3：先清索引再全量 add，强制全量重哈希，规避 racy-clean 漏检。"""
    _run(["git", "rm", "-r", "--cached", "-q", "."], repo, check=False)
    _run(["git", "add", "-A"], repo)


def gen_complete_real_diff(cve: str, override_pair: Optional[Path] = None) -> tuple[str, dict]:
    """G1：canonical diff（clean 路径 a/x b/x，末尾换行，可直接 apply）。"""
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
        _git_index_add(repo)
        _run(["git", "commit", "-qm", "vuln"], repo)
        vrev = _run(["git", "rev-parse", "HEAD"], repo).stdout.strip()
        shutil.rmtree(repo / "vuln")
        shutil.move(str(repo / "fixed"), str(repo / "vuln"))
        _git_index_add(repo)
        _run(["git", "commit", "-qm", "fixed"], repo)
        r = _run(["git", "diff", "--binary", "--full-index", "-M",
                  f"{vrev}..HEAD", "--", "vuln/"], repo)
        full = r.stdout
    norm = _norm_header(full)
    return norm, _parse_sections(norm)


def apply_and_verify(cve: str, diff_text: str) -> tuple[bool, str]:
    """G1 树等价门禁：canonical diff 应用到根级 vuln 副本 → 与 fixed 双向路径集合相等
    + 逐文件字节 + 文件类型一致。"""
    with tempfile.TemporaryDirectory() as td:
        work = Path(td) / "work"
        work.mkdir()
        for p in (PAIRS / cve / "vuln").iterdir():
            if p.is_dir():
                shutil.copytree(p, work / p.name)
            else:
                shutil.copy2(p, work / p.name)
        patch = Path(td) / "p.diff"
        patch.write_text(diff_text, encoding="utf-8")
        r = subprocess.run(["git", "apply", "--binary", "--check", str(patch)],
                           capture_output=True, text=True, cwd=str(work), **_ENC)
        if r.returncode != 0:
            return False, f"apply --check 失败: {r.stderr.strip()[:200]}"
        r2 = subprocess.run(["git", "apply", "--binary", str(patch)],
                            capture_output=True, text=True, cwd=str(work), **_ENC)
        if r2.returncode != 0:
            return False, f"apply 失败: {r2.stderr.strip()[:200]}"
        applied = list_tree(work)
        fixed = list_tree(PAIRS / cve / "fixed")
        if set(applied) != set(fixed):
            return False, (f"路径集合不等: 仅applied {sorted(set(applied) - set(fixed))[:3]} "
                           f"仅fixed {sorted(set(fixed) - set(applied))[:3]}")
        for rel in applied:
            if file_kind(applied[rel]) != file_kind(fixed[rel]):
                return False, f"文件类型不符: {rel}"
            if file_hash(applied[rel]) != file_hash(fixed[rel]):
                return False, f"字节不符: {rel}"
        return True, "应用后与 fixed 树逐文件哈希一致（双向集合+字节+类型）"


# ---------------------------------------------------------------------------
# G2 placebo
# ---------------------------------------------------------------------------
_DECORATION_WORDS = ("maintenance", "refactor", "cleanup", "format",
                     "readability", "routine", "cosmetic", "整理", "维护", "可读性",
                     "unchanged", "behavior", "drift", "change", "no-op",
                     "preserve", "preserving", "as authored", "intended")
_DIRECTIVE = ("coding:", "type:", "noqa", "pylint:", "flake8:", "coverage:",
              "isort:", "mypy:", "pyright:")


def _first_def(text: str) -> str:
    m = re.search(r"^(?:async\s+def|def|class)\s+([A-Za-z_]\w*)", text, re.M)
    return m.group(1) if m else ""


def _enclosing_def(text: str, pos: int) -> str:
    head = text[:pos]
    names = [m.group(1) for m in
             re.finditer(r"^(?:async\s+def|def|class)\s+([A-Za-z_]\w*)", head, re.M)]
    return names[-1] if names else ""


def _next_identifier(text: str, pos: int) -> str:
    rest = text[pos:]
    m = re.search(r"^\s*([A-Za-z_][A-Za-z0-9_]*)", rest, re.M)
    return m.group(1) if m else ""


def _make_natural_comment(text: str, pos: int, rel: str, cve: str = "") -> Optional[str]:
    """从真实代码结构生成注释：fn（最近 def/class）优先，否则下一代码标识符；
    **无 fn/ident 则返回 None（跳过该文件，绝不产出 stem==stem 同义反复）**。
    后缀按 (cve, rel) 确定性选一，避免全局统一模板。无行为声明、无装饰词。"""
    fn = _enclosing_def(text, pos)
    ident = _next_identifier(text, pos) if not fn else ""
    ref = fn or ident
    if not ref or ref in ("def", "class", "import", "from", "return", "if", "for"):
        return None
    variants = (
        "referenced by the block below",
        "see the following lines",
        "entry point of the nearby code",
        "used around this section",
    )
    k = (hash(cve + "|" + rel) & 0x7FFFFFFF) % len(variants)
    return f"# {ref} — {variants[k]}\n"


def _safe_anchor(text: str) -> Optional[int]:
    """找首个安全 COMMENT token 所在行的【行首字符偏移】（tokenize 的 start[1] 是
    列号非字节偏移，必须自行换算为全文字符偏移）。排除 shebang、编码声明与
    noqa/type/coverage 等指令。无则 None（走 EOF 兜底）。"""
    lines = text.splitlines(keepends=True)
    line_offsets = [0]
    for ln in lines:
        line_offsets.append(line_offsets[-1] + len(ln))
    try:
        for tok in tokenize.generate_tokens(io.StringIO(text).readline):
            if tok.type != tokenize.COMMENT:
                continue
            t = tok.string.strip()
            if t.startswith("!") or t.startswith("#!"):
                continue
            if tok.start[0] <= 1:
                continue  # 跳过第 1 行（许可头/模块首注释），避免文件头位移
            low = t.lstrip("# ").strip().lower()
            if low.startswith(_DIRECTIVE):
                continue
            return line_offsets[tok.start[0] - 1]  # 行首字符偏移
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return None
    return None


def gen_placebo_diff(cve: str, seed_files: int = 2) -> tuple[str, dict]:
    """G2：真实 vuln 文件上 AST 等价的交叉引用注释插入。无版本号变更、无行为自述。"""
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
            pos = _safe_anchor(txt)
            if pos is None:
                pos = len(txt)  # EOF 兜底
            try:
                before = ast.dump(ast.parse(txt))
            except SyntaxError:
                continue
            comment = _make_natural_comment(txt, pos, rel=p.relative_to(dst).as_posix(), cve=cve)
            if comment is None:
                ref = _first_def(txt) or _next_identifier(txt, 0)
                if not ref or ref in ("def", "class", "import", "from"):
                    continue
                variants = ("referenced by the block below", "see the following lines",
                            "entry point of the nearby code", "used around this section")
                k = (hash(cve + "|" + p.relative_to(dst).as_posix()) & 0x7FFFFFFF) % len(variants)
                comment = f"# {ref} — {variants[k]}\n"
                pos = len(txt)  # EOF 兜底
            if any(w in comment.lower() for w in _DECORATION_WORDS):
                continue
            if pos == len(txt):
                new_txt = txt + ("" if txt.endswith("\n") else "\n") + comment
            else:
                line_start = txt.rfind("\n", 0, pos) + 1
                new_txt = txt[:line_start] + comment + txt[line_start:]
            try:
                after = ast.dump(ast.parse(new_txt))
            except SyntaxError:
                continue
            if before != after:
                ast_ok = False
                continue
            # 硬断言：shebang 不位移（仅当原文件首行为 #! 时）
            if txt.startswith("#!"):
                if not new_txt.startswith("#!"):
                    continue
            p.write_text(new_txt, encoding="utf-8")
            edits.append(f"comment in {p.relative_to(dst).as_posix()}: {comment.strip()[:60]}")
            done += 1
        if not edits:
            return "", {"edits": [], "ast_equivalent": False, "error": "no edit possible"}
        with tempfile.TemporaryDirectory() as td2:
            pair = Path(td2)
            shutil.copytree(src, pair / "vuln")
            shutil.move(str(dst), str(pair / "fixed"))
            diff_text, rep = gen_complete_real_diff(cve, override_pair=pair)
            rep["edits"] = edits
            rep["ast_equivalent"] = ast_ok
            rep["apply_clean"] = False
            # 对 canonical placebo diff 做根级 apply --check
            work = Path(td2) / "ac"; work.mkdir()
            for q in src.iterdir():
                if q.is_dir():
                    shutil.copytree(q, work / q.name)
                else:
                    shutil.copy2(q, work / q.name)
            patch = Path(td2) / "pl.diff"
            patch.write_text(diff_text, encoding="utf-8")
            chk = subprocess.run(["git", "apply", "--binary", "--check", str(patch)],
                                 capture_output=True, text=True, cwd=str(work), **_ENC)
            rep["apply_clean"] = (chk.returncode == 0)
            rep["apply_error"] = "" if chk.returncode == 0 else chk.stderr.strip()[:120]
            return diff_text, rep


def tokens_estimate(text: str) -> int:
    """PROXY 估算（非门禁）：ASCII≈4/tok、CJK≈1/tok。真实 token 门禁在 prompt
    组装后由实际 tokenizer 计，见 EXPERIMENT-FREEZE §2。"""
    ascii_n = sum(1 for ch in text if ord(ch) < 0x80)
    cjk_n = sum(1 for ch in text if 0x4E00 <= ord(ch) <= 0x9FFF)
    other = len(text) - ascii_n - cjk_n
    return max(1, ascii_n // 4 + cjk_n + other // 2)


def diff_sha256(diff_text: str) -> str:
    return hashlib.sha256(diff_text.encode("utf-8")).hexdigest()


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("cves", nargs="+")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    results = {}
    for cve in args.cves:
        entry = {}
        try:
            rd, rrep = gen_complete_real_diff(cve)
            ok, msg = apply_and_verify(cve, rd)
            entry.update({"g1_files": rrep["n_files"], "g1_added": rrep["added"],
                          "g1_deleted": rrep["deleted"], "g1_renamed": rrep["renamed"],
                          "g1_binary": rrep["binary"], "g1_len_chars": len(rd),
                          "g1_diff_sha256": diff_sha256(rd),
                          "g1_tree": msg, "g1_pass": ok})
        except Exception as e:
            entry["g1_error"] = str(e)[:200]
        try:
            pd, prep = gen_placebo_diff(cve)
            entry.update({"g2_len_chars": len(pd), "g2_edits": prep.get("edits"),
                          "g2_ast_equivalent": prep.get("ast_equivalent"),
                          "g2_apply_clean": prep.get("apply_clean"),
                          "g2_apply_error": prep.get("apply_error", "")})
            if rd:
                entry["g2_token_ratio_proxy"] = round(tokens_estimate(pd) /
                                                      tokens_estimate(rd), 3)
        except Exception as e:
            entry["g2_error"] = str(e)[:200]
        results[cve] = entry
    if args.json:
        print(json.dumps(results, ensure_ascii=False, indent=1))
    else:
        for cve, e in results.items():
            print(cve, json.dumps(e, ensure_ascii=False)[:320])
