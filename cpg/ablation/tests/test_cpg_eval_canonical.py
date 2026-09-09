# -*- coding: utf-8 -*-
"""cpg_eval 的 canonical 行序测试：确定性排序与行哈希全序性。

目标：验证 sort_taint_rows_canonical 对同一「集合」不同「顺序」输入产出相同结果，
且排序键在 (cwe, rel_path, source/sink line, node) 全相同（行哈希兜底）时仍为全序。
"""
import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from cpg.ablation import cpg_eval  # noqa: E402


def _row(cwe, rel, src, snk, sn=None, kn=None, abs_path=None, file=None):
    return {
        "cwe": cwe,
        "file": file or rel.rsplit("/", 1)[-1],
        "sourceLine": src,
        "sinkLine": snk,
        "sourceNode": sn or f"node-src-{rel}-{src}",
        "sinkNode": kn or f"node-snk-{rel}-{snk}",
        "abs_path": abs_path or f"C:/x/staging/corpus_src/CVE-2026-45019_vuln/{rel}",
    }


class TestCanonicalSort(unittest.TestCase):
    def test_stable_across_permutations(self):
        rows = [
            _row("CWE-022", "backend/mcp.py", 10, 40),
            _row("CWE-022", "backend/mcp.py", 5, 30),
            _row("CWE-089", "db/query.py", 1, 2),
            _row("CWE-078", "a.py", 7, 8),
        ]
        import itertools
        canon = [cpg_eval.canonical_row_hash(r) for r in
                 cpg_eval.sort_taint_rows_canonical(rows)]
        for perm in itertools.permutations(rows):
            got = [cpg_eval.canonical_row_hash(r) for r in
                   cpg_eval.sort_taint_rows_canonical(list(perm))]
            self.assertEqual(got, canon, "排序结果必须与输入顺序无关")

    def test_sorted_by_cwe_then_rel_then_lines(self):
        rows = [
            _row("CWE-078", "z.py", 1, 1),
            _row("CWE-022", "a.py", 1, 1),
            _row("CWE-022", "a.py", 1, 9),   # 同 CWE/路径，sink 行不同
            _row("CWE-022", "b.py", 1, 1),
        ]
        got = cpg_eval.sort_taint_rows_canonical(rows)
        self.assertEqual([r["cwe"] for r in got],
                         ["CWE-022", "CWE-022", "CWE-022", "CWE-078"])
        # CWE-022 内部按 rel_path 排序：a.py 先于 b.py；a.py 内按 source/sink 行
        self.assertEqual([(r["file"], r["sinkLine"]) for r in got[:3]],
                         [("a.py", 1), ("a.py", 9), ("b.py", 1)])

    def test_duplicate_fields_total_order_by_row_hash(self):
        # (cwe, rel, src, snk, sourceNode, sinkNode) 全同，仅靠行哈希兜底仍稳定
        r1 = _row("CWE-022", "x.py", 3, 4, sn="S", kn="K")
        r2 = _row("CWE-022", "x.py", 3, 4, sn="S", kn="K")
        # 给二者一个不同字段制造真实差异（abs_path 不同），行哈希仍全序
        r2["abs_path"] = r2["abs_path"].replace("vuln", "fixed")
        got = cpg_eval.sort_taint_rows_canonical([r2, r1])
        self.assertEqual([cpg_eval.canonical_row_hash(r) for r in got],
                         sorted([cpg_eval.canonical_row_hash(r1),
                                 cpg_eval.canonical_row_hash(r2)]))

    def test_row_hash_independent_of_dict_order(self):
        r = {"a": "1", "b": "2", "c": "3"}
        r_rev = dict(reversed(list(r.items())))
        self.assertEqual(cpg_eval.canonical_row_hash(r),
                         cpg_eval.canonical_row_hash(r_rev))

    def test_row_hash_independent_of_clone_root(self):
        # 相同行、不同仓库根路径：abs_path 前缀不同，但 row hash 必须相同
        r1 = _row("CWE-022", "backend/mcp.py", 10, 40,
                  abs_path="C:/Users/lenovo/a/staging/corpus_src/CVE-2026-45019_vuln/backend/mcp.py")
        r2 = _row("CWE-022", "backend/mcp.py", 10, 40,
                  abs_path="D:/other/clone/b/staging/corpus_src/CVE-2026-45019_vuln/backend/mcp.py")
        self.assertEqual(cpg_eval.canonical_row_hash(r1),
                         cpg_eval.canonical_row_hash(r2),
                         "row hash 不得受仓库根路径影响")

    def test_sort_and_render_identical_across_clone_roots(self):
        # 相同行集合、不同根路径 → 排序顺序与渲染文本完全一致
        def build(root):
            return [
                _row("CWE-022", "b.py", 1, 2, abs_path=f"{root}/corpus_src/CVE-2026-45019_vuln/b.py"),
                _row("CWE-022", "a.py", 3, 4, abs_path=f"{root}/corpus_src/CVE-2026-45019_vuln/a.py"),
                _row("CWE-089", "z.py", 5, 6, abs_path=f"{root}/corpus_src/CVE-2026-45019_vuln/z.py"),
            ]
        s1 = cpg_eval.build_cpg_slices_text(
            cpg_eval.sort_taint_rows_canonical(build("C:/Users/lenovo/clone1")), "")
        s2 = cpg_eval.build_cpg_slices_text(
            cpg_eval.sort_taint_rows_canonical(build("D:/mnt/elsewhere/clone2")), "")
        self.assertEqual(s1, s2)

    def test_relative_path_extraction(self):
        ap = "C:/x/staging/corpus_src/CVE-2026-45019_vuln/backend/chainlit/mcp.py"
        self.assertEqual(cpg_eval._relative_path(ap), "backend/chainlit/mcp.py")
        # 无侧目录标记：退化为 basename
        self.assertEqual(cpg_eval._relative_path("/a/b/c.py"), "c.py")
        self.assertEqual(cpg_eval._relative_path(None), "")

    def test_build_cpg_slices_text_order_follows_input(self):
        # 渲染顺序跟随传入行序：canonical 排序后输出可复现
        rows = [_row("CWE-089", "q.py", 1, 2), _row("CWE-022", "p.py", 3, 4)]
        s1 = cpg_eval.build_cpg_slices_text(rows, "")
        s2 = cpg_eval.build_cpg_slices_text(
            cpg_eval.sort_taint_rows_canonical(rows), "")
        # 排序后 CWE-022 在前
        self.assertTrue(s2.index("### CWE-022") < s2.index("### CWE-089"))


if __name__ == "__main__":
    unittest.main()
