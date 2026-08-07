"""Turn CodeQL CSV exports into an LLM-readable CPG text slice.

Input : output/{ast,cfg,dfg,taint}.csv produced by queries/*.ql
Output: output/slice_<function>.txt

Design notes
------------
The raw CodeQL tables are node-level and extremely noisy (expression
evaluation order shows up as CFG edges). An LLM does not need that. What it
needs is:

  1. the source, with line numbers, so every claim can be grounded;
  2. branch structure, so it can reason about "is this path reachable";
  3. value propagation, so it can answer "does untrusted input reach the sink";
  4. the source -> sink verdict, which is the one fact a request-only
     detector can never observe.

So we aggregate to line level by default and keep node level behind a flag.
"""

from __future__ import annotations

import argparse
import csv
from collections import OrderedDict
from pathlib import Path

CSV_ENCODING = "utf-8"


def read_rows(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open(newline="", encoding=CSV_ENCODING) as fh:
        return list(csv.DictReader(fh))


def dedupe(items: list[tuple]) -> list[tuple]:
    """Order-preserving dedupe (dict keeps insertion order in 3.7+)."""
    return list(OrderedDict.fromkeys(items))


def render_source(source_path: Path, first_line: int, last_line: int) -> str:
    lines = source_path.read_text(encoding="utf-8").splitlines()
    lo = max(1, first_line)
    hi = min(len(lines), last_line)
    width = len(str(hi))
    return "\n".join(f"L{str(n).rjust(width)} | {lines[n - 1]}" for n in range(lo, hi + 1))


def clean_node(text: str) -> str:
    """Strip CodeQL's verbose ControlFlowNode wrapper."""
    prefix = "ControlFlowNode for "
    return text[len(prefix):] if text.startswith(prefix) else text


def cfg_label(line: int, node_text: str) -> str:
    """Entry/exit nodes both sit on the `def` line, which reads as a bogus back-edge."""
    if node_text.startswith("Entry node"):
        return "[entry]"
    if node_text.startswith("Exit node"):
        return "[exit]"
    return f"L{line}"


def build_cfg_section(rows: list[dict[str, str]], func: str, node_level: bool) -> list[str]:
    edges: list[tuple] = []
    for r in rows:
        if r["func"] != func:
            continue
        src, dst = int(r["fromLine"]), int(r["toLine"])
        kind = r["edgeKind"]
        if node_level:
            edges.append((src, clean_node(r["fromNode"]), kind, dst, clean_node(r["toNode"])))
            continue
        src_label = cfg_label(src, r["fromNode"])
        dst_label = cfg_label(dst, r["toNode"])
        # Line level: intra-line "next" edges are just evaluation order -> drop.
        if kind == "next" and src_label == dst_label:
            continue
        edges.append((src, src_label, kind, dst, dst_label))

    edges = dedupe(edges)
    if node_level:
        edges.sort()
    else:
        # entry first, exit last, everything else by source line.
        rank = {"[entry]": (-1, ""), "[exit]": (10**9, "")}
        edges.sort(key=lambda e: (rank.get(e[1], (e[0], e[1])), e[2], e[3], e[4]))

    out = []
    for e in edges:
        if node_level:
            src, s_txt, kind, dst, d_txt = e
            out.append(f"L{src} {s_txt}  --{kind}-->  L{dst} {d_txt}")
        else:
            _, s_label, kind, _, d_label = e
            arrow = "-->" if kind == "next" else f"--{kind}-->"
            out.append(f"{s_label}  {arrow}  {d_label}")
    return out


def build_dfg_section(rows: list[dict[str, str]], func: str) -> list[str]:
    own = [r for r in rows if r["func"] == func]
    # A phi node is placed on the first CFG node of the merge block, so its raw label
    # ("ControlFlowNode for db") is actively misleading wherever it appears — both as
    # the target of a phi edge and as the definition of a later def-use edge.
    phi_sites = {(int(r["toLine"]), r["variable"]) for r in own if r["edgeKind"] == "phi"}

    def label(line: int, text: str, var: str) -> str:
        return f"phi({var})" if (line, var) in phi_sites else clean_node(text)

    edges: list[tuple] = []
    for r in own:
        var, kind = r["variable"], r["edgeKind"]
        src, dst = int(r["fromLine"]), int(r["toLine"])
        src_txt = label(src, r["fromNode"], var)
        dst_txt = f"phi({var})" if kind == "phi" else label(dst, r["toNode"], var)
        edges.append((src, src_txt, kind, dst, dst_txt, var))

    edges = dedupe(edges)
    edges.sort()
    return [
        f"[{var}] L{a} {at}  --{kind}-->  L{b} {bt}"
        for a, at, kind, b, bt, var in edges
    ]


def build_taint_section(rows: list[dict[str, str]], source_path: Path) -> list[str]:
    """CodeQL's node labels ("ControlFlowNode for Attribute()") are unreadable.

    The line of real source is both shorter and more informative, so quote that
    and keep the node label only as a disambiguator.
    """
    src_lines = source_path.read_text(encoding="utf-8").splitlines()

    def quote(line: int) -> str:
        return src_lines[line - 1].strip() if 1 <= line <= len(src_lines) else "?"

    edges = dedupe(
        [
            (int(r["sourceLine"]), r["sourceNode"], int(r["sinkLine"]), r["sinkNode"])
            for r in rows
        ]
    )
    edges.sort()
    return [
        f"UNTRUSTED  L{a}: {quote(a)}\n"
        f"           ==> reaches sink at L{b}: {quote(b)}\n"
        f"           (flow: {clean_node(at)} -> {clean_node(bt)})"
        for a, at, b, bt in edges
    ]


def function_line_range(ast_rows: list[dict[str, str]], func: str) -> tuple[int, int]:
    lines = [
        int(v)
        for r in ast_rows
        if r["func"] == func
        for v in (r["parentLine"], r["childLine"])
    ]
    if not lines:
        raise SystemExit(f"function {func!r} not found in ast.csv")
    return min(lines), max(lines)


def build_ast_section(rows: list[dict[str, str]], func: str) -> list[str]:
    edges = dedupe(
        [
            (
                int(r["parentLine"]),
                r["parentKind"],
                r["parentText"],
                int(r["childLine"]),
                r["childKind"],
                r["childText"],
            )
            for r in rows
            if r["func"] == func
        ]
    )
    edges.sort()
    return [
        f"L{pl} {pk}({pt})  ->  L{cl} {ck}({ct})" for pl, pk, pt, cl, ck, ct in edges
    ]


def build_slice(
    out_dir: Path, source: Path, func: str, node_level: bool, include_ast: bool = False
) -> str:
    ast_rows = read_rows(out_dir / "ast.csv")
    cfg_rows = read_rows(out_dir / "cfg.csv")
    dfg_rows = read_rows(out_dir / "dfg.csv")
    taint_rows = read_rows(out_dir / "taint.csv")

    first, last = function_line_range(ast_rows, func)
    # The def line sits one above the first statement we can see in the AST.
    first = max(1, first - 1)

    cfg = build_cfg_section(cfg_rows, func, node_level)
    dfg = build_dfg_section(dfg_rows, func)
    taint = build_taint_section(taint_rows, source)

    parts = [
        f"# CPG SLICE — {source.name}::{func}",
        "",
        "## SOURCE",
        render_source(source, first, last),
        "",
        "## CONTROL FLOW",
        *(cfg or ["(no control-flow edges extracted)"]),
        "",
        "## DATA FLOW (SSA def-use, phi = branch merge)",
        *(dfg or ["(no data-flow edges extracted)"]),
        "",
        "## TAINT VERDICT",
        *(taint or ["(no untrusted input reaches a modelled sink)"]),
        "",
    ]
    # The AST is intentionally omitted by default: for an LLM the source text above
    # already encodes it, and duplicating it burns tokens without adding signal.
    # CFG / DFG / taint are the parts a model cannot reliably infer from text alone.
    # Whether that assumption holds is itself an ablation we can run later.
    if include_ast:
        parts += ["## AST", *build_ast_section(ast_rows, func), ""]
    return "\n".join(parts)


def main() -> None:
    here = Path(__file__).resolve().parent
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out-dir", type=Path, default=here / "output")
    ap.add_argument("--source", type=Path, default=here / "samples" / "cve_sqli_demo.py")
    ap.add_argument("--function", default="get_user_profile")
    ap.add_argument(
        "--node-level",
        action="store_true",
        help="keep raw node-level CFG edges instead of aggregating to lines",
    )
    ap.add_argument(
        "--include-ast",
        action="store_true",
        help="append the AST edge list (off by default, see build_slice docstring)",
    )
    args = ap.parse_args()

    text = build_slice(
        args.out_dir, args.source, args.function, args.node_level, args.include_ast
    )
    dest = args.out_dir / f"slice_{args.function}.txt"
    dest.write_text(text, encoding="utf-8")
    print(text)
    print(f"\n[written] {dest}")


if __name__ == "__main__":
    main()
