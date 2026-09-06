# -*- coding: utf-8 -*-
"""v4_gates_smoke.py：G1/G2 全量门禁测试 + 持久化 JSON 报告 + 失败记录。

用法：python cpg/ablation/v4_gates_smoke.py --cves <cves> --out <report.json>
exit 0 = 全部 G1/G2 通过；非 0 = 存在失败（报告内记 fail 原因）。
这是 Gate A 候选包机器验证的雏形——失败记录随报告持久化，不只在终端。
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))
from cpg.ablation.v4_patch_gen import (gen_complete_real_diff, apply_and_verify,
                                       gen_placebo_diff, diff_sha256, tokens_estimate)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cves", nargs="+", required=True)
    ap.add_argument("--out", default="cpg/ablation/.work/v4_gates_report.json")
    args = ap.parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    import platform, subprocess as _sp, hashlib as _hl
    _gen_src = Path('cpg/ablation/v4_patch_gen.py').read_text(encoding='utf-8')
    report = {"generated_from": {
        "git_commit": _sp.run(["git", "rev-parse", "HEAD"], capture_output=True,
                              text=True, encoding="utf-8").stdout.strip(),
        "generator_sha256": _hl.sha256(_gen_src.encode('utf-8')).hexdigest(),
        "python": platform.python_version(),
        "git_version": _sp.run(["git", "--version"], capture_output=True,
                               text=True, encoding="utf-8").stdout.strip(),
        "invocation": " ".join(sys.argv),
    }, "cves": {}}
    all_ok = True
    for cve in args.cves:
        e = {}
        try:
            rd, rrep = gen_complete_real_diff(cve)
            ok, msg = apply_and_verify(cve, rd)
            e["g1"] = {"files": rrep["n_files"], "added": rrep["added"],
                       "deleted": rrep["deleted"], "renamed": rrep["renamed"],
                       "binary": rrep["binary"], "len_chars": len(rd),
                       "diff_sha256": diff_sha256(rd), "tree": msg, "pass": ok}
            if not ok:
                all_ok = False
        except Exception as ex:
            e["g1"] = {"pass": False, "error": str(ex)[:200]}; all_ok = False
        try:
            pd, prep = gen_placebo_diff(cve)
            e["g2"] = {"len_chars": len(pd), "edits": prep.get("edits"),
                       "ast_equivalent": prep.get("ast_equivalent"),
                       "apply_clean": prep.get("apply_clean"),
                       "apply_error": prep.get("apply_error", "")}
            if rd and pd:
                e["g2"]["token_ratio_proxy"] = round(tokens_estimate(pd) /
                                                     tokens_estimate(rd), 3)
            if not (e["g2"].get("apply_clean") and e["g2"].get("ast_equivalent")):
                all_ok = False
        except Exception as ex:
            e["g2"] = {"pass": False, "error": str(ex)[:200]}; all_ok = False
        report["cves"][cve] = e
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"[report] 已写 {out}")
    print("[RESULT]", "G1_G2_STRUCTURAL_PASS" if all_ok else "HAS_FAILURES")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
