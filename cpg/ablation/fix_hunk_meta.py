# -*- coding: utf-8 -*-
"""重算 hunk 元数据（用负向后行断言，修正 meta.json 漂移）。一次性工具。"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RERUN = ROOT / "cpg/ablation/.work/rerun_61539"


def _has_danger_eval(code):
    for line in code.splitlines():
        code_part = line.split("#", 1)[0]
        if re.search(r"(?<![\w.])eval\s*\(", code_part):
            return True
    return False


def main():
    for v in ("v1", "v2"):
        p = RERUN / v / "meta.json"
        d = json.loads(p.read_text(encoding="utf-8"))
        for side in ("vuln", "fixed"):
            prompt = (RERUN / v / f"{side}.prompt.txt").read_text(encoding="utf-8")
            m = re.search(r"```\n(.*?)\n```", prompt, re.DOTALL)
            code = m.group(1) if m else ""
            ct = d["prompts"][side]
            ct["hunk_eval_call"] = _has_danger_eval(code)
            ct["hunk_json_loads"] = "json.loads" in code
            ct["hunk_ast_literal_eval"] = "ast.literal_eval" in code
        p.write_text(json.dumps(d, ensure_ascii=False, indent=1), encoding="utf-8")
        print(f"{v}: vuln eval={d['prompts']['vuln']['hunk_eval_call']} "
              f"fixed eval={d['prompts']['fixed']['hunk_eval_call']} "
              f"fixed json_loads={d['prompts']['fixed']['hunk_json_loads']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
