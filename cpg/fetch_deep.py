#!/usr/bin/env python3
"""深度采集 advisory 全量（cursor 分页 + 重试）——扩样本用。

GitHub Advisory API 使用 cursor 分页（Link header 的 rel="next" after 参数），
``page`` 参数被忽略（所有 page 返回同一批）。本脚本沿 Link header 逐页拉取，
每页重试 3 次，合并进 raw_advisories.json（按 ghsa_id 去重）。
用法：
    python cpg/fetch_deep.py --max-pages 60 --eco pip
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RAW = ROOT / "raw_advisories.json"
TOKEN = os.environ.get("GITHUB_TOKEN", "")

_HDR_TMP = Path("C:/tmp/gh_hdrs.txt")
_BODY_TMP = Path("C:/tmp/gh_body.json")


def fetch_page(url: str, retries: int = 3):
    """返回 (data_list, next_url_or_None)。"""
    auth = ["-H", f"Authorization: Bearer {TOKEN}"] if TOKEN else []
    for attempt in range(1, retries + 1):
        try:
            r = subprocess.run(
                ["curl", "-sS", "-m", "30", "-D", str(_HDR_TMP), "-o", str(_BODY_TMP),
                 "-H", "Accept: application/vnd.github+json",
                 "-H", "X-GitHub-Api-Version: 2022-11-28", *auth, url],
                capture_output=True, text=True, timeout=60)
            hdrs = _HDR_TMP.read_text(encoding="utf-8", errors="ignore") if _HDR_TMP.exists() else ""
            m = re.search(r"<([^>]+)>;\s*rel=\"next\"", hdrs)
            nxt = m.group(1) if m else None
            if _BODY_TMP.exists():
                data = json.loads(_BODY_TMP.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    return data, nxt
            err = r.stderr[:120]
        except Exception as exc:
            err = str(exc)[:120]
        print(f"  [retry {attempt}/{retries}] {url[:90]} failed: {err}")
        time.sleep(5)
    return [], None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-pages", type=int, default=60)
    ap.add_argument("--eco", type=str, default="pip")
    ap.add_argument("--sort", type=str, default="published")
    args = ap.parse_args()

    cached: dict[str, dict] = {}
    if RAW.exists():
        try:
            for a in json.loads(RAW.read_text(encoding="utf-8")):
                if a.get("ghsa_id"):
                    cached[a["ghsa_id"]] = a
        except Exception:
            pass
    print(f"[init] cached {len(cached)} advisories")

    url = (f"https://api.github.com/advisories?ecosystem={args.eco}"
           f"&per_page=100&sort={args.sort}")
    total_new = 0
    for i in range(args.max_pages):
        data, nxt = fetch_page(url)
        if not data:
            print(f"[stop] page {i+1} empty/failed")
            break
        new = 0
        for a in data:
            gid = a.get("ghsa_id")
            if gid and gid not in cached:
                cached[gid] = a
                new += 1
        total_new += new
        print(f"[fetch] page {i+1}: +{new} new (total {len(cached)})")
        if not nxt:
            print("[done] no more pages")
            break
        url = nxt
        time.sleep(1)  # 避免限流

    out = list(cached.values())
    RAW.write_text(json.dumps(out, indent=1), encoding="utf-8")
    print(f"[ok] saved {len(out)} unique advisories -> {RAW} (+{total_new} this run)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
