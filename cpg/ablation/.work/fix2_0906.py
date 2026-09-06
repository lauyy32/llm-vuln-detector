# -*- coding: utf-8 -*-
import io

# --- analyze_p1_13.py ---
p = 'cpg/ablation/.work/analyze_p1_13.py'
s = io.open(p, encoding='utf-8').read()

old = """    n_disc = len(disc)
    p_one = sum(math.comb(len(pairs), k) for k in range(n_disc, len(pairs) + 1)) * 0.5 ** len(pairs) \\
        if pairs else 1.0
"""
new = """    n_disc = len(disc)
    # 判别率 CP-CI（替代初版无意义"vs 0.5"稻草人检验；strict 口径）
    def _ble(x, n, p):
        return sum(math.comb(n, k) * p**k * (1 - p)**(n - k) for k in range(0, x + 1))
    def _bge(x, n, p):
        return sum(math.comb(n, k) * p**k * (1 - p)**(n - k) for k in range(x, n + 1))
    def _cp(x, n):
        def si(fn, t):
            lo, hi = 0.0, 1.0
            for _ in range(80):
                mid = (lo + hi) / 2
                if fn(mid) > t:
                    hi = mid
                else:
                    lo = mid
            return (lo + hi) / 2
        def sd(fn, t):
            lo, hi = 0.0, 1.0
            for _ in range(80):
                mid = (lo + hi) / 2
                if fn(mid) > t:
                    lo = mid
                else:
                    hi = mid
            return (lo + hi) / 2
        lo = 0.0 if x == 0 else si(lambda pp: _bge(x, n, pp), 0.025)
        up = 1.0 if x == n else sd(lambda pp: _ble(x, n, pp), 0.025)
        u1 = 1.0 if x == n else sd(lambda pp: _ble(x, n, pp), 0.05)
        return lo, up, u1
    ci_lo, ci_up, ci_u1 = _cp(n_disc, len(pairs)) if pairs else (0.0, 0.0, 0.0)
    p_one = None
"""
assert s.count(old) == 1, 'A1'
s = s.replace(old, new)

old2 = """    print(f"BA={ba:.3f} MCC={mcc:+.3f}（平凡基线 F1=0.667 不适用此任务；参考本地 7B 判别 3/82、BA=0.512）")
    print(f"判别 ≥ 观察值的单侧精确二项 p={p_one:.2e}（H0: 判别率=0.5×？仅作描述）")
"""
new2 = """    print(f"BA={ba:.3f} MCC={mcc:+.3f}（answered-only；参考本地 7B strict 判别 2/82、BA=0.514）")
    print(f"判别率 CP-CI [{ci_lo*100:.1f}%, {ci_up*100:.1f}%] 单侧95%上界 {ci_u1*100:.1f}%（strict）")
"""
assert s.count(old2) == 1, 'A2'
s = s.replace(old2, new2)

old3 = 'LOCAL_DISC = {"CVE-2026-54574", "CVE-2026-61539", "CVE-2026-67435"}  # 本地 3/82 判别集'
new3 = 'LOCAL_DISC = {"CVE-2026-61539", "CVE-2026-67435"}  # 本地 strict 2/82 判别集（54574=复现弃权行为）'
assert s.count(old3) == 1, 'A3'
s = s.replace(old3, new3)
io.open(p, 'w', encoding='utf-8', newline='').write(s)
print('analyze fixed')

# --- scorers.py _log_raw 加 version ---
p2 = 'cpg/ablation/scorers.py'
s2 = io.open(p2, encoding='utf-8').read()
old4 = '''            rec = {
                "cve_id": (ctx.advisory_meta or {}).get("cve_id"),
                "mode": "request" if (ctx.cpg_slices is None and not ctx.code_text) else
                        ("both" if ctx.request_info else "code"),'''
new4 = '''            rec = {
                "cve_id": (ctx.advisory_meta or {}).get("cve_id"),
                "version": getattr(ctx, "version", None),
                "mode": "request" if (ctx.cpg_slices is None and not ctx.code_text) else
                        ("both" if ctx.request_info else "code"),'''
assert s2.count(old4) == 1, 'S1'
s2 = s2.replace(old4, new4)
io.open(p2, 'w', encoding='utf-8', newline='').write(s2)
print('scorers fixed')
