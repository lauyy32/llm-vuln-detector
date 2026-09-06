# -*- coding: utf-8 -*-
"""G-3 复算门禁执行器（v2，真验证器）：
- claims.json 是唯一事实源：逐 claim 读取 expect/n/data/script；
- 脚本路径用 git ls-files 精确行匹配（非子串）；
- data 字段必须指向真实存在的文件（支持 glob）；
- 重复 claim ID 报错；
- 运行 strict_recompute.py → 读其结构化输出 strict_recompute_out.json，
  逐字段与 expect 精确比较（浮点容差 1e-6）；
fail-closed：任何缺失/不符即非零退出。
用法：python cpg/ablation/.work/verify_claims.py
"""
import glob, json, math, os, subprocess, sys

CLAIMS = 'cpg/ablation/.work/claims.json'
OUT = 'cpg/ablation/.work/strict_recompute_out.json'
TOL = 1e-6


def fail(msg):
    print(f'[FAIL] {msg}')
    return False


def approx(a, b):
    try:
        return math.isclose(float(a), float(b), abs_tol=TOL)
    except (TypeError, ValueError):
        return False


def main() -> int:
    claims = json.load(open(CLAIMS, encoding='utf-8'))['claims']
    ok = True

    # 0) 重复 claim ID
    ids = [c['id'] for c in claims]
    if len(ids) != len(set(ids)):
        ok = fail(f'重复 claim ID: {[i for i in ids if ids.count(i) > 1]}')

    # 1) 脚本精确在库 + data 文件存在
    tracked = subprocess.run(['git', 'ls-files'], capture_output=True, text=True).stdout.splitlines()
    for c in claims:
        if c['script'] not in tracked:
            ok = fail(f"脚本未入库（精确匹配）: {c['script']}（{c['id']}）")
        for d in c.get('data_files', []):
            if not glob.glob(d):
                ok = fail(f"数据文件不存在: {d}（{c['id']}）")

    # 2) 运行复算脚本并读结构化输出
    r = subprocess.run([sys.executable, 'cpg/ablation/.work/strict_recompute.py'],
                       capture_output=True, text=True)
    if r.returncode != 0:
        print('[FAIL] strict_recompute.py 运行失败:'); print(r.stderr[-400:]); return 1
    res = json.load(open(OUT, encoding='utf-8'))

    # 3) 逐 claim 逐字段精确比较
    for c in claims:
        cid, exp = c['id'], c['expect']
        if cid in ('local7b_strict_disc_d1', 'local14b_strict_disc_74',
                   'frontier_strict_disc_r1'):
            key = {'local7b_strict_disc_d1': '7B v9 D1',
                   'local14b_strict_disc_74': '14B v9 74',
                   'frontier_strict_disc_r1': 'DS r1'}[cid]
            got_n = res['disc_strict'][key]['n']
            got_c = res['disc_strict'][key]['strict_count']
            if got_n != c['n']:
                ok = fail(f"{cid}: n {got_n} != expect {c['n']}")
            if got_c != exp:
                ok = fail(f"{cid}: strict_count {got_c} != expect {exp}")
            else:
                print(f'[ok] {cid}: {got_c}/{got_n}')
        elif cid == 'frontier_vs_local_mcnemar':
            got = res['mcnemar']['DS r1']
            for k in ('b', 'c'):
                if got[k] != exp[k]:
                    ok = fail(f"{cid}.{k}: {got[k]} != {exp[k]}")
            if not approx(got['p'], exp['p']):
                ok = fail(f"{cid}.p: {got['p']} != {exp['p']}")
            if ok:
                print(f"[ok] {cid}: b={got['b']} c={got['c']} p={got['p']:.4f}")
        elif cid.startswith('frontier_directional_'):
            tag = 'DS r1' if cid.endswith('r1') else 'DS r2'
            got = res['directional'][tag]
            for k in ('correct', 'inverted', 'answered_pairs'):
                if got[k] != exp[k]:
                    ok = fail(f"{cid}.{k}: {got[k]} != {exp[k]}")
            if not approx(got['p'], exp['p']):
                ok = fail(f"{cid}.p: {got['p']} != {exp['p']}")
            if ok:
                print(f"[ok] {cid}: {got['correct']}/{got['inverted']} p={got['p']:.6f} ({got['answered_pairs']} 对)")
        elif cid == 'frontier_abstain_genuine_rate':
            got = res['abstain']
            if got['genuine'] != exp['genuine'] or got['total'] != exp['total'] \
               or not approx(got['rate'], exp['rate']):
                ok = fail(f"{cid}: {got} != {exp}")
            else:
                print(f"[ok] {cid}: {got['genuine']}/{got['total']} = {got['rate']:.3f}")
        else:
            ok = fail(f"unknown claim id: {cid}")

    print('\nVERIFY_CLAIMS:', 'PASS' if ok else 'FAIL')
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
