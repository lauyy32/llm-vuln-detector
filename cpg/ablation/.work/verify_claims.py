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
import csv as csv_module
import glob, json, math, os, subprocess, sys
from pathlib import Path

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

    # 0) 语料完整性 fail-closed（2026-09-07）：五态审计存在未解决 CORPUS_ERROR 时，
    #    拒绝冻结 canonical claims（PROVISIONAL），防"语料缺陷地基上的数字被写死"。
    audit_path = Path('cpg/ablation/.work/upstream_five_state.json')
    if audit_path.exists():
        audit = json.load(open(audit_path, encoding='utf-8'))
        errs = [c for c, r in audit.items() if r['status'] == 'CORPUS_ERROR']
        if errs:
            ok = fail(f"语料错误未解决 {len(errs)} 例，拒绝冻结 canonical claims: "
                      f"{sorted(errs)[:6]}")
    else:
        ok = fail("upstream_five_state.json 缺失，无法确认语料完整性，拒绝冻结")

    # 0b) 重复 claim ID
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


def self_test() -> int:
    """负向变异测试（G-3 的门禁的门禁）：验证器在数据/账本被破坏时必须失败。"""
    import shutil, tempfile
    ok = True
    # T1 篡改 expect → 比较必须 FAIL
    claims = json.load(open(CLAIMS, encoding='utf-8'))['claims']
    c0 = next(c for c in claims if c['id'] == 'local7b_strict_disc_d1')
    res = json.load(open(OUT, encoding='utf-8'))
    got = res['disc_strict']['7B v9 D1']['strict_count']
    tampered = c0['expect'] + 1
    if got == tampered:
        ok = fail('T1 失效：篡改 expect 后仍通过')
    else:
        print(f'[ok] T1 篡改 expect({c0["expect"]}→{tampered}) 被正确拒绝')
    # T2 篡改数据（复制一行）→ strict_recompute 必须 FAIL（行级唯一键断言）
    tmp = tempfile.mkdtemp(prefix='st_t2_')
    dst = os.path.join(tmp, 'v9_llm_d1')
    shutil.copytree('cpg/ablation/seeds/v9_llm_d1', dst)
    csv_path = os.path.join(dst, 'results.csv')
    lines = open(csv_path, encoding='utf-8').read().splitlines()
    api = [i for i, l in enumerate(lines[1:], 1)
           if ',LocalLLMScorer,' in l and ',code,' in l]
    lines.insert(api[0], lines[api[0]])
    open(csv_path, 'w', encoding='utf-8', newline='').write('\n'.join(lines) + '\n')
    r = subprocess.run([sys.executable, 'cpg/ablation/.work/strict_recompute.py'],
                       capture_output=True, text=True,
                       env={**os.environ, 'ST_SEEDS': tmp})
    if r.returncode != 0 and '重复键' in (r.stderr + r.stdout):
        print('[ok] T2 复制原始行 → 行级唯一键断言正确触发 FAIL')
    else:
        ok = fail(f'T2 失效：重复行未触发 fail-closed（rc={r.returncode}）')
    # T3 篡改一行预测（61539 fixed LocalLLMScorer benign→abstain）→ strict 计数必须变化
    # 行级字符串替换（与 T2 同法）：该 CSV 含带内嵌换行的引用字段，csv 整文件往返会丢行
    tmp3 = tempfile.mkdtemp(prefix='st_t3_')
    dst3 = os.path.join(tmp3, 'v9_llm_d1')
    shutil.copytree('cpg/ablation/seeds/v9_llm_d1', dst3)
    csv3 = os.path.join(dst3, 'results.csv')
    lines_ = open(csv3, encoding='utf-8').read().splitlines()
    hit = None
    for i_, l in enumerate(lines_[1:], 1):
        if l.startswith('CVE-2026-61539,fixed,code,LocalLLMScorer,benign,'):
            hit = i_; break
    assert hit is not None, 'T3 自检：目标行定位失败'
    lines_[hit] = lines_[hit].replace(',code,LocalLLMScorer,benign,', ',code,LocalLLMScorer,abstain,', 1)
    open(csv3, 'w', encoding='utf-8', newline='').write('\n'.join(lines_) + '\n')
    r3 = subprocess.run([sys.executable, 'cpg/ablation/.work/strict_recompute.py'],
                        capture_output=True, text=True,
                        env={**os.environ, 'ST_SEEDS': tmp3})
    # v10 等目录在 tmp3 缺失属预期 fail-closed；只检查 D1 行是否从 2 变 1
    if '7B v9 D1   n=82 strict 1/82' in r3.stdout:
        print('[ok] T3 篡改预测 → strict 计数正确变化（2→1）')
    else:
        ok = fail('T3 失效：篡改预测后计数未变化\n--- r3.stdout ---\n' + r3.stdout[:300] + '\n--- stderr ---\n' + r3.stderr[-400:] + '\n--- end ---')
    print('\nSELF_TEST:', 'PASS' if ok else 'FAIL')
    return 0 if ok else 1


if __name__ == '__main__':
    if '--self-test' in sys.argv:
        sys.exit(self_test())
    sys.exit(main())
