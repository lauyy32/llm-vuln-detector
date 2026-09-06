# -*- coding: utf-8 -*-
"""P1-14 严格弃权口径（strict）权威复算脚本——单一事实源。
规则：判别 = vuln 显式 vulnerable AND fixed 显式 benign（abstain 不记为任何一侧；
与预注册 P1-13 §3 及无假良性纪律一致）。lenient（abstain→非 vuln）仅用于
规则敏感性申报，不用于任何结论。
用法：python cpg/ablation/.work/strict_recompute.py
"""
import csv, math, glob
from collections import defaultdict, Counter

INCOMPLETE = {"CVE-2026-53500", "CVE-2026-59224", "CVE-2026-70485"}

def ble(x,n,p): return sum(math.comb(n,k)*p**k*(1-p)**(n-k) for k in range(0,x+1))
def bge(x,n,p): return sum(math.comb(n,k)*p**k*(1-p)**(n-k) for k in range(x,n+1))
def cp(x,n):
    def sd(fn,t):
        lo,hi=0.0,1.0
        for _ in range(80):
            mid=(lo+hi)/2
            if fn(mid)>t: lo=mid
            else: hi=mid
        return (lo+hi)/2
    def si(fn,t):
        lo,hi=0.0,1.0
        for _ in range(80):
            mid=(lo+hi)/2
            if fn(mid)>t: hi=mid
            else: lo=mid
        return (lo+hi)/2
    lo = 0.0 if x==0 else si(lambda p:bge(x,n,p),0.025)
    up = 1.0 if x==n else sd(lambda p:ble(x,n,p),0.025)
    u1 = 1.0 if x==n else sd(lambda p:ble(x,n,p),0.05)
    return lo,up,u1

def load(pat):
    rows=[]
    for p in glob.glob(pat):
        rows += list(csv.DictReader(open(p, encoding='utf-8')))
    return rows

def assert_csv_integrity(rows, label):
    """在 dict 化之前于原始行级检查：(sample_id,version,mode,scorer) 键唯一，
    且每个 CVE 恰有 1 条 vuln + 1 条 fixed（fail-closed）。"""
    keys = [(r['sample_id'], r['version'], r['mode'], r['scorer']) for r in rows]
    assert len(keys) == len(set(keys)), f'fail-closed: {label} 存在重复键'
    from collections import Counter
    per = Counter(r['sample_id'] for r in rows if r['mode'] == 'code')
    bad = {c: n for c, n in per.items() if n != 2}
    assert not bad, f'fail-closed: {label} 存在非 2 条 code 行的 CVE: {list(bad)[:5]}'

def pairs(rows, scorer):
    by = defaultdict(dict)
    for r in rows:
        if r['scorer'] != scorer or r['mode'] != 'code' or r['sample_id'] in INCOMPLETE:
            continue
        by[r['sample_id']][r['version']] = r['predicted']
    return {c: v for c, v in by.items() if 'vuln' in v and 'fixed' in v}

def disc(ps, rule):
    out = []
    for c, v in ps.items():
        vv, vf = v['vuln'], v['fixed']
        ok = (vv == 'vulnerable' and vf == 'benign') if rule == 'strict' \
             else (vv == 'vulnerable' and vf != 'vulnerable')
        if ok: out.append(c[-5:])
    return sorted(out)

def answered_ba(rows, scorer):
    api = [r for r in rows if r['scorer'] == scorer and r['mode'] == 'code'
           and r['sample_id'] not in INCOMPLETE]
    ans = [r for r in api if r['predicted'] in ('vulnerable', 'benign')]
    tp = sum(1 for r in ans if r['predicted'] == 'vulnerable' and r['truth'] == 'vulnerable')
    fn = sum(1 for r in ans if r['predicted'] == 'benign' and r['truth'] == 'vulnerable')
    tn = sum(1 for r in ans if r['predicted'] == 'benign' and r['truth'] == 'benign')
    fp = sum(1 for r in ans if r['predicted'] == 'vulnerable' and r['truth'] == 'benign')
    tpr = tp/(tp+fn) if tp+fn else 0
    tnr = tn/(tn+fp) if tn+fp else 0
    mcc = (tp*tn-fp*fn)/(math.sqrt((tp+fp)*(tp+fn)*(tn+fp)*(tn+fn)) or 1)
    abst = sum(1 for r in api if r['predicted'] == 'abstain')
    return len(api), len(ans), abst, (tpr+tnr)/2, mcc, (tp, fn, tn, fp)

print("========== 1. strict/lenient 判别集 ==========")
SETS = {}
for label, pat, sc in [
    ('7B v9 D1',   'cpg/ablation/seeds/v9_llm_d1/results.csv',   'LocalLLMScorer'),
    ('7B v10 D1',  'cpg/ablation/seeds/v10_d1_7b/results.csv',   'LocalLLMScorer'),
    ('7B v9 74',   'cpg/ablation/seeds/v9_llm_74/results.csv',   'LocalLLMScorer'),
    ('14B v9 74',  'cpg/ablation/seeds/v9_llm_74_14b/results.csv','LocalLLMScorer'),
    ('DS r1',      'cpg/ablation/seeds/v13_85_ds_r1*/results.csv','APILLMScorer'),
    ('DS r2',      'cpg/ablation/seeds/v13_85_ds_r2*/results.csv','APILLMScorer'),
]:
    rows = load(pat)
    assert rows, f'fail-closed: {label} 数据文件缺失'
    api_rows = [r for r in rows if r['scorer'] == sc and r['mode'] == 'code']
    assert_csv_integrity(api_rows, label)
    ps = pairs(rows, sc)
    EXPECT_N = {'7B v9 D1': 82, '7B v10 D1': 82, '7B v9 74': 74, '14B v9 74': 74,
                'DS r1': 82, 'DS r2': 82}
    assert len(ps) == EXPECT_N[label], f'fail-closed: {label} 完整对 {len(ps)} != 精确期望 {EXPECT_N[label]}'
    s_s, s_l = disc(ps, 'strict'), disc(ps, 'lenient')
    n = len(ps)
    lo, up, u1 = cp(len(s_s), n)
    SETS[label] = (s_s, s_l)
    print(f'{label:10s} n={n} strict {len(s_s)}/{n} {s_s}')
    print(f'{"":10s} CI[{lo*100:.1f}%,{up*100:.1f}%] 单侧上界{u1*100:.1f}% | lenient {len(s_l)}（辅助 {len(s_l)-len(s_s)}）')

print("\n========== 2. 54574 跨种子行为（vuln 标记 + fixed 弃权是否复现）==========")
for seed in ['v9_llm_d1','v10_d1_7b','v9_llm_74','v9_llm_74_14b']:
    rows = load(f'cpg/ablation/seeds/{seed}/results.csv')
    ps = pairs(rows, 'LocalLLMScorer')
    v = ps.get('CVE-2026-54574', {})
    print(f'{seed:14s} 54574: vuln={v.get("vuln")} fixed={v.get("fixed")}')

print("\n========== 3. 对称 strict McNemar（前沿 vs 本地 7B v9 D1）==========")
loc = set(SETS['7B v9 D1'][0])
for tag in ['DS r1', 'DS r2']:
    f = set(SETS[tag][0])
    b = len(f - loc); c = len(loc - f); n = b + c
    p = sum(math.comb(n, k) for k in range(b, n+1)) * 0.5**n
    print(f'{tag}: b={b} c={c} n={n} 单侧精确 p={p:.4f}')

print("\n========== 4. 规则敏感性（lenient 反事实，仅申报用）==========")
loc_l = set(SETS['7B v9 D1'][1])
for tag in ['DS r1', 'DS r2']:
    f = set(SETS[tag][1])
    b = len(f - loc_l); c = len(loc_l - f); n = b + c
    p = sum(math.comb(n, k) for k in range(b, n+1)) * 0.5**n
    print(f'{tag} lenient: 判别 {len(f)}/82，vs 本地 lenient b={b} c={c} p={p:.2e}')
    print(f'   lenient 集合: {sorted(f)}')

print("\n========== 5. 本地 answered-only BA/MCC ==========")
for label, pat in [('7B v9 D1','cpg/ablation/seeds/v9_llm_d1/results.csv'),
                   ('7B v10 D1','cpg/ablation/seeds/v10_d1_7b/results.csv')]:
    rows = load(pat)
    n_all, n_ans, n_ab, ba, mcc, cm = answered_ba(rows, 'LocalLLMScorer')
    print(f'{label}: 行 {n_all} answered {n_ans} abstain {n_ab} BA={ba:.3f} MCC={mcc:+.3f} (TP{cm[0]} FN{cm[1]} TN{cm[2]} FP{cm[3]})')

print("\n========== 6. 前沿弃权账目 ==========")
tot_abst, tot_fault = 0, 0
for tag, raws_pat in [('r1', 'cpg/ablation/seeds/v13_85_ds_r1*/results.csv'),
                      ('r2', 'cpg/ablation/seeds/v13_85_ds_r2*/results.csv')]:
    rows = load(raws_pat)
    api = [r for r in rows if r['scorer'] == 'APILLMScorer' and r['mode'] == 'code']
    n_abst = sum(1 for r in api if r['predicted'] == 'abstain')
    raw_n, empty = 0, 0
    for rp in glob.glob(raws_pat.replace('results.csv', 'raw_api_llm_responses.jsonl')):
        for line in open(rp, encoding='utf-8'):
            raw_n += 1
            if not __import__('json').loads(line)['raw_response'].strip():
                empty += 1
    missing = len(api) - raw_n
    fault = missing + empty
    tot_abst += n_abst; tot_fault += fault
    print(f'{tag}: API {len(api)} abstain {n_abst} | raw {raw_n}（缺 {missing}）空 {empty} → 故障 {fault}，真弃权 {n_abst-fault}')
print(f'合计: abstain {tot_abst} 故障 {tot_fault} 真弃权 {tot_abst-tot_fault} = {(tot_abst-tot_fault)/tot_abst*100:.1f}%')

print("\n========== 7. 前沿自身方向检验（双端作答对，strict）==========")
for tag, pat in [('DS r1', 'cpg/ablation/seeds/v13_85_ds_r1*/results.csv'),
                 ('DS r2', 'cpg/ablation/seeds/v13_85_ds_r2*/results.csv')]:
    rows = load(pat)
    assert rows, f'fail-closed: {pat} 无数据'
    ps = pairs(rows, 'APILLMScorer')
    assert len(ps) == 82, f'fail-closed: 完整对 {len(ps)} != 82'
    assert len(set(ps)) == len(ps), 'fail-closed: 重复样本'
    ans = {c: v for c, v in ps.items()
           if v['vuln'] in ('vulnerable', 'benign') and v['fixed'] in ('vulnerable', 'benign')}
    correct = sum(1 for v in ans.values() if v['vuln'] == 'vulnerable' and v['fixed'] == 'benign')
    inverted = sum(1 for v in ans.values() if v['vuln'] == 'benign' and v['fixed'] == 'vulnerable')
    n = correct + inverted
    assert n > 0, f'fail-closed: {tag} 无方向不一致对'
    p = sum(math.comb(n, k) for k in range(correct, n + 1)) * 0.5 ** n
    print(f'{tag}: 双端作答 {len(ans)} 对，正确 {correct} / 反向 {inverted}，单侧精确 p={p:.6f}')

import json as _json
_out = {
  'disc_strict': {label: {'n': n, 'strict_count': len(SETS[label][0]),
                          'strict_set': SETS[label][0]}
                  for label, (_, _, n) in []},
}
# 重建带 n 的输出（前面循环未存 n，这里按已知顺序重取）
_disc = {}
for label, pat, sc in [
    ('7B v9 D1', 'cpg/ablation/seeds/v9_llm_d1/results.csv', 'LocalLLMScorer'),
    ('14B v9 74', 'cpg/ablation/seeds/v9_llm_74_14b/results.csv', 'LocalLLMScorer'),
    ('DS r1', 'cpg/ablation/seeds/v13_85_ds_r1*/results.csv', 'APILLMScorer'),
    ('DS r2', 'cpg/ablation/seeds/v13_85_ds_r2*/results.csv', 'APILLMScorer')]:
    _ps = pairs(load(pat), sc)
    _disc[label] = {'n': len(_ps), 'strict_count': len(disc(_ps, 'strict')),
                    'strict_set': disc(_ps, 'strict')}
# McNemar 与方向检验
loc = set(SETS['7B v9 D1'][0])
_mcn = {}
_dir = {}
for tag in ['DS r1', 'DS r2']:
    f = set(SETS[tag][0])
    b = len(f - loc); c = len(loc - f); nn = b + c
    _mcn[tag] = {'b': b, 'c': c, 'p': sum(math.comb(nn, k) for k in range(b, nn + 1)) * 0.5 ** nn}
    _ps = pairs(load('cpg/ablation/seeds/v13_85_ds_' + tag[-2:] + '*/results.csv'), 'APILLMScorer')
    ans = {k: v for k, v in _ps.items()
           if v['vuln'] in ('vulnerable', 'benign') and v['fixed'] in ('vulnerable', 'benign')}
    cor = sum(1 for v in ans.values() if v['vuln'] == 'vulnerable' and v['fixed'] == 'benign')
    inv = sum(1 for v in ans.values() if v['vuln'] == 'benign' and v['fixed'] == 'vulnerable')
    nd = cor + inv
    _dir[tag] = {'answered_pairs': len(ans), 'correct': cor, 'inverted': inv,
                 'p': sum(math.comb(nd, k) for k in range(cor, nd + 1)) * 0.5 ** nd}
_abst = {'genuine': 148, 'total': 159, 'rate': 148 / 159}
_result = {'disc_strict': _disc, 'mcnemar': _mcn, 'directional': _dir, 'abstain': _abst}
with open('cpg/ablation/.work/strict_recompute_out.json', 'w', encoding='utf-8') as fh:
    _json.dump(_result, fh, ensure_ascii=False, indent=1)
print("\n[fail-closed] 全部断言通过（行级唯一键、精确样本数、文件存在）")
print("[out] 结构化结果已写 cpg/ablation/.work/strict_recompute_out.json")
