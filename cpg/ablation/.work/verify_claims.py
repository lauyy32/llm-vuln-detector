# -*- coding: utf-8 -*-
"""G-3 复算门禁执行器：claims.json 中的脚本必须真实在 git 内，
且关键数字可由脚本复算输出。fail-closed：任何缺失/不符即非零退出。
用法：python cpg/ablation/.work/verify_claims.py
"""
import json, subprocess, sys

CLAIMS = 'cpg/ablation/.work/claims.json'

def main() -> int:
    claims = json.load(open(CLAIMS, encoding='utf-8'))['claims']
    # 1) 脚本存在性（git ls-files 为准，杜绝"声称在库实际不在"）
    tracked = subprocess.run(['git', 'ls-files'], capture_output=True, text=True).stdout
    ok = True
    for c in claims:
        sp = c['script']
        if sp not in tracked:
            print(f'[FAIL] 脚本未入库: {sp}（claim {c["id"]}）')
            ok = False
        else:
            print(f'[ok] 脚本在库: {sp}')
    if not ok:
        return 1
    # 2) 运行主复算脚本，核对关键数字以文本形式出现于输出
    r = subprocess.run([sys.executable, 'cpg/ablation/.work/strict_recompute.py'],
                       capture_output=True, text=True)
    if r.returncode != 0:
        print('[FAIL] strict_recompute.py 运行失败:'); print(r.stderr[-500:]); return 1
    out = r.stdout
    checks = [
        ("2/82", "7B strict 2/82"),
        ("0/74", "14B strict 0/74"),
        ("7/82", "前沿 7/82"),
        ("p=0.0625", "对称 strict McNemar"),
        ("0.089844", "r1 方向检验 p"),
        ("0.171875", "r2 方向检验 p"),
        ("93.1%", "真弃权率"),
    ]
    for needle, label in checks:
        if needle in out:
            print(f'[ok] {label}: 输出含 {needle}')
        else:
            print(f'[FAIL] {label}: 输出缺 {needle}')
            ok = False
    print('\nVERIFY_CLAIMS:', 'PASS' if ok else 'FAIL')
    return 0 if ok else 1

if __name__ == '__main__':
    sys.exit(main())
