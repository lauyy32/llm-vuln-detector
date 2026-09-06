# -*- coding: utf-8 -*-
"""McNemar（exact binomial）功效/可检测效应分析（P0-3 要求，纯标准库可复算）。

背景：主 estimand = 确认性合格样本中 real vs partial 的配对判定差异。
McNemar 检验的有效信息量在 **discordant pairs**（b + c = m），不在总样本 n。
本脚本对给定 discordant pairs 数 m 与效应 p1 = b/m，计算双侧 exact binomial
检验（α=0.05）的功效，回答"m 个 discordant 下能检测到多大的不对称"。

用法：python cpg/ablation/mcnemar_power.py [--m-max 15]
"""
import argparse
from math import comb


def binom_pdf(m, p):
    return [comb(m, k) * (p ** k) * ((1 - p) ** (m - k)) for k in range(m + 1)]


def two_sided_p_value(b, m):
    """双侧 exact binomial p 值：2 * min(P(X>=b), P(X<=b))，X~Bin(m, 0.5)。"""
    pmf = binom_pdf(m, 0.5)
    # P(X <= b) 与 P(X >= b)
    p_le = sum(pmf[:b + 1])
    p_ge = sum(pmf[b:])
    return min(1.0, 2 * min(p_le, p_ge))


def rejection_set(m, alpha=0.05):
    """在 H0: p=0.5 下拒绝域（观测 b 的集合）。"""
    return {b for b in range(m + 1) if two_sided_p_value(b, m) <= alpha}


def power_at(m, p1, alpha=0.05):
    """H1: p=p1 下，exact 双侧检验的功效。"""
    rej = rejection_set(m, alpha)
    pmf1 = binom_pdf(m, p1)
    return sum(pmf1[b] for b in rej)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--m-max", type=int, default=15)
    ap.add_argument("--alpha", type=float, default=0.05)
    args = ap.parse_args()

    p1s = [0.60, 0.70, 0.80, 0.90, 1.00]
    print("功效表：P(双侧 exact binomial 拒绝 H0 | 真实 discordant 比例 p1=b/m)")
    print("（m = discordant pairs 数；α=%.2f）" % args.alpha)
    print()
    hdr = f"{'m':>3} | " + " | ".join(f"p1={p:.2f}" for p in p1s)
    print(hdr)
    print("-" * len(hdr))
    for m in range(1, args.m_max + 1):
        row = f"{m:>3} | " + " | ".join(f"{power_at(m, p, args.alpha):>7.3f}" for p in p1s)
        print(row)

    print()
    print("判读：功效 ≥0.80 记为可检测。m 越小，能检测的效应越弱（越接近 0.5 越难）。")
    print("例：m=8 时 p1=0.90 功效≈? ；m=12 时 p1=0.80 功效≈?——据此冻结确认性最低 n。")
    # 关键锚点显式打印
    print()
    print("关键锚点：")
    for m in (8, 10, 12, 15):
        for p in (0.70, 0.80, 0.90):
            print(f"  m={m:>2}  p1={p:.2f}  power={power_at(m, p, args.alpha):.3f}")


if __name__ == "__main__":
    main()
