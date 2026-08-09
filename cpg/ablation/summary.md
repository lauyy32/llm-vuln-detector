# 三模式上下文消融实验 - 结果汇总

- 生成时间: 2026-08-09 05:51 UTC
- 数据来源: dataset.jsonl (真实 CVE)
- 样本版本数: 32  (vuln=正例 / fixed=负例)
- 跳过基线: False
- CodeQL: 2.26.2  python Security/CWE 定向查询（覆盖数据集 CWE-022/918/020/295）

## 全局指标（正类=vulnerable；abstain 计为未判 vulnerable → 正例召回 0）

| scorer | mode | P | R | F1 | support | TP | FP | TN | FN |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| StructuralHeuristicScorer | request | 0.000 | 0.000 | 0.000 | 32 | 0 | 0 | 16 | 16 |
| StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 32 | 0 | 0 | 16 | 16 |
| StructuralHeuristicScorer | both | 0.000 | 0.000 | 0.000 | 32 | 0 | 0 | 16 | 16 |
| CodeQLBaselineScorer | request | 0.500 | 0.062 | 0.111 | 32 | 1 | 1 | 15 | 15 |
| CodeQLBaselineScorer | code | 0.500 | 0.062 | 0.111 | 32 | 1 | 1 | 15 | 15 |
| CodeQLBaselineScorer | both | 0.500 | 0.062 | 0.111 | 32 | 1 | 1 | 15 | 15 |

## 分组指标（可污点类 vs 逻辑类）

| group | scorer | mode | P | R | F1 | support |
| --- | --- | --- | --- | --- | --- | --- |
| taint | StructuralHeuristicScorer | request | 0.000 | 0.000 | 0.000 | 8 |
| taint | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 8 |
| taint | StructuralHeuristicScorer | both | 0.000 | 0.000 | 0.000 | 8 |
| taint | CodeQLBaselineScorer | request | 0.500 | 0.250 | 0.333 | 8 |
| taint | CodeQLBaselineScorer | code | 0.500 | 0.250 | 0.333 | 8 |
| taint | CodeQLBaselineScorer | both | 0.500 | 0.250 | 0.333 | 8 |
| logic | StructuralHeuristicScorer | request | 0.000 | 0.000 | 0.000 | 24 |
| logic | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 24 |
| logic | StructuralHeuristicScorer | both | 0.000 | 0.000 | 0.000 | 24 |
| logic | CodeQLBaselineScorer | request | 0.000 | 0.000 | 0.000 | 24 |
| logic | CodeQLBaselineScorer | code | 0.000 | 0.000 | 0.000 | 24 |
| logic | CodeQLBaselineScorer | both | 0.000 | 0.000 | 0.000 | 24 |

## 每 CWE 指标（StructuralHeuristicScorer）

| cwe | mode | P | R | F1 | support |
| --- | --- | --- | --- | --- | --- |
| CWE-020 | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-020 | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-020 | both | 0.000 | 0.000 | 0.000 | 2 |
| CWE-022 | request | 0.000 | 0.000 | 0.000 | 6 |
| CWE-022 | code | 0.000 | 0.000 | 0.000 | 6 |
| CWE-022 | both | 0.000 | 0.000 | 0.000 | 6 |
| CWE-059 | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-059 | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-059 | both | 0.000 | 0.000 | 0.000 | 2 |
| CWE-200 | request | 0.000 | 0.000 | 0.000 | 4 |
| CWE-200 | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-200 | both | 0.000 | 0.000 | 0.000 | 4 |
| CWE-295 | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-295 | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-295 | both | 0.000 | 0.000 | 0.000 | 2 |
| CWE-400 | request | 0.000 | 0.000 | 0.000 | 4 |
| CWE-400 | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-400 | both | 0.000 | 0.000 | 0.000 | 4 |
| CWE-444 | request | 0.000 | 0.000 | 0.000 | 4 |
| CWE-444 | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-444 | both | 0.000 | 0.000 | 0.000 | 4 |
| CWE-639 | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-639 | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-639 | both | 0.000 | 0.000 | 0.000 | 2 |
| CWE-862 | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-862 | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-862 | both | 0.000 | 0.000 | 0.000 | 2 |
| CWE-863 | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-863 | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-863 | both | 0.000 | 0.000 | 0.000 | 2 |
| CWE-918 | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-918 | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-918 | both | 0.000 | 0.000 | 0.000 | 2 |

## 混淆矩阵（全局，行=预测 / 列=真值）

### StructuralHeuristicScorer
| predicted \ truth | vulnerable | benign | abstain | error |
| --- | --- | --- | --- | --- |
| vulnerable | 0 | 0 | 0 | 0 |
| benign | 32 | 32 | 0 | 0 |
| abstain | 16 | 16 | 0 | 0 |
| error | 0 | 0 | 0 | 0 |

### CodeQLBaselineScorer
| predicted \ truth | vulnerable | benign | abstain | error |
| --- | --- | --- | --- | --- |
| vulnerable | 3 | 3 | 0 | 0 |
| benign | 45 | 45 | 0 | 0 |
| abstain | 0 | 0 | 0 | 0 |
| error | 0 | 0 | 0 | 0 |
