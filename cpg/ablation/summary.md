# 三模式上下文消融实验 - 结果汇总

- 生成时间: 2026-08-18 12:12 UTC
- 数据来源: dataset.jsonl (真实 CVE)
- 样本版本数: 32  (vuln=正例 / fixed=负例)
- 跳过基线: False
- CodeQL: 2.26.2  python Security/CWE 定向查询（覆盖数据集 CWE-022/918/020/295）
- ConfigSig: 结构型/配置签名基线（CWE-295/059/200 精确签名；020/400/444/639/862/863 显式 abstain）

## 全局指标（正类=vulnerable；abstain 计为未判 vulnerable → 正例召回 0）

| scorer | mode | P | R | F1 | support | TP | FP | TN | FN |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| StructuralHeuristicScorer | request | 0.000 | 0.000 | 0.000 | 32 | 0 | 0 | 16 | 16 |
| StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 32 | 0 | 0 | 16 | 16 |
| StructuralHeuristicScorer | both | 0.000 | 0.000 | 0.000 | 32 | 0 | 0 | 16 | 16 |
| CodeQLBaselineScorer | request | 0.500 | 0.062 | 0.111 | 32 | 1 | 1 | 15 | 15 |
| CodeQLBaselineScorer | code | 0.500 | 0.062 | 0.111 | 32 | 1 | 1 | 15 | 15 |
| CodeQLBaselineScorer | both | 0.500 | 0.062 | 0.111 | 32 | 1 | 1 | 15 | 15 |
| ConfigSigScorer | request | 0.000 | 0.000 | 0.000 | 32 | 0 | 0 | 16 | 16 |
| ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 32 | 0 | 0 | 16 | 16 |
| ConfigSigScorer | both | 0.000 | 0.000 | 0.000 | 32 | 0 | 0 | 16 | 16 |

## 分组指标（可污点类 vs 逻辑类）

| group | scorer | mode | P | R | F1 | support |
| --- | --- | --- | --- | --- | --- | --- |
| taint | StructuralHeuristicScorer | request | 0.000 | 0.000 | 0.000 | 8 |
| taint | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 8 |
| taint | StructuralHeuristicScorer | both | 0.000 | 0.000 | 0.000 | 8 |
| taint | CodeQLBaselineScorer | request | 0.500 | 0.250 | 0.333 | 8 |
| taint | CodeQLBaselineScorer | code | 0.500 | 0.250 | 0.333 | 8 |
| taint | CodeQLBaselineScorer | both | 0.500 | 0.250 | 0.333 | 8 |
| taint | ConfigSigScorer | request | 0.000 | 0.000 | 0.000 | 8 |
| taint | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 8 |
| taint | ConfigSigScorer | both | 0.000 | 0.000 | 0.000 | 8 |
| logic | StructuralHeuristicScorer | request | 0.000 | 0.000 | 0.000 | 24 |
| logic | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 24 |
| logic | StructuralHeuristicScorer | both | 0.000 | 0.000 | 0.000 | 24 |
| logic | CodeQLBaselineScorer | request | 0.000 | 0.000 | 0.000 | 24 |
| logic | CodeQLBaselineScorer | code | 0.000 | 0.000 | 0.000 | 24 |
| logic | CodeQLBaselineScorer | both | 0.000 | 0.000 | 0.000 | 24 |
| logic | ConfigSigScorer | request | 0.000 | 0.000 | 0.000 | 24 |
| logic | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 24 |
| logic | ConfigSigScorer | both | 0.000 | 0.000 | 0.000 | 24 |

## 每 CWE 指标（StructuralHeuristic / ConfigSig）

| cwe | scorer | mode | P | R | F1 | support |
| --- | --- | --- | --- | --- | --- | --- |
| CWE-020 | StructuralHeuristicScorer | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-020 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-020 | StructuralHeuristicScorer | both | 0.000 | 0.000 | 0.000 | 2 |
| CWE-022 | StructuralHeuristicScorer | request | 0.000 | 0.000 | 0.000 | 6 |
| CWE-022 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 6 |
| CWE-022 | StructuralHeuristicScorer | both | 0.000 | 0.000 | 0.000 | 6 |
| CWE-059 | StructuralHeuristicScorer | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-059 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-059 | StructuralHeuristicScorer | both | 0.000 | 0.000 | 0.000 | 2 |
| CWE-200 | StructuralHeuristicScorer | request | 0.000 | 0.000 | 0.000 | 4 |
| CWE-200 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-200 | StructuralHeuristicScorer | both | 0.000 | 0.000 | 0.000 | 4 |
| CWE-295 | StructuralHeuristicScorer | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-295 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-295 | StructuralHeuristicScorer | both | 0.000 | 0.000 | 0.000 | 2 |
| CWE-400 | StructuralHeuristicScorer | request | 0.000 | 0.000 | 0.000 | 4 |
| CWE-400 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-400 | StructuralHeuristicScorer | both | 0.000 | 0.000 | 0.000 | 4 |
| CWE-444 | StructuralHeuristicScorer | request | 0.000 | 0.000 | 0.000 | 4 |
| CWE-444 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-444 | StructuralHeuristicScorer | both | 0.000 | 0.000 | 0.000 | 4 |
| CWE-639 | StructuralHeuristicScorer | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-639 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-639 | StructuralHeuristicScorer | both | 0.000 | 0.000 | 0.000 | 2 |
| CWE-862 | StructuralHeuristicScorer | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-862 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-862 | StructuralHeuristicScorer | both | 0.000 | 0.000 | 0.000 | 2 |
| CWE-863 | StructuralHeuristicScorer | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-863 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-863 | StructuralHeuristicScorer | both | 0.000 | 0.000 | 0.000 | 2 |
| CWE-918 | StructuralHeuristicScorer | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-918 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-918 | StructuralHeuristicScorer | both | 0.000 | 0.000 | 0.000 | 2 |
| CWE-020 | ConfigSigScorer | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-020 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-020 | ConfigSigScorer | both | 0.000 | 0.000 | 0.000 | 2 |
| CWE-022 | ConfigSigScorer | request | 0.000 | 0.000 | 0.000 | 6 |
| CWE-022 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 6 |
| CWE-022 | ConfigSigScorer | both | 0.000 | 0.000 | 0.000 | 6 |
| CWE-059 | ConfigSigScorer | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-059 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-059 | ConfigSigScorer | both | 0.000 | 0.000 | 0.000 | 2 |
| CWE-200 | ConfigSigScorer | request | 0.000 | 0.000 | 0.000 | 4 |
| CWE-200 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-200 | ConfigSigScorer | both | 0.000 | 0.000 | 0.000 | 4 |
| CWE-295 | ConfigSigScorer | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-295 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-295 | ConfigSigScorer | both | 0.000 | 0.000 | 0.000 | 2 |
| CWE-400 | ConfigSigScorer | request | 0.000 | 0.000 | 0.000 | 4 |
| CWE-400 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-400 | ConfigSigScorer | both | 0.000 | 0.000 | 0.000 | 4 |
| CWE-444 | ConfigSigScorer | request | 0.000 | 0.000 | 0.000 | 4 |
| CWE-444 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-444 | ConfigSigScorer | both | 0.000 | 0.000 | 0.000 | 4 |
| CWE-639 | ConfigSigScorer | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-639 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-639 | ConfigSigScorer | both | 0.000 | 0.000 | 0.000 | 2 |
| CWE-862 | ConfigSigScorer | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-862 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-862 | ConfigSigScorer | both | 0.000 | 0.000 | 0.000 | 2 |
| CWE-863 | ConfigSigScorer | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-863 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-863 | ConfigSigScorer | both | 0.000 | 0.000 | 0.000 | 2 |
| CWE-918 | ConfigSigScorer | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-918 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-918 | ConfigSigScorer | both | 0.000 | 0.000 | 0.000 | 2 |

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

### ConfigSigScorer
| predicted \ truth | vulnerable | benign | abstain | error |
| --- | --- | --- | --- | --- |
| vulnerable | 0 | 0 | 0 | 0 |
| benign | 16 | 16 | 0 | 0 |
| abstain | 32 | 32 | 0 | 0 |
| error | 0 | 0 | 0 | 0 |
