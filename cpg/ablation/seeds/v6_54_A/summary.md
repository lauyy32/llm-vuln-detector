# 三模式上下文消融实验 - 结果汇总

- 生成时间: 2026-08-28 08:01 UTC
- 数据来源: dataset.jsonl (真实 CVE)
- 样本版本数: 54  (vuln=正例 / fixed=负例)
- 跳过基线: False
- CodeQL: 2.26.2  python Security/CWE 定向查询（覆盖数据集 CWE-022/918/020/295）
- ConfigSig: 结构型/配置签名基线（CWE-295/059/200 精确签名；020/400/444/639/862/863 显式 abstain）
- CPGEvidence: 直接解析 CPG 污点切片文本做确定性判定（为 LocalLLMScorer 提供同吃切片文本的对照基线）

## 全局指标（正类=vulnerable；abstain 计为未判 vulnerable → 正例召回 0）

| scorer | mode | P | R | F1 | support | TP | FP | TN | FN |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| StructuralHeuristicScorer | request | 0.000 | 0.000 | 0.000 | 54 | 0 | 0 | 27 | 27 |
| StructuralHeuristicScorer | code | 0.500 | 0.185 | 0.270 | 54 | 5 | 5 | 22 | 22 |
| StructuralHeuristicScorer | both | 0.500 | 0.185 | 0.270 | 54 | 5 | 5 | 22 | 22 |
| CodeQLBaselineScorer | request | 0.500 | 0.037 | 0.069 | 54 | 1 | 1 | 26 | 26 |
| CodeQLBaselineScorer | code | 0.500 | 0.037 | 0.069 | 54 | 1 | 1 | 26 | 26 |
| CodeQLBaselineScorer | both | 0.500 | 0.037 | 0.069 | 54 | 1 | 1 | 26 | 26 |
| ConfigSigScorer | request | 0.000 | 0.000 | 0.000 | 54 | 0 | 0 | 27 | 27 |
| ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 54 | 0 | 0 | 27 | 27 |
| ConfigSigScorer | both | 0.000 | 0.000 | 0.000 | 54 | 0 | 0 | 27 | 27 |
| CPGEvidenceScorer | request | 0.000 | 0.000 | 0.000 | 54 | 0 | 0 | 27 | 27 |
| CPGEvidenceScorer | code | 0.526 | 0.370 | 0.435 | 54 | 10 | 9 | 18 | 17 |
| CPGEvidenceScorer | both | 0.526 | 0.370 | 0.435 | 54 | 10 | 9 | 18 | 17 |
| LocalLLMScorer | request | 0.000 | 0.000 | 0.000 | 54 | 0 | 0 | 27 | 27 |
| LocalLLMScorer | code | 0.500 | 0.407 | 0.449 | 54 | 11 | 11 | 16 | 16 |
| LocalLLMScorer | both | 0.500 | 0.407 | 0.449 | 54 | 11 | 11 | 16 | 16 |

## 分组指标（可污点类 vs 逻辑类）

| group | scorer | mode | P | R | F1 | support |
| --- | --- | --- | --- | --- | --- | --- |
| taint | StructuralHeuristicScorer | request | 0.000 | 0.000 | 0.000 | 12 |
| taint | StructuralHeuristicScorer | code | 0.500 | 0.833 | 0.625 | 12 |
| taint | StructuralHeuristicScorer | both | 0.500 | 0.833 | 0.625 | 12 |
| taint | CodeQLBaselineScorer | request | 0.500 | 0.167 | 0.250 | 12 |
| taint | CodeQLBaselineScorer | code | 0.500 | 0.167 | 0.250 | 12 |
| taint | CodeQLBaselineScorer | both | 0.500 | 0.167 | 0.250 | 12 |
| taint | ConfigSigScorer | request | 0.000 | 0.000 | 0.000 | 12 |
| taint | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 12 |
| taint | ConfigSigScorer | both | 0.000 | 0.000 | 0.000 | 12 |
| taint | CPGEvidenceScorer | request | 0.000 | 0.000 | 0.000 | 12 |
| taint | CPGEvidenceScorer | code | 0.500 | 1.000 | 0.667 | 12 |
| taint | CPGEvidenceScorer | both | 0.500 | 1.000 | 0.667 | 12 |
| taint | LocalLLMScorer | request | 0.000 | 0.000 | 0.000 | 12 |
| taint | LocalLLMScorer | code | 0.500 | 1.000 | 0.667 | 12 |
| taint | LocalLLMScorer | both | 0.500 | 1.000 | 0.667 | 12 |
| logic | StructuralHeuristicScorer | request | 0.000 | 0.000 | 0.000 | 42 |
| logic | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 42 |
| logic | StructuralHeuristicScorer | both | 0.000 | 0.000 | 0.000 | 42 |
| logic | CodeQLBaselineScorer | request | 0.000 | 0.000 | 0.000 | 42 |
| logic | CodeQLBaselineScorer | code | 0.000 | 0.000 | 0.000 | 42 |
| logic | CodeQLBaselineScorer | both | 0.000 | 0.000 | 0.000 | 42 |
| logic | ConfigSigScorer | request | 0.000 | 0.000 | 0.000 | 42 |
| logic | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 42 |
| logic | ConfigSigScorer | both | 0.000 | 0.000 | 0.000 | 42 |
| logic | CPGEvidenceScorer | request | 0.000 | 0.000 | 0.000 | 42 |
| logic | CPGEvidenceScorer | code | 0.571 | 0.190 | 0.286 | 42 |
| logic | CPGEvidenceScorer | both | 0.571 | 0.190 | 0.286 | 42 |
| logic | LocalLLMScorer | request | 0.000 | 0.000 | 0.000 | 42 |
| logic | LocalLLMScorer | code | 0.500 | 0.238 | 0.323 | 42 |
| logic | LocalLLMScorer | both | 0.500 | 0.238 | 0.323 | 42 |

## 每 CWE 指标（StructuralHeuristic / ConfigSig / CPGEvidence）

| cwe | scorer | mode | P | R | F1 | support |
| --- | --- | --- | --- | --- | --- | --- |
| CWE-020 | StructuralHeuristicScorer | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-020 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-020 | StructuralHeuristicScorer | both | 0.000 | 0.000 | 0.000 | 2 |
| CWE-022 | StructuralHeuristicScorer | request | 0.000 | 0.000 | 0.000 | 6 |
| CWE-022 | StructuralHeuristicScorer | code | 0.500 | 1.000 | 0.667 | 6 |
| CWE-022 | StructuralHeuristicScorer | both | 0.500 | 1.000 | 0.667 | 6 |
| CWE-059 | StructuralHeuristicScorer | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-059 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-059 | StructuralHeuristicScorer | both | 0.000 | 0.000 | 0.000 | 2 |
| CWE-095 | StructuralHeuristicScorer | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-095 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-095 | StructuralHeuristicScorer | both | 0.000 | 0.000 | 0.000 | 2 |
| CWE-1333 | StructuralHeuristicScorer | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-1333 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-1333 | StructuralHeuristicScorer | both | 0.000 | 0.000 | 0.000 | 2 |
| CWE-200 | StructuralHeuristicScorer | request | 0.000 | 0.000 | 0.000 | 8 |
| CWE-200 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 8 |
| CWE-200 | StructuralHeuristicScorer | both | 0.000 | 0.000 | 0.000 | 8 |
| CWE-295 | StructuralHeuristicScorer | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-295 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-295 | StructuralHeuristicScorer | both | 0.000 | 0.000 | 0.000 | 2 |
| CWE-400 | StructuralHeuristicScorer | request | 0.000 | 0.000 | 0.000 | 8 |
| CWE-400 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 8 |
| CWE-400 | StructuralHeuristicScorer | both | 0.000 | 0.000 | 0.000 | 8 |
| CWE-444 | StructuralHeuristicScorer | request | 0.000 | 0.000 | 0.000 | 4 |
| CWE-444 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-444 | StructuralHeuristicScorer | both | 0.000 | 0.000 | 0.000 | 4 |
| CWE-601 | StructuralHeuristicScorer | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-601 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-601 | StructuralHeuristicScorer | both | 0.000 | 0.000 | 0.000 | 2 |
| CWE-639 | StructuralHeuristicScorer | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-639 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-639 | StructuralHeuristicScorer | both | 0.000 | 0.000 | 0.000 | 2 |
| CWE-770 | StructuralHeuristicScorer | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-770 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-770 | StructuralHeuristicScorer | both | 0.000 | 0.000 | 0.000 | 2 |
| CWE-862 | StructuralHeuristicScorer | request | 0.000 | 0.000 | 0.000 | 4 |
| CWE-862 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-862 | StructuralHeuristicScorer | both | 0.000 | 0.000 | 0.000 | 4 |
| CWE-863 | StructuralHeuristicScorer | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-863 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-863 | StructuralHeuristicScorer | both | 0.000 | 0.000 | 0.000 | 2 |
| CWE-918 | StructuralHeuristicScorer | request | 0.000 | 0.000 | 0.000 | 6 |
| CWE-918 | StructuralHeuristicScorer | code | 0.500 | 0.667 | 0.571 | 6 |
| CWE-918 | StructuralHeuristicScorer | both | 0.500 | 0.667 | 0.571 | 6 |
| CWE-020 | ConfigSigScorer | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-020 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-020 | ConfigSigScorer | both | 0.000 | 0.000 | 0.000 | 2 |
| CWE-022 | ConfigSigScorer | request | 0.000 | 0.000 | 0.000 | 6 |
| CWE-022 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 6 |
| CWE-022 | ConfigSigScorer | both | 0.000 | 0.000 | 0.000 | 6 |
| CWE-059 | ConfigSigScorer | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-059 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-059 | ConfigSigScorer | both | 0.000 | 0.000 | 0.000 | 2 |
| CWE-095 | ConfigSigScorer | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-095 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-095 | ConfigSigScorer | both | 0.000 | 0.000 | 0.000 | 2 |
| CWE-1333 | ConfigSigScorer | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-1333 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-1333 | ConfigSigScorer | both | 0.000 | 0.000 | 0.000 | 2 |
| CWE-200 | ConfigSigScorer | request | 0.000 | 0.000 | 0.000 | 8 |
| CWE-200 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 8 |
| CWE-200 | ConfigSigScorer | both | 0.000 | 0.000 | 0.000 | 8 |
| CWE-295 | ConfigSigScorer | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-295 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-295 | ConfigSigScorer | both | 0.000 | 0.000 | 0.000 | 2 |
| CWE-400 | ConfigSigScorer | request | 0.000 | 0.000 | 0.000 | 8 |
| CWE-400 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 8 |
| CWE-400 | ConfigSigScorer | both | 0.000 | 0.000 | 0.000 | 8 |
| CWE-444 | ConfigSigScorer | request | 0.000 | 0.000 | 0.000 | 4 |
| CWE-444 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-444 | ConfigSigScorer | both | 0.000 | 0.000 | 0.000 | 4 |
| CWE-601 | ConfigSigScorer | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-601 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-601 | ConfigSigScorer | both | 0.000 | 0.000 | 0.000 | 2 |
| CWE-639 | ConfigSigScorer | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-639 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-639 | ConfigSigScorer | both | 0.000 | 0.000 | 0.000 | 2 |
| CWE-770 | ConfigSigScorer | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-770 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-770 | ConfigSigScorer | both | 0.000 | 0.000 | 0.000 | 2 |
| CWE-862 | ConfigSigScorer | request | 0.000 | 0.000 | 0.000 | 4 |
| CWE-862 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-862 | ConfigSigScorer | both | 0.000 | 0.000 | 0.000 | 4 |
| CWE-863 | ConfigSigScorer | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-863 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-863 | ConfigSigScorer | both | 0.000 | 0.000 | 0.000 | 2 |
| CWE-918 | ConfigSigScorer | request | 0.000 | 0.000 | 0.000 | 6 |
| CWE-918 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 6 |
| CWE-918 | ConfigSigScorer | both | 0.000 | 0.000 | 0.000 | 6 |
| CWE-020 | CPGEvidenceScorer | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-020 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-020 | CPGEvidenceScorer | both | 0.000 | 0.000 | 0.000 | 2 |
| CWE-022 | CPGEvidenceScorer | request | 0.000 | 0.000 | 0.000 | 6 |
| CWE-022 | CPGEvidenceScorer | code | 0.500 | 1.000 | 0.667 | 6 |
| CWE-022 | CPGEvidenceScorer | both | 0.500 | 1.000 | 0.667 | 6 |
| CWE-059 | CPGEvidenceScorer | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-059 | CPGEvidenceScorer | code | 0.500 | 1.000 | 0.667 | 2 |
| CWE-059 | CPGEvidenceScorer | both | 0.500 | 1.000 | 0.667 | 2 |
| CWE-095 | CPGEvidenceScorer | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-095 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-095 | CPGEvidenceScorer | both | 0.000 | 0.000 | 0.000 | 2 |
| CWE-1333 | CPGEvidenceScorer | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-1333 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-1333 | CPGEvidenceScorer | both | 0.000 | 0.000 | 0.000 | 2 |
| CWE-200 | CPGEvidenceScorer | request | 0.000 | 0.000 | 0.000 | 8 |
| CWE-200 | CPGEvidenceScorer | code | 0.667 | 0.500 | 0.571 | 8 |
| CWE-200 | CPGEvidenceScorer | both | 0.667 | 0.500 | 0.571 | 8 |
| CWE-295 | CPGEvidenceScorer | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-295 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-295 | CPGEvidenceScorer | both | 0.000 | 0.000 | 0.000 | 2 |
| CWE-400 | CPGEvidenceScorer | request | 0.000 | 0.000 | 0.000 | 8 |
| CWE-400 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 8 |
| CWE-400 | CPGEvidenceScorer | both | 0.000 | 0.000 | 0.000 | 8 |
| CWE-444 | CPGEvidenceScorer | request | 0.000 | 0.000 | 0.000 | 4 |
| CWE-444 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-444 | CPGEvidenceScorer | both | 0.000 | 0.000 | 0.000 | 4 |
| CWE-601 | CPGEvidenceScorer | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-601 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-601 | CPGEvidenceScorer | both | 0.000 | 0.000 | 0.000 | 2 |
| CWE-639 | CPGEvidenceScorer | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-639 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-639 | CPGEvidenceScorer | both | 0.000 | 0.000 | 0.000 | 2 |
| CWE-770 | CPGEvidenceScorer | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-770 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-770 | CPGEvidenceScorer | both | 0.000 | 0.000 | 0.000 | 2 |
| CWE-862 | CPGEvidenceScorer | request | 0.000 | 0.000 | 0.000 | 4 |
| CWE-862 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-862 | CPGEvidenceScorer | both | 0.000 | 0.000 | 0.000 | 4 |
| CWE-863 | CPGEvidenceScorer | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-863 | CPGEvidenceScorer | code | 0.500 | 1.000 | 0.667 | 2 |
| CWE-863 | CPGEvidenceScorer | both | 0.500 | 1.000 | 0.667 | 2 |
| CWE-918 | CPGEvidenceScorer | request | 0.000 | 0.000 | 0.000 | 6 |
| CWE-918 | CPGEvidenceScorer | code | 0.500 | 1.000 | 0.667 | 6 |
| CWE-918 | CPGEvidenceScorer | both | 0.500 | 1.000 | 0.667 | 6 |

## 混淆矩阵（全局，行=预测 / 列=真值）

### StructuralHeuristicScorer
| predicted \ truth | vulnerable | benign | abstain | error |
| --- | --- | --- | --- | --- |
| vulnerable | 10 | 10 | 0 | 0 |
| benign | 44 | 44 | 0 | 0 |
| abstain | 27 | 27 | 0 | 0 |
| error | 0 | 0 | 0 | 0 |

### CodeQLBaselineScorer
| predicted \ truth | vulnerable | benign | abstain | error |
| --- | --- | --- | --- | --- |
| vulnerable | 3 | 3 | 0 | 0 |
| benign | 78 | 78 | 0 | 0 |
| abstain | 0 | 0 | 0 | 0 |
| error | 0 | 0 | 0 | 0 |

### ConfigSigScorer
| predicted \ truth | vulnerable | benign | abstain | error |
| --- | --- | --- | --- | --- |
| vulnerable | 0 | 0 | 0 | 0 |
| benign | 32 | 32 | 0 | 0 |
| abstain | 49 | 49 | 0 | 0 |
| error | 0 | 0 | 0 | 0 |

### CPGEvidenceScorer
| predicted \ truth | vulnerable | benign | abstain | error |
| --- | --- | --- | --- | --- |
| vulnerable | 20 | 18 | 0 | 0 |
| benign | 34 | 36 | 0 | 0 |
| abstain | 27 | 27 | 0 | 0 |
| error | 0 | 0 | 0 | 0 |

### LocalLLMScorer
| predicted \ truth | vulnerable | benign | abstain | error |
| --- | --- | --- | --- | --- |
| vulnerable | 22 | 22 | 0 | 0 |
| benign | 16 | 14 | 0 | 0 |
| abstain | 43 | 45 | 0 | 0 |
| error | 0 | 0 | 0 | 0 |
