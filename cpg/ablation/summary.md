# 三模式上下文消融实验 - 结果汇总

- 生成时间: 2026-08-28 04:05 UTC
- 数据来源: dataset.jsonl (真实 CVE)
- 样本版本数: 38  (vuln=正例 / fixed=负例)
- 跳过基线: False
- CodeQL: 2.26.2  python Security/CWE 定向查询（覆盖数据集 CWE-022/918/020/295）
- ConfigSig: 结构型/配置签名基线（CWE-295/059/200 精确签名；020/400/444/639/862/863 显式 abstain）
- CPGEvidence: 直接解析 CPG 污点切片文本做确定性判定（为 LocalLLMScorer 提供同吃切片文本的对照基线）

## 全局指标（正类=vulnerable；abstain 计为未判 vulnerable → 正例召回 0）

| scorer | mode | P | R | F1 | support | TP | FP | TN | FN |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| StructuralHeuristicScorer | request | 0.000 | 0.000 | 0.000 | 38 | 0 | 0 | 19 | 19 |
| StructuralHeuristicScorer | code | 0.500 | 0.211 | 0.296 | 38 | 4 | 4 | 15 | 15 |
| StructuralHeuristicScorer | both | 0.500 | 0.211 | 0.296 | 38 | 4 | 4 | 15 | 15 |
| CodeQLBaselineScorer | request | 0.500 | 0.053 | 0.095 | 38 | 1 | 1 | 18 | 18 |
| CodeQLBaselineScorer | code | 0.500 | 0.053 | 0.095 | 38 | 1 | 1 | 18 | 18 |
| CodeQLBaselineScorer | both | 0.500 | 0.053 | 0.095 | 38 | 1 | 1 | 18 | 18 |
| ConfigSigScorer | request | 0.000 | 0.000 | 0.000 | 38 | 0 | 0 | 19 | 19 |
| ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 38 | 0 | 0 | 19 | 19 |
| ConfigSigScorer | both | 0.000 | 0.000 | 0.000 | 38 | 0 | 0 | 19 | 19 |
| CPGEvidenceScorer | request | 0.000 | 0.000 | 0.000 | 38 | 0 | 0 | 19 | 19 |
| CPGEvidenceScorer | code | 0.500 | 0.368 | 0.424 | 38 | 7 | 7 | 12 | 12 |
| CPGEvidenceScorer | both | 0.500 | 0.368 | 0.424 | 38 | 7 | 7 | 12 | 12 |
| LocalLLMScorer | request | 0.000 | 0.000 | 0.000 | 38 | 0 | 0 | 19 | 19 |
| LocalLLMScorer | code | 0.471 | 0.421 | 0.444 | 38 | 8 | 9 | 10 | 11 |
| LocalLLMScorer | both | 0.471 | 0.421 | 0.444 | 38 | 8 | 9 | 10 | 11 |

## 分组指标（可污点类 vs 逻辑类）

| group | scorer | mode | P | R | F1 | support |
| --- | --- | --- | --- | --- | --- | --- |
| taint | StructuralHeuristicScorer | request | 0.000 | 0.000 | 0.000 | 8 |
| taint | StructuralHeuristicScorer | code | 0.500 | 1.000 | 0.667 | 8 |
| taint | StructuralHeuristicScorer | both | 0.500 | 1.000 | 0.667 | 8 |
| taint | CodeQLBaselineScorer | request | 0.500 | 0.250 | 0.333 | 8 |
| taint | CodeQLBaselineScorer | code | 0.500 | 0.250 | 0.333 | 8 |
| taint | CodeQLBaselineScorer | both | 0.500 | 0.250 | 0.333 | 8 |
| taint | ConfigSigScorer | request | 0.000 | 0.000 | 0.000 | 8 |
| taint | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 8 |
| taint | ConfigSigScorer | both | 0.000 | 0.000 | 0.000 | 8 |
| taint | CPGEvidenceScorer | request | 0.000 | 0.000 | 0.000 | 8 |
| taint | CPGEvidenceScorer | code | 0.500 | 1.000 | 0.667 | 8 |
| taint | CPGEvidenceScorer | both | 0.500 | 1.000 | 0.667 | 8 |
| taint | LocalLLMScorer | request | 0.000 | 0.000 | 0.000 | 8 |
| taint | LocalLLMScorer | code | 0.500 | 1.000 | 0.667 | 8 |
| taint | LocalLLMScorer | both | 0.500 | 1.000 | 0.667 | 8 |
| logic | StructuralHeuristicScorer | request | 0.000 | 0.000 | 0.000 | 30 |
| logic | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 30 |
| logic | StructuralHeuristicScorer | both | 0.000 | 0.000 | 0.000 | 30 |
| logic | CodeQLBaselineScorer | request | 0.000 | 0.000 | 0.000 | 30 |
| logic | CodeQLBaselineScorer | code | 0.000 | 0.000 | 0.000 | 30 |
| logic | CodeQLBaselineScorer | both | 0.000 | 0.000 | 0.000 | 30 |
| logic | ConfigSigScorer | request | 0.000 | 0.000 | 0.000 | 30 |
| logic | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 30 |
| logic | ConfigSigScorer | both | 0.000 | 0.000 | 0.000 | 30 |
| logic | CPGEvidenceScorer | request | 0.000 | 0.000 | 0.000 | 30 |
| logic | CPGEvidenceScorer | code | 0.500 | 0.200 | 0.286 | 30 |
| logic | CPGEvidenceScorer | both | 0.500 | 0.200 | 0.286 | 30 |
| logic | LocalLLMScorer | request | 0.000 | 0.000 | 0.000 | 30 |
| logic | LocalLLMScorer | code | 0.444 | 0.267 | 0.333 | 30 |
| logic | LocalLLMScorer | both | 0.444 | 0.267 | 0.333 | 30 |

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
| CWE-200 | StructuralHeuristicScorer | request | 0.000 | 0.000 | 0.000 | 6 |
| CWE-200 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 6 |
| CWE-200 | StructuralHeuristicScorer | both | 0.000 | 0.000 | 0.000 | 6 |
| CWE-295 | StructuralHeuristicScorer | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-295 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-295 | StructuralHeuristicScorer | both | 0.000 | 0.000 | 0.000 | 2 |
| CWE-400 | StructuralHeuristicScorer | request | 0.000 | 0.000 | 0.000 | 4 |
| CWE-400 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-400 | StructuralHeuristicScorer | both | 0.000 | 0.000 | 0.000 | 4 |
| CWE-434 | StructuralHeuristicScorer | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-434 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-434 | StructuralHeuristicScorer | both | 0.000 | 0.000 | 0.000 | 2 |
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
| CWE-918 | StructuralHeuristicScorer | code | 0.500 | 1.000 | 0.667 | 2 |
| CWE-918 | StructuralHeuristicScorer | both | 0.500 | 1.000 | 0.667 | 2 |
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
| CWE-200 | ConfigSigScorer | request | 0.000 | 0.000 | 0.000 | 6 |
| CWE-200 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 6 |
| CWE-200 | ConfigSigScorer | both | 0.000 | 0.000 | 0.000 | 6 |
| CWE-295 | ConfigSigScorer | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-295 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-295 | ConfigSigScorer | both | 0.000 | 0.000 | 0.000 | 2 |
| CWE-400 | ConfigSigScorer | request | 0.000 | 0.000 | 0.000 | 4 |
| CWE-400 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-400 | ConfigSigScorer | both | 0.000 | 0.000 | 0.000 | 4 |
| CWE-434 | ConfigSigScorer | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-434 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-434 | ConfigSigScorer | both | 0.000 | 0.000 | 0.000 | 2 |
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
| CWE-200 | CPGEvidenceScorer | request | 0.000 | 0.000 | 0.000 | 6 |
| CWE-200 | CPGEvidenceScorer | code | 1.000 | 0.333 | 0.500 | 6 |
| CWE-200 | CPGEvidenceScorer | both | 1.000 | 0.333 | 0.500 | 6 |
| CWE-295 | CPGEvidenceScorer | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-295 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-295 | CPGEvidenceScorer | both | 0.000 | 0.000 | 0.000 | 2 |
| CWE-400 | CPGEvidenceScorer | request | 0.000 | 0.000 | 0.000 | 4 |
| CWE-400 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-400 | CPGEvidenceScorer | both | 0.000 | 0.000 | 0.000 | 4 |
| CWE-434 | CPGEvidenceScorer | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-434 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-434 | CPGEvidenceScorer | both | 0.000 | 0.000 | 0.000 | 2 |
| CWE-444 | CPGEvidenceScorer | request | 0.000 | 0.000 | 0.000 | 4 |
| CWE-444 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-444 | CPGEvidenceScorer | both | 0.000 | 0.000 | 0.000 | 4 |
| CWE-639 | CPGEvidenceScorer | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-639 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-639 | CPGEvidenceScorer | both | 0.000 | 0.000 | 0.000 | 2 |
| CWE-862 | CPGEvidenceScorer | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-862 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-862 | CPGEvidenceScorer | both | 0.000 | 0.000 | 0.000 | 2 |
| CWE-863 | CPGEvidenceScorer | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-863 | CPGEvidenceScorer | code | 0.500 | 1.000 | 0.667 | 2 |
| CWE-863 | CPGEvidenceScorer | both | 0.500 | 1.000 | 0.667 | 2 |
| CWE-918 | CPGEvidenceScorer | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-918 | CPGEvidenceScorer | code | 0.500 | 1.000 | 0.667 | 2 |
| CWE-918 | CPGEvidenceScorer | both | 0.500 | 1.000 | 0.667 | 2 |

## 混淆矩阵（全局，行=预测 / 列=真值）

### StructuralHeuristicScorer
| predicted \ truth | vulnerable | benign | abstain | error |
| --- | --- | --- | --- | --- |
| vulnerable | 8 | 8 | 0 | 0 |
| benign | 30 | 30 | 0 | 0 |
| abstain | 19 | 19 | 0 | 0 |
| error | 0 | 0 | 0 | 0 |

### CodeQLBaselineScorer
| predicted \ truth | vulnerable | benign | abstain | error |
| --- | --- | --- | --- | --- |
| vulnerable | 3 | 3 | 0 | 0 |
| benign | 54 | 54 | 0 | 0 |
| abstain | 0 | 0 | 0 | 0 |
| error | 0 | 0 | 0 | 0 |

### ConfigSigScorer
| predicted \ truth | vulnerable | benign | abstain | error |
| --- | --- | --- | --- | --- |
| vulnerable | 0 | 0 | 0 | 0 |
| benign | 22 | 22 | 0 | 0 |
| abstain | 35 | 35 | 0 | 0 |
| error | 0 | 0 | 0 | 0 |

### CPGEvidenceScorer
| predicted \ truth | vulnerable | benign | abstain | error |
| --- | --- | --- | --- | --- |
| vulnerable | 14 | 14 | 0 | 0 |
| benign | 24 | 24 | 0 | 0 |
| abstain | 19 | 19 | 0 | 0 |
| error | 0 | 0 | 0 | 0 |

### LocalLLMScorer
| predicted \ truth | vulnerable | benign | abstain | error |
| --- | --- | --- | --- | --- |
| vulnerable | 16 | 18 | 0 | 0 |
| benign | 12 | 12 | 0 | 0 |
| abstain | 29 | 27 | 0 | 0 |
| error | 0 | 0 | 0 | 0 |
