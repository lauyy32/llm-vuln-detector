# 三模式上下文消融实验 - 结果汇总

- 生成时间: 2026-08-27 13:40 UTC
- 数据来源: dataset.jsonl (真实 CVE)
- 样本版本数: 32  (vuln=正例 / fixed=负例)
- 跳过基线: False
- CodeQL: 2.26.2  python Security/CWE 定向查询（覆盖数据集 CWE-022/918/020/295）
- ConfigSig: 结构型/配置签名基线（CWE-295/059/200 精确签名；020/400/444/639/862/863 显式 abstain）
- CPGEvidence: 直接解析 CPG 污点切片文本做确定性判定（为 LocalLLMScorer 提供同吃切片文本的对照基线）

## 全局指标（正类=vulnerable；abstain 计为未判 vulnerable → 正例召回 0）

| scorer | mode | P | R | F1 | support | TP | FP | TN | FN |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| StructuralHeuristicScorer | request | 0.000 | 0.000 | 0.000 | 32 | 0 | 0 | 16 | 16 |
| StructuralHeuristicScorer | code | 0.500 | 0.188 | 0.273 | 32 | 3 | 3 | 13 | 13 |
| StructuralHeuristicScorer | both | 0.500 | 0.188 | 0.273 | 32 | 3 | 3 | 13 | 13 |
| CodeQLBaselineScorer | request | 0.500 | 0.062 | 0.111 | 32 | 1 | 1 | 15 | 15 |
| CodeQLBaselineScorer | code | 0.500 | 0.062 | 0.111 | 32 | 1 | 1 | 15 | 15 |
| CodeQLBaselineScorer | both | 0.500 | 0.062 | 0.111 | 32 | 1 | 1 | 15 | 15 |
| ConfigSigScorer | request | 0.000 | 0.000 | 0.000 | 32 | 0 | 0 | 16 | 16 |
| ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 32 | 0 | 0 | 16 | 16 |
| ConfigSigScorer | both | 0.000 | 0.000 | 0.000 | 32 | 0 | 0 | 16 | 16 |
| CPGEvidenceScorer | request | 0.000 | 0.000 | 0.000 | 32 | 0 | 0 | 16 | 16 |
| CPGEvidenceScorer | code | 0.533 | 0.500 | 0.516 | 32 | 8 | 7 | 9 | 8 |
| CPGEvidenceScorer | both | 0.533 | 0.500 | 0.516 | 32 | 8 | 7 | 9 | 8 |
| LocalLLMScorer | request | 0.000 | 0.000 | 0.000 | 32 | 0 | 0 | 16 | 16 |
| LocalLLMScorer | code | 0.500 | 0.375 | 0.429 | 32 | 6 | 6 | 10 | 10 |
| LocalLLMScorer | both | 0.500 | 0.375 | 0.429 | 32 | 6 | 6 | 10 | 10 |

## 分组指标（可污点类 vs 逻辑类）

| group | scorer | mode | P | R | F1 | support |
| --- | --- | --- | --- | --- | --- | --- |
| taint | StructuralHeuristicScorer | request | 0.000 | 0.000 | 0.000 | 8 |
| taint | StructuralHeuristicScorer | code | 0.500 | 0.750 | 0.600 | 8 |
| taint | StructuralHeuristicScorer | both | 0.500 | 0.750 | 0.600 | 8 |
| taint | CodeQLBaselineScorer | request | 0.500 | 0.250 | 0.333 | 8 |
| taint | CodeQLBaselineScorer | code | 0.500 | 0.250 | 0.333 | 8 |
| taint | CodeQLBaselineScorer | both | 0.500 | 0.250 | 0.333 | 8 |
| taint | ConfigSigScorer | request | 0.000 | 0.000 | 0.000 | 8 |
| taint | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 8 |
| taint | ConfigSigScorer | both | 0.000 | 0.000 | 0.000 | 8 |
| taint | CPGEvidenceScorer | request | 0.000 | 0.000 | 0.000 | 8 |
| taint | CPGEvidenceScorer | code | 0.500 | 0.750 | 0.600 | 8 |
| taint | CPGEvidenceScorer | both | 0.500 | 0.750 | 0.600 | 8 |
| taint | LocalLLMScorer | request | 0.000 | 0.000 | 0.000 | 8 |
| taint | LocalLLMScorer | code | 0.500 | 0.750 | 0.600 | 8 |
| taint | LocalLLMScorer | both | 0.500 | 0.750 | 0.600 | 8 |
| logic | StructuralHeuristicScorer | request | 0.000 | 0.000 | 0.000 | 24 |
| logic | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 24 |
| logic | StructuralHeuristicScorer | both | 0.000 | 0.000 | 0.000 | 24 |
| logic | CodeQLBaselineScorer | request | 0.000 | 0.000 | 0.000 | 24 |
| logic | CodeQLBaselineScorer | code | 0.000 | 0.000 | 0.000 | 24 |
| logic | CodeQLBaselineScorer | both | 0.000 | 0.000 | 0.000 | 24 |
| logic | ConfigSigScorer | request | 0.000 | 0.000 | 0.000 | 24 |
| logic | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 24 |
| logic | ConfigSigScorer | both | 0.000 | 0.000 | 0.000 | 24 |
| logic | CPGEvidenceScorer | request | 0.000 | 0.000 | 0.000 | 24 |
| logic | CPGEvidenceScorer | code | 0.556 | 0.417 | 0.476 | 24 |
| logic | CPGEvidenceScorer | both | 0.556 | 0.417 | 0.476 | 24 |
| logic | LocalLLMScorer | request | 0.000 | 0.000 | 0.000 | 24 |
| logic | LocalLLMScorer | code | 0.500 | 0.250 | 0.333 | 24 |
| logic | LocalLLMScorer | both | 0.500 | 0.250 | 0.333 | 24 |

## 每 CWE 指标（StructuralHeuristic / ConfigSig / CPGEvidence）

| cwe | scorer | mode | P | R | F1 | support |
| --- | --- | --- | --- | --- | --- | --- |
| CWE-020 | StructuralHeuristicScorer | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-020 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-020 | StructuralHeuristicScorer | both | 0.000 | 0.000 | 0.000 | 2 |
| CWE-022 | StructuralHeuristicScorer | request | 0.000 | 0.000 | 0.000 | 6 |
| CWE-022 | StructuralHeuristicScorer | code | 0.500 | 0.667 | 0.571 | 6 |
| CWE-022 | StructuralHeuristicScorer | both | 0.500 | 0.667 | 0.571 | 6 |
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
| CWE-020 | CPGEvidenceScorer | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-020 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-020 | CPGEvidenceScorer | both | 0.000 | 0.000 | 0.000 | 2 |
| CWE-022 | CPGEvidenceScorer | request | 0.000 | 0.000 | 0.000 | 6 |
| CWE-022 | CPGEvidenceScorer | code | 0.500 | 0.667 | 0.571 | 6 |
| CWE-022 | CPGEvidenceScorer | both | 0.500 | 0.667 | 0.571 | 6 |
| CWE-059 | CPGEvidenceScorer | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-059 | CPGEvidenceScorer | code | 0.500 | 1.000 | 0.667 | 2 |
| CWE-059 | CPGEvidenceScorer | both | 0.500 | 1.000 | 0.667 | 2 |
| CWE-200 | CPGEvidenceScorer | request | 0.000 | 0.000 | 0.000 | 4 |
| CWE-200 | CPGEvidenceScorer | code | 1.000 | 0.500 | 0.667 | 4 |
| CWE-200 | CPGEvidenceScorer | both | 1.000 | 0.500 | 0.667 | 4 |
| CWE-295 | CPGEvidenceScorer | request | 0.000 | 0.000 | 0.000 | 2 |
| CWE-295 | CPGEvidenceScorer | code | 0.500 | 1.000 | 0.667 | 2 |
| CWE-295 | CPGEvidenceScorer | both | 0.500 | 1.000 | 0.667 | 2 |
| CWE-400 | CPGEvidenceScorer | request | 0.000 | 0.000 | 0.000 | 4 |
| CWE-400 | CPGEvidenceScorer | code | 0.500 | 0.500 | 0.500 | 4 |
| CWE-400 | CPGEvidenceScorer | both | 0.500 | 0.500 | 0.500 | 4 |
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
| vulnerable | 6 | 6 | 0 | 0 |
| benign | 26 | 26 | 0 | 0 |
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

### CPGEvidenceScorer
| predicted \ truth | vulnerable | benign | abstain | error |
| --- | --- | --- | --- | --- |
| vulnerable | 16 | 14 | 0 | 0 |
| benign | 16 | 18 | 0 | 0 |
| abstain | 16 | 16 | 0 | 0 |
| error | 0 | 0 | 0 | 0 |

### LocalLLMScorer
| predicted \ truth | vulnerable | benign | abstain | error |
| --- | --- | --- | --- | --- |
| vulnerable | 12 | 12 | 0 | 0 |
| benign | 12 | 12 | 0 | 0 |
| abstain | 24 | 24 | 0 | 0 |
| error | 0 | 0 | 0 | 0 |
