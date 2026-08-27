# 三模式上下文消融实验 - 结果汇总

- 生成时间: 2026-08-27 10:02 UTC
- 数据来源: demo (cpg/samples + sample_db)
- 样本版本数: 4  (vuln=正例 / fixed=负例)
- 跳过基线: False
- CodeQL: 2.26.2  python Security/CWE 定向查询（覆盖数据集 CWE-022/918/020/295）
- ConfigSig: 结构型/配置签名基线（CWE-295/059/200 精确签名；020/400/444/639/862/863 显式 abstain）
- CPGEvidence: 直接解析 CPG 污点切片文本做确定性判定（为 LocalLLMScorer 提供同吃切片文本的对照基线）

> 注：demo 模式仅含 4 个 vuln 正例（无 fixed 负例），用于验证聚合链路；真实 dataset.jsonl 全量已通过语料库级单数据库（建库一次 + 6 次 taint 查询 + 1 次 analyze）完成。

## 全局指标（正类=vulnerable；abstain 计为未判 vulnerable → 正例召回 0）

| scorer | mode | P | R | F1 | support | TP | FP | TN | FN |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| StructuralHeuristicScorer | request | 0.000 | 0.000 | 0.000 | 4 | 0 | 0 | 0 | 4 |
| StructuralHeuristicScorer | code | 1.000 | 1.000 | 1.000 | 4 | 4 | 0 | 0 | 0 |
| StructuralHeuristicScorer | both | 1.000 | 1.000 | 1.000 | 4 | 4 | 0 | 0 | 0 |
| CodeQLBaselineScorer | request | 1.000 | 1.000 | 1.000 | 4 | 4 | 0 | 0 | 0 |
| CodeQLBaselineScorer | code | 1.000 | 1.000 | 1.000 | 4 | 4 | 0 | 0 | 0 |
| CodeQLBaselineScorer | both | 1.000 | 1.000 | 1.000 | 4 | 4 | 0 | 0 | 0 |
| ConfigSigScorer | request | 0.000 | 0.000 | 0.000 | 4 | 0 | 0 | 0 | 4 |
| ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 4 | 0 | 0 | 0 | 4 |
| ConfigSigScorer | both | 0.000 | 0.000 | 0.000 | 4 | 0 | 0 | 0 | 4 |
| CPGEvidenceScorer | request | 0.000 | 0.000 | 0.000 | 4 | 0 | 0 | 0 | 4 |
| CPGEvidenceScorer | code | 1.000 | 1.000 | 1.000 | 4 | 4 | 0 | 0 | 0 |
| CPGEvidenceScorer | both | 1.000 | 1.000 | 1.000 | 4 | 4 | 0 | 0 | 0 |
| LocalLLMScorer | request | 0.000 | 0.000 | 0.000 | 4 | 0 | 0 | 0 | 4 |
| LocalLLMScorer | code | 1.000 | 1.000 | 1.000 | 4 | 4 | 0 | 0 | 0 |
| LocalLLMScorer | both | 1.000 | 1.000 | 1.000 | 4 | 4 | 0 | 0 | 0 |

## 分组指标（可污点类 vs 逻辑类）

| group | scorer | mode | P | R | F1 | support |
| --- | --- | --- | --- | --- | --- | --- |
| taint | StructuralHeuristicScorer | request | 0.000 | 0.000 | 0.000 | 4 |
| taint | StructuralHeuristicScorer | code | 1.000 | 1.000 | 1.000 | 4 |
| taint | StructuralHeuristicScorer | both | 1.000 | 1.000 | 1.000 | 4 |
| taint | CodeQLBaselineScorer | request | 1.000 | 1.000 | 1.000 | 4 |
| taint | CodeQLBaselineScorer | code | 1.000 | 1.000 | 1.000 | 4 |
| taint | CodeQLBaselineScorer | both | 1.000 | 1.000 | 1.000 | 4 |
| taint | ConfigSigScorer | request | 0.000 | 0.000 | 0.000 | 4 |
| taint | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| taint | ConfigSigScorer | both | 0.000 | 0.000 | 0.000 | 4 |
| taint | CPGEvidenceScorer | request | 0.000 | 0.000 | 0.000 | 4 |
| taint | CPGEvidenceScorer | code | 1.000 | 1.000 | 1.000 | 4 |
| taint | CPGEvidenceScorer | both | 1.000 | 1.000 | 1.000 | 4 |
| taint | LocalLLMScorer | request | 0.000 | 0.000 | 0.000 | 4 |
| taint | LocalLLMScorer | code | 1.000 | 1.000 | 1.000 | 4 |
| taint | LocalLLMScorer | both | 1.000 | 1.000 | 1.000 | 4 |

## 每 CWE 指标（StructuralHeuristic / ConfigSig / CPGEvidence）

| cwe | scorer | mode | P | R | F1 | support |
| --- | --- | --- | --- | --- | --- | --- |
| CWE-022 | StructuralHeuristicScorer | request | 0.000 | 0.000 | 0.000 | 1 |
| CWE-022 | StructuralHeuristicScorer | code | 1.000 | 1.000 | 1.000 | 1 |
| CWE-022 | StructuralHeuristicScorer | both | 1.000 | 1.000 | 1.000 | 1 |
| CWE-079 | StructuralHeuristicScorer | request | 0.000 | 0.000 | 0.000 | 1 |
| CWE-079 | StructuralHeuristicScorer | code | 1.000 | 1.000 | 1.000 | 1 |
| CWE-079 | StructuralHeuristicScorer | both | 1.000 | 1.000 | 1.000 | 1 |
| CWE-089 | StructuralHeuristicScorer | request | 0.000 | 0.000 | 0.000 | 1 |
| CWE-089 | StructuralHeuristicScorer | code | 1.000 | 1.000 | 1.000 | 1 |
| CWE-089 | StructuralHeuristicScorer | both | 1.000 | 1.000 | 1.000 | 1 |
| CWE-918 | StructuralHeuristicScorer | request | 0.000 | 0.000 | 0.000 | 1 |
| CWE-918 | StructuralHeuristicScorer | code | 1.000 | 1.000 | 1.000 | 1 |
| CWE-918 | StructuralHeuristicScorer | both | 1.000 | 1.000 | 1.000 | 1 |
| CWE-022 | ConfigSigScorer | request | 0.000 | 0.000 | 0.000 | 1 |
| CWE-022 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 1 |
| CWE-022 | ConfigSigScorer | both | 0.000 | 0.000 | 0.000 | 1 |
| CWE-079 | ConfigSigScorer | request | 0.000 | 0.000 | 0.000 | 1 |
| CWE-079 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 1 |
| CWE-079 | ConfigSigScorer | both | 0.000 | 0.000 | 0.000 | 1 |
| CWE-089 | ConfigSigScorer | request | 0.000 | 0.000 | 0.000 | 1 |
| CWE-089 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 1 |
| CWE-089 | ConfigSigScorer | both | 0.000 | 0.000 | 0.000 | 1 |
| CWE-918 | ConfigSigScorer | request | 0.000 | 0.000 | 0.000 | 1 |
| CWE-918 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 1 |
| CWE-918 | ConfigSigScorer | both | 0.000 | 0.000 | 0.000 | 1 |
| CWE-022 | CPGEvidenceScorer | request | 0.000 | 0.000 | 0.000 | 1 |
| CWE-022 | CPGEvidenceScorer | code | 1.000 | 1.000 | 1.000 | 1 |
| CWE-022 | CPGEvidenceScorer | both | 1.000 | 1.000 | 1.000 | 1 |
| CWE-079 | CPGEvidenceScorer | request | 0.000 | 0.000 | 0.000 | 1 |
| CWE-079 | CPGEvidenceScorer | code | 1.000 | 1.000 | 1.000 | 1 |
| CWE-079 | CPGEvidenceScorer | both | 1.000 | 1.000 | 1.000 | 1 |
| CWE-089 | CPGEvidenceScorer | request | 0.000 | 0.000 | 0.000 | 1 |
| CWE-089 | CPGEvidenceScorer | code | 1.000 | 1.000 | 1.000 | 1 |
| CWE-089 | CPGEvidenceScorer | both | 1.000 | 1.000 | 1.000 | 1 |
| CWE-918 | CPGEvidenceScorer | request | 0.000 | 0.000 | 0.000 | 1 |
| CWE-918 | CPGEvidenceScorer | code | 1.000 | 1.000 | 1.000 | 1 |
| CWE-918 | CPGEvidenceScorer | both | 1.000 | 1.000 | 1.000 | 1 |

## 混淆矩阵（全局，行=预测 / 列=真值）

### StructuralHeuristicScorer
| predicted \ truth | vulnerable | benign | abstain | error |
| --- | --- | --- | --- | --- |
| vulnerable | 8 | 0 | 0 | 0 |
| benign | 0 | 0 | 0 | 0 |
| abstain | 4 | 0 | 0 | 0 |
| error | 0 | 0 | 0 | 0 |

### CodeQLBaselineScorer
| predicted \ truth | vulnerable | benign | abstain | error |
| --- | --- | --- | --- | --- |
| vulnerable | 12 | 0 | 0 | 0 |
| benign | 0 | 0 | 0 | 0 |
| abstain | 0 | 0 | 0 | 0 |
| error | 0 | 0 | 0 | 0 |

### ConfigSigScorer
| predicted \ truth | vulnerable | benign | abstain | error |
| --- | --- | --- | --- | --- |
| vulnerable | 0 | 0 | 0 | 0 |
| benign | 8 | 0 | 0 | 0 |
| abstain | 4 | 0 | 0 | 0 |
| error | 0 | 0 | 0 | 0 |

### CPGEvidenceScorer
| predicted \ truth | vulnerable | benign | abstain | error |
| --- | --- | --- | --- | --- |
| vulnerable | 8 | 0 | 0 | 0 |
| benign | 0 | 0 | 0 | 0 |
| abstain | 4 | 0 | 0 | 0 |
| error | 0 | 0 | 0 | 0 |

### LocalLLMScorer
| predicted \ truth | vulnerable | benign | abstain | error |
| --- | --- | --- | --- | --- |
| vulnerable | 8 | 0 | 0 | 0 |
| benign | 0 | 0 | 0 | 0 |
| abstain | 4 | 0 | 0 | 0 |
| error | 0 | 0 | 0 | 0 |
