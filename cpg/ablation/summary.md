# 三模式上下文消融实验 - 结果汇总

- 生成时间: 2026-08-08 08:29 UTC
- 数据来源: demo (cpg/samples + sample_db)
- 样本版本数: 4  (vuln=正例 / fixed=负例)
- 跳过基线: False
- CodeQL: 2.26.2  python-code-scanning 套件

> 注：demo 模式仅含 4 个 vuln 正例（无 fixed 负例），用于验证聚合链路；真实 dataset.jsonl 全量需逐样本建 DB，已用 demo 验证聚合逻辑。

## 全局指标（正类=vulnerable；abstain 计为未判 vulnerable → 正例召回 0）

| scorer | mode | P | R | F1 | support | TP | FP | TN | FN |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| StructuralHeuristicScorer | request | 0.000 | 0.000 | 0.000 | 4 | 0 | 0 | 0 | 4 |
| StructuralHeuristicScorer | code | 1.000 | 1.000 | 1.000 | 4 | 4 | 0 | 0 | 0 |
| StructuralHeuristicScorer | both | 1.000 | 1.000 | 1.000 | 4 | 4 | 0 | 0 | 0 |
| CodeQLBaselineScorer | request | 1.000 | 1.000 | 1.000 | 4 | 4 | 0 | 0 | 0 |
| CodeQLBaselineScorer | code | 1.000 | 1.000 | 1.000 | 4 | 4 | 0 | 0 | 0 |
| CodeQLBaselineScorer | both | 1.000 | 1.000 | 1.000 | 4 | 4 | 0 | 0 | 0 |

## 分组指标（可污点类 vs 逻辑类）

| group | scorer | mode | P | R | F1 | support |
| --- | --- | --- | --- | --- | --- | --- |
| taint | StructuralHeuristicScorer | request | 0.000 | 0.000 | 0.000 | 4 |
| taint | StructuralHeuristicScorer | code | 1.000 | 1.000 | 1.000 | 4 |
| taint | StructuralHeuristicScorer | both | 1.000 | 1.000 | 1.000 | 4 |
| taint | CodeQLBaselineScorer | request | 1.000 | 1.000 | 1.000 | 4 |
| taint | CodeQLBaselineScorer | code | 1.000 | 1.000 | 1.000 | 4 |
| taint | CodeQLBaselineScorer | both | 1.000 | 1.000 | 1.000 | 4 |

## 每 CWE 指标（StructuralHeuristicScorer）

| cwe | mode | P | R | F1 | support |
| --- | --- | --- | --- | --- | --- |
| CWE-022 | request | 0.000 | 0.000 | 0.000 | 1 |
| CWE-022 | code | 1.000 | 1.000 | 1.000 | 1 |
| CWE-022 | both | 1.000 | 1.000 | 1.000 | 1 |
| CWE-079 | request | 0.000 | 0.000 | 0.000 | 1 |
| CWE-079 | code | 1.000 | 1.000 | 1.000 | 1 |
| CWE-079 | both | 1.000 | 1.000 | 1.000 | 1 |
| CWE-089 | request | 0.000 | 0.000 | 0.000 | 1 |
| CWE-089 | code | 1.000 | 1.000 | 1.000 | 1 |
| CWE-089 | both | 1.000 | 1.000 | 1.000 | 1 |
| CWE-918 | request | 0.000 | 0.000 | 0.000 | 1 |
| CWE-918 | code | 1.000 | 1.000 | 1.000 | 1 |
| CWE-918 | both | 1.000 | 1.000 | 1.000 | 1 |

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
