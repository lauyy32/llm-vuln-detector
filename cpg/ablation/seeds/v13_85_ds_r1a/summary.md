# 上下文消融实验 - 结果汇总

- 生成时间: 2026-09-05 15:16 UTC
- 数据来源: dataset.jsonl (真实 CVE)
- 样本版本数: 86  (vuln=正例 / fixed=负例)
- 模式: code
- 公告摘要注入: False（主结果默认关闭，避免标签泄漏）
- 跳过基线: True
- CodeQL: 2.26.2  python Security/CWE 定向查询（覆盖数据集 CWE-022/918/020/295）
- ConfigSig: 结构型/配置签名基线（CWE-295/059/200 精确签名；020/400/444/639/862/863 显式 abstain）
- CPGEvidence: 直接解析 CPG 污点切片文本做确定性判定（为 LocalLLMScorer 提供同吃切片文本的对照基线）

## 污点覆盖与 CPG 证据排除（8 个样本）

> 以下「可污点类 CWE」样本的 repo 污点查询产出 0 行（建库 / checkout 静默失败），其 CPG 证据评分已显式 **abstain**（不再误判 benign），从 CPGEvidence 指标中自动剔除。CPG 增益仅在这些样本修复并重跑后才可公平评估。完整清单见 `taint_coverage.json`。

- CVE-2026-48782
- CVE-2026-48782
- CVE-2026-50180
- CVE-2026-50180
- CVE-2026-54654
- CVE-2026-54654
- CVE-2026-9335
- CVE-2026-9335

## 全局指标（正类=vulnerable；abstain 计为未判 vulnerable → 正例召回 0）

| scorer | mode | P | R | F1 | support | TP | FP | TN | FN |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| StructuralHeuristicScorer | code | 0.500 | 0.140 | 0.218 | 86 | 6 | 6 | 37 | 37 |
| ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 86 | 0 | 0 | 43 | 43 |
| CPGEvidenceScorer | code | 0.500 | 0.140 | 0.218 | 86 | 6 | 6 | 37 | 37 |
| APILLMScorer | code | 0.640 | 0.372 | 0.471 | 86 | 16 | 9 | 34 | 27 |

## 分组指标（可污点类 vs 逻辑类）

| group | scorer | mode | P | R | F1 | support |
| --- | --- | --- | --- | --- | --- | --- |
| taint | StructuralHeuristicScorer | code | 0.500 | 0.545 | 0.522 | 22 |
| taint | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 22 |
| taint | CPGEvidenceScorer | code | 0.500 | 0.545 | 0.522 | 22 |
| taint | APILLMScorer | code | 0.750 | 0.545 | 0.632 | 22 |
| logic | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 64 |
| logic | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 64 |
| logic | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 64 |
| logic | APILLMScorer | code | 0.588 | 0.312 | 0.408 | 64 |

## 每 CWE 指标（StructuralHeuristic / ConfigSig / CPGEvidence）

| cwe | scorer | mode | P | R | F1 | support |
| --- | --- | --- | --- | --- | --- | --- |
| CWE-020 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-022 | StructuralHeuristicScorer | code | 0.500 | 0.750 | 0.600 | 16 |
| CWE-059 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-061 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-074 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-088 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-094 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-095 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-1333 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-178 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-200 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-287 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-295 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-306 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-346 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-400 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 10 |
| CWE-407 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-455 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-552 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-601 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-639 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-668 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-732 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-863 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-918 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-020 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-022 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 16 |
| CWE-059 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-061 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-074 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-088 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-094 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-095 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-1333 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-178 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-200 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-287 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-295 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-306 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-346 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-400 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 10 |
| CWE-407 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-455 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-552 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-601 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-639 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-668 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-732 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-863 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-918 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-020 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-022 | CPGEvidenceScorer | code | 0.500 | 0.750 | 0.600 | 16 |
| CWE-059 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-061 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-074 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-088 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-094 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-095 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-1333 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-178 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-200 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-287 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-295 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-306 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-346 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-400 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 10 |
| CWE-407 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-455 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-552 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-601 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-639 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-668 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-732 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-863 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-918 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 4 |

## 混淆矩阵（全局，行=预测 / 列=真值）

### StructuralHeuristicScorer
| predicted \ truth | vulnerable | benign | abstain | error |
| --- | --- | --- | --- | --- |
| vulnerable | 6 | 6 | 0 | 0 |
| benign | 37 | 37 | 0 | 0 |
| abstain | 0 | 0 | 0 | 0 |
| error | 0 | 0 | 0 | 0 |

### ConfigSigScorer
| predicted \ truth | vulnerable | benign | abstain | error |
| --- | --- | --- | --- | --- |
| vulnerable | 0 | 0 | 0 | 0 |
| benign | 33 | 32 | 0 | 0 |
| abstain | 10 | 11 | 0 | 0 |
| error | 0 | 0 | 0 | 0 |

### CPGEvidenceScorer
| predicted \ truth | vulnerable | benign | abstain | error |
| --- | --- | --- | --- | --- |
| vulnerable | 6 | 6 | 0 | 0 |
| benign | 0 | 0 | 0 | 0 |
| abstain | 37 | 37 | 0 | 0 |
| error | 0 | 0 | 0 | 0 |

### APILLMScorer
| predicted \ truth | vulnerable | benign | abstain | error |
| --- | --- | --- | --- | --- |
| vulnerable | 16 | 9 | 0 | 0 |
| benign | 9 | 13 | 0 | 0 |
| abstain | 18 | 21 | 0 | 0 |
| error | 0 | 0 | 0 | 0 |
