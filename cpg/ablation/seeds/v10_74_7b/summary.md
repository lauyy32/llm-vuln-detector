# 上下文消融实验 - 结果汇总

- 生成时间: 2026-09-04 11:04 UTC
- 数据来源: dataset.jsonl (真实 CVE)
- 样本版本数: 148  (vuln=正例 / fixed=负例)
- 模式: code
- 公告摘要注入: False（主结果默认关闭，避免标签泄漏）
- 跳过基线: True
- CodeQL: 2.26.2  python Security/CWE 定向查询（覆盖数据集 CWE-022/918/020/295）
- ConfigSig: 结构型/配置签名基线（CWE-295/059/200 精确签名；020/400/444/639/862/863 显式 abstain）
- CPGEvidence: 直接解析 CPG 污点切片文本做确定性判定（为 LocalLLMScorer 提供同吃切片文本的对照基线）

## 污点覆盖与 CPG 证据排除（20 个样本）

> 以下「可污点类 CWE」样本的 repo 污点查询产出 0 行（建库 / checkout 静默失败），其 CPG 证据评分已显式 **abstain**（不再误判 benign），从 CPGEvidence 指标中自动剔除。CPG 增益仅在这些样本修复并重跑后才可公平评估。完整清单见 `taint_coverage.json`。

- CVE-2026-48782
- CVE-2026-48782
- CVE-2026-50180
- CVE-2026-50180
- CVE-2026-54654
- CVE-2026-54654
- CVE-2026-57516
- CVE-2026-57516
- CVE-2026-59820
- CVE-2026-59820
- CVE-2026-59894
- CVE-2026-59894
- CVE-2026-61632
- CVE-2026-61632
- CVE-2026-68508
- CVE-2026-68508
- CVE-2026-73417
- CVE-2026-73417
- CVE-2026-9335
- CVE-2026-9335

## 全局指标（正类=vulnerable；abstain 计为未判 vulnerable → 正例召回 0）

| scorer | mode | P | R | F1 | support | TP | FP | TN | FN |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| StructuralHeuristicScorer | code | 0.500 | 0.122 | 0.196 | 148 | 9 | 9 | 65 | 65 |
| ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 148 | 0 | 0 | 74 | 74 |
| CPGEvidenceScorer | code | 0.500 | 0.122 | 0.196 | 148 | 9 | 9 | 65 | 65 |
| LocalLLMScorer | code | 0.548 | 0.230 | 0.324 | 148 | 17 | 14 | 60 | 57 |

## 分组指标（可污点类 vs 逻辑类）

| group | scorer | mode | P | R | F1 | support |
| --- | --- | --- | --- | --- | --- | --- |
| taint | StructuralHeuristicScorer | code | 0.500 | 0.450 | 0.474 | 40 |
| taint | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 40 |
| taint | CPGEvidenceScorer | code | 0.500 | 0.450 | 0.474 | 40 |
| taint | LocalLLMScorer | code | 0.500 | 0.500 | 0.500 | 40 |
| logic | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 108 |
| logic | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 108 |
| logic | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 108 |
| logic | LocalLLMScorer | code | 0.636 | 0.130 | 0.215 | 108 |

## 每 CWE 指标（StructuralHeuristic / ConfigSig / CPGEvidence）

| cwe | scorer | mode | P | R | F1 | support |
| --- | --- | --- | --- | --- | --- | --- |
| CWE-020 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-022 | StructuralHeuristicScorer | code | 0.500 | 0.636 | 0.560 | 22 |
| CWE-059 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-061 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-074 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-079 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-088 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-094 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 8 |
| CWE-095 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-125 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-1333 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 6 |
| CWE-176 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-178 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-200 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 10 |
| CWE-201 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-287 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-295 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-306 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 6 |
| CWE-346 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-347 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-400 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 16 |
| CWE-444 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 6 |
| CWE-455 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-552 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-601 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-639 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 8 |
| CWE-668 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-732 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-770 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-834 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-862 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-863 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-918 | StructuralHeuristicScorer | code | 0.500 | 0.500 | 0.500 | 8 |
| CWE-020 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-022 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 22 |
| CWE-059 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-061 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-074 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-079 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-088 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-094 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 8 |
| CWE-095 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-125 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-1333 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 6 |
| CWE-176 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-178 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-200 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 10 |
| CWE-201 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-287 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-295 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-306 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 6 |
| CWE-346 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-347 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-400 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 16 |
| CWE-444 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 6 |
| CWE-455 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-552 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-601 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-639 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 8 |
| CWE-668 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-732 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-770 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-834 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-862 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-863 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-918 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 8 |
| CWE-020 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-022 | CPGEvidenceScorer | code | 0.500 | 0.636 | 0.560 | 22 |
| CWE-059 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-061 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-074 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-079 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-088 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-094 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 8 |
| CWE-095 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-125 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-1333 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 6 |
| CWE-176 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-178 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-200 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 10 |
| CWE-201 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-287 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-295 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-306 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 6 |
| CWE-346 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-347 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-400 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 16 |
| CWE-444 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 6 |
| CWE-455 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-552 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-601 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-639 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 8 |
| CWE-668 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-732 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-770 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-834 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-862 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-863 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-918 | CPGEvidenceScorer | code | 0.500 | 0.500 | 0.500 | 8 |

## 混淆矩阵（全局，行=预测 / 列=真值）

### StructuralHeuristicScorer
| predicted \ truth | vulnerable | benign | abstain | error |
| --- | --- | --- | --- | --- |
| vulnerable | 9 | 9 | 0 | 0 |
| benign | 65 | 65 | 0 | 0 |
| abstain | 0 | 0 | 0 | 0 |
| error | 0 | 0 | 0 | 0 |

### ConfigSigScorer
| predicted \ truth | vulnerable | benign | abstain | error |
| --- | --- | --- | --- | --- |
| vulnerable | 0 | 0 | 0 | 0 |
| benign | 54 | 54 | 0 | 0 |
| abstain | 20 | 20 | 0 | 0 |
| error | 0 | 0 | 0 | 0 |

### CPGEvidenceScorer
| predicted \ truth | vulnerable | benign | abstain | error |
| --- | --- | --- | --- | --- |
| vulnerable | 9 | 9 | 0 | 0 |
| benign | 0 | 0 | 0 | 0 |
| abstain | 65 | 65 | 0 | 0 |
| error | 0 | 0 | 0 | 0 |

### LocalLLMScorer
| predicted \ truth | vulnerable | benign | abstain | error |
| --- | --- | --- | --- | --- |
| vulnerable | 17 | 14 | 0 | 0 |
| benign | 48 | 52 | 0 | 0 |
| abstain | 9 | 8 | 0 | 0 |
| error | 0 | 0 | 0 | 0 |
