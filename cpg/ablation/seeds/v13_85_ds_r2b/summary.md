# 上下文消融实验 - 结果汇总

- 生成时间: 2026-09-05 16:02 UTC
- 数据来源: dataset.jsonl (真实 CVE)
- 样本版本数: 84  (vuln=正例 / fixed=负例)
- 模式: code
- 公告摘要注入: False（主结果默认关闭，避免标签泄漏）
- 跳过基线: True
- CodeQL: 2.26.2  python Security/CWE 定向查询（覆盖数据集 CWE-022/918/020/295）
- ConfigSig: 结构型/配置签名基线（CWE-295/059/200 精确签名；020/400/444/639/862/863 显式 abstain）
- CPGEvidence: 直接解析 CPG 污点切片文本做确定性判定（为 LocalLLMScorer 提供同吃切片文本的对照基线）

## 污点覆盖与 CPG 证据排除（11 个样本）

> 以下「可污点类 CWE」样本的 repo 污点查询产出 0 行（建库 / checkout 静默失败），其 CPG 证据评分已显式 **abstain**（不再误判 benign），从 CPGEvidence 指标中自动剔除。CPG 增益仅在这些样本修复并重跑后才可公平评估。完整清单见 `taint_coverage.json`。

- CVE-2026-57516
- CVE-2026-57516
- CVE-2026-59820
- CVE-2026-59820
- CVE-2026-61632
- CVE-2026-61632
- CVE-2026-62677
- CVE-2026-62677
- CVE-2026-70485
- CVE-2026-73417
- CVE-2026-73417

## 全局指标（正类=vulnerable；abstain 计为未判 vulnerable → 正例召回 0）

| scorer | mode | P | R | F1 | support | TP | FP | TN | FN |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| StructuralHeuristicScorer | code | 0.571 | 0.095 | 0.163 | 84 | 4 | 3 | 39 | 38 |
| ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 84 | 0 | 0 | 42 | 42 |
| CPGEvidenceScorer | code | 0.571 | 0.095 | 0.163 | 84 | 4 | 3 | 39 | 38 |
| APILLMScorer | code | 0.611 | 0.262 | 0.367 | 84 | 11 | 7 | 35 | 31 |

## 分组指标（可污点类 vs 逻辑类）

| group | scorer | mode | P | R | F1 | support |
| --- | --- | --- | --- | --- | --- | --- |
| taint | StructuralHeuristicScorer | code | 0.571 | 0.364 | 0.444 | 22 |
| taint | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 22 |
| taint | CPGEvidenceScorer | code | 0.571 | 0.364 | 0.444 | 22 |
| taint | APILLMScorer | code | 0.556 | 0.455 | 0.500 | 22 |
| logic | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 62 |
| logic | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 62 |
| logic | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 62 |
| logic | APILLMScorer | code | 0.667 | 0.194 | 0.300 | 62 |

## 每 CWE 指标（StructuralHeuristic / ConfigSig / CPGEvidence）

| cwe | scorer | mode | P | R | F1 | support |
| --- | --- | --- | --- | --- | --- | --- |
| CWE-020 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-022 | StructuralHeuristicScorer | code | 0.500 | 0.250 | 0.333 | 8 |
| CWE-079 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 6 |
| CWE-094 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-095 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-116 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-125 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-1333 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-176 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-184 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-200 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 8 |
| CWE-201 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-208 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-287 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-319 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-400 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 12 |
| CWE-405 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-444 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-639 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-834 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-862 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 6 |
| CWE-918 | StructuralHeuristicScorer | code | 0.600 | 1.000 | 0.750 | 6 |
| CWE-020 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-022 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 8 |
| CWE-079 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 6 |
| CWE-094 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-095 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-116 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-125 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-1333 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-176 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-184 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-200 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 8 |
| CWE-201 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-208 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-287 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-319 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-400 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 12 |
| CWE-405 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-444 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-639 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-834 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-862 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 6 |
| CWE-918 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 6 |
| CWE-020 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-022 | CPGEvidenceScorer | code | 0.500 | 0.250 | 0.333 | 8 |
| CWE-079 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 6 |
| CWE-094 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-095 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-116 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-125 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-1333 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-176 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-184 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-200 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 8 |
| CWE-201 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-208 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-287 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-319 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-400 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 12 |
| CWE-405 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-444 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-639 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-834 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-862 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 6 |
| CWE-918 | CPGEvidenceScorer | code | 0.600 | 1.000 | 0.750 | 6 |

## 混淆矩阵（全局，行=预测 / 列=真值）

### StructuralHeuristicScorer
| predicted \ truth | vulnerable | benign | abstain | error |
| --- | --- | --- | --- | --- |
| vulnerable | 4 | 3 | 0 | 0 |
| benign | 38 | 39 | 0 | 0 |
| abstain | 0 | 0 | 0 | 0 |
| error | 0 | 0 | 0 | 0 |

### ConfigSigScorer
| predicted \ truth | vulnerable | benign | abstain | error |
| --- | --- | --- | --- | --- |
| vulnerable | 0 | 0 | 0 | 0 |
| benign | 28 | 26 | 0 | 0 |
| abstain | 14 | 16 | 0 | 0 |
| error | 0 | 0 | 0 | 0 |

### CPGEvidenceScorer
| predicted \ truth | vulnerable | benign | abstain | error |
| --- | --- | --- | --- | --- |
| vulnerable | 4 | 3 | 0 | 0 |
| benign | 0 | 0 | 0 | 0 |
| abstain | 38 | 39 | 0 | 0 |
| error | 0 | 0 | 0 | 0 |

### APILLMScorer
| predicted \ truth | vulnerable | benign | abstain | error |
| --- | --- | --- | --- | --- |
| vulnerable | 11 | 7 | 0 | 0 |
| benign | 13 | 16 | 0 | 0 |
| abstain | 18 | 19 | 0 | 0 |
| error | 0 | 0 | 0 | 0 |
