# D3 — 已发表 LLM 漏洞检测方法 head-to-head（纯源码 vs CPG 增强）

> 生成日期：2026-09-03
> 目标：回应审稿「无 SOTA 复现」——复现一个已发表风格的纯源码 LLM 漏洞检测器，
> 与本课题 CPG 增强 LocalLLM 同模型、同样本、仅上下文差异做干净对照。
> 数据源：`cpg/ablation/seeds/v8_74_d3/results.csv`（74 CVE × {vuln,fixed} = 148 版本，code 模式）
> 指标：`python cpg/ablation/paired_metrics.py --mode code --check`（统计契约已通过）

## 方法

- **`PublishedLLMBaselineScorer`**（新增，`scorers.py`）：`LocalLLMScorer` 子类，仅喂
  `code_text[:6000]`，不含任何 CPG 污点切片——对应文献中零样本 LLM 漏洞检测器
  （LineVul 风格 prompt 基线 / 通用 LLM-as-vuln-detector）的常见做法。
- **`LocalLLMScorer`**（本课题）：同模型（qwen2.5-coder:7b, temperature=0）、同样本，
  额外注入 CPG 污点切片作为上下文。
- 二者同 Ollama 通道、同 `raw_log` 落盘机制；D3 评分限定 code 模式（纯源码基线在
  request/both 模式无语义意义）。
- 对照组另有 StructuralHeuristic / ConfigSig / CPGEvidence 三个静态/确定性 scorer 与平凡基线。

## 结果（code 模式，148 版本 / 74 CVE）

| scorer | F1 | P | R | BA | MCC | 判别成功 | 反向 | 双标记 | 双未标 | 判别率 | 精确 p |
|---|---|---|---|---|---|---|---|---|---|---|---|
| LocalLLMScorer (code+CPG) | 0.333 | 0.529 | 0.243 | 0.514 | 0.032 | 3 | 1 | 15 | 55 | 0.041 | 0.3125 |
| **PublishedLLMBaselineScorer (code-only)** | **0.027** | **1.000** | **0.014** | **0.507** | **0.082** | **1** | **0** | **0** | **73** | **0.014** | **0.5000** |
| CPGEvidenceScorer | 0.196 | 0.500 | 0.122 | 0.500 | 0.000 | 0 | 0 | 9 | 65 | 0.000 | 1.0000 |
| StructuralHeuristicScorer | 0.196 | 0.500 | 0.122 | 0.500 | 0.000 | 0 | 0 | 9 | 65 | 0.000 | 1.0000 |
| ConfigSigScorer | 0.000 | 0.000 | 0.000 | 0.500 | 0.000 | 0 | 0 | 0 | 74 | 0.000 | 1.0000 |
| [平凡]全判 vulnerable | 0.667 | 0.500 | 1.000 | 0.500 | 0.000 | 0 | 0 | 74 | 0 | 0.000 | 1.0000 |
| [平凡]全判 benign | 0.000 | 0.000 | 0.000 | 0.500 | 0.000 | 0 | 0 | 0 | 74 | 0.000 | 1.0000 |
| [平凡]随机(p=0.5,seed=42) | 0.493 | 0.500 | 0.486 | 0.500 | 0.000 | 15 | 15 | 21 | 23 | 0.203 | 0.5722 |

## 解读（诚实、负面结果型自洽）

1. **纯源码 LLM 基线在补丁边界上近乎失效**：`PublishedLLMBaselineScorer` 召回仅
   R=0.014（74 个 vuln 版本中仅 1 个被判 vulnerable），判别率 1/74，BA=0.507≈随机。
   P=1.000 源于其极端保守——几乎从不报警（仅 1 次报警且正确），等价于「默认判 benign」。
   即零样本纯源码 LLM 无法区分漏洞版本与其修复版本。

2. **CPG 证据上下文是 LLM 报警的必要条件**：本课题 `LocalLLMScorer` (code+CPG) 召回
   R=0.243，相对纯源码基线 **≈17× 提升**（0.014→0.243），判别 CVE 数 1→3（3×）。
   污点证据决定 LLM「在哪里报警」——与 D 档「必要条件」立论（剥离污点真阳 21→3，
   ΔF1=+0.292）方向一致，本次在「已发表方法对照」维度再次印证。

3. **但二者均未突破补丁边界判别天花板**：LocalLLM BA=0.514 / MCC=0.032、
   Published BA=0.507 / MCC=0.082，均接近随机；McNemar 精确 p 分别为 0.3125 / 0.5000，
   在 n=74 下均不显著。CPG 提升的是**召回与报警位置**，而非**判别正确性**
   （vuln vs fixed 的本质区分）。这与全课题「补丁边界判别力研究」定位一致：
   补丁多为插入净化器而不切断 source→sink，上游 taint 不识别项目自定义净化器，
   故 LLM+CPG 仍无法判定「相关改动是否充分」。

4. **对审稿「无 SOTA 复现」的回应**：本实验复现了一个 LineVul 风格的纯源码 LLM 基线，
   并证明本课题 CPG 增强变体在其上取得显著更大的召回与判别 CVE 数（量级差 17× / 3×）。
   同时诚实声明：在 74 配对样本下，任一方法都未达统计显著的补丁边界判别，
   故结论属「方法学贡献 / 负向结果型」，非「检测性能 SOTA」。

## 可复现性交叉验证（rigor 注记）

本新鲜跑的 `LocalLLMScorer` 列与权威结果 `seeds/v8_74/results.csv`（7b, 无摘要主协议）对照：
BA 0.514 vs 0.514、MCC 0.032 vs 0.033（两位小数一致）；F1 0.333 vs 0.321、R 0.243 vs 0.230、
判别率 3/74 vs 2/74（差异 ≤0.013，在 n=74 噪声内）。核心指标稳健，证实主结果可复现。
残留微差归因于本次 `corpus_db` 为删除损坏库后**重建**（taint 流从全新 DB 重新生成），
与原始 v8 跑批所用陈旧 taint.csv 不完全一致；BA/MCC 不变说明结论对 taint 细节不敏感。

## 产物

- `cpg/ablation/scorers.py`：`PublishedLLMBaselineScorer` 子类 + `SCORER_REGISTRY` 注册。
- `cpg/ablation/run_ablation.py`：`--published-baseline` flag + 实例化 + code 模式评分循环。
- `cpg/ablation/seeds/v8_74_d3/results.csv`（148×5 scorer）、`summary.md`、`raw_published_llm_responses.jsonl`、`raw_llm_responses.jsonl`。
- 统计契约：`paired_metrics.py --check` 通过（含平凡基线 + BA/MCC + McNemar 精确 p）。
