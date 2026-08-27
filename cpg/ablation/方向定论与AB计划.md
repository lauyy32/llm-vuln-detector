# CPG 路线方向定论与 A+B 执行计划

> 日期：2026-08-27
> 背景：LocalLLMScorer 接入后，真实 CVE 全量消融 LLM 与静态基线持平（0 召回），
> 引发"CPG 这条路是否没有成效"的疑虑。本文给出基于数据的判定与对策。

## 1. 0 召回是实验假象，不是 CPG 失效

对 `dataset.jsonl` 16 条真实 CVE 的 CWE 构成做了精确拆解，并结合 corpus 级
`taint.csv`（仅表头、0 行）定位根因：

| 类别 | CWE | 样本 | 占比 | 应由谁覆盖 |
|------|-----|------|------|-----------|
| 数据流污点型 | CWE-22×3、CWE-918×2 | 5 | 31% | CPG taint（A 领地） |
| 语义/逻辑型 | CWE-863/862/639（鉴权越权）×5、CWE-200×3、CWE-400×2、CWE-444×2、CWE-59/20/295×1 | 11 | 69% | LLM 语义推理（B 领地） |

**两层次根因：**

1. **69% 的样本是语义/逻辑型漏洞**（鉴权缺失、DoS 无界、请求走私、信息泄露）。
   这类缺陷在原理上就不是数据流问题——`taint` 永远表达不了"某处缺少一个检查"。
   所以 CPG→LLM 的污点证据层在这些样本上**必然为空**，LLM 看到空证据判 benign 是预期行为，
   不是 CPG 或 LLM 失败。
2. **剩余 31% 污点型样本之所以 0 命中，是查询覆盖缺口**：corpus 仓库用的是自定义框架
   入口（thumbor `load(context, path)` 的 `path` 参数、flytohub/linuxfabrik `fetch()` 的 URL 参数），
   CodeQL 标准 `PathInjectionFlow`/`FullServerSideRequestForgeryFlow` 只认识官方框架 source，
   不认识这些自定义入口——sink（`open()`）认识，source（自定义参数）不认识，流断在源头。

已验证：CodeQLBaseline（官方查询套件）在同一语料上找到 2 个真漏洞，证明 **CPG/CodeQL
本身能命中真实漏洞**，死的是"自定义 CPG→LLM 证据层"这条提取链，而非 CPG 方向。

## 2. 方向判定：CPG 路线正确，贡献点须重构为"互补性"

正确立论不是"LLM+CPG 胜过静态分析"，而是**互补性（complementarity）**：

- CPG/taint 吃下 31% 数据流漏洞；
- LLM 语义层吃下 69% 逻辑漏洞（消费 CPG 结构上下文做推理）；
- 二者合并覆盖全集，单拎任何一个都覆盖不全。

这恰好是课题"基于大语言模型的**上下文增强**智能漏洞检测"最自洽的落地形态，
且对审稿人"为什么既要 CPG 又要 LLM"有清晰应答。

## 3. A+B 执行计划（已建任务）

### A — 强化 CPG 提取（数据流域 31%）

- **A-1** 写 `cpg_sources.qll`：把 thumbor `load` 的 `path` 参数、fetch/request 的 URL 参数
  声明为污点 source；`taint.ql` 改走 `CustomPathInjectionConfig`（复用 `PathInjection::Sink`），
  `cwe-918.ql` 通过 `extends ServerSideRequestForgery::Configuration` 加 source。
  —— **已落地，后台对 corpus DB 跑验证中。**
- **A-2** 重跑 corpus 级 6 个 taint 查询，确认 CWE-22/CWE-918 在真实代码上产生非空命中行。

### B — LLM 语义层（逻辑域 69%，核心贡献）

- **B-1** harness（`run_ablation.py`）对语义型样本注入 **CPG 结构切片**（AST/CFG/DFG 文本）
  + 漏洞函数源码 + fix diff，作为"部分/歧义证据"交给 LocalLLMScorer 推理
  （scorer 已支持 `cpg_slices`/`code_text`，缺的是 harness 接线）。
- **B-2** 构造"部分证据"基准：语义型样本给 LLM 定位可疑区域但 taint 无流，要求语义判定；
  对照组 StructuralHeuristic/ConfigSig 在逻辑型上实测 0 召回，
  验证 LLM+CPG结构 在该子集 P/R/F1 显著高于确定性基线。
- **B-3** 消融报告按漏洞类型分组（污点子集 vs 语义子集）分别报各 Scorer 指标，
  显式写出互补性结论。

## 4. 当前进度

- Ollama + `qwen2.5-coder:7b` 就绪，LocalLLMScorer 集成验证可用（demo F1=1.0）。
- A-1/A-2 均已完成：corpus 级真实污点版全量消融已跑通，LocalLLMScorer F1 由 0.000（空污点）提升至 **0.483**（真实污点），证实"上下文增强"假设；但 LLM 与确定性 CPGEvidence（F1=0.516）持平略低，"LLM 优于静态"未成立，贡献点重构为互补性。
- A-1 实证（查漏补缺）：`taint.ql`(CWE-022)=115 行、`cwe-918.ql`(CWE-918)=10 行真实污点流，fresh re-run 可复现。已提交 `b72f15f`（本地，未推送，待新 PAT）。
- **B-0.5（深坑修复，已完成）**：真实样本 `code_text` 曾被硬编码空串（LLM 看不到源码）→ 修复为 `_load_sample_code` 注入真实源码（taint 锚点块优先、≤6000 字符）+ `build_cpg_slices_text` 按 abs_path 读行。同时发现并治理 2 个污染样本（69248/69249，Rust 修复、Python 侧 diff=0），harness 新增 `--exclude-cves`。
- **干净版消融（28 样本）**：LocalLLMScorer F1=**0.462**、CPGEvidence F1=0.480——LLM 与确定性解析器基本打平（差 0.018），仍未证明独有优势。
- **B-2 实证素材已找到**：CVE-2026-53505（thumbor CWE-400）——无 taint 证据，CPGEvidence 判 benign（错），LLM 语义推理判 vulnerable（对），rationale 实证。这是"确定性解析器必然失败、LLM 语义成功"的天然样本；LLM 另有 4 个独错（3 个诚实 abstain）。
- **A 系列迭代（已完成）**：新增 `tarslip.ql`（复用官方 TarSlipFlow），覆盖 CWE-022 的 tar 提取子类（PathInjection 只认 open 类 sink，extractall/extract 此前失明）；corpus DB 实测命中 50558 的 2 行真实流（vuln 无守卫 extractall / fixed safe wrapper 内 guarded extractall）。同时修复 `_load_sample_code` 锚点排序 bug（sink 密集区间被 6000 字符截断挤出，安全包装定义丢失）。
- **含 TarSlip 证据干净消融（28 样本）**：**LocalLLMScorer F1=0.500（P=0.500 R=0.500），首次追平反超 CPGEvidence（F1=0.480）**；taint 子集三者并列 0.600；**logic 子集 LLM 0.444 首次反超 CPGEvidence 0.400**。改善来自 67435_vuln（abstain→vulnerable，带摘要稳定可复现）。注：样本量小（1-2 样本差异），需多 seed 验证；7B 在复杂语义（TarSlip 安全包装识别）上仍失败，14B 因 17GB RAM 受限列为 future work。
