# PRD：三模式上下文消融实验（LLM + CPG 漏洞检测）

> 课题：基于大语言模型的上下文增强智能漏洞检测（校企合作研究生课题）
> 文档类型：产品需求文档（MVP 消融实验）
> 作者：lauyy32
> 基线事实：已读 `cpg/pipeline.py`、`cpg/dataset.jsonl`、`cpg/slice_builder.py`、`backend/tests/evaluate_v2.py`、`docs/RESEARCH-DESIGN.md`、`docs/decisions/ADR-001.md`；并参照 LLMxCPG(USENIX) — CPG 切片使 F1 提升 15–40%。

## 1. 实验假设
- H1（主）：在请求侧信息量受控下，向 LLM 注入代码级 CPG 上下文（ast/cfg/dfg/taint 文本切片）显著提升样本级判定 F1（相对仅请求模式）。
- H2（副）：「请求+代码」联合模式 F1 不低于纯 CodeQL 2.26.2 基线；若未超越，论证价值落在零规则维护与可解释性，而非绝对精度。

## 2. 变量与对照
- 自变量：输入模式 `{request, code, both}`（三处理）。
- 因变量：样本级二分类正确率 → 精度/召回/F1。
- 控制变量：同一 `dataset.jsonl`、同一可插拔 Scorer 底座（先接 CodeQL 基线 + 结构启发式，后插 Ollama Qwen2.5-Coder）、固定随机种子、CodeQL 锁版 2.26.2。
- 对照：CodeQL 原生 CLI 在同源数据集的判定（外部基线，非引用论文数字）。

## 3. 数据集与划分
- 构成：`dataset.jsonl` 共 16 条真实 CVE（修复前后代码对），跨 11 仓库、11 CWE 族群，语言 Python，单条 `label=vulnerable_before_fixed`。
- 实例展开：每条取 vuln 版本=正例（漏洞）、fixed 版本=负例（良性）→ 共 32 判定实例（「16 样本」=16 CVE）。良性来源即用配对修复版，禁用 SARD 类合成集。
- 划分：样本量极小，不做 train/val/test 拆分；采用全量报告 + 按 CVE leave-one-out 交叉（验证跨 CVE 泛化）+ per-CWE 明细。
- 缺口（须补齐）：`request` 模式需逐 CVE 的攻击者可控输入 / PoC 请求。当前 `dataset.jsonl` 仅含 `summary`/`files`，无请求字段；应由 `cpg/raw_advisories.json` + `evaluate_v2.py` 的 HTTP 模板派生。

## 4. 评估指标与协议
- 定义：TP=正例判漏洞；TN=负例判良性；FP/FN 反之。Precision=TP/(TP+FP)，Recall=TP/(TP+FN)，F1=调和均值。
- 聚合：全局 P/R/F1 + per-CWE 重算 + 混淆矩阵（期望 CWE × 判定 CWE）。
- CodeQL 归一：将 `taint.csv` 的 `(cwe,file)` 命中映射为该文件「存在对应 CWE 漏洞」的判定，文件级对齐样本级。
- 多 seed：锁 Ollama，seed∈{1,2,3} 各跑全量，报告均值±标准差；API 漂移期已弃用。
- 协议：复用 `evaluate_v2.py` 的并发/重试/指标骨架，新增 `code`/`both` 端点与 CodeQL 适配器，输出增量 delta（code−request、both−code）。

## 5. 效度威胁
- 小样本（16 CVE / 32 实例）：F1 置信区间宽，须配 LOO 与效应量，勿过度宣称。
- 数据泄漏：数据取自公开 GitHub CVE，本地模型训练集或含同源仓库 → 须显式声明并讨论；本地模型 + 封闭评估降低风险。
- 基线盲区（最关键）：本集 11 CWE 多为逻辑/访问控制类（CWE-863/862/639/444/295/200/400），CodeQL 库存 taint 查询覆盖弱，基线天然漏报；「both 超 CodeQL」可能源于基线盲区而非 CPG 增益。须分「可污点类 CWE」与「逻辑类 CWE」两组分别报告。
- 版本固化：CodeQL 2.26.2 结果不可跨版本复现，须锁版并记录。

## 6. 构建优先级（RICE）
| 模块 | R | I | C | E | 分 | 序 |
|---|---|---|---|---|---|---|
| 端点骨架 `POST /detect{mode}` | 10 | 2 | 1.0 | 2 | 10.0 | 1 |
| CodeQL 基线适配器 | 10 | 2 | 1.0 | 2 | 10.0 | 1 |
| 可插拔 Scorer 抽象 + 注册 | 10 | 3 | .9 | 3 | 9.0 | 2 |
| `code`/`both` 上下文构造（CPG 切片） | 10 | 3 | .8 | 4 | 6.0 | 3 |
| 三模式消融脚本（复用 evaluate_v2） | 10 | 2 | .9 | 3 | 6.0 | 4 |
| per-CWE + LOO + 多 seed 报告 | 10 | 1 | .9 | 2 | 5.0 | 5 |

MVP 范围：端点骨架 + 可插拔 Scorer + CodeQL 适配器 + 单 seed 全量消融表即可验证 H1/H2。多 seed / LOO / per-CWE 成本可忽略，建议本阶段同步交付，避免二次返工。

## 附：非功能与交付约束
- 图标仅用文字描述（判定徽章、状态标记），禁用 emoji 作功能图标；视觉禁用紫→粉渐变。
- 端点的 `mode` 参数枚举校验：`request|code|both`，非法值返回 422。
- 可复现：所有实验脚本锁定 CodeQL 版本、Ollama 模型标签、随机种子，输出写入 `tests/reports/`。
