# LLM-VulnDetector

> 基于 LLM 的 HTTP 攻击载荷识别原型（CoT 分步推理增强版） | LLM-Assisted HTTP Attack Payload Classifier (CoT-Enhanced)

输入一条原始 HTTP 请求 → 多维上下文解析（编码检测 + 混淆分析 + 正则预扫描）→ LLM CoT 分步推理 → 输出该请求是否疑似包含某类攻击 payload。

**Author**: [lauyy32](https://github.com/lauyy32)

---

## 这个项目能做什么 / 不能做什么

**能做的**：判断一条 HTTP 请求的参数值里，是否出现某类攻击的典型 payload 特征（SQL 注入、XSS、命令注入等 10 类），并给出类型、置信度和成因分析。**v2.0 增加了编码检测与混淆分析**，能透视 URL 编码/Unicode/双重编码等绕过手法。

**不能做的**：
- 看不到服务端源码，无法判断参数是否真的被拼进 SQL / shell —— **不能确认漏洞可利用**
- 不能替代 SQLMap、Burp Active Scan 等需要服务端反馈的工具
- 不是 SAST/DAST，不做代码扫描，不做流量代理
- v2.0 的上下文增强仍是请求侧分析，未引入 CPG/AST 等代码级分析

**所以本质上**：这是一个"疑似攻击请求分类器"，"is_vulnerable=true"的真实含义是"该请求携带了某类攻击的典型 payload"，而不是"目标系统存在该漏洞"。

这个项目是我的研究生课题"基于大语言模型的上下文增强智能漏洞检测技术研究"的**最小可行原型**，用来验证"上下文增强能否提升 LLM 对攻击请求的识别效果"这个想法。

---

## v2.0 核心升级：Chain-of-Thought 分步推理

相较于 v1.0 的"正则预扫描 → LLM 直接判定"，v2.0 引入了一个**更深的上下文增强层**：

```
原始 HTTP 请求
      │
      ▼
┌─────────────────────────────┐
│ 1. 编码检测与逐层解码         │  ← URL编码/Unicode/HTML实体/Base64
│    (detect_encoding_layers)  │
└──────────┬──────────────────┘
           ▼
┌─────────────────────────────┐
│ 2. 混淆模式分析              │  ← 大小写/空白符/注释注入/NULL截断
│    (analyze_confusion)       │
└──────────┬──────────────────┘
           ▼
┌─────────────────────────────┐
│ 3. 风险信号预扫描（22 类正则）│  ← 原 v1.0 信号 + 编码/混淆专属信号
└──────────┬──────────────────┘
           ▼
┌─────────────────────────────┐
│ 4. 多维上下文构造             │  ← 编码报告 + 混淆报告 + 预扫描报告
│    (build_structured_context)│
└──────────┬──────────────────┘
           ▼
┌─────────────────────────────┐
│ 5. LLM CoT 分步推理          │  ← 步骤1:理解上下文 → 步骤2:解码还原
│    (System Prompt v2.0)      │      → 步骤3:识别混淆 → 步骤4:语义分析
│                              │      → 步骤5:综合判定          │
└──────────┬──────────────────┘
           ▼
   检测结果 JSON (含 CoT 推理摘要)
```

**关键创新点**：不是简单地让 LLM 看 raw HTTP，而是给它一个**分析过的、解码过的、去混淆的**结构化上下文，再引导它按 CoT 步骤推理。这对应课题中"上下文增强"的核心概念——探索什么样的上下文信息能让 LLM 的检测效果最优。

---

## 功能特性

- **10 类攻击 payload 识别**：SQL注入、XSS、命令注入、路径穿越、SSRF、文件上传、XXE、SSTI、NoSQL注入、开放重定向
- **编码检测与解码**：自动识别 URL编码/Unicode/HTML实体/Base64 等编码层级，逐层解码还原真实 payload
- **混淆模式分析**：检测大小写混淆、空白符替代、注释注入、NULL截断、宽字节绕过等绕过手法
- **CoT 分步推理**：引导 LLM 先理解上下文 → 解码 → 去混淆 → 语义分析 → 综合判定（非一次性输出）
- **三种检测模式**（用于消融实验）：
  - `cot` — 增强上下文 + CoT 分步推理（默认，最强）
  - `standard` — 增强上下文 + 标准 Prompt（对比 CoT 的增益）
  - `no-context` — 无上下文增强（基线）
- **降误报设计**：few-shot 示例 + 自检机制 + 置信度量化（0-100）
- **批量检测 + SQLite 持久化 + 统计面板**
- **Docker 一键部署**

---

## 技术栈

| 层 | 技术 |
|---|---|
| 后端 | Python 3.11+ / FastAPI / httpx / Pydantic v2 / SQLite |
| 前端 | Vue 3 / Element Plus / Vite / Axios |
| LLM | DeepSeek-Chat（兼容 OpenAI 接口，可替换） |
| 部署 | Docker / docker-compose / Nginx |

---

## 快速开始

### Docker 一键部署（推荐）

```bash
cp .env.example .env   # 编辑 .env，填入 DeepSeek API Key
docker-compose up -d
# 前端: http://localhost
# API 文档: http://localhost:8000/docs
```

### 本地开发

```bash
# 后端
cd backend
pip install -r requirements.txt
cp .env.example .env   # 填入 DeepSeek API Key
uvicorn app.main:app --reload --port 8000

# 前端
cd frontend
npm install
npm run dev            # http://localhost:5173
```

---

## API

| 接口 | 方法 | 说明 |
|---|---|---|
| `/api/detect` | POST | **CoT 模式** — 增强上下文 + 分步推理（推荐） |
| `/api/detect-standard` | POST | **标准模式** — 增强上下文 + 标准 Prompt（消融对比） |
| `/api/detect-no-context` | POST | **消融基线** — 无上下文增强 |
| `/api/batch-detect` | POST | 批量识别（最多50条） |
| `/api/history` | GET | 历史记录（分页） |
| `/api/history/{id}` | GET | 单条历史详情 |
| `/api/history` | DELETE | 清空历史记录 |
| `/api/stats` | GET | 检测统计 |
| `/health` | GET | 健康检查 |

启动后端后访问 `http://localhost:8000/docs` 查看完整 Swagger 文档。

---

## 测试与评测

### 单元测试

```bash
cd backend
python -m pytest tests/ -v
```
覆盖模块：context_builder、llm_engine、schemas、history_store（54 个测试用例）

### 综合评测（v2.1 三模式消融 + 完整指标）

> **研究问题**：上下文增强 + CoT 推理是否提升 LLM 攻击载荷识别效果？
> 通过 CoT / Standard / No-Context 三模式在同一数据集上的指标差异（Δ）量化各自贡献。

```bash
cd backend
# 启动后端: uvicorn app.main:app --reload --port 8000

# Dry-run（验证数据，不调 API）
python tests/evaluate_v2.py --dry-run

# 全量三模式消融评测（302 样本 = 56 标准 + 246 对抗，× 3 模式）
python tests/evaluate_v2.py --dataset all --modes cot standard no-context

# 仅对抗样本三模式
python tests/evaluate_v2.py --dataset adversarial --modes cot standard no-context

# 快速测试（仅前20条，三模式）
python tests/evaluate_v2.py --max-samples 20 --modes cot standard no-context
```

**评测特性（v2.1）**：
- **异步并发**：`VD_CONCURRENCY`（默认 6）+ 信号量限流，批量评测从"串行数十分钟"降到数分钟
- **重试退避**：超时 / 429 / 5xx 自动重试（指数退避，尊重 `Retry-After`）
- **完整指标**：攻击级召回(Recall)、类型精确检出率、Precision / Recall / F1 / Accuracy、类型准确率
- **类型级混淆矩阵**：`expected_type × detected_type`，定位"错判成什么"
- **错误透明化**：逐条记录真实 API 错误原因（超时 / 限流 / 服务端错误），便于诊断

**评测产出**：
- `backend/tests/reports/evaluation_v2_report.json` — 三模式消融对比报告
- `backend/tests/reports/evaluation_v2_report_details.json` — 逐条详细结果

### 数据集

| 数据集 | 数量 | 说明 |
|---|---|---|
| `dataset/test_cases.json` | 56 条 | 手工构造（41攻击 + 12正常 + 3边界） |
| `dataset/adversarial_samples.json` | 246 条 | 205 条攻击（编码/混淆/绕过/WAF）+ 41 条正常混淆样本（含 1 条原 WAF 样本 `adv_waf_011` 纠正为良性） |

### DVWA 靶场端到端验证 + ModSecurity 对比

```bash
# 启动靶场和 WAF（3 档 Paranoia Level）
docker-compose up -d dvwa modsecurity-pl1 modsecurity-pl2 modsecurity-pl3

# 启动后端 + 运行评测
cd backend
python tests/benchmark_dvwa.py                    # 完整: 3 难度 × 3 PL
python tests/benchmark_dvwa.py --no-modsec         # 仅 LLM
```

测试矩阵：**DVWA low/medium/high（3 档）× 6 个场景 × 2 种请求 = 36 条 LLM 检测**，每条同时过 ModSecurity PL1/PL2/PL3（3 档），共 108 次 WAF 检测。

### 消融实验

```bash
cd backend
python tests/ablation.py   # 对比 有上下文增强 vs 无上下文增强（v1.0 模式）
python tests/evaluate_v2.py --dataset adversarial --modes cot standard no-context  # v2.0 三模式
```

---

## 评测结果

> **说明**：v1.0 在 56 条手工构造测试用例上达到 100% 准确率；v2.0/v2.1 已完成 246 条对抗样本（205 攻击 + 41 正常混淆）+ 56 条标准样本的三模式完整消融实测（含 Precision/Recall/F1/Accuracy 与类型级混淆矩阵），结果见下方「v2.1 三模式消融对比」与「v2.0 CoT 实测」。

### v2.0 CoT 模式在 246 条对抗样本上的实测结果

测试时间：2026-07-24 18:13 | 数据集：`dataset/adversarial_samples.json`（246 条，已校正） | 模式：`cot`

| 指标 | 数值 | 说明 |
|---|---|---|
| 总样本数 | 246 | 205 攻击 + 41 正常（0 API 错误） |
| 类型精确检出率（类型也正确） | 91.7% | 188/205 攻击正确识别类型 |
| 攻击级召回（识别为攻击） | 99.5% | 204/205 攻击载荷被识别 |
| 漏报率 | 0.5% | 仅 1 条攻击未被识别 |
| **误报率** | **31.7%** | 13/41 正常混淆样本被误判为攻击 |
| API 错误 | 0 | 本次评测 0 超时 / 0 限流 |

**按类型拆分（cot / 对抗集）**：

| 类型 | 样本数 | 类型正确率 | 识别为攻击率 | 主要问题 |
|---|---|---|---|---|
| SQL注入 | 59 | 100.0% | 100.0% | — |
| XSS | 67 | 100.0% | 100.0% | — |
| 命令注入 | 29 | 100.0% | 100.0% | — |
| 文件包含 | 19 | 15.8% | 100.0% | 多数错判为「路径穿越」 |
| WAF绕过/综合 | 31 | 96.8% | 96.8% | 1 条漏报 |
| **正常请求** | **41** | **68.3%** | — | **13 条被误报为攻击** |

**正常样本误报明细**：41 条正常混淆样本（SQL 关键字搜索、URL 编码 HTML、Base64 正常数据等），系统正确识别 28 条（68.3%），**误报 13 条（31.7%）**。这些误报集中在：
- 包含 SQL 关键字的正常搜索文本（如 "how to use UNION in SQL"）
- Base64 编码的正常内容（如 "SGVsbG8gV29ybGQ="）
- URL 编码的合法 HTML（如 `<div>Hello</div>`）
- JSON 中含 `$gt` 等 NoSQL 操作符的正常查询

**结果解读**：
- CoT 模式对传统攻击类型（SQLi / XSS / 命令注入）保持 **100% 类型正确率与识别率**。
- **攻击级召回 99.5%**：系统几乎识别出了所有攻击载荷，仅漏报 1 条。
- **误报率 31.7% 仍是关键短板**：系统对"含有攻击关键字但语义正常的请求"容易误判。这是 LLM 在安全检测中的典型困境——缺乏对请求意图的深度理解。这恰好也是课题"上下文增强"要解决的核心问题：什么样的上下文能让 LLM 区分"真攻击"和"看起来像攻击"。
- **文件包含类型识别仅 15.8%**（多数错判为「路径穿越」）是第二大短板；WAF 绕过/综合经数据集校正后已达 96.8%，不再是瓶颈。

### v1.0 基准结果（56 条手工用例）

在 56 条手工构造的测试用例上（41 条攻击正例 + 12 条正常请求 + 3 条边界用例）：

| 指标 | 二分类（宽松） | 严格（类型也正确） |
|---|---|---|
| 准确率 | 100.0% | 100.0% |
| 误报率 | 0.0% | — |
| 漏报率 | 0.0% | — |

**在此必须说明的局限性**：

1. **样本量小且为教科书式**。56 条正例都是教科书 payload，这些特征直接出现在正则规则和 few-shot 示例里，相当于"先告诉答案再考试"。
2. **对抗样本 CoT 模式已完成完整评测**。246 条（205 攻击 + 41 正常）实测结果如上，且 Standard / No-Context 三模式消融已完成（见 v2.1）。
3. **检测的是请求，不是漏洞**。系统能判断"这条请求长得像 SQL 注入"，不能判断"目标系统真的存在 SQL 注入"。
4. **DVWA 评测尚未实际运行**。代码已支持三档难度 + 三级 ModSecurity PL，但因需要完整 Docker 环境，尚未获取实测数据。

**补充验证能力（v2.0）**：
- ✅ CoT 分步推理模式——编码检测 + 混淆分析 + 分步推理
- ✅ Standard 模式——消融对比（量化 CoT 的增益）
- ✅ 三模式评分框架——cot vs standard vs no-context
- ✅ 246 条对抗样本数据集（205 攻击 + 41 正常混淆，已校正）
- ✅ 对抗样本 CoT 完整实测（246 条，含误报率）
- ✅ DVWA 三档难度验证框架（代码已就绪，待运行）
- ✅ ModSecurity CRS PL1/PL2/PL3 三级对比框架（代码已就绪，待运行）
- ✅ Standard / No-Context 三模式实测（已完成 2026-07-24，v2.1 完整指标）
- ⬜ DVWA + ModSecurity 实测结果

### v2.1 三模式消融对比（完整指标）

> 评测时间 2026-07-24 18:13｜样本 302 条（对抗 246 = 205 攻击 + 41 正常；标准 56 = 41 攻击 + 15 良性）｜三模式各跑全量。
> 指标定义：**攻击级召回** = 攻击被识别为攻击（类型对错不论）；**类型精确检出率** = 攻击且类型被正确识别；两者满足「类型精确 ≤ 攻击级召回」。

**对抗样本数据集（246 条 = 205 攻击 + 41 正常）**：

| 模式 | 攻击级召回 | 类型精确检出率 | 误报率(FPR) | Precision | F1 | Accuracy | 错误 |
|---|---|---|---|---|---|---|---|
| CoT（增强+CoT） | 99.5% | 91.7% | 31.7% | 94.0% | 96.7% | 94.3% | 0 |
| Standard（增强） | 100.0% | 91.1% | 39.0% | 92.7% | 96.2% | 93.4% | 2 |
| No-Context（基线） | 100.0% | 91.2% | 31.7% | 94.0% | 96.9% | 94.7% | 0 |
| **Δ CoT−Standard** | −0.5pp | +0.6pp | **−7.3pp** | +1.3pp | +0.5pp | +0.9pp | — |
| **Δ CoT−NoContext** | −0.5pp | +0.5pp | +0.0pp | +0.0pp | −0.2pp | −0.4pp | — |
| **Δ Standard−NoContext** | 0.0pp | −0.1pp | +7.3pp | −1.3pp | −0.7pp | −1.3pp | — |

**标准数据集（56 条 = 41 攻击 + 15 良性，教科书式样本）**：

| 模式 | 攻击级召回 | 类型精确检出率 | 误报率(FPR) | Precision | F1 | Accuracy | 错误 |
|---|---|---|---|---|---|---|---|
| CoT（增强+CoT） | 100.0% | 100.0% | 0.0% | 100.0% | 100.0% | 100.0% | 0 |
| Standard（增强） | 100.0% | 100.0% | 6.7% | 97.6% | 98.8% | 98.2% | 0 |
| No-Context（基线） | 100.0% | 100.0% | 0.0% | 100.0% | 100.0% | 100.0% | 0 |
| **Δ CoT−Standard** | 0.0pp | 0.0pp | −6.7pp | +2.4pp | +1.2pp | +1.8pp | — |
| **Δ CoT−NoContext** | 0.0pp | 0.0pp | 0.0pp | 0.0pp | 0.0pp | 0.0pp | — |
| **Δ Standard−NoContext** | 0.0pp | 0.0pp | +6.7pp | −2.4pp | −1.2pp | −1.8pp | — |

**结论与解读（诚实呈现）**：

1. **标准（教科书）数据集无法区分三模式**：三种模式均接近 100%，因为样本 payload 与提示/正则高度重合（"先告诉答案再考试"），该数据集仅适合做冒烟测试，不适合论证方法增益。
2. **对抗数据集上，"上下文增强 + CoT"未带来显著精度提升**：CoT 相对 No-Context 基线，攻击级召回 −0.5pp、类型精确 +0.5pp、F1 −0.2pp、误报率持平（31.7%）。**原核心命题（上下文增强提升检测效果）在当前数据集上未被证实有统计意义的增益**。
3. **CoT 分步推理的真实价值在「降误报」而非「提检出」**：CoT 相比 Standard（同带上下文增强但无 CoT 分步）误报率显著低 7.3pp（31.7% vs 39.0%），F1 +0.5pp。说明逐步推理让模型更谨慎地对待"像攻击的正常请求"。
4. **两大短板（即下一阶段创新方向）**：
   - **正常请求误报率 ~31.7%**（13/41）：集中在含 SQL/NoSQL 关键字的正常查询、Base64、URL 编码 HTML。根因是模型按"关键字特征"而非"请求语义/上下文"判据。
   - **文件包含（LFI/RFI）类型识别仅 15.8%**：19 条中 16 条被错判为「路径穿越」，类型混淆严重。
5. **这恰好印证课题的 CPG 属性图创新点必要性**：请求侧关键字/上下文分析的上限已显现，只有引入代码属性图（调用链、数据流、sink 可达性）才能从根本上区分"真漏洞触发"与"形似攻击的正常流量"。

> 注：LLM 输出具非确定性，单次评测的 ±0.5pp 波动属正常（如 CoT 有 1 条漏报、Standard 有 2 条 API 超限重试），结论以 Δ 量级与短板一致性为准。另：对抗集 `standard` 模式因 2 条样本（adv_waf_019 SSTI、adv_waf_024 SSRF）遭遇 DeepSeek 服务端 HTTP 502、重试耗尽而透明排除，该模式按 244/246 计算；`cot` 与 `no-context` 模式为完整 246 条、0 错误，核心对比不受影响。

---

## 与课题的关联

| 课题要求 | 本项目对应 |
|---|---|
| 上下文增强 | `context_builder.py` — 编码检测 + 混淆分析 + 22 类正则预扫描（v2.0 多维上下文） |
| 智能（LLM）分析 | `llm_engine.py` + `prompt_templates.py` — CoT 分步推理 + Standard 消融 Prompt |
| 消融实验 | `/api/detect` vs `/api/detect-standard` vs `/api/detect-no-context` 三模式对比 |
| 量化评测 | 56 条标准 + 246 条对抗样本 + `evaluate_v2.py`（三模式对比框架） |
| 端到端验证 | DVWA 靶场 + `benchmark_dvwa.py`（真实攻击场景，三档难度） |
| 横向对比 | ModSecurity OWASP CRS 三档 PL 对比（工业级 WAF 基线） |
| 属性图（CPG）创新点 | **尚未实现** — 当前 v2.0 的上下文增强是请求侧分析，CPG 是下一阶段核心创新方向 |

---

## 后续计划

- [x] 引入 DVWA 靶场验证 + ModSecurity CRS 横向对比
- [x] 增加对抗性测试（246 条：206 攻击 + 40 正常混淆）
- [x] DVWA 三档难度（low/medium/high）+ ModSecurity 三级 PL
- [x] CoT 分步推理 — 编码检测 + 混淆分析 + 深度上下文增强（v2.0）
- [x] 三模式消融对比框架（cot / standard / no-context）
- [x] 运行 246 条对抗样本 CoT 模式实测
- [x] 补充 40 条正常混淆样本到对抗数据集（支持误报率评测）
- [x] 运行 246 条对抗样本完整评测（含正常样本，获取真实误报率）
- [x] 运行三模式对比评测（Standard / No-Context，量化 CoT 增益）— 已完成 2026-07-24（v2.1 完整指标，906 次调用）
- [ ] 运行 DVWA + ModSecurity 实测 + 披露对比结果
- [ ] 扩大数据集至 500+ 真实/对抗混合样本
- [ ] 与 SQLMap、Burp Active Scan 横向对比
- [ ] 接入服务端反馈（HTTP 响应），从"payload 识别"走向"漏洞确认"
- [ ] **探索 CPG（Code Property Graph）级别上下文增强** — 将 AST/CFG/PDG 信息作为 LLM 上下文

---

## 项目结构

```
llm-vuln-detector/
├── backend/
│   ├── app/
│   │   ├── main.py                # FastAPI 入口（v2.0）
│   │   ├── config.py              # 配置管理
│   │   ├── api/
│   │   │   ├── routes.py          # API 路由（三模式）
│   │   │   └── dependencies.py    # 依赖注入
│   │   ├── core/
│   │   │   ├── llm_engine.py      # LLM 调用引擎（v2.0 CoT）
│   │   │   ├── context_builder.py # HTTP解析 + 编码检测 + 混淆分析 + 上下文构造（v2.0）
│   │   │   └── prompt_templates.py# CoT + Standard 双 Prompt 模板（v2.0）
│   │   ├── models/schemas.py      # Pydantic 数据模型
│   │   └── utils/history_store.py # SQLite 持久化
│   ├── tests/
│   │   ├── test_*.py              # 单元测试（54个）
│   │   ├── evaluate_v2.py         # 综合评测 — 三模式 × 两数据集（v2.0 新增）
│   │   ├── evaluate.py            # v1.0 评测脚本（56条）
│   │   ├── ablation.py            # 消融实验脚本
│   │   ├── benchmark_dvwa.py      # DVWA 端到端 + ModSecurity 多维度对比
│   │   ├── generate_adversarial.py# 对抗样本生成器 + 正常样本（246条）
│   │   ├── gen_eval_report.py     # Word 评测报告生成
│   │   ├── gen_ablation_report.py # Word 消融实验报告生成
│   │   └── dataset/
│   │       ├── test_cases.json    # 56 条标准评测数据集
│   │       └── adversarial_samples.json  # 246 条对抗样本（206攻击+40正常）
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── App.vue                # 主页面（3个Tab）
│   │   └── components/            # 5个组件
│   ├── Dockerfile
│   └── nginx.conf
├── docker-compose.yml
├── .env.example
└── README.md
```

---

## License

MIT

---

<p align="center">
  Made with curiosity by <a href="https://github.com/lauyy32">lauyy32</a>
</p>
