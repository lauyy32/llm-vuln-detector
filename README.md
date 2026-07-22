# LLM-VulnDetector

> 基于 LLM 的 HTTP 攻击载荷识别原型 | LLM-Assisted HTTP Attack Payload Classifier

输入一条原始 HTTP 请求 → 结构化解析 + 正则预扫描 → LLM 分析 → 输出该请求是否疑似包含某类攻击 payload。

**Author**: [lauyy32](https://github.com/lauyy32) 🛡️

---

## ⚠️ 这个项目能做什么 / 不能做什么

**能做的**：判断一条 HTTP 请求的参数值里，是否出现某类攻击的典型 payload 特征（SQL 注入、XSS、命令注入等 10 类），并给出类型、置信度和成因分析。

**不能做的**：
- 看不到服务端源码，无法判断参数是否真的被拼进 SQL / shell —— **不能确认漏洞可利用**
- 不能替代 SQLMap、Burp Active Scan 等需要服务端反馈的工具
- 不是 SAST/DAST，不做代码扫描，不做流量代理

**所以本质上**：这是一个"疑似攻击请求分类器"，"is_vulnerable=true"的真实含义是"该请求携带了某类攻击的典型 payload"，而不是"目标系统存在该漏洞"。

这个项目是我的研究生课题"基于大语言模型的上下文增强智能漏洞检测技术研究"的**最小可行原型**，用来验证"上下文增强能否提升 LLM 对攻击请求的识别效果"这个想法，更偏向于一个demo，暂时不是可部署的正式安全产品。

## 功能特性

- **10 类攻击 payload 识别**：SQL注入、XSS、命令注入、路径穿越、SSRF、文件上传、XXE、SSTI、NoSQL注入、开放重定向
- **上下文增强**：HTTP 请求结构化解析 + 13 类正则预扫描，将风险信号作为上下文提供给 LLM
- **DVWA 靶场端到端验证**：在真实 Web 漏洞靶场上自动化攻击 + 检测，覆盖 SQLi / Blind SQLi / XSS / CMDi / LFI
- **ModSecurity CRS 横向对比**：与 OWASP ModSecurity CRS（工业级 WAF）双轨评测，对比检出率与误报率
- **消融实验支持**：内置无上下文增强对照接口，可对比"有/无上下文增强"的效果差异
- **降误报设计**：few-shot 示例 + 自检机制 + 置信度量化
- **批量检测 + SQLite 持久化 + 统计面板**
- **Docker 一键部署**

## 技术栈

| 层 | 技术 |
|---|---|
| 后端 | Python 3.11+ / FastAPI / httpx / Pydantic v2 / SQLite |
| 前端 | Vue 3 / Element Plus / Vite / Axios |
| LLM | DeepSeek-Chat |
| 部署 | Docker / docker-compose / Nginx |

## 快速开始

### 方式一：Docker 一键部署（推荐）

```bash
cp .env.example .env   # 编辑 .env，填入 DeepSeek API Key
docker-compose up -d
# 前端: http://localhost
# API 文档: http://localhost:8000/docs
```

### 方式二：本地开发

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

## API

| 接口 | 方法 | 说明 |
|---|---|---|
| `/api/detect` | POST | 识别 HTTP 请求中的攻击 payload（有上下文增强） |
| `/api/detect-no-context` | POST | 消融实验对照（无上下文增强） |
| `/api/batch-detect` | POST | 批量识别（最多50条） |
| `/api/history` | GET | 历史记录（分页） |
| `/api/stats` | GET | 检测统计 |
| `/health` | GET | 健康检查 |

启动后端后访问 `http://localhost:8000/docs` 查看完整 Swagger 文档。

## 测试与评测

### 单元测试

```bash
cd backend
python -m pytest tests/ -v
```

覆盖模块：context_builder、llm_engine、schemas、history_store（54 个测试用例）

### 评测脚本

```bash
cd backend
python tests/evaluate.py                     # 全量评测（56条标准数据集）
python tests/evaluate.py --category SQL注入   # 只评某一类
python tests/evaluate.py --output report.json # 输出到文件
```

### DVWA 靶场端到端验证 + ModSecurity 对比

```bash
# 1. 启动靶场和 WAF（3 档 Paranoia Level）
docker-compose up -d dvwa modsecurity-pl1 modsecurity-pl2 modsecurity-pl3
# 等待容器启动（约30秒）

# 2. 启动 LLM-VulnDetector 后端
docker-compose up -d backend
# 或手动: uvicorn app.main:app --reload --port 8000

# 3. 运行多维度对比评测
cd backend
python tests/benchmark_dvwa.py                    # 完整: 3 难度 x 3 PL
python tests/benchmark_dvwa.py --modsec-pls PL1   # 仅 PL1
python tests/benchmark_dvwa.py --no-modsec         # 仅 LLM（无 ModSecurity）
```

测试矩阵：**DVWA low/medium/high（3 档）x 6 个场景 x 2 种请求 = 36 条 LLM 检测**，每条同时过 ModSecurity PL1/PL2/PL3（3 档），共 108 次 WAF 检测。

| 对比维度 | LLM-VulnDetector | ModSecurity OWASP CRS |
|---|---|---|
| 检测方式 | 离线分析 raw HTTP | 在线 WAF 拦截（3 档 PL） |
| 攻击场景 | SQLi / Blind SQLi / Reflected XSS / Stored XSS / CMDi / LFI |
| 难度梯度 | DVWA low → medium → high | Paranoia 1 → 2 → 3 |
| 用例数 | 36 | 108（36 × 3 PL） |

### 对抗样本测试

```bash
cd backend
python tests/generate_adversarial.py    # 生成 206 条编码/混淆/绕过样本
python tests/evaluate.py --dataset dataset/adversarial_samples.json  # 对抗样本评测
```

样本覆盖：URL编码/双编码、Unicode、HTML实体、大小写混淆、注释绕过、空白符变体、HTTP头注入、协议走私等。

### 消融实验

```bash
cd backend
python tests/ablation.py   # 对比 有上下文增强 vs 无上下文增强
```

## 评测结果

在 56 条手工构造的测试用例上（41 条攻击正例 + 12 条正常请求 + 3 条边界用例）：

| 指标 | 二分类（宽松） | 严格（类型也正确） |
|---|---|---|
| 准确率 | 100.0% | 100.0% |
| 误报率 | 0.0% | — |
| 漏报率 | 0.0% | — |

**在此必须说明的局限性**：

1. **样本量略小**。56 条用例可能不足以证明泛化能力，个人认为真实场景的攻击变体远比这复杂。
2. **我所采用的正例都是教科书式 payload**。"1' OR '1'='1"、"<script>alert(1)</script>"这类特征直接出现在正则规则和 few-shot 示例里，个人认为相当于"先告诉答案再考试"。
3. **并没有盲测**。正在通过对抗样本数据集（206 条编码/混淆/绕过变体）补充对抗性测试。
4. **检测的是请求，不是漏洞**。系统能判断"这条请求长得像 SQL 注入"，不能判断"目标系统真的存在 SQL 注入"。

所以这个 100% 只能说明"原型在自建数据集上能跑通"，**不代表真实场景下的检测能力**。

> **补充验证**：项目已支持 DVWA 真实靶场端到端验证（3 档难度）+ ModSecurity CRS 三级 Paranoia Level 横向对比（见上方 "DVWA 靶场端到端验证"）。另含 206 条对抗样本数据集（编码/混淆/绕过变体），用于鲁棒性测试。

## 与我所正在研究的课题的关联

| 课题要求 | 本项目对应 |
|---|---|
| 上下文增强 | `context_builder.py` 结构化解析 + 13 类正则预扫描 |
| 智能（LLM）分析 | `llm_engine.py` + `prompt_templates.py` Prompt 工程 |
| 消融实验 | `/api/detect-no-context` + `ablation.py` |
| 量化评测 | 56 条数据集 + `evaluate.py`（宽松/严格两套指标） |
| 端到端验证 | DVWA 靶场 + `benchmark_dvwa.py`（真实攻击场景） |
| 横向对比 | ModSecurity OWASP CRS 双轨评测（工业级 WAF 基线） |
| 属性图（CPG）创新点 | **尚未实现**，当前结构化上下文是理解 CPG 的第一步 |

## 后续计划

- [x] 引入 DVWA 靶场验证 + ModSecurity CRS 横向对比
- [x] 增加对抗性测试（206 条编码绕过、WAF 绕过等变体）
- [x] DVWA 三档难度（low/medium/high）+ ModSecurity 三级 PL
- [ ] 对抗样本评测结果补充到 README
- [ ] 扩大数据集至 500+ 真实/对抗混合样本
- [ ] 与 SQLMap、Burp Active Scan 横向对比
- [ ] 探索 CPG（Code Property Graph）级别的上下文增强
- [ ] 接入服务端反馈（HTTP 响应状态/内容），从"payload 识别"走向"漏洞确认"

## 项目结构

```
llm-vuln-detector/
├── backend/
│   ├── app/
│   │   ├── main.py                # FastAPI 入口
│   │   ├── config.py              # 配置管理
│   │   ├── api/routes.py          # API 路由
│   │   ├── core/
│   │   │   ├── llm_engine.py      # LLM 调用引擎
│   │   │   ├── context_builder.py # HTTP 解析 + 上下文构造
│   │   │   └── prompt_templates.py# Prompt 模板
│   │   ├── models/schemas.py      # Pydantic 数据模型
│   │   └── utils/history_store.py # SQLite 持久化
│   ├── tests/
│   │   ├── test_*.py              # 单元测试（54个）
│   │   ├── evaluate.py            # 评测脚本（56条数据集）
│   │   ├── ablation.py            # 消融实验脚本
│   │   ├── benchmark_dvwa.py      # DVWA 端到端 + ModSecurity 对比评测（多难度）
│   │   └── dataset/test_cases.json# 56条评测数据集
│   │       adversarial_samples.json # 206条对抗样本数据集
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
  Made with curiosity by <a href="https://github.com/lauyy32">lauyy32</a> 🛡️
</p>
