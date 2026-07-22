# LLM-VulnDetector

> 基于大语言模型的上下文增强 Web 漏洞检测工具

输入 HTTP 请求 → 结构化解析 + 正则预扫描 → LLM 智能分析 → 输出漏洞类型、置信度、成因分析和修复建议。

**Author**: [lauyy32](https://github.com/lauyy32) 🛡️

---

## 为什么做这个项目

做这个项目主要是想把自己对 Web 安全的理解落到代码里。课题方向是「基于大语言模型的上下文增强智能漏洞检测」，所以先做了一个最小可行实现练手。

选 LLM + 漏洞检测这个方向，是因为之前接触过一些 SAST 工具，觉得误报太多是个痛点。LLM 有语义理解能力，理论上能做得更好，但直接把 HTTP 请求丢给 LLM 效果不够稳定。所以我在中间加了一层「上下文增强」——先做结构化解析和正则预扫描，把风险信号提取出来，再喂给 LLM。这个思路和属性图（Code Property Graph）的方向是一致的，只是粒度不同。

## 功能特性

- **10 类漏洞检测**：SQL注入、XSS、命令注入、路径穿越、SSRF、文件上传、XXE、SSTI、NoSQL注入、开放重定向
- **上下文增强**：HTTP 请求结构化解析 + 13类正则预扫描，将风险信号作为上下文提供给 LLM
- **降误报设计**：few-shot 示例 + 自检机制（false_positive_check）+ 置信度量化
- **批量检测**：支持上传 .txt 文件批量检测（最多50条）
- **SQLite 持久化**：检测历史持久存储，支持分页查询和统计分析
- **统计面板**：总检测数、检出率、漏洞类型分布、风险等级分布
- **消融实验支持**：内置无上下文增强对照接口，可以跑消融实验验证上下文增强的效果
- **Docker 一键部署**：docker-compose 一键启动前后端

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
# 1. 配置 API Key
cp .env.example .env
# 编辑 .env，填入 DeepSeek API Key

# 2. 启动
docker-compose up -d

# 3. 访问
# 前端: http://localhost
# API 文档: http://localhost:8000/docs
```

### 方式二：本地开发

#### 1. 后端

```bash
cd backend

# 安装依赖
pip install -r requirements.txt

# 配置环境变量
cp .env.example .env
# 编辑 .env，填入 DeepSeek API Key

# 启动服务
uvicorn app.main:app --reload --port 8000
```

#### 2. 前端

```bash
cd frontend

# 安装依赖
npm install

# 启动开发服务器
npm run dev
```

访问 http://localhost:5173 即可使用。

### 3. 使用

1. **单条检测**：在输入框粘贴原始 HTTP 请求（或点击「加载示例」），点击「检测漏洞」
2. **批量检测**：上传 .txt 文件（请求间用空行分隔），点击「开始批量检测」
3. **统计面板**：查看总体检测统计、漏洞类型分布、风险等级分布

## API 文档

启动后端后访问 http://localhost:8000/docs 查看 Swagger 文档。

| 接口 | 方法 | 说明 |
|---|---|---|
| `/api/detect` | POST | 提交 HTTP 请求进行漏洞检测（有上下文增强） |
| `/api/detect-no-context` | POST | 消融实验对照接口（无上下文增强） |
| `/api/batch-detect` | POST | 批量检测（最多50条） |
| `/api/history` | GET | 获取历史检测记录（分页） |
| `/api/history/{id}` | GET | 获取单条检测详情 |
| `/api/history` | DELETE | 清空所有历史记录 |
| `/api/stats` | GET | 获取检测统计信息 |
| `/health` | GET | 健康检查 |

## 测试与评测

### 单元测试

```bash
cd backend
python -m pytest tests/ -v
```

覆盖模块：context_builder、llm_engine、schemas、history_store（54个测试用例）

### 评测脚本

```bash
cd backend

# 使用标准数据集评测（56条用例，覆盖10类漏洞）
python tests/evaluate.py

# 只评测某一类别
python tests/evaluate.py --category SQL注入

# 输出报告到文件
python tests/evaluate.py --output report.json
```

评测指标：准确率(Accuracy)、精确率(Precision)、召回率(Recall)、F1-Score、误报率(FPR)、漏报率(FNR)、各漏洞类型检出率

### 消融实验

```bash
cd backend

# 对比 有上下文增强 vs 无上下文增强
python tests/ablation.py

# 快速验证（只跑前10条）
python tests/ablation.py --limit 10
```

## 评测结果

在 56 条标准评测数据集上（41 条漏洞正例 + 12 条正常请求 + 3 条边界用例），系统达到了：

| 指标 | 数值 |
|---|---|
| 准确率 | 100.0% |
| 精确率 | 100.0% |
| 召回率 | 100.0% |
| F1-Score | 100.0% |
| 误报率 | 0.0% |
| 漏报率 | 0.0% |
| 平均置信度 | 93.3% |
| 平均检测耗时 | 2.06s/条 |

消融实验结果详见 `backend/tests/reports/ablation_report.json`。

## 项目结构

```
llm-vuln-detector/
├── backend/
│   ├── app/
│   │   ├── main.py                  # FastAPI 入口
│   │   ├── config.py                # 配置管理
│   │   ├── api/
│   │   │   ├── routes.py            # API 路由（检测/批量/历史/统计）
│   │   │   └── dependencies.py      # 依赖注入
│   │   ├── core/
│   │   │   ├── llm_engine.py        # LLM 调用引擎（异步+重试+容错）
│   │   │   ├── context_builder.py   # HTTP 解析 + 上下文构造 + 消融接口
│   │   │   └── prompt_templates.py  # Prompt 模板（CoT+few-shot+自检）
│   │   ├── models/
│   │   │   └── schemas.py           # Pydantic 数据模型
│   │   └── utils/
│   │       ├── logger.py            # 日志配置
│   │       └── history_store.py     # SQLite 持久化存储
│   ├── tests/
│   │   ├── test_context_builder.py  # HTTP解析+预扫描测试
│   │   ├── test_llm_engine.py       # LLM引擎+JSON容错测试
│   │   ├── test_schemas.py          # 数据模型校验测试
│   │   ├── test_history_store.py    # SQLite存储测试
│   │   ├── evaluate.py              # 评测脚本
│   │   ├── ablation.py              # 消融实验脚本
│   │   └── dataset/
│   │       └── test_cases.json      # 56条标准评测数据集
│   ├── Dockerfile
│   ├── requirements.txt
│   └── .env.example
├── frontend/
│   ├── src/
│   │   ├── App.vue                  # 主页面（3个Tab）
│   │   ├── main.js                  # 入口
│   │   ├── api/detect.js            # API 调用
│   │   ├── utils/request.js         # Axios 封装
│   │   └── components/
│   │       ├── HttpRequestInput.vue  # 请求输入组件
│   │       ├── DetectionResult.vue   # 结果展示组件
│   │       ├── HistoryList.vue       # 历史记录组件
│   │       ├── BatchInput.vue        # 批量上传组件
│   │       └── StatsPanel.vue        # 统计面板组件
│   ├── Dockerfile
│   ├── nginx.conf
│   ├── package.json
│   └── vite.config.js
├── docker-compose.yml
├── .env.example
└── README.md
```

## 与课题的关联

本项目是课题「基于大语言模型的上下文增强智能漏洞检测技术研究」的最小可行实现：

- **上下文增强** → `context_builder.py` 中的结构化解析 + 13类正则预扫描
- **智能漏洞检测** → `llm_engine.py` 中的 LLM 调用 + `prompt_templates.py` 中的 Prompt 工程
- **消融实验验证** → `/api/detect-no-context` 对照接口 + `ablation.py` 实验脚本
- **量化评测** → 56条标准数据集 + `evaluate.py` 评测脚本
- **属性图（课题创新点）** → 当前上下文结构化表示是理解属性图的第一步，后续将探索 CPG 级别的上下文增强

## 后续计划

- [ ] 引入 DVWA 靶场真实漏洞样本，扩大评测数据集
- [ ] 增加对抗性测试（编码绕过、WAF 绕过等高级变体）
- [ ] 与 SQLMap、Burp Suite Active Scan 等成熟工具横向对比
- [ ] 探索 CPG（Code Property Graph）级别的上下文增强
- [ ] 集成密码误用检测子维度（硬编码密钥、弱哈希等）

---

## License

MIT

---

<p align="center">
  Made with curiosity by <a href="https://github.com/lauyy32">lauyy32</a> 🛡️
</p>
