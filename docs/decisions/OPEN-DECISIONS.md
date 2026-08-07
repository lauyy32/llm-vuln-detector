# OPEN-DECISIONS（悬而未决登记册）

每次会话开头复现，逐条判断能否关闭。只追加 + 就地关闭（OPEN → RESOLVED，补 Resolution 字段）。

| Date | Source | Open Item | Related Constraints | Current Leaning | Blocked By | Resolves When | Status | Resolution |
|------|--------|-----------|---------------------|-----------------|------------|---------------|--------|-----------|
| 2026-08-07 | CPG阶段 | CodeQL vs Joern 最终选型 | Java(CodeQL强)/C·C++(Joern强)；真实CVE数据集语言分布决定工具 | 先 CodeQL——**Python 管线已端到端跑通**（AST/CFG/DFG 三查询稳定出结果；taint 受本机 Defender 锁缓存阻塞，见下方新增条目） | 目标语言与数据集未定 | 选定真实CVE数据集语言后 | RESOLVED | 本地原生 CodeQL CLI 2.26.2 已验证 Python 提取 AST/CFG/DFG 正确（27/31/9 边，切片可读）；taint 仅环境阻塞非工具缺陷 |
| 2026-08-07 | CPG阶段 | 真实CVE数据源 | 禁用SARD合成集；Devign真实仓库/其他开源CVE | Devign 真实仓库数据（已有论文背书） | 数据集可获取性、许可证 | 能拉到修复前后代码对 | OPEN |
| 2026-08-07 | 实验设计 | 本地模型 vs API | 7/24 deepseek-chat下架教训→API漂移风险；可复现要求 | 优先锁本地模型(Ollama Qwen2.5-Coder/Codellama) | 本机算力/GPU；模型对代码理解力 | 环境就绪后验证 | OPEN |
| 2026-08-07 | 实验设计 | 三模式消融指标侧重 | 重点看「仅代码」vs「仅请求」增益、「请求+代码」是否超 CodeQL | 主指标：按漏洞类型的检出率/误报率；次指标：可解释性/零规则维护成本 | 数据标注粒度 | 数据集定后 | OPEN |
| 2026-08-07 | CPG切片设计 | AST 要不要进文本切片 | 源码文本对 LLM 已隐含编码 AST，重复塞入只烧 token；但显式 AST 可能帮小模型 | 默认**不进**（`slice_builder.py --include-ast` 可开），ast.ql 照常提取备用 | 需要真实数据集才能量化 | 跑「切片含AST vs 不含AST」消融后 | OPEN |
| 2026-08-07 | CPG工程 | 逐样本建库 vs 语料库级单库 | 数据流查询有与代码量无关的固定开销（加载数千条 MaD 框架模型），逐样本会把它乘以样本数 | 语料库级单 DB → 查询跑一次 → 按函数切片 | 语料目录结构未定（需保证同名函数可区分） | 真实 CVE 语料落地时 | OPEN |
| 2026-08-07 | CPG查询 | taint.ql 的 Config 用启发式还是上游查询 | 当前用方法名启发式（`get`→`execute`），因独立片段无框架建模；上游 `py/sql-injection` 更准但依赖框架识别 | 冒烟阶段留启发式；正式语料换上游按 CWE 的配置 | 真实语料的框架分布未知 | 语料确定后 | OPEN |
| 2026-08-07 | CPG工程(环境) | 本机 Windows Defender 锁 CodeQL 缓存→taint 查询不可重复运行 | ast/cfg/dfg 轻量查询在全新 DB 上稳定通过；taint（数据流）写大缓存包 `predicates/43.pack`/`cached-strings/tuple-pool` 被 Defender 实时扫描锁死，报 `Severe disk cache trouble`/`Cant write tuple pool file`(AccessDenied/NoSuchFile) | 管理员执行 `Add-MpPreference -ExclusionPath "C:/Users/lenovo/cpg_db"` 排除 DB 目录；排除后 taint 应可跑通。另：被 kill 的 codeql 进程会遗留锁定缓存，须 `taskkill /F /T /PID` 清干净再 `--rebuild` | 本机无管理员权限（自动化环境），需用户手动加排除 | 用户加完 Defender 排除并重跑 `pipeline.py --rebuild --force` 后 | RESOLVED | 用户以管理员 PowerShell 执行 `Add-MpPreference -ExclusionPath "C:/Users/lenovo/cpg_db"` 后，`pipeline.py --rebuild --force` 端到端四查询全部通过：ast/cfg/dfg/taint = ok，taint 耗时 1.9s，输出 taint.csv 1 row |
