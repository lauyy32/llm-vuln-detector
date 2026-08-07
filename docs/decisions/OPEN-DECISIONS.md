# OPEN-DECISIONS（悬而未决登记册）

每次会话开头复现，逐条判断能否关闭。只追加 + 就地关闭（OPEN → RESOLVED，补 Resolution 字段）。

| Date | Source | Open Item | Related Constraints | Current Leaning | Blocked By | Resolves When | Status |
|------|--------|-----------|---------------------|-----------------|------------|---------------|--------|
| 2026-08-07 | CPG阶段 | CodeQL vs Joern 最终选型 | Java(CodeQL强)/C·C++(Joern强)；真实CVE数据集语言分布决定工具 | 先 CodeQL（规则现成、上手快、Docker镜像成熟） | 目标语言与数据集未定 | 选定真实CVE数据集语言后 | OPEN |
| 2026-08-07 | CPG阶段 | 真实CVE数据源 | 禁用SARD合成集；Devign真实仓库/其他开源CVE | Devign 真实仓库数据（已有论文背书） | 数据集可获取性、许可证 | 能拉到修复前后代码对 | OPEN |
| 2026-08-07 | 实验设计 | 本地模型 vs API | 7/24 deepseek-chat下架教训→API漂移风险；可复现要求 | 优先锁本地模型(Ollama Qwen2.5-Coder/Codellama) | 本机算力/GPU；模型对代码理解力 | 环境就绪后验证 | OPEN |
| 2026-08-07 | 实验设计 | 三模式消融指标侧重 | 重点看「仅代码」vs「仅请求」增益、「请求+代码」是否超 CodeQL | 主指标：按漏洞类型的检出率/误报率；次指标：可解释性/零规则维护成本 | 数据标注粒度 | 数据集定后 | OPEN |
