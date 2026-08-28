# 设计方向：三模式检测结果展示（极简科研工具）

> 作者：lauyy32
> 文档类型：极简结果展示设计方向（科研工具，非消费级产品）
> 对标：CodeQL「Show paths」source→sink 数据流编号 + Semgrep 代码切片行高亮 + severity/confidence 徽章（科研工具通行信息密度范式，直接复用）

## 1. 信息层级（结果页）
- **主视觉·顶部**：判定徽章（`vulnerable` 红 / `benign` 绿）+ `confidence` 环 + `CWE` + `mode` 标签
- **核心·中部**：代码切片（`JetBrains Mono` 等宽），`source` 行红描边、`sink` 行红填充，taint 路径 `1→2→3` 串联
- **次要·底部**：mode 对照（request/code/both 并排 verdict+confidence，语料无请求字段时 request 恒 abstain、both=code，如实展示）或 dataset 基线 P/R/F1 小字

## 2. 设计 Token（锁定）
- **双主题**：浅 `#F8FAFC` / 深 `#0D1117`，冷灰蓝中性；强调色单冷蓝 `#2563EB`，每屏 ≤2 处
- **语义**：红 `#DC2626`=漏洞、绿 `#16A34A`=安全（红危绿安，沿用中国习惯）
- **字体**：`Inter, Noto Sans SC` + `JetBrains Mono`（代码等宽）
- **图标库**：`lucide`（描边 SVG，16/20/24px，禁 emoji）；颜色全走 CSS 变量，禁硬编码（除 `#fff`/`#000`）；圆角 8–12px，4px 网格，动效 ≤200ms + `reduced-motion`

## 3. 页面清单
- **检测表单页（密度中高）**：选 `mode` + 粘贴样本/选仓库 + 运行；含 Loading/Error/Empty
- **结果页（密度高）**：判定徽章 + 切片 + 三模式对照；含骨架屏/Empty/Error

## 4. 明确不做
不堆花哨动效、不做营销 Hero、不做社交/分享/评论、不虚构指标、不 emoji 图标、不紫粉渐变、不奶油暖底。

## 5. 顾问建议（待本地模型接入后补）
- 结果页支持**按 mode 切换**而非并排三栏以省空间
- 评分器对照区块的空/Error 态视觉，待 LocalLLMScorer 接入后补

## P0 自检
零 emoji（全程 lucide）、无紫→粉渐变（仅冷蓝纯色）、颜色全 Token、无空洞占位文案——全部通过。
