# CPG 阶段工作区（最小管线验证）

> 课题：基于大语言模型的上下文增强智能漏洞检测
> 路线：ADR-001（CPG 代码级上下文为主路线）
> 状态：**step 1 已完成** —— 对一个函数提取 AST/CFG/DFG/污点路径 → 序列化为文本切片。全程不接 LLM、不耗 API。

## 快速复现

```bash
export JAVA_HOME="C:/Program Files/Java/jdk-21.0.1"
cd cpg
python pipeline.py --rebuild          # 建库 + 跑 4 个查询 + 导出 CSV
python slice_builder.py               # CSV → output/slice_<func>.txt
```

## 为什么是原生 CodeQL CLI（不是 Docker 镜像）

`ghcr.io` 在本机网络下对匿名拉取返回 denied（`docker manifest inspect ghcr.io/github/codeql:stable`
报 denied，`/v2/` 返回 401 匿名挑战）。`github.com` 可达（HTTP 200），故改从 GitHub Releases 下载
`codeql-bundle-win64.tar.gz`，版本锁 **v2.26.2**。

**实测更正**（此前的假设是错的，留档避免重蹈）：

| 假设 | 实际 |
|------|------|
| bundle 自带查询库 | ❌ 只含 CLI + 提取器 + dbscheme，**无任何 qlpack** |
| bundle 自带 JDK | ❌ 必须外部提供，`JAVA_HOME` 未设时 `codeql version` 静默退出码 2 |

查询库另行 sparse clone `github/codeql`，分支锁 `codeql-cli/v2.26.2` 与 CLI 版本严格对应：

```bash
git clone --filter=blob:none --sparse --branch codeql-cli/v2.26.2 \
  https://github.com/github/codeql.git codeql-queries
cd codeql-queries && git sparse-checkout set python shared misc
```

`shared` 与 `misc` 不能省：`codeql/python-all` 的依赖写的是 `${workspace}`，
指向 `shared/**/qlpack.yml` 与 `misc/suite-helpers/qlpack.yml`。

## Windows 特有的三个坑

1. **JAVA_HOME**：不设则 `codeql` 无任何输出、退出码 2。
2. **Defender 锁文件**：数据库放在仓库内时，`finalize` 阶段把 `db-python/default/strings/0`
   重命名为 `pools/0` 会撞 `AccessDeniedException`；缓存目录 `cache/relations/*.pack` 也会被
   删到 `NoSuchFileException`。解法是把 DB 放到仓库外的**短路径**：`C:/Users/lenovo/cpg_db/sample_db`。
   **但还有更深一层的锁**（见下节「Defender 阻塞 taint 查询」）：即便 DB 在仓库外，实时扫描仍会
   锁住 `db-python/default/cache/predicates/*.pack` 与 `cached-strings/tuple-pool/*`，导致
   数据流类查询写缓存失败。
3. **路径翻译**：`codeql.exe` 是原生 Windows 程序，MSYS 风格的 `/c/Users/...` 会被翻译成
   `C:\c\Users\...`。一律传 `C:/Users/...`。

## Defender 阻塞 taint 查询（本机实测 2026-08-07，已修复）

**现象**：`ast` / `cfg` / `dfg` 三个轻量查询在**全新 DB** 上稳定通过（27 / 31 / 9 边）；
但 `taint`（数据流）在 `query run` 阶段报：

```
A fatal error occurred: Severe disk cache trouble (corruption or out of space)
  at ...\db-python\default\cache\predicates\43.pack: Failed to write item to disk
(eventual cause: NoSuchFileException "...\cache\predicates\43.pack")
```

（更早的变体是 `ResourceError: Cant write tuple pool file` + `AccessDeniedException`
于 `cached-strings\tuple-pool\tuples#DataFlowDispatch#...`。两者同源：Defender 实时扫描
锁死了 CodeQL 写缓存包的文件。）

**根因**：轻量查询写出的缓存包小，Defender 放过去；数据流查询要写大缓存包（`predicates/43.pack`），
实时扫描在写入瞬间持锁，CodeQL 拿不到写权限 → 崩溃。这与 DB 是否在仓库内无关，是
**实时扫描对 `cpg_db` 目录的锁定**。

**修复（已验证）**：

```powershell
# 以管理员身份运行 PowerShell
Add-MpPreference -ExclusionPath "C:/Users/lenovo/cpg_db"
```

加完后重跑：

```bash
python pipeline.py --rebuild --force
```

实测 `taint` 查询在 1.9s 内完成，正常输出 `taint.csv`（1 row）。
`pipeline.py` 已对 `AccessDenied` / `Cant write tuple pool` / `Severe disk cache trouble`
做了检测，失败时打印上述提示而非静默挂死。

** poisoned 缓存陷阱**：被 kill 的 `codeql.exe`（以及它拉起的 java 子进程）会**遗留锁定的
缓存文件**，导致后续查询在旧 DB 上反复 `AccessDenied`。先用
`taskkill /F /T /PID <pid>` 把整棵树（含 java）清掉，再 `--rebuild`（或确认 DB 已被覆盖）。
`pipeline.py` 的看门狗超时即用 `taskkill /F /T` 杀整棵树，避免孤儿 java 持锁。

**结论 / 当前可用性**：CPG 最小管线的**四步（AST+CFG+DFG+taint → 文本切片）已在本机端到端验证可用**。
`taint` 之前被 Windows Defender 实时扫描阻塞，加 DB 目录排除项后已跑通。


## 性能：`--ram` 不是可选项

CodeQL 在最大堆 < 约 2 GB 时会打印
`Not caching stages during query-loading, since max heap size is only 1800 MB`
并放弃阶段缓存。首版 `dfg.ql` 基于 `TaintTracking::localTaintStep` 且未加限制，
在这个配置下跑 **17 分钟未出结果**；改为 SSA def-use + `--ram=3000 --threads=8` 后
**26.9 秒**完成。`pipeline.py` 已把这两个参数写死为默认值。

## 目录结构

| 路径 | 内容 |
|------|------|
| `samples/` | 漏洞样本（当前仅冒烟测试用；正式数据来自 Devign 真实 CVE 仓库） |
| `queries/` | 4 个 CPG 提取查询 + `CpgTarget.qll` 公共谓词 + `qlpack.yml` |
| `pipeline.py` | 建库 → 跑查询 → 导 CSV |
| `slice_builder.py` | CSV → LLM 可读文本切片 |
| `output/` | `*.csv` 原始表 + `slice_*.txt` 文本切片 |
| `codeql/` | 解压后的 CodeQL bundle（gitignore） |
| `codeql-queries/` | sparse clone 的官方查询库（gitignore） |

## 四个查询各自负责什么

| 查询 | 产出 | 说明 |
|------|------|------|
| `ast.ql` | 父→子 AST 边 | 默认**不**进切片：源码文本对 LLM 而言已编码了 AST，重复塞进去只烧 token。是否真的无增益，本身是一个可做的消融。 |
| `cfg.ql` | 控制流后继边（带 true/false 分支标签） | 行级聚合，丢弃同行的表达式求值顺序边 |
| `dfg.ql` | SSA def-use + phi 边 | **刻意不用** `TaintTracking::localTaintStep`（见上面性能一节）。这也是 CPG 教科书定义的 DFG。 |
| `taint.ql` | source → sink 污点路径 | 这是"请求侧检测器永远看不到"的那条信息，是本课题立论的核心证据。本机需把 DB 目录加入 Windows Defender 排除项才能跑通（见上节）。 |

`taint.ql` 当前用的是基于方法名的启发式 Config（`get` → `execute`），
因为独立代码片段没有框架建模。正式语料会换成上游 `py/sql-injection` 等按 CWE 的配置。

## 已知的规模化问题（写在前面，避免后面撞墙）

数据流查询有一笔**与代码量无关的固定开销**（加载数千条 MaD 框架模型）。
按样本逐个建库会把这笔开销乘以样本数。正式语料应当
**整个语料库建一个 DB → 查询跑一次 → 再按函数切片**。

## 纪律（来自长期研究支撑协议 §6）

- 正式评测必须用真实 CVE 修复前后代码（Devign 真实仓库），禁用 SARD 合成集。
- 实验设计须含「仅请求 / 仅代码(CPG) / 请求+代码」三模式 + CodeQL 基线正面对比。
- 优先锁本地模型（Ollama）消除 API 漂移；本步不耗 API。
