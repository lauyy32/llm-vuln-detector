# 第二步 · taint 提取覆盖根因验证报告（2026-09-04）

> 任务：终版计划 ② —— 修复 10(74-set)+5(D1) 个零污点行 CVE 的 taint 提取覆盖。
> 用户要求：先根因验证（分 a clone 失败 / b 分支缺失 / c 建模盲区）；分批重试；死磕不过排除+申报。
> 状态：重建已后台启动（task QXebM3，force 重建语料库级 corpus_db）。

## 1. 根因分类（15 CVE 逐一定位）

**库存盘点**：15/15 的 vuln/fixed 源均在 `corpus_src`（含 .py，1–20 个）；目标 CWE 全部落在 taint 覆盖集
{CWE-022/078/079/089/094/918} 内。→ **排除 (a) clone 失败**（源在场）。

| 归属 | CVE | 目标 CWE | 是否在 corpus_db(src.zip) | 根因 |
|---|---|---|---|---|
| 74-set | 48782 | 918 | ✅ vuln+fixed 各 2 文件 | **(c) 查询建模盲区**——SSRF 守卫绕过（IPv6 转换/NAT64 绕过，vuln→fixed 为守卫加固），非 source→sink 注入，taint 查询类无法表达 |
| 74-set | 50180 / 54654 / 57516 / 59894 / 68508 | 22·89 / 94 / 94 / 94 / 94 | ✅ 双侧完整 | **(c) 查询建模盲区**——CWE-094 族（sqlparse 解析、ray/hydra 反射实例化、datamodel-code-gen）sink 为 `eval/importlib/__import__/pickle` 等，CodeQL python 对多数反射/反序列化 sink 无成熟建模；langroid CWE-22/89 为 agent SQL 工具，入参 source 未声明 |
| 74-set | 59820 / 61632 / 9335 / 73417 | 22 / 22 / 22 / 79 | ✅ 双侧完整 | **(c) 查询建模盲区（sink 在但入口非声明 source）**——litellm sandbox 路径、keras zip 成员、pymdown/jupyterlab 的文件/HTML 路径来自**库内部/工具入参**，corpus 级 source 仅按"path 命名参数"声明，未命中 |
| **D1** | 62677 / 70479 / 70486 / 70492 | 22 / 918 / 79·1021 / 79 | ❌ **不在 src.zip** | **(b) 建库缺口**——语料库级 DB 早于 D1 语料建成；补源重建即可入 |
| **D1** | 70485 | 918 | ❌ 不在 src.zip；且 **fixed 侧源缺失（corpus_src fixed.py=0）** | **(b)+(d) 语料缺口**——重建后 fixed 侧仍无法 taint，申报排除该版本 |

**74-set 10 个双侧源完整在 DB 却零行** → 与"09-03 审计结论（建模盲区）"一致、与"v9 summary（建库/checkout 失败）"表述部分不符（后者对 74-set 不成立，仅对 D1 成立）。

## 2. 处置策略（分批）

- **批次 1（D1-5，建库缺口）→ 修复**：force 重建 corpus_db（含全部 corpus_src 96 对 = 74∪D1），重跑 7 taint 查询 + baseline analyze。已启动（QXebM3）。
  - 重建后预期：62677/70479/70486/70492 若代码含建模 sink（FastAPI/open-webui 的 request source 已建模）→ 将产出污点行；70485 申报 fixed 侧缺口。
- **批次 2（74-set 10，建模盲区）→ 验证 + 定向通用扩展**：
  - 重建后先复验 10 个是否仍零行（确认非建库时序问题）。
  - 唯一可做的 corpus-level 通用扩展（对齐 D5-A 纪律、无 per-CVE 调参）：给 CWE-918 查询加"url/fetch_url 命名参数"为通用 source（对称于 022 的 CpgPathSource）。
  - 守卫绕过类（48782）与反射/反序列化 sink 类（sqlparse/ray/hydra）**无通用修复 → 申报排除**（per-CVE 建模即泄漏，按纪律不做）。
- **批次 3（死磕不过）→ 排除 + 申报**：逐 CVE 写入申报表，论文局限节引用。

## 3. 复验与测量（重建完成后）

1. 重跑 `d5_flowcut_baserate.py` → 覆盖/flow-cut 变化；
2. 重跑 `pair_aware_gate.py` → 看是否出现 rule1（vuln target 流 ∧ fixed 无）新事件；
3. 若 D1-5 出现流 → 其 fixed 侧若被切断即"修复引入 cut"证据，抬升 CPG 判别下界。
