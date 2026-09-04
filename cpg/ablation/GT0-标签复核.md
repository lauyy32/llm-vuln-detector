# GT 复核报告（第 0 步 A，2026-09-04）

> 目的：关闭"标签污染压低判别率"的最后开放通道——人工复核 contested 样本的 fixed 版本是否**真修复**。
> 复核人：lauyy32（基于本地 vuln→fixed 源码 diff 逐样本判读）
> 数据产物：`cpg/ablation/.work/gt_recheck_samples.json`（contested 集合）+ `gt_verdicts.json`（判定）+ `gt_review_prod.txt`（判读材料）
> 前置：第三轮 AI 评审（2026-09-04）将 GT 复核列为修订计划第 0 步；54785 为已知疑点。

## 1. Contested 集合（操作化定义）

**17 个 CVE**：v9 口径下任一判定器（CPGEvidence / LocalLLM，7B / 14B）在 **fixed 版本判 vulnerable**（即双标或 fixed 侧 FP）的并集——
与 b2_74_7b pre-gate cpg_full 双标 17 完全一致，亦为 B4 三臂的 17 理论总体。三臂 real 漏判为 17 的子集（非附加项）。

## 2. 复核结论（总览）

| 统计 | 值 |
|---|---|
| 复核样本数 | **17 / 17** |
| fixed = **真修复** | **17** |
| fixed 疑似未修复 | **0** |
| 无法判定 | **0** |

> **结论：在 17 个 contested 样本上未发现标签污染实锤。** "fixed 已修复" 这一标签全部成立。
> 判别率近随机**不是**"fixed 侧标签错"造成的假象——该污染通道关闭（负向结果，反而加固"判别力弱是真实现象"的立论）。

## 3. 逐样本判定

| CVE | 仓库 | 漏洞类型 | fixed 判定 | 置信 | 关键证据 |
|---|---|---|---|---|---|
| 12482 | keras-team/keras | tar symlink 路径穿越 | 真修复 | 高 | resolve_path 去 abspath；filter_safe_tarinfos 拒 symlink 路由成员 + 回归测试 |
| 45019 | Chainlit/chainlit | SSRF via MCP SSE | 真修复 | 高 | MCP SSE 默认关、user_servers URL 白名单默认拒绝（夹带大重构） |
| 49257 | mcp_pinot | 未认证暴露+非只读 SQL | 真修复 | 高 | 默认绑 127.0.0.1；非回环无 OAuth 拒启；sqlglot 仅 SELECT/WITH |
| 50181 | langroid/langroid | file tools 路径穿越 | 真修复 | 高 | safe_resolve_path 拒 `..`/绝对/symlink 越界 |
| 50558 | brightio/penelope | tar 解包穿越 | 真修复 | 高 | safe_tar_extractall commonpath 守卫 |
| 53502 | thumbor/thumbor | %2e%2e 编码穿越 | 真修复 | 高 | 先 unquote 再 abspath+commonpath（D5 cut 例） |
| 53598 | microsoft/prompty | ${file:} 引用穿越 | 真修复 | 高 | allowed_file_roots 规范化拒越界 |
| 54574 | termux/proot-distro | tar symlink→host 写 | 真修复 | 高 | _safe_resolve 每 hop 钳 rootfs；hardlink 过滤 |
| 54706 | onionshare/onionshare | 分享 symlink 泄露 | 真修复 | 高 | 跳 symlink + followlinks=False + 容器校验 |
| 54707 | onionshare/onionshare | upload 禁用绕过 | 真修复 | 中高 | 禁用时显式拒文件提交 |
| **54785** | eLyiN/gemini-bridge | 任意本地文件读 | **真修复** | 高 | resolve()+relative_to(root)，越界 None；调用点 198/254 行跳过+告警 → **疑点解除** |
| 59890 | pypa/setuptools | Unicode 归一绕过排除 | 真修复 | 高 | _NormalizedMatcher NFC 归一（GHSA-h35f） |
| 67424 | flytohub/flyto-core | SSRF 批量加固 | 真修复 | 高 | 全出站模块 SSRF 门禁 + redirect 逐跳校验 + callback 白名单 |
| 67425 | flytohub/flyto-core | env 插值/凭据/路径 | 真修复 | 高 | ${env.*} deny-by-default；凭据禁转发非信任端点；路径中心沙箱 |
| 67428 | flytohub/flyto-core | SSRF 批量加固 | 真修复 | 高 | 同 67424 同型改动 |
| 70491 | open-webui/open-webui | 工具元数据越权 | 真修复 | 中 | write_access 判定与 data 注入拆分 |
| 73498 | sooperset/mcp-atlassian | SSRF rebinding+路径 | 真修复 | 高 | DNS pinning 反 TOCTOU、redirect hook、工作区路径限制、token 0600、XSS escape |

## 4. 附带发现（对测量方法学重要）

1. **⚠️ 67424 与 67428 为近似重复样本**：二者 diff 的**文件集与逐文件行数逐字节相同**（vision_analyze +7、http/get +13/-2 … utils +71、verification_service +85/-2 全同），疑为同一修复批次/提交被两个 GHSA 各采一次。判定：
   - 对配对判别：二者同为"双标"（贡献 concordant 计数），不直接扭曲 n_disc，但**语料独立样本数实际 <74**；
   - 待办：比对二者 `fix_commit` 是否相同（本地 candidates 仅查到 67424 = 0a0a5285…），相同则论文须申报并合并/剔除其一。
2. **批量加固提交的 diff 噪声解释了"判别失败"而非标签错误**：45019（+1400 行夹带重构）、67424/67425/67428（全仓加固）、73498（多 GHSA 合并）的 fixed 侧改动远超最小修复。这些样本 fixed 标签正确，但模型要从中挑出"哪个改动切断了我这条 source→sink"——信号被噪声淹没。这与 D5「净化器盲区」机制互补：一类是"补丁不切流"（真无信号），一类是"补丁夹带过多"（有信号但难提取）。
3. **全部 17 样本的修复都以"插入守卫/净化器"为主形态**（validate_safe_path / enforce_outbound_url / _safe_resolve / allowed_file_roots / 白名单），再次印证立论：CPG/LLM 需识别自定义净化器才能判"已修复"——正是净化器盲区的直接证据面。

## 5. 对研究的影响

- **标签污染通道关闭（负向结果）**：判别近随机不能归因于 fixed 侧标签错。
- 立论叙事强化："补丁边界判别力弱"是真实测量（17/17 标签无误的前提下），但**判别力弱的部分原因不是没有判别信号，而是信号被 ① 净化器盲区 ② 批量加固噪声 ③ 重复样本稀释** 三种结构性因素掩盖——这为论文 Discussion 提供了比"模型不行"更细的机制解释。
- 后续动作：比对 67424/67428 fix_commit；70491/54707 低置信项对照 advisory 复核。

## 6. 复现

```bash
# 派生 contested 集合（多源 union）
python - <<EOF  # 见会话内脚本：v9_llm_74/74_14b results.csv + b2_74_7b.json + patch_verify_control_p0_2_full.json
# 生成判读材料
# corpus_src/<cve>_{vuln,fixed} → difflib 生产代码 diff
```
