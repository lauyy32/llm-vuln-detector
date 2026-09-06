# 数据字典（2026-09-06，集合关系由脚本实测复算）

## 1. 语料集与集合关系（实测值，非手抄）

```
全 mined 并集 = 93
├── 74 主集 ∩ D1 = 66
├── D1 独有 = 19      （D1 = 85 = 66 + 19）
└── 74 主集独有 = 8   （74 主集 = 74 = 66 + 8；74 ⊄ 85）

配对完整集（配对判别的分析分母） = 82
  = D1(85) − 3 个 fixed 空源码（CVE-2026-53500 / 59224 / 70485，
    pair_completeness.py 门禁）

placebo/partial 子集 = 15
  = CPG 双标 17 − 2（CVE-2026-49257 / 67428 为 74 主集独有、
    不在 D1，脚本按"不在 dataset"跳过——源码实存 corpus_src，
    排除原因是语料集关系而非源码缺失，P1-12 已勘误）
```

> 注：曾见"82 = 74 + 8"的写法——**错误**。74 与 D1 是兄弟集不是父子集，
> "8"是 74 主集独有、不在 D1；任何合并叙述必须给全 66/19/8/93 四个数。

## 2. dataset_d1.jsonl 字段（85 行，实测首行 schema）

| 字段 | 含义 |
|---|---|
| cve_id | CVE 编号（CVE-2026-*） |
| ghsa_id | GitHub Security Advisory 编号 |
| repo_slug | 上游仓库（如 keras、thumbor、flyto-core、open-webui） |
| fix_commit | 修复提交哈希 |
| cwes | 关联 CWE 列表（首个为主 CWE） |
| severity | 公告严重度 |
| summary | 公告摘要（默认不注入 prompt，防标签泄漏） |
| files | 修复涉及文件清单（vuln/fixed 双侧，corpus_pairs/ 下有树） |
| label | 样本标签用途（vuln/fixed 配对生成） |
| language | 语言（全部 python） |

## 3. 仓库聚集披露（样本非完全独立）

- D1 共 56 仓库；open-webui 13 条、thumbor 5 条、flyto-core 3 条为最大聚集；
- 同 fix commit 对：67424/67428（67428 不在 D1，82 口径主数字不受影响；
  67424 入前沿 r1 判别集、67425 入 r2 判别集——P1-13 §Threats 已脚注）；
- 聚类敏感性（leave-one-repo-out + 仓库聚集处置）为实验冻结包 §4 待办，
  结果进论文鲁棒性段。

## 4. 排除样本全账（5 例，逐例理由）

| CVE | 排除自 | 理由 |
|---|---|---|
| 53500 / 59224 / 70485 | n=82 配对分析 | fixed 侧无源码（pair_completeness 门禁） |
| 49257 / 67428 | placebo/partial 子集 | 74 主集独有、不在 D1（语料集关系，非源码缺失） |

## 5. seeds/ 版本谱系（判别数字口径）

| 目录 | 内容 | 口径 |
|---|---|---|
| v9_llm_74 / v9_llm_d1 | 本地 7B 主协议（v9 scorer） | 权威 |
| v10_d1_7b | 独立重建复跑（稳健性） | 对照 |
| v9_llm_74_14b | 本地 14B | 对照 |
| v13_85_ds_r{1,2}{a,b} | 前沿 DeepSeek RQ1 臂（4 片×2 轮） | 探索性（A/C 重叠） |
| patch_verify_control_v3_{7b,14b}.json | placebo v3（vuln 基线） | **v3 pilot** |
| 旧 patch_verify_control*.json | placebo v1/v2（fixed 基线） | flawed pilot，留档不池化 |
