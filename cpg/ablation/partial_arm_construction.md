# partial 臂构造文档（P1-15 §2，先于标注冻结）

> 构造规则：partial 补丁 = 真实修复 diff **删除安全关键 hunk**（保留其余 hunks）。
> "不充分"由构造保证（安全关键 hunk = 直接切断漏洞路径/引入守卫的变更，
> 删除后漏洞仍可被利用），不凭直觉声明。逐 CVE 给出：文件、hunk 定位、
> 关键性理由、partial 类型。无法确定安全关键 hunk 的 CVE 按"宁缺毋滥"剔除。
> 标注者（师兄）盲标前**不得阅读本文档**；导师仲裁完成前亦不可见。

| # | CVE | 项目 | 安全关键 hunk | 关键性理由 | partial 类型 |
|---|---|---|---|---|---|
| 1 | 12482 | keras | `file_utils.py`：`resolve_path` 由 `realpath(abspath(path))` 改 `realpath(path)`（@@ -41,7 @@ 单行） | 唯一行为变更；删除后补丁只剩"新增安全回归测试"——测试存在而防护不存在 | **有测试无修复** |
| 2 | 70491 | open-webui | `tools.py`：`data = tools.model_dump()` + `if not write_access: data.pop('content', None)`（两行） | 删除后响应仍携带 write-only content（信息泄露）；返回值重构外形完全保留 | **有外形无防护** |
| 3 | 50558 | flyto-core | `penelope.py` 新函数 `guarded` 内的 `_is_within_directory` 路径检查与符号链接目标检查（保留 mode 掩码与调用点） | 删除后 `safe_tar_extractall` 外壳仍在但不做任何路径/链接拒绝——tar slip 仍可穿越 | **有外壳无检查** |
| 4 | 67424 | flyto-core | 三处 `enforce_outbound_url` 调用点中**删除 proxy_rotate.py 一处**（保留 vision_analyze/slack_send 两处） | 删除后仍有一个 SSRF 入口未设防——"大部分入口已修"的典型不充分修复 | **覆盖不全** |
| 5 | 53502 | thumbor | `file_loader.py`：用 commonpath 的 `_inside_root_path` 检查（保留 unquote 提前与 startswith 旧检查） | 只先解码但沿用 startswith：`/images-sibling` 前缀攻击仍可通过（%2e%2e 修了、兄弟前缀没修） | **修了一半** |
| 6 | 73498 | mcp-atlassian | `client.py`：SSRF redirect hook + `mount_ssrf_pinning` DNS 锁定（保留 attachments 路径约束与 search 的 CQL 白名单） | 删除后出站请求仍无 SSRF 防护（重定向/DNS rebinding 通道开放）；其余两文件修复照在 | **多文件修一半** |
| 7-15 | （分析中）45019/50181/53598/54574/54706/54707/54785/59890/67425 | — | — | 下批补入；不适格者按"宁缺毋滥"剔除并记录理由 | — |

## 构造实现

- 每个 partial 由 `make_partial_diffs.py` 按上表"hunk 删除规则"从真实 diff
  机械生成（`partial_diffs.json`），删除过程可复算、可审计；
- 注入：`patch_verify_control.py --arms ... partial`（第四臂），与 v3 三臂
  同 vuln 基线/同 prompt/同温度；
- 期望判定 = vulnerable（补丁不充分）；统计：partial 被判 benign 的比率 +
  双侧 95% CP-CI。

## 状态

- [x] 6/15 构造规则定型（本表 #1-6）
- [ ] 9/15 剩余分析
- [ ] `make_partial_diffs.py` + `partial_diffs.json`
- [ ] 构造者（杨阳）逐条终审 → 剔除不适格
- [ ] 盲标包（四臂混合打乱，无臂属标识）→ 师兄盲标 → 导师仲裁 → κ+一致率
