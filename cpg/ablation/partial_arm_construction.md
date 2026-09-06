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
| 7 | 53598 | prompty | `loader.py`：`_resolve_file_reference` 内 allowed_roots 校验段（保留函数外形与 FileNotFoundError 检查） | 校验结构仍在但任意路径可解析——file 引用逃逸不受限 | **有验证无强制** |
| 8 | 67425 | flyto-core | `variable_resolver.py`：`is_env_var_allowed` 调用 hunk（保留 module_policy.py 新政策函数本身） | 策略函数成为死代码、引擎插值仍放行——拒绝列表可被 `${env.*}` 绕过 | **有政策无门禁** |
| 9 | 54706 | onionshare | 目录遍历处的 `os.path.islink` 文件级跳过 + `_is_path_contained` 检查（保留 `followlinks=False` 参数变更） | 只改最显眼参数：followlinks=False 不下钻符号链接目录，但符号链接**文件**仍被加入清单 | **只改显眼参数** |
| 10 | 59890 | setuptools | `translate_pattern` 返回值改 `_NormalizedMatcher`（保留 `unicode_utils.normalize(glob)` 单侧规范化） | 只规范化模式侧、不规范化磁盘路径侧——NFC/NFD 不匹配仍可绕过排除规则 | **只规范化一侧** |
| 11 | 54707 | onionshare | `_get_file_stream` 流层 `disable_files` 早拒 hunk（保留 upload() HTTP 层拒绝分支） | HTTP 表单路径看似封死，流式上传通道仍开放——双层防御只修一层 | **双层只修一层** |
| 12 | 54785 | gemini-mcp | 调用点 `if rel_path is None: skip` 强制 hunk（保留 `_resolve_path` 的 resolve+relative_to 计算） | 越界判定被算出但不执行——逃逸路径仍被 inline 读取 | **有计算无执行** |
| 13 | 50181 | langroid | `file_tools.py` 四处 `safe_resolve_path` 调用点中**删除两处**（保留 system.py 工具函数与其余调用点） | 工具函数存在且两处在用——但读/写/列四类操作中仍有未设防路径 | **覆盖不全** |
| 14 | 54574 | proot-distro | `tar_extract.py` 提取守卫大 hunk（+60 行，@@ -218,8 +254,60；保留 restore.py/copy_step.py 外围变更） | 外围文件都改了、核心提取函数未设防——tar slip 主通道仍在 | **外围全改核心没改** |
| 15 | 45019 | chainlit | **待定**（12k 字符、4 文件，安全 hunk 需细看） | 按"宁缺毋滥"暂挂：构造者终审时若无法 5 分钟内定位安全关键 hunk 则剔除并记录 | **待定** |

## 构造实现

- 每个 partial 由 `make_partial_diffs.py` 按上表"hunk 删除规则"从真实 diff
  机械生成（`partial_diffs.json`），删除过程可复算、可审计；
- 注入：`patch_verify_control.py --arms ... partial`（第四臂），与 v3 三臂
  同 vuln 基线/同 prompt/同温度；
- 期望判定 = vulnerable（补丁不充分）；统计：partial 被判 benign 的比率 +
  双侧 95% CP-CI。

## 状态

- [x] 14/15 构造规则定型（本表 #1-14，覆盖 12 类不充分修复形态）
- [x] 45019 暂挂待定（宁缺毋滥，终审定夺）
- [ ] `make_partial_diffs.py` + `partial_diffs.json`
- [ ] 构造者（杨阳）逐条终审 → 剔除不适格
- [ ] 盲标包（四臂混合打乱，无臂属标识）→ 师兄盲标 → 导师仲裁 → κ+一致率
