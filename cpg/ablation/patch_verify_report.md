# 补丁验证基准（第二研究问题）

> 18 个 fixed 样本 · diff 注入（vuln→fixed）· qwen2.5-coder:7b temperature=0

| 样本 | 无diff判定 | 有diff判定 | 结果 | LLM 依据 |
| --- | --- | --- | --- | --- |
| CVE-2026-50558_fixed | vulnerable | benign | ✅ 误报修复 | The patch adds a `safe_tar_extractall` function that checks if the ext |
| CVE-2026-53502_fixed | vulnerable | benign | ✅ 误报修复 | The patch correctly decodes percent-encoded paths before performing se |
| CVE-2026-53505_fixed | benign | benign |  | The patch adds a check to ensure the value is between 0 and 1.0, preve |
| CVE-2026-54338_fixed | benign | benign |  | The patch limits the length of the username logged in error messages,  |
| CVE-2026-54548_fixed | benign | benign |  | The patch adds a conditional check to disable SSH host key checking on |
| CVE-2026-54553_fixed | abstain | benign | ✅ 误报修复 | The patch adds validation for the `order_by` parameter to ensure that  |
| CVE-2026-54569_fixed | vulnerable | benign | ✅ 误报修复 | The patch replaces the use of `eval` with `parse_record_literal`, whic |
| CVE-2026-54706_fixed | vulnerable | benign | ✅ 误报修复 | The patch adds a `_is_path_contained` method to verify that paths are  |
| CVE-2026-54707_fixed | vulnerable | benign | ✅ 误报修复 | The patch adds a check to reject file uploads when disabled, preventin |
| CVE-2026-54785_fixed | vulnerable | vulnerable |  | The fix does not address the vulnerability in the `_resolve_path` func |
| CVE-2026-59881_fixed | abstain | benign | ✅ 误报修复 | The fix ensures that the `compress` parameter is explicitly converted  |
| CVE-2026-67424_fixed | vulnerable | benign | ✅ 误报修复 | The patch adds an SSRF guard to validate outbound URLs, preventing pot |
| CVE-2026-67435_fixed | vulnerable | benign | ✅ 误报修复 | The patch adds a function `_install_safe_redirect_stripping` that wrap |
| CVE-2026-69243_fixed | benign | benign |  | The patch introduces a flag `_pending_upgrade` to defer any requested  |
| CVE-2026-70487_fixed | benign | benign |  | 补丁通过 `_set_direct_model` 函数对 `direct` 模型知识进行了访问控制，确保只有可访问的文件内容被传递给模型。 |
| CVE-2026-70488_fixed | abstain | benign | ✅ 误报修复 | The patch adds checks to ensure that only files and directories belong |
| CVE-2026-71433_fixed | abstain | benign | ✅ 误报修复 | The patch adds namespace validation and escaping, effectively preventi |
| CVE-2026-71554_fixed | benign | benign |  | The patch adds a check to raise an exception if a second Host header i |

**汇总：误报修复 7 个（判定改善 11/18）**