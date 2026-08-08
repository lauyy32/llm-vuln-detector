"""
Minimal, realistic vulnerable function used ONLY to validate the CPG
extraction -> text-slice pipeline (RESEARCH-DESIGN 第5节 step 1).

真实世界 SQL 注入模式的忠实最小复现：攻击者可控的 HTTP 请求参数被
拼接进传给 sqlite3 执行的 SQL 查询字符串。使用 flask 模块级 `request`
（CodeQL 建模的远程 source）与 sqlite3 明确建模的 SQL sink，使上游
SqlInjectionFlow 能稳定命中。

本文件仅用于管线冒烟测试。完整评测数据集将使用真实仓库里的真实 CVE
修复前/后代码——那份才是严肃数据。

结构要点（供 CPG 提取验证）：
  - CFG：if/else 分支
  - DFG：user_id（SOURCE，来自 request.args）流向 query，再流入 conn.execute（SINK）
"""

import sqlite3
from flask import request


def get_user_profile(admin_mode):
    # SOURCE: 攻击者可控的 HTTP 请求输入（flask 模块级 request，被 CodeQL 建模）
    user_id = request.args.get("id")

    if admin_mode:
        # 分支 -> 用于验证 CFG
        query = "SELECT name, email FROM users"
    else:
        # 污点传播：user_id（source）流入 query（接近 sink）
        query = "SELECT name, email FROM users WHERE id = " + user_id

    # SINK: sqlite3 明确建模的 SQL 执行点；admin_mode 为 False 时发生 SQL 注入
    conn = sqlite3.connect("app.db")
    conn.execute(query)
    return conn
