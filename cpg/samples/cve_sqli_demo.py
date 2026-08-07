"""
Minimal, realistic vulnerable function used ONLY to validate the CPG
extraction -> text-slice pipeline (RESEARCH-DESIGN 第5节 step 1).

这是一个真实世界 SQL 注入模式的忠实最小复现（一类 CVE：未净化的
HTTP 请求参数被拼接进传给 cursor.execute 的 SQL 查询字符串）。它是
应用级代码，不是 SARD 风格的、带明显标记名的合成玩具。

本文件仅用于管线冒烟测试。完整评测数据集（step 3）将使用 Devign
真实仓库里的真实 CVE 修复前/后代码——那份才是严肃数据。

结构要点（供 CPG 提取验证）：
  - CFG：if/else 分支
  - DFG：user_id（SOURCE，来自请求）流向 query，再流入 cursor.execute（SINK）
"""

def get_user_profile(db, request, admin_mode):
    # SOURCE: 攻击者可控的 HTTP 请求输入
    user_id = request.args.get("id")

    if admin_mode:
        # 分支 -> 用于验证 CFG
        query = "SELECT name, email FROM users"
    else:
        # 污点传播：user_id（source）流入 query（接近 sink）
        query = "SELECT name, email FROM users WHERE id = " + user_id

    cursor = db.cursor()
    # SINK: 若 admin_mode 为 False，则发生 SQL 注入
    cursor.execute(query)
    return cursor.fetchall()
