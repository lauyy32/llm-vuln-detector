#!/usr/bin/env python
"""生成 40 条正常请求样本，追加到 adversarial_samples.json，使数据集正负均衡。"""

import json
from pathlib import Path

DATASET_FILE = Path(__file__).parent / "dataset" / "adversarial_samples.json"

benign_samples = [
    # === 易与 SQLi 混淆 (8条) ===
    {"id": "ben_sqli_001", "category": "正常请求", "subcategory": "SQL关键字误判",
     "payload": "q=how+to+use+UNION+in+SQL+tutorial",
     "description": "搜索SQL教程，含UNION关键字", "expected_vulnerable": False, "difficulty": "easy"},
    {"id": "ben_sqli_002", "category": "正常请求", "subcategory": "SQL关键字误判",
     "payload": "comment=I+love+OR+AND+NOT+logic+gates",
     "description": "评论含SQL布尔关键字", "expected_vulnerable": False, "difficulty": "easy"},
    {"id": "ben_sqli_003", "category": "正常请求", "subcategory": "SQL关键字误判",
     "payload": "search=SELECT+*+FROM+table+syntax+explained",
     "description": "搜索SQL语法文档", "expected_vulnerable": False, "difficulty": "medium"},
    {"id": "ben_sqli_004", "category": "正常请求", "subcategory": "SQL关键字误判",
     "payload": "bio=I%27m+a+database+administrator",
     "description": "URL编码的单引号(正常使用)", "expected_vulnerable": False, "difficulty": "medium"},
    {"id": "ben_sqli_005", "category": "正常请求", "subcategory": "编码误判",
     "payload": "token=d3d3LmV4YW1wbGUuY29tL2xvZ2lu",
     "description": "Base64编码的正常URL", "expected_vulnerable": False, "difficulty": "hard"},
    {"id": "ben_sqli_006", "category": "正常请求", "subcategory": "SQL关键字误判",
     "payload": "msg=you+have+1+new+message+%26+2+notifications",
     "description": "URL编码的&符号(正常通知)", "expected_vulnerable": False, "difficulty": "medium"},
    {"id": "ben_sqli_007", "category": "正常请求", "subcategory": "数字序列误判",
     "payload": "id=12345678901234567890",
     "description": "长数字ID(非SQLi)", "expected_vulnerable": False, "difficulty": "hard"},
    {"id": "ben_sqli_008", "category": "正常请求", "subcategory": "编码误判",
     "payload": "q=%E6%95%B0%E6%8D%AE%E5%BA%93%E6%9F%A5%E8%AF%A2",
     "description": "URL编码的中文(数据库查询)", "expected_vulnerable": False, "difficulty": "medium"},

    # === 易与 XSS 混淆 (8条) ===
    {"id": "ben_xss_001", "category": "正常请求", "subcategory": "HTML标签误判",
     "payload": "q=javascript+tutorial+for+beginners+2025",
     "description": "搜索JavaScript教程", "expected_vulnerable": False, "difficulty": "easy"},
    {"id": "ben_xss_002", "category": "正常请求", "subcategory": "HTML标签误判",
     "payload": "content=%3Cdiv+class%3D%22container%22%3EHello%3C%2Fdiv%3E",
     "description": "URL编码的合法HTML片段", "expected_vulnerable": False, "difficulty": "easy"},
    {"id": "ben_xss_003", "category": "正常请求", "subcategory": "HTML标签误判",
     "payload": "title=How+to+use+%3Cscript%3E+tag+in+HTML",
     "description": "讨论HTML script标签用法", "expected_vulnerable": False, "difficulty": "medium"},
    {"id": "ben_xss_004", "category": "正常请求", "subcategory": "HTML标签误判",
     "payload": "signature=%3Cb%3EJohn+Doe%3C%2Fb%3E+-+CEO",
     "description": "签名中的加粗标签", "expected_vulnerable": False, "difficulty": "medium"},
    {"id": "ben_xss_005", "category": "正常请求", "subcategory": "HTML实体误判",
     "payload": "bio=%26lt%3Bdiv%26gt%3B+is+an+HTML+element",
     "description": "HTML实体用于教学文本", "expected_vulnerable": False, "difficulty": "hard"},
    {"id": "ben_xss_006", "category": "正常请求", "subcategory": "事件处理误判",
     "payload": "description=The+onclick+event+triggers+on+mouse+click",
     "description": "讨论onclick事件(纯文本)", "expected_vulnerable": False, "difficulty": "medium"},
    {"id": "ben_xss_007", "category": "正常请求", "subcategory": "编码误判",
     "payload": "code=x3Cscriptx3E+is+used+in+tests",
     "description": "Unicode编码的正常讨论", "expected_vulnerable": False, "difficulty": "hard"},
    {"id": "ben_xss_008", "category": "正常请求", "subcategory": "SVG标记误判",
     "payload": "icon=%3Csvg+width%3D24+height%3D24%3E%3C%2Fsvg%3E",
     "description": "合法SVG图标数据", "expected_vulnerable": False, "difficulty": "hard"},

    # === 易与命令注入混淆 (6条) ===
    {"id": "ben_cmdi_001", "category": "正常请求", "subcategory": "命令关键字误判",
     "payload": "q=linux+cat+command+tutorial+%26+grep+examples",
     "description": "搜索Linux命令教程", "expected_vulnerable": False, "difficulty": "easy"},
    {"id": "ben_cmdi_002", "category": "正常请求", "subcategory": "命令关键字误判",
     "payload": "note=To+check+logs+run%3A+cat+%2Fvar%2Flog%2Fsyslog",
     "description": "技术文档中的命令示例", "expected_vulnerable": False, "difficulty": "medium"},
    {"id": "ben_cmdi_003", "category": "正常请求", "subcategory": "管道符号误判",
     "payload": "input=option+a+%7C+option+b+%7C+option+c",
     "description": "竖线作为选项分隔符", "expected_vulnerable": False, "difficulty": "medium"},
    {"id": "ben_cmdi_004", "category": "正常请求", "subcategory": "命令关键字误判",
     "payload": "filename=ping_backup_2025-07-22.tar.gz",
     "description": "文件名含ping关键字", "expected_vulnerable": False, "difficulty": "hard"},
    {"id": "ben_cmdi_005", "category": "正常请求", "subcategory": "反向shell误判",
     "payload": "message=nc+is+short+for+netcat+tool",
     "description": "讨论netcat工具(纯文本)", "expected_vulnerable": False, "difficulty": "hard"},
    {"id": "ben_cmdi_006", "category": "正常请求", "subcategory": "Base64误判",
     "payload": "data=d2hvYW1p+ZWNobyAiaGVsbG8i",
     "description": "截断的Base64(非注入)", "expected_vulnerable": False, "difficulty": "hard"},

    # === 易与路径穿越混淆 (4条) ===
    {"id": "ben_lfi_001", "category": "正常请求", "subcategory": "路径误判",
     "payload": "path=../public/images/logo.png",
     "description": "相对路径引用静态资源", "expected_vulnerable": False, "difficulty": "easy"},
    {"id": "ben_lfi_002", "category": "正常请求", "subcategory": "路径误判",
     "payload": "template=../../templates/email/welcome.html",
     "description": "模板引擎相对路径", "expected_vulnerable": False, "difficulty": "medium"},
    {"id": "ben_lfi_003", "category": "正常请求", "subcategory": "null字节误判",
     "payload": "file=report.pdf%00backup.bak",
     "description": "Null截断的正常文件名", "expected_vulnerable": False, "difficulty": "hard"},
    {"id": "ben_lfi_004", "category": "正常请求", "subcategory": "路径误判",
     "payload": "dir=%2e%2e%2f%2e%2e%2fshared%2fconfig.json",
     "description": "URL编码的相对路径(配置访问)", "expected_vulnerable": False, "difficulty": "hard"},

    # === 易与 SSRF/XXE 混淆 (5条) ===
    {"id": "ben_web_001", "category": "正常请求", "subcategory": "SSRF误判",
     "payload": "{\"url\":\"https://api.github.com/repos/lauyy32/repos\"}",
     "description": "正常API URL请求", "expected_vulnerable": False, "difficulty": "easy"},
    {"id": "ben_web_002", "category": "正常请求", "subcategory": "SSRF误判",
     "payload": "webhook=http://localhost:8080/health",
     "description": "本地健康检查webhook", "expected_vulnerable": False, "difficulty": "medium"},
    {"id": "ben_web_003", "category": "正常请求", "subcategory": "XML误判",
     "payload": "<?xml version=\"1.0\"?><note><to>Tove</to></note>",
     "description": "合法XML文档推送", "expected_vulnerable": False, "difficulty": "medium"},
    {"id": "ben_web_004", "category": "正常请求", "subcategory": "文件上传误判",
     "payload": "filename=report.php.pdf",
     "description": "php.pdf文件名(非PHP文件)", "expected_vulnerable": False, "difficulty": "hard"},
    {"id": "ben_web_005", "category": "正常请求", "subcategory": "开放重定向误判",
     "payload": "redirect=https%3A%2F%2Fexample.com%2Flogin",
     "description": "正常OAuth redirect_uri", "expected_vulnerable": False, "difficulty": "hard"},

    # === 综合混淆 (9条) ===
    {"id": "ben_misc_001", "category": "正常请求", "subcategory": "综合混淆",
     "payload": "input=hello%26world%27s+data+%3Cb%3Etest%3C%2Fb%3E",
     "description": "混合特殊字符的正常文本", "expected_vulnerable": False, "difficulty": "medium"},
    {"id": "ben_misc_002", "category": "正常请求", "subcategory": "综合混淆",
     "payload": "json={\"search\":\"SELECT 1 FROM dual\",\"page\":1}",
     "description": "JSON中嵌SQL示例文本", "expected_vulnerable": False, "difficulty": "hard"},
    {"id": "ben_misc_003", "category": "正常请求", "subcategory": "编码混淆",
     "payload": "data=SGVsbG8gV29ybGQhIEkgYW0gYSBub3JtYWwgdXNlci4=",
     "description": "Base64编码的Hello World", "expected_vulnerable": False, "difficulty": "hard"},
    {"id": "ben_misc_004", "category": "正常请求", "subcategory": "Unicode混淆",
     "payload": "name=\\u004a\\u006f\\u0068\\u006e\\u0020\\u0044\\u006f\\u0065",
     "description": "Unicode转义的正常姓名(John Doe)", "expected_vulnerable": False, "difficulty": "hard"},
    {"id": "ben_misc_005", "category": "正常请求", "subcategory": "Hex编码",
     "payload": "color=0xDEADBEEF&type=0xCAFEBABE",
     "description": "十六进制颜色/魔数(非注入)", "expected_vulnerable": False, "difficulty": "medium"},
    {"id": "ben_misc_006", "category": "正常请求", "subcategory": "堆叠查询误判",
     "payload": "query=SELECT+1%3B+SELECT+2%3B+COMMIT%3B",
     "description": "SQL教学多语句示例", "expected_vulnerable": False, "difficulty": "hard"},
    {"id": "ben_misc_007", "category": "正常请求", "subcategory": "SSTI误判",
     "payload": "template=Hello+{{username}}+welcome+to+our+site",
     "description": "Mustache模板语法(非SSTI攻击)", "expected_vulnerable": False, "difficulty": "hard"},
    {"id": "ben_misc_008", "category": "正常请求", "subcategory": "NoSQL误判",
     "payload": "{\"query\":{\"$gt\":\"\"},\"fields\":[\"name\",\"email\"]}",
     "description": "MongoDB合法查询操作符", "expected_vulnerable": False, "difficulty": "hard"},
    {"id": "ben_misc_009", "category": "正常请求", "subcategory": "多语言混淆",
     "payload": "text=%E6%B3%A8%E5%85%A5+%E6%BC%8F%E6%B4%9E+%E6%A3%80%E6%B5%8B+%E6%8A%80%E6%9C%AF",
     "description": "URL编码中文(注入漏洞检测技术)", "expected_vulnerable": False, "difficulty": "easy"},
]


def main():
    with open(DATASET_FILE, "r", encoding="utf-8") as f:
        existing = json.load(f)

    print(f"Existing: {len(existing)} samples")

    existing.extend(benign_samples)

    print(f"New total: {len(existing)} samples (added {len(benign_samples)} benign)")

    # Verify
    ids = [s["id"] for s in existing]
    assert len(ids) == len(set(ids)), "Duplicate IDs!"
    attack = sum(1 for s in existing if s.get("expected_vulnerable", True))
    benign = sum(1 for s in existing if not s.get("expected_vulnerable", True))
    print(f"  Attack: {attack}, Benign: {benign}")

    with open(DATASET_FILE, "w", encoding="utf-8") as f:
        json.dump(existing, f, indent=2, ensure_ascii=False)

    print("Done.")


if __name__ == "__main__":
    main()
