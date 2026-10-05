"""外部规则（Sigma / Suricata ET）→ 内置攻击大类的映射表。

为什么需要它：开源规则库的"分类体系"与本系统不同（Sigma 用 logsource/tags，ET 用 msg 文案），
而检测链路、告警文案、前端展示、修复建议都按**本系统的 17 个攻击大类**组织，
因此加载期必须把外部规则映射到大类；无法映射的规则一律跳过（并写日志），
绝不猜测式归类，避免污染告警统计。
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

# 顺序敏感：越具体的类别必须越靠前（如 sql 盲注要先于 sql 注入匹配）
CATEGORY_KEYWORDS: List[Tuple[str, Tuple[str, ...]]] = (
    ("sql_injection_blind", ("sql blind", "blind sql", "blind sqli", "boolean-based",
                             "time-based", "time based", "sql_injection_blind")),
    ("sql_injection", ("sql injection", "sqli", "sql_injection", "union select", "union all select",
                       "information_schema", "or 1=1", "sqlmap", "select.*from")),
    ("ssti", ("ssti", "server-side template injection", "template injection", "expression language",
              "el injection", "spring4shell", "velocity template", "thymeleaf", "freemarker")),
    ("command_injection", ("command injection", "os command", "shell command", "remote code execution",
                           "rce ", "rce attempt", "jndi", "log4shell", "log4j", "shellshock",
                           "reverse shell", "netcat", "code execution")),
    ("file_inclusion", ("file inclusion", "local file inclusion", "remote file inclusion",
                        " lfi", " rfi", "lfi/", "rfi/")),
    ("file_upload", ("file upload", "upload attempt", "malicious upload", "unrestricted upload",
                     "webshell upload", "arbitrary file write")),
    ("webshell", ("webshell", "web shell", "web-shell", "backdoor", "china chopper", "c99 shell",
                  "cmd shell", "shell access")),
    ("path_traversal", ("path traversal", "directory traversal", "traversal", "dot-dot-slash",
                        "dot dot slash")),
    ("ssrf", ("ssrf", "server-side request forgery", "server side request forgery")),
    ("xxe", ("xxe", "xml external entity", "external entity", "doctype system")),
    ("ldap_nosql_injection", ("ldap injection", "nosql", "mongodb injection", "ldap query",
                             "ldap_nosql")),
    ("crlf_injection", ("crlf", "header injection", "http response splitting", "response splitting")),
    ("csrf", ("csrf", "cross-site request forgery", "cross site request forgery", "xsrf")),
    ("insecure_captcha", ("captcha", "verification code")),
    ("brute_force", ("brute force", "bruteforce", "password guessing", "credential stuffing",
                     "login failure", "authentication failure", "failed login")),
    ("xss_stored", ("stored xss", "persistent xss", "stored cross-site")),
    ("xss_reflected", ("xss", "cross-site scripting", "cross site scripting", "script injection")),
)

# 每类攻击的默认修复建议（外部规则通常只写"检测"不写"修复"，这里补全，
# 保证前端「处置建议」在混合规则库下始终有内容可展示）
DEFAULT_REMEDIATION: Dict[str, str] = {
    "sql_injection": "把该接口改为参数化查询/预编译语句；封禁来源 IP，并核查数据库审计日志是否出现批量查询。",
    "sql_injection_blind": "盲注伴随大量相似请求：封禁来源网段、检查数据库负载与出网行为，并修复注入点。",
    "xss_reflected": "修复回显参数的输出编码（上下文相关转义）并加 CSP；对来源 IP 限速。",
    "xss_stored": "清理已入库的恶意内容，对输出做上下文转义，并封禁提交者。",
    "command_injection": "立即隔离主机取证：检查进程、计划任务、反弹 Shell；封禁来源 IP 并修复命令拼接逻辑。",
    "file_inclusion": "关闭 allow_url_include / allow_url_fopen，路径参数改为白名单映射；封禁来源 IP。",
    "file_upload": "检查上传目录是否已有脚本落地（Webshell），禁止该目录执行脚本；封禁来源并轮换凭据。",
    "brute_force": "封禁来源 IP；对登录接口启用验证码、失败锁定与双因素认证，并检查登录日志。",
    "csrf": "确认接口是否缺少 CSRF Token；补齐 Token + SameSite，并核查来源是否为恶意诱导页面。",
    "insecure_captcha": "验证码改为服务端强校验（一次性 + 有效期 + 会话绑定）；对验证码接口限速。",
    "path_traversal": "路径参数改为白名单映射；确认敏感文件是否可读，并轮换可能已泄露的密钥。",
    "ssrf": "收紧出站白名单与云元数据访问；封禁来源 IP 并核查是否已读取凭据。",
    "xxe": "关闭 XML 外部实体（使用安全解析器）；排查已泄露文件与凭据。",
    "webshell": "高度疑似主机已被控制：立即封禁来源、隔离主机、定位删除后门文件并轮换凭据。",
    "ssti": "定位模板渲染点，改为数据与模板分离；封禁来源 IP 并检查是否已执行系统命令。",
    "ldap_nosql_injection": "对 LDAP / NoSQL 查询做参数化与类型校验；封禁来源 IP。",
    "crlf_injection": "对进入响应头的参数做 CR/LF 过滤；封禁来源 IP 并检查是否已注入假 Cookie。",
    "cve_vulnerability": "按漏洞公告升级到修复版本；无法升级时收紧暴露面（限制来源网段/关闭对应服务）。",
}

# 兜底参考链接（外部规则未提供 references 时使用，保证前端可跳转核实）
DEFAULT_REFERENCES: Dict[str, str] = {
    "sql_injection": "https://owasp.org/Top10/A03_2021-Injection/",
    "sql_injection_blind": "https://owasp.org/Top10/A03_2021-Injection/",
    "xss_reflected": "https://owasp.org/Top10/A03_2021-Injection/",
    "xss_stored": "https://owasp.org/Top10/A03_2021-Injection/",
    "command_injection": "https://owasp.org/Top10/A03_2021-Injection/",
    "file_inclusion": "https://owasp.org/Top10/A03_2021-Injection/",
    "file_upload": "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
    "brute_force": "https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks",
    "csrf": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
    "insecure_captcha": "https://owasp.org/www-community/controls/CAPTCHA",
    "path_traversal": "https://owasp.org/www-community/attacks/Path_Traversal",
    "ssrf": "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
    "xxe": "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_%28XXE%29_Processing",
    "webshell": "https://attack.mitre.org/techniques/T1505/003/",
    "ssti": "https://owasp.org/www-community/attacks/Server_Side_Template_Injection",
    "ldap_nosql_injection": "https://owasp.org/www-community/attacks/LDAP_Injection",
    "crlf_injection": "https://owasp.org/www-community/attacks/HTTP_Response_Splitting",
    "cve_vulnerability": "https://nvd.nist.gov/",
}


def category_of(text: str) -> Optional[str]:
    """从标题 / 标签 / msg 文案里推断攻击大类；无法判定返回 None（调用方应跳过该规则）。"""
    haystack = str(text or "").lower()
    if not haystack:
        return None
    for category, keywords in CATEGORY_KEYWORDS:
        for keyword in keywords:
            if keyword.strip() and keyword.strip() in haystack:
                return category
    return None


def remediation_of(category: str) -> str:
    return DEFAULT_REMEDIATION.get(category, "建议人工核对流量与主机日志后再决定处置动作。")


def references_of(category: str) -> List[str]:
    link = DEFAULT_REFERENCES.get(category)
    return [link] if link else []
