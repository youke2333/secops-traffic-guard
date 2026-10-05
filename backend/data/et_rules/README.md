# Suricata / ET Open 规则目录（`backend/data/et_rules/`）

把 Suricata（或 ET Open）规则文件（`*.rules` / `*.txt`）放进本目录即可被加载，**无需改代码**：

* **加载方式**：`app/rules/et_loader.py` 逐行解析 `alert` 动作行 → 转换为统一 `Rule` →
  与内置知识库合并参与检测；
* **生效时机**：重启服务，或 `POST /api/v1/rules/reload`（也可等 `RULE_RELOAD_INTERVAL_SEC`，默认 300s）；
* **查看结果**：`GET /api/v1/rules/sources` 的 `et` 行（规则数 / HTTP 侧可用数 / 直达数）。

## 筛选策略

| 情况 | 处理 |
| --- | --- |
| `alert` 动作 + `http` 协议 + 入向（`->` / `<>`） | 加载 |
| 非 `alert`（`drop`/`pass`/`reject`）或非 `http`（如 `dns`、`tls`） | 跳过 |
| 响应方向（`flow:...to_client`、`from_server`） | 跳过（本系统只检测入向请求） |
| content 含十六进制字节块（如 `\|0a 0d\|`）、`content\|base64_decode`、`byte_test`/`byte_jump` 等 | 跳过该 content；若整条规则无可用 content/pcre 则整条跳过 |
| `msg`/`classtype` 无法映射到内置 17 个攻击大类 | 跳过 |

## 关键字与映射

| Suricata 关键字 | 本系统处理 |
| --- | --- |
| `msg` | 规则标题（同时参与攻击大类映射） |
| `content` + `http_uri` | 匹配目标 `any`（覆盖请求行 + path + query） |
| `content` + `http_client_body` | 匹配目标 `body` |
| `content` + `http_header` / `http_host` | 匹配目标 `header` |
| `content` + `http_cookie` / `http_user_agent` / `http_referer` | 对应字段 |
| `pcre:"/re/im"` | 转为正则（含 `U`/`R`/`B` 等无法等价表达的 flag 时跳过） |
| `flow` | 仅用于方向判定（`to_server` 保留） |
| `classtype` | 严重度映射（`web-application-attack` → high，`shellcode-detect`/`trojan-activity` → critical…） |
| `threshold: type …, count N, seconds S` | 转为知识库的 `threshold = {window_sec: S, count: N}` |
| `reference:url,…` | 转为规则参考链接（用于前端「修复建议/参考」） |

语义说明：**多个 content 之间是 AND**（全部命中才算命中）；`nocase` 无需处理（本系统正则默认不区分大小写）。

## 目录内容

* `web_attack.rules` —— 示例集（SQL 注入、PHP Webshell、命令注入、目录穿越、Log4Shell、LDAP 注入、
  一条响应方向规则用于演示"被跳过"）。
  **SID 使用私有段 9000001+**：示例参考 ET Open 公开签名（如
  "ET WEB_SERVER Possible SQL Injection Attempt"）改写而来；生产接入请从
  <https://rules.emergingthreats.net/> 拉取官方规则集并保留其原始 SID 与引用信息。
