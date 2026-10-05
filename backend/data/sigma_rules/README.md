# Sigma 规则目录（`backend/data/sigma_rules/`）

把 Sigma 规则（`*.yml` / `*.yaml`）放进本目录即可被加载，**无需改代码**：

* **加载方式**：`app/rules/sigma_loader.py` 解析 → 转换为统一 `Rule` → 与内置知识库
  （`web_attack_rules.json`）合并参与检测；
* **生效时机**：重启服务，或 `POST /api/v1/rules/reload`（也可等 `RULE_RELOAD_INTERVAL_SEC`，默认 300s）；
* **查看结果**：`GET /api/v1/rules/sources` 的 `sigma` 行（规则数 / HTTP 侧可用数 / 直达数）。

## 筛选策略（只加载"能在流量侧匹配"的规则）

| 情况 | 处理 |
| --- | --- |
| `logsource.category` ∈ {webserver, proxy, http, web, waf, ids}，或 `product` ∈ {apache, nginx, iis, tomcat, java, php…} | 加载 |
| `detection` 字段能映射到 HTTP 字段（见下表） | 加载（即使 logsource 未声明） |
| 进程创建 / 注册表 / 文件系统 / Windows 事件日志（`process_creation`、`registry_*`、`file_event`、`sysmon`…） | **跳过并计数**（不在本系统的匹配能力范围内） |
| 条件表达式超出支持范围（如 `selection1 and selection2 or 1 of filter*`） | 跳过 |
| 值修饰符无法等价表达（`base64`、`base64offset`、`windash`、`cidr`、`gt/lt`…） | 跳过 |
| 标题/描述/标签无法映射到内置 17 个攻击大类 | 跳过（避免污染告警统计） |

## 字段与修饰符映射

| Sigma 字段 | 本系统匹配目标 |
| --- | --- |
| `cs-uri-query` / `c-uri-query` / `cs-uri` | `query` |
| `cs-uri-stem` / `c-uri` / `uri` / `request-uri` | `path` |
| `cs-body` | `body` |
| `cs-user-agent` / `c-useragent` | `user_agent` |
| `cs-referer` | `referer` |
| `cs-cookie` | `cookie` |
| `cs-header` | `header`（写在 `filter` 里时 → `require_absent`） |
| `cs-uri-extension` | `filename` |
| `cs-method` | `method_in`（方法白名单） |
| `sc-status` | `status_in`（响应码白名单，用于 401/403 类频次规则） |

支持的修饰符：`contains`（默认，等价"包含"语义）、`startswith`、`endswith`、`re`、`all`。
语义还原：同一 selection 内多个字段是 **AND**（映射为 `match_all=True`）；列表值之间是 **OR**；
`|all` 表示该字段的多个值全部命中（同样映射为 `match_all=True`）。
**请避免写 "字段A AND (字段B1 OR 字段B2)" 这种混合结构 —— 请拆成两条规则。**

## 目录内容

* `web_exploitation.yml` —— 示例集（Log4Shell、SQL 联合查询、Webshell 访问、XXE、目录穿越），
  条目参考 [SigmaHQ](https://github.com/SigmaHQ/sigma) `rules/web/` 目录改写并补充中文说明；
  建议按需从上游同步，保留原始 `author` 与 `references` 以便合规引用。
