# 规则包（rulesets）

本目录是三个独立规则包，合计 **1371 条**。当前接入状态：

* **入侵包**：HTTP 部分已接入 Web 引擎，按 `RULES_TIERS` 分档（默认 core）；
* **研判包**：执行器已实现，`TRIAGE_ENABLED=true` 时在聚合前运行，默认关闭；
* **病毒包**：数据已就绪，文件扫描执行器属于后续批次，默认关闭。

| 文件 | 包 | 条数 | 匹配对象 | 当前状态 |
|---|---|---|---|---|
| `intrusion_rules.json` | 入侵检测 | 742 | HTTP 请求内容（633）/ 网络流（109） | HTTP 已接入；流级 109 条后续批次 |
| `triage_rules.json` | 研判 | 300 | 告警及其上下文 | 执行器已实现，默认关闭 |
| `malware_signatures.json` | 病毒特征 | 329 | 文件内容 / 进程命令行 | 数据就绪，扫描器后续批次 |
| `index.json` | 索引 | — | — | — |

> 接入代码：`backend/app/rules/packs.py`、`backend/app/detection/kb_factory.py`、
> `backend/app/analysis/triage.py`。类目先合并 taxonomy 再合并规则，未定义类别默认拒绝加载。

## 1. 入侵检测规则

### 1.1 字段

`http_text` 规则与现有 `web_attack_rules.json` 兼容，可直接被
`WebAttackKnowledgeBase._merge_external()` 消费（前提是类别已存在）：

```json
{
  "id": "INT-SQLI-016",
  "title": "MySQL 时间盲注：SLEEP",
  "category": "sql_injection",
  "severity": "critical",
  "cvss": 9.1,
  "confidence": "high",
  "mitre": "T1190",
  "match_targets": ["path", "query", "body", "header", "cookie"],
  "match_mode": "normalized",
  "patterns": ["sleep\\s*\\(\\s*\\d+\\s*\\)"],
  "threshold": {"count": 3, "window_sec": 60},
  "tier": "core",
  "enabled_by_default": true,
  "false_positive_hint": "",
  "description": "...",
  "remediation": "...",
  "references": ["..."]
}
```

`flow` 规则不使用正则，改用结构化条件，需要流级求值器：

```json
{
  "id": "INT-PROTO-001",
  "title": "TCP 扫描：SYN 半开",
  "category": "protocol_anomaly",
  "match_engine": "flow",
  "flow_condition": {"all": [
    {"field": "flow.syn_ratio", "op": ">=", "value": 0.9},
    {"field": "flow.synack_ratio", "op": "<=", "value": 0.2},
    {"field": "flow.dst_ports", "op": ">=", "value": 30}
  ]}
}
```

### 1.2 分层

`tier` 决定默认是否启用，是控制资源开销的主要手段：

- **core（89 条）**：高置信、低误报，建议默认开启；
- **extended（630 条）**：覆盖完整但需要按资产裁剪；
- **lab（23 条）**：`python-requests`、`curl`、`okhttp` 等通用 UA，以及 CSRF/OTP 这类
  低置信规则，**只能用于演练环境或与其它信号组合**。

### 1.3 类别

原有 17 类全部覆盖，新增 9 类（现有知识库未定义，合并前需扩展分类表）：
`scanner_fingerprint`、`recon_scan`、`deserialization`、`protocol_anomaly`、`ddos_flood`、
`dns_tunnel`、`crypto_mining`、`c2_beacon`、`api_abuse`。

`taxonomy[].maps_to_kb_category` 标明该类别能否被现有加载器识别。

## 2. 研判规则

输入不是请求，而是「告警 + 上下文」。每条规则是一组条件 + 一个结论：

```json
{
  "id": "TRI-0134",
  "name": "文件包含 + 敏感文件回显",
  "stage": "aggregate",
  "priority": 98,
  "when": {"all": [
    {"field": "rule.category", "op": "==", "value": "file_inclusion"},
    {"field": "http.status", "op": "==", "value": 200},
    {"field": "http.response_body", "op": "regex", "value": "root:[x*]?:0:0:"}
  ]},
  "verdict": "confirmed",
  "action": "confirm",
  "score_delta": 3.5,
  "reason": "响应中出现 /etc/passwd 内容，确认任意文件读取",
  "mitre": "T1005",
  "ttl_sec": 3600
}
```

- `verdict`：`benign`（误报）/ `suspicious`（降级）/ `escalate`（提级）/ `confirmed`（确认）；
- `action`：`suppress_alert` / `downgrade` / `escalate` / `confirm`；
- `score_delta`：对风险分的增减，正数提级、负数降噪；
- `priority`：同一告警多条规则命中时的执行顺序，大者优先；
- 支持的算子：`== != > >= < <= in not_in contains regex exists not_exists`。

可用上下文域见 `triage_rules.json` 的 `context_fields`（rule / http / src / dst / asset /
history / time / intel / flow / tls / dns / host / process / file）。

## 3. 病毒特征

YARA 子集语义，不依赖 libyara：

```json
{
  "id": "MAL-0001",
  "family": "China Chopper",
  "malware_type": "webshell",
  "platform": "php",
  "severity": "critical",
  "strings": [
    {"type": "text", "value": "eval($_POST[", "modifiers": ["nocase", "ascii"]},
    {"type": "text", "value": "$_POST['z0'", "modifiers": ["nocase", "ascii"]}
  ],
  "condition": "any",
  "file_types": [".php"],
  "mitre": "T1505.003",
  "hash": null
}
```

- `condition`：`any` / `all` / `2_of`；
- `strings[].type`：`text` / `hex` / `regex`；
- `file_types` 为空表示不限，建议按扩展名先过滤再扫描内容。

**关于哈希**：`hash` 字段一律为 `null`。不内置未经验证的 MD5/SHA256——哈希必须来自
样本或情报源，凭记忆填写会造成误删合法文件。接入时由 MISP / VT 导出填充。

## 4. 质量状态

- 全部正则已通过 `re.compile` 校验；ID 唯一；每个类别都有元数据。
- 与现有 63 条基线规则的**正则重复仅 7 条**（870 条中的 0.8%），不会造成大面积重复告警。
- 未在真实流量上标定误报率。上线前必须按第 5 节做影子运行。
- 病毒特征基于公开家族的字符串与扩展名特征，**需用真实样本回归**后再启用。
- 生成器与校验脚本位于 `.workbuddy/rulegen/`（不在应用代码路径内）。

## 5. 建议的上线顺序

1. 只启用 `tier=core` 的 89 条，影子模式（只记录不封禁）运行 1–2 周；
2. 按 `false_positive_hint` 与研判规则调优，把误报规则降到 `lab`；
3. 按资产类型增量启用 `extended`（Web 服务器先开注入/文件类，网关先开扫描/协议类）；
4. 病毒特征只对上传目录与落地文件启用，先跑 `file_types` 过滤。
