# 智能流量安全检测与分析系统

资源占用可控、可本地化部署的**流量安全监控与自动化响应平台**：实时大屏监控、异常端口流量检测、
风险 IP 自动封禁、威胁告警证据留存、安全事件报告、漏洞提醒与修复建议、动态资产台账，
采用 FastAPI + 原生 JS/ECharts，单机即可跑起来（`docker compose up -d` 或裸机脚本二选一）。

> 前端为深蓝科技风大屏：真实后端驱动 + 实时 SSE 推送，后端不可用时自动降级为演示数据模式。

**目录**：[1 项目速览](#1-项目速览) · [2 目录结构](#2-目录结构) · [3 技术架构](#3-技术架构) ·
[4 快速开始](#4-快速开始本地开发3-条命令) · [5 业务站点部署](#5-vmware-ubuntu--apache-web-业务站点8080部署) ·
[6 容器化部署](#6-容器化部署) · [7 环境配置与依赖清单](#7-环境配置与依赖清单) · [8 安全默认值](#8-安全默认值重要) ·
[9 Web 攻击知识库](#9-web-攻击检测知识库http-侧) · [10 规则来源层](#10-规则来源层内置知识库--开源规则库) ·
[11 AI 技术方案](#11-ai-技术方案选型--集成--优化) · [12 评分与研判](#12-评分--直达--自适应阈值--ai-研判v2-新增能力一览) ·
[13 创新点](#13-创新点说明) · [14 测试](#14-测试) · [15 文档](#15-文档) ·
[16 页面导航与在线演示](#16-页面导航与在线演示) · [17 落地边界](#17-v6-落地范围与边界) ·
[18 云端协同](#18-云端协同workbuddy-云服务)

---

## 1. 项目速览

**一句话定位**：把「流量采集 → 规则 / 统计 / 机器学习检测 → 聚合研判 → 自动处置 → 证据留存」这条
安全运营闭环，做成一套**单机可跑、资源占用可控、可本地化部署**的 Web 系统；
AI 只提供**可追溯的研判建议**，不接管处置判定 —— 避免模型幻觉直接改写防火墙规则。

| 维度 | 实测数据（可现场复核） |
| --- | --- |
| 代码规模 | 后端 84 个 Python 模块（`backend/app`）、大屏 15 个 JS 模块 + 11 个页面 |
| 接口规模 | 83 个 REST / SSE 接口，OpenAPI 文档由 `/docs` 实时生成 |
| 规则能力 | Web 攻击知识库 **171 条 / 21 大类**（对齐 OWASP Top 10）+ 入侵包 742 条 + 研判包 300 条 + 病毒特征 329 条；统一 `RulePlan` 预编译 436 条正则（实测构建 59.9 ms） |
| 检测算法 | EWMA + 稳健 Z-score（MAD）统计基线、Isolation Forest 多维离群确认、滑动窗口加权聚合评分 |
| 测试 | `pytest` **226 个用例全部通过**；`verify_runtime.py` 83 项端到端断言；`verify_layout.js` 128 项观感/布局断言 |
| 响应延迟 | 直达告警「投递 → SSE 收到」实测 **156 / 158 / 177 ms**（min/中位/max，设计目标 < 2 s） |
| 部署形态 | Docker Compose 一键（PostgreSQL + InfluxDB + API + nginx）或裸机 `systemd` 脚本 |

### 1.1 参赛与团队信息

> 以下信息请按实际填写后再提交（占位符形如 `【】`）。

| 项 | 内容 |
| --- | --- |
| 赛事 | 第九届传智杯 · AI WEB 网页开发挑战赛 |
| 作品名称 | 智能流量安全检测与分析系统（SecOps Traffic Guard） |
| 团队名称 | 【团队名称】 |
| 参赛成员 | 【成员1（队长）/ 成员2 / 成员3】 |
| 所在院校 | 【学校 / 学院】 |
| 指导教师 | 【指导教师】 |
| 代码仓库 | 【GitHub / Gitee 公开仓库地址】 |
| 在线演示 | <https://secops-traffic-guard.app.workbuddy.host/?sharecode=I55BLJHGXB>（见第 16 章） |
| 演示视频 | 【视频链接】（5~8 分钟，1080p，普通话讲解） |
| 技术文档 | `提交材料/智能流量安全检测与分析系统-技术文档.pdf`（PDF，≤30 页） |

### 1.2 提交材料索引

| 大赛要求 | 本项目对应位置 |
| --- | --- |
| 代码仓库（托管 / 规范 / README / Git 记录 / 环境配置） | 本仓库根目录；README 即本文档；`.env` 模板见 `backend/.env.example`、`deploy/env.web.example` |
| 演示视频（5~8 分钟） | 见 `提交材料/演示视频脚本.md` 分镜脚本 |
| 技术文档（PDF ≤30 页） | `提交材料/智能流量安全检测与分析系统-技术文档.pdf` |
| 在线演示（可选） | 见第 16 章；演示地址与访问方式见 16.1 / 16.2 |
| 提交自查 | `提交材料/提交自查清单.md`（逐条对照大赛要求 + 自检命令与结果） |

---

## 2. 目录结构

```
xm/
├── backend/                        # 后端：采集 → 检测 → 响应 → API
│   ├── app/
│   │   ├── config.py               # 全部可调参数（环境变量 / .env）
│   │   ├── database.py models.py   # ORM（资产/告警/封禁/漏洞/用户/会话/威胁事件/报告）
│   │   ├── auth/                   # 登录、服务端会话、CSRF、审计（v6 P0）
│   │   ├── threat/                 # 威胁事件落库、标签、留存清理（v6 P1）
│   │   ├── reports/                # 封禁证据报告（自包含 HTML）（v6 P1）
│   │   ├── schemas.py              # Pydantic 出参/入参契约
│   │   ├── bus.py                  # 进程内事件总线（采集线程 → SSE）
│   │   ├── main.py                 # FastAPI 入口（挂载 API + 大屏静态目录）
│   │   ├── collector/              # 采集层：eBPF / scapy / 仿真 + 滑动窗口 + InfluxDB 写入
│   │   ├── detection/              # 检测层：EWMA/MAD-Z-score + Isolation Forest
│   │   ├── response/               # 响应层：防火墙适配 + 白名单 + 封禁编排（TTL 自动解封）
│   │   ├── alerting/               # 告警层：钉钉/企微/通用 Webhook、邮件、Syslog
│   │   ├── scanner/                # 资产层：nmap/banner 指纹 + CVE 知识库 + Web 应用漏扫（webapp.py）
│   │   └── api/                    # REST + SSE 接口（含 /web/*、/rules/*、/ai/*）
│   ├── data/cve_rules.json         # 可维护的 CVE 知识库（18 条内置规则）
│   ├── data/web_attack_rules.json  # Web 攻击检测知识库（17 大类 / 63 条规则，覆盖 OWASP Top 10 与通用攻击类型）
│   ├── data/cve_rules_extended.json# 扩展 CVE 知识库（由开源签名库转换，与内置合并，同编号以扩展为准）
│   ├── data/sigma_rules/*.yml      # Sigma 规则（只保留可在流量侧匹配的条目，加载期自动转换）
│   ├── data/et_rules/*.rules       # Suricata / ET Open 规则（同上）
│   ├── data/web_strict_rules.json  # 高置信直达规则（只看载荷，不限路径/产品，用于自动封禁判定）
│   ├── data/rulesets/              # v6 规则包：入侵 742 / 研判 300 / 病毒 329（默认只装 core HTTP）
│   ├── app/rules/                  # 统一规则加载层（native / sigma / et / cve_ext / rulesets → 统一 Schema）
│   ├── app/detection/matcher/      # RulePlan 预编译 + 可选 RE2 多模式预筛（v6 P2）
│   ├── app/analysis/               # AI 研判、研判规则执行器与降级链、攻击流量→漏洞研判（web_vuln_infer.py）
│   ├── tests/                      # pytest 单测/集成测试（226 个用例）
│   ├── Dockerfile
│   └── .env.example                # 全部环境变量说明
├── dashboard/                      # 大屏与模块页面（纯静态，可独立打开）
│   ├── login.html                  #   登录与首次改密（v6 P0）
│   ├── index.html                  #   监控大屏（总览）
│   ├── traffic.html                #   流量监控
│   ├── threat.html                 #   威胁告警（证据 / 标签 / 导出，v6 P1）
│   ├── block.html                  #   封禁管理 + 安全事件报告（v6 P1）
│   ├── anomaly.html                #   异常端口与阈值信号
│   ├── rules.html                  #   规则包 / 档位 / 匹配引擎（v6 P2）
│   ├── response.html               #   兼容旧链接：自动跳转 block.html
│   ├── vuln.html                   #   漏洞提醒
│   ├── asset.html                  #   资产管理
│   ├── css/dashboard.css
│   ├── js/api.js                   #   数据层：SSE + 轮询 + 演示模式自动降级
│   ├── js/mock.js                  #   演示数据源（后端未启动时接管全部接口，含处置动作）
│   ├── js/ui.js                    #   共享 UI 工具：导航/格式化/抽屉/CSV 导出
│   ├── js/dashboard.js             #   大屏渲染层
│   ├── js/page-*.js                #   各模块页面的渲染与处置逻辑
│   └── img/ lib/                   #   背景图与 ECharts
├── deploy/
│   ├── docker-compose.yml          # 一键部署：PostgreSQL + InfluxDB + 后端 + nginx 大屏
│   ├── docker-compose.host.yml     # 覆盖文件：host 网络 + NET_ADMIN（真抓包/真封禁）
│   ├── nginx/nginx.conf            # 大屏托管 + API 反代（SSE 关闭缓冲）
│   ├── env.web.example             # 单机 Web 业务（Apache 8080）推荐配置
│   └── install.sh                  # 裸机安装脚本（systemd + setcap；--web-profile 用业务模板）
├── scripts/
│   ├── verify_runtime.py           # 端到端验证：真实 uvicorn + REST + SSE + 封禁闭环 + 全部页面
│   ├── verify_layout.js            # 观感/布局自动检查：真实执行页面脚本 + 结构与样式断言
│   ├── verify_web_scan.py          # 通用漏扫离线自检（靶场式站点应命中、加固站点应零误报）
│   ├── web_healthcheck.sh          # Apache/8080/日志/服务 部署预检（通用）
│   ├── web_attack_test.sh          # 通用攻击序列（含 --normal-only 误报复核）
│   ├── http_proxy.py               # 高保真接入代理（8080→8081，完整请求投递；--http-proxy 自动部署）
│   ├── reset-attack-data.sh        # 清理测试期攻击数据（保留账号/白名单/资产/规则库）
│   ├── verify_time.py              # 时间口径自检：库内 UTC/本地时间换算是否正确
│   └── migrate_v2.py               # 旧库升级到 v2（幂等，只补列不删列）
├── data/                           # 运行期 SQLite（告警/封禁/资产/漏洞），首次启动自动创建
└── docs/                           # 架构指南 / 系统使用说明 / 部署操作手册
```

---

## 3. 技术架构

### 3.1 分层结构

```
┌──────────────────────────────────────────────────────────────────────┐
│  展示层  dashboard/  原生 JS + ECharts 大屏（10 个页面）              │
│          SSE 实时推送 → 断线自动轮询 → 后端不可用降级演示数据          │
├──────────────────────────────────────────────────────────────────────┤
│  接口层  backend/app/api/   83 个 REST + 2 个 SSE 流                  │
│          会话/CSRF/API Token 双鉴权 · Pydantic 出入参契约             │
├──────────────────────────────────────────────────────────────────────┤
│  分析层  analysis/    AI 研判（LLM → 本地规则 → 模板 → 待人工）        │
│          detection/   EWMA + MAD-Z-score · Isolation Forest · 评分聚合 │
│          rules/       统一规则层：native/Sigma/ET/CVE/CVE 扩展 → RulePlan│
├──────────────────────────────────────────────────────────────────────┤
│  响应层  response/    五道闸门（白名单→级别→TTL→DRY_RUN→防火墙适配）   │
│          alerting/    钉钉 / 企微 / Webhook / 邮件 / Syslog            │
│          threat/      威胁事件落库 + 标签 + 留存清理                   │
├──────────────────────────────────────────────────────────────────────┤
│  采集层  collector/   eBPF → scapy → 仿真（三级自动降级）              │
│                      滑动窗口聚合 · 500 ms tick · InfluxDB 可选写入    │
├──────────────────────────────────────────────────────────────────────┤
│  存储层  SQLite / PostgreSQL（告警、封禁、资产、漏洞、用户、审计）      │
│          InfluxDB（时序指标，可关） · 本地 JSON（规则知识库）           │
└──────────────────────────────────────────────────────────────────────┘
```

**一次攻击的完整链路（以 SQL 注入为例）**：
`采集` 抓到 `POST /login` 请求体 → `归一化`（多轮 URL 解码 + HTML 实体 + 注释折叠）→
`规则匹配` 命中 `WEB-SQLI-*`（权重 = 严重度 × 置信度）→ `评分聚合` 300 s 窗口累计风险分 →
`AI 研判` 输出 confirm/dismiss + 来源 → `响应` 判定是否达自动封禁门槛 →
`告警` 推送到钉钉/企微 + SSE 推送大屏 → `留存` 落库为威胁事件并生成九章 HTML 报告。

### 3.2 技术选型与理由

| 层 | 选型 | 为什么不用别的 |
| --- | --- | --- |
| Web 框架 | FastAPI + Uvicorn | 原生 async 可直接扛 SSE 长连接；Pydantic 自动生成接口契约与 `/docs`，评审可直接点开验证 |
| 前端 | 原生 JS + ECharts，无构建链 | 大屏要求「打开就能看」，不引入 Node 构建步骤，降低部署与评审成本；`verify_layout.js` 仍可在 Node 里跑断言 |
| 采集 | eBPF → scapy → 仿真 三级降级 | 生产用 eBPF（低开销），无权限用 scapy，Windows/演示用仿真 —— 保证**任何环境都能跑通全链路** |
| 统计检测 | EWMA + 稳健 Z-score(MAD) | 均值/标准差会被攻击流量本身污染，MAD 更抗离群点 |
| 机器学习 | Isolation Forest（scikit-learn） | 无监督、无需标注、单机毫秒级；缺失时自动降级为纯统计，不阻断主流程 |
| 规则引擎 | 自研统一 RulePlan（native/Sigma/ET/CVE 同构） | 直接对接开源规则生态（ET Open、Sigma），避免只依赖自建知识库；可选 RE2 多模式预筛 |
| 存储 | SQLAlchemy + SQLite / PostgreSQL | 单机零依赖启动，需要并发时切 PG 只改 `DB_URL` 一个变量 |
| 大模型 | DeepSeek V4-Flash（OpenAI 兼容） | 中文安全语料表现好、延迟低、单价低；接口兼容意味着**换成任何 OpenAI 兼容服务只改 `LLM_BASE_URL`** |

### 3.3 三条刻意的设计红线

1. **AI 不碰处置权**：研判结论只影响告警展示与排序，自动封禁门槛始终由 `AUTO_BLOCK_*` 决定，
   杜绝「模型说封就封」导致的误封生产。
2. **降级必须可见**：每一级降级都写入 `source` 与 `degraded=True`，前端显示「来源 local_rules（已降级）」，
   不允许把兜底结果伪装成模型输出。
3. **只发摘要不出网**：Prompt 只包含结构化字段（评分、规则 ID、类别、证据键值），
   原始 payload / URL / UA / Cookie 一律不发送，内网 IP 默认脱敏。

---

## 4. 快速开始（本地开发，3 条命令）

```bash
# 1) 安装依赖
python -m venv .venv
.venv/Scripts/python -m pip install -r backend/requirements.txt      # Windows
# source .venv/bin/activate && pip install -r backend/requirements.txt  # Linux/macOS

# 2) 启动后端（Windows 无抓包能力时自动降级为仿真流量）
.venv/Scripts/python -m uvicorn app.main:app --app-dir backend --port 8000
#    托管环境（只注入 PORT 变量）可用等价入口：
#    PORT=8080 python serve.py

# 3) 打开大屏
#    http://127.0.0.1:8000/          ← 首次访问会跳转 /login.html
#    http://127.0.0.1:8000/docs      ← OpenAPI 交互文档
```

* **首次登录**：默认 `AUTH_ENABLED=true`。`ADMIN_INITIAL_PASSWORD` 留空时，首次启动会生成一次性
  随机密码并打印到启动日志（`journalctl -u secops-traffic-guard | grep 一次性密码`），
  登录后强制改密。仅本地演示可临时设置 `AUTH_ENABLED=false`（不推荐）。
* 只想看大屏效果：直接用浏览器打开 `dashboard/index.html` 即可 —— 检测不到后端时会自动
  切换为**演示数据模式**（右上角标注「演示数据」），并周期性模拟端口扫描/暴破/突发流量等剧本。
* 需要真实抓包与封禁：Linux 下以 root 运行，或执行
  `sudo setcap cap_net_raw,cap_net_admin+eip $(readlink -f $(which python3))`。

## 5. VMware Ubuntu + Apache Web 业务站点（8080）部署

完整步骤见 [`docs/部署操作手册.md`](docs/部署操作手册.md)（第 7 章「接入被测 Web 业务站点」），最短路径：

```bash
# Ubuntu 虚拟机内（业务站点已运行在 8080）
cp deploy/env.web.example .env
vi .env            # 修改 CAPTURE_IFACE、WHITELIST_CIDRS；首次保持 DRY_RUN=true
sudo bash deploy/install.sh --web-profile
bash scripts/web_healthcheck.sh          # Apache/8080/日志/服务 预检

# 需要检出命令注入/文件上传（POST body）时改用高保真模式：
# sudo bash deploy/install.sh --http-proxy   # 代理占 8080，Apache 退到 8081，完整请求投递
# 安装脚本会在 API_TOKEN 为空时自动生成；手动启动代理时必须传 --token 或设置 API_TOKEN
```

从**另一台机器**验证检测与封禁：

```bash
bash scripts/web_attack_test.sh --target http://<Ubuntu-IP>:8080/ --normal-only
bash scripts/web_attack_test.sh --target http://<Ubuntu-IP>:8080/
```

* 正常流量不产生 `web_*` 告警；攻击流量产生直达告警并在 `DRY_RUN=false` 时自动 iptables 封禁；
* 漏洞页输入 站点地址点「Web 漏扫」，可得到 `WEB-001/005/009...` 与 Apache/PHP CVE；
* AI 研判与修复建议在 `LLM_API_KEY` 配置后走真实模型，未配置时自动降级且标注来源。

## 6. 容器化部署

```bash
cd deploy
cp ../backend/.env.example .env      # 按需修改：DRY_RUN、告警通道、白名单…
docker compose up -d --build
# 大屏: http://<服务器IP>:8080/dashboard/    API: http://<服务器IP>:8080/docs
# 首次密码：未设置 ADMIN_INITIAL_PASSWORD 时，docker compose logs api | grep 一次性密码
```

需要「抓宿主机全部流量 + 真实下发防火墙规则」时叠加覆盖文件：

```bash
docker compose -f docker-compose.yml -f docker-compose.host.yml up -d --build
```

## 7. 环境配置与依赖清单

### 7.1 运行环境

| 项 | 要求 | 说明 |
| --- | --- | --- |
| Python | 3.10 ~ 3.12（开发环境 3.11 / 3.13 均已验证） | 后端运行时 |
| 操作系统 | Windows / Linux（Ubuntu 20.04+）/ macOS | Linux 下才有真实抓包与 iptables/nftables 封禁 |
| 数据库 | 默认 SQLite（零配置）；生产建议 PostgreSQL 14+ | 只改 `DB_URL` |
| 时序库 | InfluxDB 2.x（**可选**，不配则只存内存趋势） | `INFLUX_URL` 为空即关闭 |
| 浏览器 | Chrome / Edge 最新版 | 大屏与 ECharts |
| Node.js | ≥ 18（**仅**用于跑 `scripts/verify_layout.js` 观感断言） | 非运行时依赖 |

### 7.2 依赖清单（`backend/requirements.txt`，共 12 项）

| 依赖 | 版本约束 | 用途 | 缺失时行为 |
| --- | --- | --- | --- |
| `fastapi` | ≥0.111,<1.0 | Web 框架、OpenAPI 文档 | 必需 |
| `uvicorn[standard]` | ≥0.30 | ASGI 服务器（含 SSE 所需依赖） | 必需 |
| `pydantic` / `pydantic-settings` | ≥2.7 / ≥2.3 | 出入参契约 + `.env` 配置加载 | 必需 |
| `SQLAlchemy` | ≥2.0.30 | ORM | 必需 |
| `psycopg2-binary` | ≥2.9.9 | PostgreSQL 驱动（仅非 Windows 安装） | 用 SQLite 时不需要 |
| `numpy` | ≥1.26 | 统计基线 / EWMA 计算 | 必需 |
| `scapy` | ≥2.6.0 | 用户态抓包兜底 | 缺失则只能用 eBPF 或仿真 |
| `scikit-learn` | ≥1.4 | Isolation Forest 离群确认 | **自动降级**为纯统计模型 |
| `pyyaml` | ≥6.0 | Sigma 规则解析 | **自动跳过** Sigma 来源 |
| `httpx` | ≥0.27 | 告警外呼 + AI 研判 HTTP 客户端 | AI 与 Webhook 不可用 |
| `pytest` | ≥8.2 | 测试 | 仅开发 |
| `google-re2` | 可选（默认注释） | 多模式预筛加速 | **自动回落** python 匹配后端 |

> **设计原则**：除前 4 项外，所有依赖缺失都会触发**降级而不是崩溃**，这是它能"在任何机器上跑起来"的前提。

### 7.3 环境变量模板（136 个变量 / 18 个分组）

模板文件：[`backend/.env.example`](backend/.env.example)（逐项中文注释，含取值范围与安全性说明）；
Web 业务站点场景用 [`deploy/env.web.example`](deploy/env.web.example)。

```bash
cp backend/.env.example .env      # 按需修改；.env 已在 .gitignore 中，永远不会入库
```

| 分组 | 关键变量 | 默认值 / 提示 |
| --- | --- | --- |
| 基础 | `DEBUG` `API_TOKEN` `CORS_ORIGINS` `DASHBOARD_DIR` | `API_TOKEN` 为空时仅浏览器会话鉴权 |
| 存储 | `DB_URL` `INFLUX_URL` `INFLUX_TOKEN` `INFLUX_ORG` `INFLUX_BUCKET` | `sqlite:///./data/secops.db` |
| 采集 | `CAPTURE_MODE` `CAPTURE_IFACE` `BPF_FILTER` `TICK_INTERVAL_MS` | `auto` 自动挑 eBPF/scapy/仿真；tick 500 ms |
| 检测参数 | `ZSCORE_THRESHOLD` `PORT_SCAN_UNIQUE_PORTS` `BRUTE_FORCE_ATTEMPTS` `IFOREST_ENABLED` | 3.5 / 60 / 40 / true |
| 响应 | `AUTO_BLOCK_ENABLED` `AUTO_BLOCK_MIN_SEVERITY` `BLOCK_TTL_SEC` `DRY_RUN` `WHITELIST_CIDRS` | **`DRY_RUN=true`** 只记录不真封 |
| 告警通道 | `ALERT_CHANNELS` `DINGTALK_WEBHOOK` `WECOM_WEBHOOK` `SMTP_*` | 默认 `log` |
| 规则层 | `RULES_TIERS` `RULES_SHADOW_MODE` `MATCH_BACKEND` `RULE_RELOAD_INTERVAL_SEC` | `core` / false / auto / 300 s |
| 评分与直达 | `ALERT_SCORE_THRESHOLD` `SCORING_WINDOW_SEC` `DIRECT_ALERT_*` | 6.0 / 300 s / 开启 |
| 自适应阈值 | `ADAPTIVE_THRESHOLD_ENABLED` `THRESHOLD_*` | 开启，幅度限制 0.5~2.0 倍 |
| **AI 研判** | `LLM_ENABLED` `LLM_API_KEY` `LLM_BASE_URL` `LLM_MODEL` `LLM_TIMEOUT_SEC` `LLM_MASK_INTERNAL_IP` | Key 留空=自动降级；超时 3 s；脱敏默认开 |
| 扫描与 CVE | `SCANNER_ENABLED` `NMAP_PATH` `SCAN_TARGETS` | nmap 缺失时自动跳过主动扫描 |
| Web 攻击检测 | `WEB_DETECT_SOURCE` `WEB_LOG_PATH` `WEB_*_RULES_FILE` | `demo` / `log` / `api` 三选一 |
| 流量→漏洞研判 | `WEB_VULN_INFER_ENABLED` `WEB_VULN_INFER_AI` | 开启；AI 复核可关 |
| 登录与会话 | `AUTH_ENABLED` `ADMIN_INITIAL_PASSWORD` `SESSION_TTL_SEC` `LOGIN_MAX_FAILS` | 首启生成一次性密码并强制改密 |
| 威胁事件与报告 | `THREAT_STORE_ENABLED` `THREAT_RETENTION_DAYS` `THREAT_MASK_SECRETS` | 留存 7 天，自动脱敏密钥 |
| 规则包与引擎 | `RULESETS_ENABLED` `RULES_MAX_COUNT` `TRIAGE_ENABLED` `FLOW_RULES_ENABLED` | 只装 core HTTP 规则 |

### 7.4 密钥与敏感信息处理（大赛合规项）

* `LLM_API_KEY`、`DINGTALK_WEBHOOK`、`WECOM_WEBHOOK`、`SMTP_PASSWORD`、`INFLUX_TOKEN` **全部通过环境变量注入**，
  仓库里只保留 `.env.example` 中的空值占位；
* `.gitignore` 已排除 `.env`、`data/`、`*.db`、`*.log`、`.venv/`；
* 提交前可执行一次自检：

```bash
git grep -nE "sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}" -- . || echo "未发现明文密钥"
git ls-files | grep -E "(^|/)\.env$" && echo "⚠️ .env 被误提交" || echo "OK：.env 未入库"
```

---

## 8. 安全默认值（重要）

| 配置 | 默认值 | 说明 |
| --- | --- | --- |
| `DRY_RUN` | `true` | 只记录封禁动作、不真正改内核防火墙；验证无误后再改 `false` |
| `AUTO_BLOCK_ENABLED` | `true` | 仅当严重级别 ≥ `AUTO_BLOCK_MIN_SEVERITY`（默认 high）才自动封禁 |
| `BLOCK_TTL_SEC` | `1800` | 每条封禁 30 分钟自动解除，避免一次误判造成永久断网 |
| `WHITELIST_CIDRS` | 回环/组播/链路本地 | 封禁前的最后一道闸门，支持 API 动态维护 |
| `AUTH_ENABLED` | `true` | 全站登录；未登录 API 返回 401、页面跳登录。`false` 仅限内网应急 |
| `ADMIN_INITIAL_PASSWORD` | 空 | 留空=首启生成一次性随机密码（日志可见），登录后强制改密 |
| `API_TOKEN` | 空 | 机器调用令牌（WAF/代理投递、脚本）；浏览器使用会话 + CSRF，两者其一即可 |
| `THREAT_STORE_ENABLED` | `true` | 每次规则命中落库（含被聚合抑制的），默认留存 7 天 |
| `RULES_TIERS` | `core` | 规则包档位；extended 未标定前不建议生产开启，lab 仅演练 |
| `RULES_SHADOW_MODE` | `false` | 影子模式：只记录威胁事件，不告警、不封禁（误报标定用） |
| `MATCH_BACKEND` | `auto` | 优先 RE2，未安装自动回落 python；切换只影响候选，不改变判定 |
| `DIRECT_ALERT_ENABLED` | `true` | 直达机制开关：单条致命规则命中（权重 ≥ 6.0）立即告警；关闭后全部走聚合投票 |
| `ALERT_SCORE_THRESHOLD` | `6.0` | 滑动窗口聚合风险分阈值（**只影响告警展示与排序，不改变自动封禁门槛**） |
| `ADAPTIVE_THRESHOLD_ENABLED` | `true` | 自适应阈值开关：只调整统计检测阈值，**不参与直达机制** |
| `LLM_ENABLED` | `true` | AI 研判开关；**未配置 `LLM_API_KEY` 时自动降级**，行为与关闭等价 |
| `LLM_API_KEY` | 空 | DeepSeek（或任意 OpenAI 兼容接口）密钥；留空 = 直接走本地规则/模板 |
| `LLM_MASK_INTERNAL_IP` | `true` | 发送给 LLM 前对内网 IP 脱敏，且**只发结构化摘要、不发原始 payload/URL** |

> 所有新增能力都有环境变量开关，任一关闭时系统行为回落到原版本（只增不删，可随时回滚）。

## 9. Web 攻击检测知识库（HTTP 侧）

CVE 知识库回答「主机/服务存在哪些已知漏洞」，本知识库回答「**正在发生什么 Web 攻击**」：

| 项 | 说明 |
| --- | --- |
| 知识库文件 | `backend/data/web_attack_rules.json`（17 大类 / 63 条规则，字段说明见文件内 `field_help`） |
| 覆盖大类 | SQL 注入、SQL 盲注、反射/存储型 XSS、命令注入、文件包含(LFI/RFI)、恶意文件上传、暴力破解、CSRF、不安全验证码、目录穿越、SSRF、XXE、Webshell、SSTI、LDAP/NoSQL 注入、CRLF 注入（对齐 Web 业务站点模块与 OWASP Top 10） |
| 规则字段 | `patterns`（正则，支持排除/全匹配）、`match_targets`（path/query/body/header/cookie/filename）、`match_mode`（归一化/原始）、`threshold`（窗口内次数）、`exclude_patterns`（误报抑制）、`confidence`、`cvss`、`remediation` 等 |
| 归一化 | 多轮 URL 解码（含 `%uXXXX`）→ HTML 实体解码 → SQL 注释转空格 → 空白折叠 → 转小写；专门覆盖 `%2527`、`union/**/select`、`&lt;script&gt;` 这类绕过 |
| 数据来源 | `WEB_DETECT_SOURCE=demo`（Web 业务 风格仿真）/ `log`（tail nginx·Apache combined 访问日志）/ `api`（WAF、代理通过 `POST /web/requests` 投递） |
| 检测结果 | 复用既有告警链路：落库 → 自动封禁（达到级别门槛）→ 钉钉/企微/邮件/Syslog → 大屏 SSE 推送，告警类别形如 `web_sql_injection` |
| 页面入口 | 「漏洞提醒」页「Web 攻击规则」按钮查看知识库、「异常端口检测」页 KPI「Web 攻击告警」；告警列表与详情直接展示中文攻击类型、命中片段与修复建议 |
| 常用接口 | `GET /web/kb`、`GET /web/kb/{大类}`、`GET /web/stats`、`POST /web/inspect`（单请求体检）、`POST /web/requests`（批量投递） |

```bash
# 机器调用（登录启用时需 API Token；浏览器会话也可）
TOKEN="$(grep '^API_TOKEN=' .env | cut -d= -f2- | tr -d '[:space:]')"

# 规则自测：把一条请求交给检测器，看命中哪些规则（只检测、不产生告警）
curl -s -X POST http://127.0.0.1:8000/api/v1/web/inspect \
  -H "X-API-Token: ${TOKEN}" -H 'Content-Type: application/json' \
  -d '{"method":"GET","path":"/app/demo/sqli/","query":"id=1%27+OR+%271%27%3D%271"}'

# 外部投递（WAF/代理接入）：走完整检测 + 告警 + 封禁闭环
curl -s -X POST http://127.0.0.1:8000/api/v1/web/requests \
  -H "X-API-Token: ${TOKEN}" -H 'Content-Type: application/json' \
  -d '{"requests":[{"method":"POST","path":"/upload","body":"filename=\"shell.php\""}]}'
```

> 阈值类规则（暴力破解 / CSRF / 验证码）按「窗口内累计次数」判定（例如登录接口 60 秒内 ≥10 次），
> 可用 `WEB_BRUTE_FORCE_ATTEMPTS` 覆盖；登录与认证端点已从 CSRF 规则中排除，避免与暴力破解告警重复。

**按流量研判漏洞（补主动漏扫的盲区）**：注入、上传、包含这类漏洞没有版本指纹，主动扫描永远看不见。
命中 Web 攻击后，系统用已捕获的**请求 + 响应**判断该服务是否真的被打穿——响应里出现命令回显、
SQL 报错、`/etc/passwd` 特征行、载荷原样反射才判「已确认」，只有请求没有响应包则记「疑似」。
结论写进漏洞表（`source=traffic_rule` / `traffic_ai`），资产详情的「服务与漏洞」按端口归拢展示，
也可点「按攻击流量研判漏洞」手工触发一次带 AI 复核的研判（`POST /assets/{ip}/vuln-infer`）。

> 漏洞名只取技术类型（`命令注入` / `CWE-78`），不含任何产品名、站点名；换任何业务系统结论口径一致。

## 10. 规则来源层（内置知识库 + 开源规则库）

除了内置的两个 JSON 知识库，系统还接入了开源规则库，统一转换为同一份 `Rule` 结构后一起参与检测：

| 来源 | 位置 | 说明 |
| --- | --- | --- |
| `native` | `data/web_attack_rules.json`、`data/cve_rules.json` | 内置知识库（Web 17 大类 / 63 条 + CVE 18 条） |
| `sigma` | `data/sigma_rules/*.yml` | Sigma YAML：只保留可在流量侧匹配的规则（webserver/proxy 或 detection 能映射到 HTTP 字段），进程/注册表类规则加载期跳过 |
| `et` | `data/et_rules/*.rules` | Suricata / ET Open：只解析入向 `http` 的 `alert` 行，提取 `content`/`pcre`/`threshold`（多个 content 之间按 AND 语义） |
| `cve_ext` | `data/cve_rules_extended.json` | 由开源签名库转换的扩展 CVE，与内置合并（同编号以扩展为准），CVE 规则**永不直达** |
| `intrusion` | `data/rulesets/intrusion_rules.json` | v6 入侵包：742 条（HTTP 633 + 流级 109），按 `core/extended/lab` 分档，默认只装 core 的 HTTP 部分 |
| `triage` | `data/rulesets/triage_rules.json` | v6 研判包：300 条条件规则，`TRIAGE_ENABLED=true` 时在聚合前执行 |
| `malware` | `data/rulesets/malware_signatures.json` | v6 病毒特征包：329 条；文件扫描执行器属于后续批次（默认不启用） |

* **规则包分层（v6）**：`RULES_TIERS=core` 默认只装高置信规则（内置 63 + Sigma/ET/Web 业务 + 入侵包 core），
  `extended/lab` 默认关闭；`RULES_SHADOW_MODE=true` 时只写威胁事件、不告警不封禁，用于误报标定；
* **RulePlan / RE2**：加载期预编译 path_regex、方法与字段掩码；安装 `google-re2` 后
  `MATCH_BACKEND=auto` 会用多模式预筛，只减少候选、不改变判定；未安装自动回落 python；
* **统一构建入口**：启动与 `POST /rules/reload` 共用同一份 KB 构建（含 Web 业务 规则与直达标记），
  构建完成后原子替换引用，检测线程全程使用快照；
* **直达标记自动注入**：命令注入 / Webshell / SSTI / 文件上传 / XXE（高置信度）这几类规则加载时自动
  标记 `direct_alert=True`；SQL 注入、XSS、端口扫描、暴破、目录穿越等**仍走聚合投票**，避免旧接口拼接、
  反射型回显这类场景直接触发响应动作；
* **热加载**：`POST /rules/reload` 或 `RULE_RELOAD_INTERVAL_SEC`（默认 300s）自动重载，运维放文件即生效；
* **可观测**：启动日志输出 `rules loaded: native=…, sigma=…, et=…, cve_ext=…, direct_alert=…`，
  `GET /rules/sources` 返回各来源规则数 / 直达规则数（前端「异常端口检测」页可打开「规则来源」抽屉）。

## 11. AI 技术方案（选型 · 集成 · 优化）

### 11.1 AI 用在哪四个地方

| # | 能力 | 输入 | 输出 | 价值 |
| --- | --- | --- | --- | --- |
| 1 | **告警研判** | 结构化告警摘要（类别/严重度/评分/规则 ID/证据键值） | `verdict`（confirm/suspect/dismiss/unknown）+ 置信度 + 处置建议 + 一句中文理由 | 把「一堆规则 ID」翻译成值班人员能直接决策的结论 |
| 2 | **流量研判** | 近 10 分钟窗口聚合摘要（bps/pps/连接数/告警分布） | 整体态势判断 + 发现列表 + 处置优先级 | 解释「现在到底有没有被打」 |
| 3 | **漏洞修复建议** | CVE / 版本 / 命中证据 / 资产角色 | 可执行修复步骤 + 验证方法 + 回滚注意 | 弥补运维「知道有洞、不知道怎么修」的断点 |
| 4 | **攻击流量→漏洞研判** | 已捕获的**请求 + 响应**报文特征 | 该服务是否真被打穿（已确认 / 疑似 / 未命中） | 补主动漏扫的盲区：注入、上传、包含这类漏洞**没有版本指纹**，扫不出来 |

### 11.2 选型理由

| 候选 | 结论 | 理由 |
| --- | --- | --- |
| 本地部署 7B 级模型 | 否 | 安全运营场景要求单机可跑，7B 推理至少占用数 GB 显存/内存，与"资源占用可控"的项目定位冲突；且评审环境不一定有 GPU |
| 通用闭源大模型（按 token 计价的高阶模型） | 部分否 | 单条告警研判只需短输出（≤512 token），用高阶模型属于成本浪费，且延迟高（>3 s 会拖住告警节奏） |
| **DeepSeek V4-Flash（OpenAI 兼容接口）** | **采用** | ① 中文安全语料理解好，输出稳定在 JSON；② 延迟低，实测满足 3 s 超时约束；③ 单价低，研判成本可控；④ **OpenAI 兼容**意味着换模型只改 `LLM_BASE_URL` + `LLM_MODEL` 两个环境变量，不被单一厂商锁定 |
| 传统规则/模板 | 保留为兜底 | 不作为唯一方案 —— 规则写不出「证据是否互相印证」这类判断，但它是模型不可用时的确定性保障 |

> 选型结论一句话：**用「云侧小模型 + 本地规则兜底」而不是「本地大模型」**，
> 因为安全系统的第一要求是"永远有结论且延迟可控"，而不是"模型参数最多"。

### 11.3 集成方式

```
告警/漏洞/流量事件
      │
      ▼
analysis/prompts.build_alert_digest()      ← 字段白名单 + 内网 IP 脱敏（唯一允许出网的内容）
      │
      ▼
analysis/fallback_chain.AnalysisFallbackChain.analyze()
      │  ① 线程池异步（LLM_WORKER_THREADS=1，队列 200，满则丢弃并标 pending）
      │  ② DeepSeekClient.chat_json()：timeout=3s，max_retries=1，结果缓存 3600s
      │  ③ validate_result()：verdict/suggestion 枚举 + confidence 值域校验
      ▼
{verdict, confidence, suggestion, reason, source, degraded}
      │
      ├─→ 写回告警/漏洞记录（异步）→ SSE 推送大屏 → 前端显示来源标签
      └─→ 只作建议：不参与 AUTO_BLOCK 判定
```

关键实现点（均可在代码中核对）：

* `backend/app/analysis/llm_client.py`：`DeepSeekClient.chat_json()` —— 单次 3 s 超时、只重试 1 次、
  非 2xx 或解析失败统一抛 `LLMUnavailable`（不在客户端做重试风暴）；
* `backend/app/analysis/fallback_chain.py`：四级降级编排，每级写 `source` / `degraded`；
* `backend/app/analysis/prompts.py`：`DROP_EVIDENCE_KEYS` 黑名单（`request`/`rules`/`snippets`/`message`…）
  与 `SAFE_STRING_KEYS` 白名单，从代码层面保证原始载荷出不了网；
* `backend/app/analysis/web_vuln_infer.py`：把"请求有、响应特征也对得上"才判「已确认」，否则只记「疑似」。

### 11.4 优化策略（7 条，逐条对应可观测结果）

| # | 策略 | 解决的问题 | 实现 / 证据 |
| --- | --- | --- | --- |
| 1 | **结构化摘要替代原始报文** | 隐私外泄 + Prompt 注入 | 只发 12 个白名单字段；`llm_mask_internal_ip=true` 时内网 IP 变 `192.168.*.*` |
| 2 | **严格 schema 校验，非法即降级** | 模型自由发挥破坏下游逻辑 | `verdict ∈ {confirm,suspect,dismiss,unknown}`、`confidence ∈ [0,1]`，不符合直接走下一级 |
| 3 | **四级降级链 + 来源可见** | 模型不可用时系统"装死"或"编结论" | `DeepSeek → 本地规则 → 静态模板 → 待人工`，前端标签形如「来源 local_rules（已降级）」 |
| 4 | **异步 + 队列削峰** | 研判拖慢 500 ms 主循环 | 独立工作线程（1~4）+ 200 长度队列，满则丢弃并标 `pending`，主链路零阻塞 |
| 5 | **超时与重试上限** | 网络抖动导致告警堆积 | `timeout=3s`、`max_retries=1`，失败即降级；实测直达告警端到端 156~177 ms（不经模型路径） |
| 6 | **结果缓存** | 同源同类告警重复调用浪费成本 | `LLM_CACHE_TTL_SEC=3600`，同一（源 IP + 类别）1 小时内复用结论 |
| 7 | **AI 结论与处置权解耦** | 模型幻觉导致误封生产 | 封禁门槛只看 `AUTO_BLOCK_MIN_SEVERITY` 与规则权重；研判仅影响展示排序与建议 |

### 11.5 降级链实测（**未配置 API Key 时的真实状态**）

```bash
$ curl -s http://127.0.0.1:8000/api/v1/ai/status
{"enabled":true,"model":"deepseek-v4-flash","client_available":false,
 "alert_analysis":{"total":32,"deepseek_v4_flash":0,"local_rules":30,"template":2,"pending":0},
 "traffic_analysis":{"total":1,"local_rules":1},
 "note":"AI 不可用时自动降级为本地规则/模板/知识库，结果中 source 与 degraded 字段可见；AI 结论不会直接触发封禁。"}
```

> 这正是本项目的设计取向：**演示环境不配 Key 也能跑通全部链路，且每一处结果都诚实标注来源**。
> 评审配置 `LLM_API_KEY` 后，同一套代码自动切到真实模型，`source` 变为 `deepseek_v4_flash`、`degraded=false`。

### 11.6 如何验证 AI 能力（评审可复现）

```bash
# 1) 看 AI 通道状态与各级命中数
curl -s http://127.0.0.1:8000/api/v1/ai/status

# 2) 触发一次流量研判（页面「异常端口检测 → AI 流量研判」同源接口）
curl -s "http://127.0.0.1:8000/api/v1/ai/traffic/review?minutes=10"

# 3) 对某条告警重新研判（含来源与降级标记）
curl -s -X POST http://127.0.0.1:8000/api/v1/alerts/1/reanalyze

# 4) 漏洞 AI 修复建议
curl -s -X POST http://127.0.0.1:8000/api/v1/vulns/1/ai-advice
```

界面入口：告警详情「AI 研判」区块与「重新研判」按钮、异常端口页「AI 流量研判」抽屉、
漏洞行「AI 建议」抽屉（见技术文档第 5 章的界面截图）。

---

## 12. 评分 / 直达 / 自适应阈值 / AI 研判（v2 新增能力一览）

| 能力 | 一句话说明 | 关键开关 | 前端入口 |
| --- | --- | --- | --- |
| 滑动窗口聚合评分 | 每次命中生成一个 signal（权重 = 严重度 × 置信度），`300s` 窗口内累计风险分 ≥ `ALERT_SCORE_THRESHOLD` 才告警，抑制告警风暴 | `ALERT_SCORE_THRESHOLD`、`SCORING_WINDOW_SEC` | 异常端口页「风险分」列、「阈值与信号」表格 |
| 直达机制 | 单条高置信度致命规则（权重 ≥ `DIRECT_ALERT_WEIGHT`＝critical+high）绕过聚合投票，命中即告警 | `DIRECT_ALERT_ENABLED`、`DIRECT_ALERT_WEIGHT` | 告警列表「直达」徽标、`GET /scoring/config` |
| 自适应阈值 | 按 `检测类型 × 资产口径 × 时段` 从人工反馈（确认=误报 / 封禁=真阳）学习误报率，自动收放统计阈值（幅度限制在静态基准的 0.5~2.0 倍） | `ADAPTIVE_THRESHOLD_ENABLED`、`THRESHOLD_*` | 「阈值管理」抽屉、`POST /thresholds/recompute` |
| AI 研判 + 降级链 | `DeepSeek V4-Flash → 本地规则评分 → 静态模板 → 待人工` 四级降级，每级都标注来源；Prompt 只发结构化摘要并对内网 IP 脱敏 | `LLM_ENABLED`、`LLM_API_KEY`、`LLM_BASE_URL` | 告警详情「AI 研判」区块 + 「重新研判」按钮 |
| AI 流量研判 | 只发送窗口聚合摘要（bps/pps/端口/告警类别），模型不可用时本地规则兜底；结论仅作建议，不改变封禁判定 | `LLM_ENABLED`、`LLM_API_KEY` | 异常端口页「AI 流量研判」、`GET /ai/traffic/review` |
| AI 修复建议 | 按 CVE/版本/证据生成可执行修复步骤与验证方法，API 不可用时降级到知识库模板 | `LLM_ENABLED`、`LLM_API_KEY` | 漏洞行「AI 建议」、`POST /vulns/{id}/ai-advice` |

> 两个刻意的设计决定：**① 评分与研判只影响告警展示/排序，不改变自动封禁门槛**（`AUTO_BLOCK_*` 仍是唯一入口）；
> **② 直达机制不参与自适应阈值调整**（规则固有属性，避免把对致命攻击的响应能力"调优"掉）。

## 13. 创新点说明

### 13.1 技术创新点

| # | 创新点 | 与常见方案的区别 | 可验证证据 |
| --- | --- | --- | --- |
| T1 | **「直达 + 聚合」双通道告警** | 常见方案只有阈值/窗口聚合，致命的单条攻击也要等窗口攒够分才告警；本方案对权重 ≥6.0 的单条致命规则**绕过聚合直接告警**，其余仍走聚合投票 | 投递攻击 → SSE 收到告警实测 **156 / 158 / 177 ms**（min/中位/max）；`DIRECT_ALERT_*` 可开关回滚 |
| T2 | **规则权重量化 + 直达标记自动注入** | 多数规则引擎只有"命中/未命中"；这里每条信号带 `权重 = 严重度 × 置信度`，加载期按类别自动注入 `direct_alert`，避免人工漏配 | `GET /rules/sources` 返回各来源规则数与直达规则数（内置 30 条直达） |
| T3 | **AI 降级链「来源可见」** | 业界常见做法是静默兜底，用户以为看到的是模型结论；本方案把 `source` 与 `degraded` 一路带到前端，标签直接写「local_rules（已降级）」 | `/ai/status` 四级计数；告警/漏洞/流量三处界面均显示来源徽标 |
| T4 | **流量侧漏洞研判（用响应证实打穿）** | 主动漏扫只能看版本指纹，注入/上传/包含类漏洞**扫不出来**；本方案用已捕获的"请求 + 响应"判断是否真被打穿（命令回显、SQL 报错、`/etc/passwd` 特征、载荷反射） | 漏洞表 `source=traffic_rule / traffic_ai`；`POST /assets/{ip}/vuln-infer` |
| T5 | **多源规则同构 + 分层档位** | 自建知识库难以跟上攻击演进；方案把 Sigma / Suricata-ET / CVE 扩展统一编译为同一 `Rule` 结构，按 `core/extended/lab` 分档，默认只上高置信规则 | 运行期加载：native 81 + Sigma 5 + ET 6 + CVE 扩展 8 + Web 知识库 171；`RULES_SHADOW_MODE` 可做零告警标定 |
| T6 | **自适应阈值与直达机制解耦** | 自适应阈值常被做成"统一调所有阈值"，结果把对致命攻击的敏感度也调没了；本方案明确**自适应只调统计检测阈值，不参与直达机制** | `ADAPTIVE_THRESHOLD_*` 与 `DIRECT_ALERT_*` 完全独立；单测覆盖该约束 |

### 13.2 应用创新点

| # | 创新点 | 说明 |
| --- | --- | --- |
| A1 | **零门槛可复现** | 3 条命令本地跑通（Windows 也可，自动降级仿真流量）；或 `docker compose up -d` 一键起全栈。评审无需准备 Linux 抓包环境即可看到完整链路 |
| A2 | **大屏"演示模式"降级** | 后端未启动时前端自动切换到演示数据模式并在右上角标注「演示数据」，周期性模拟端口扫描/暴破/突发流量剧本 —— 答辩现场断网也不至于开天窗 |
| A3 | **真实业务站点接入（8080 Apache）** | 提供"访问日志采集 → 高保真代理（8080→8081）→ WAF 投递"三种接入方式，并用 `web_attack_test.sh` 做正常流量零误报复核，直接对应校园/企业真实 Web 业务场景 |
| A4 | **处置留痕与合规报告** | 每次封禁生成九章自包含 HTML 报告（含证据 SHA-256）、全站登录 + CSRF + 审计日志、`DRY_RUN` 默认只记录不真封、`BLOCK_TTL_SEC` 到期自动解封 —— 面向真实运维的"敢用"设计 |
| A5 | **防误封五道闸门** | 白名单 CIDR → 级别门槛 → TTL 自动解封 → DRY_RUN 预演 → 防火墙适配回落，另加"最后管理员保护"与 `PROTECTED_CIDRS` 方向判定，避免把运维自己封在门外 |

---

## 14. 测试

```bash
# 单元 / 集成测试（226 个用例）
.venv/Scripts/python -m pytest backend/tests -q

# 真实服务端到端验证（启动 uvicorn + httpx 校验 REST/SSE/封禁闭环/Web 攻击检测/直达告警延迟/降级链）
.venv/Scripts/python scripts/verify_runtime.py

# 页面观感/布局自动检查（Node 里真实执行页面脚本 + 校验图表与样式规则）
node scripts/verify_layout.js

# 旧库升级到 v2（新增评分/直达/信号/阈值/研判字段；幂等，只补列不删列）
.venv/Scripts/python scripts/migrate_v2.py --dry-run
```

`backend/tests/` 覆盖：统计基线、4 类异常检测规则、告警冷却抑制、Isolation Forest、
白名单闸门、命令注入校验、TTL 到期解封、API 契约、CVE 匹配与版本区间比较，
以及 **Web 攻击知识库**（17 大类逐类检出、编码/注释绕过、误报抑制、频次阈值、组合攻击提级、
仿真剧本覆盖全部大类、`/web/*` 接口契约）、
**统一规则层**（native/Sigma/ET 转换与直达标记注入、类别映射与跳过策略、热加载）、
**评分与直达机制**（权重表、直达绕过聚合、增量告警无窗口延迟、冷却与窗口淘汰、多类别/critical 加成）、
**自适应阈值**（误报率驱动收放、上下限、最小样本、人工覆盖跳过、与直达解耦）、
**AI 研判降级链**（四级来源标注、schema 校验、Prompt 注入防护、异步写回与事件推送）、
**Web 业务站点适配**（严格规则路径限定与直达、正常请求零告警、`WEB_IGNORE_IPS` 抑制、版本未知不猜 CVE、
本地假 Web 业务 的认证模块漏扫与 HTTP 证据、AI 流量/漏洞建议降级）、
**v6 新增能力**（scrypt 密码与会话生命周期、威胁事件落库/标签/方向、九章报告与 SHA-256、
入侵包分档与 RulePlan 预编译、nftables `interval` 集合与 CIDR 封禁、最后管理员保护、
全站登录/CSRF 守卫）、
**v2/v3 接口契约**（新接口 + 老接口向后兼容）。
`scripts/verify_runtime.py` 覆盖 TestClient 无法验证的部分：**真实 HTTP 上的 SSE 推送**、
封禁/解封/重复封禁/白名单拒绝的语义化返回码、处置流水留痕、Web 攻击知识库与请求体检接口、
**直达告警端到端延迟（投递 → SSE 收到告警，实测 min=156ms / 中位=158ms / max=177ms，远低于 2 s 目标）**、
**聚合抑制可见（未达阈值的 signal 可在 `/signals` 查到）**、**AI 研判降级链（API 不可用时来源标注为本地规则/模板）**、
全部模块页面与静态资源可访问（共 83 项断言）。
`scripts/verify_layout.js` 覆盖"观感"类问题：所有直角坐标系图表必须 `containLabel`、
饼图必须隐藏引导线标签 + 底部横排图例 + `avoidLabelOverlap`、背景遮罩与面板不透明度、
模块导航不再遮挡图表、数值单行省略、**详情浮窗默认收起（只有点「详情」才滑入）**、
**图表尺寸自适应（先定 rem 基准再 init + 容器变化自动 resize）**、
**Web 攻击知识库前端展示与告警中文名**、
**评分/直达徽标、阈值管理抽屉、AI 研判来源标签与降级提示**等（共 128 项断言）。

## 15. 文档

* [`docs/部署操作手册.md`](docs/部署操作手册.md) —— **面向安防运维的逐步部署手册**（环境检查、安装、
  三种采集、封禁与自锁恢复、规则/引擎、Web 业务站点 8080 部署与攻击验证、验收记录表、
  日常运维、故障排查、加固清单）
* [`docs/系统使用说明.md`](docs/系统使用说明.md) —— **使用说明书**：页面地图、每个模块的字段含义与操作、
  四类告警的判定口径与处置建议、日常巡检清单、应急流程、FAQ、API 速查
* [`docs/智能流量安全检测与分析系统-架构设计与实施指南.md`](docs/智能流量安全检测与分析系统-架构设计与实施指南.md)
  —— 总体架构、技术选型、核心代码示例、部署指南、风险与优化建议

## 16. 页面导航与在线演示

| 页面 | 地址（直跑模式） | 说明 |
| --- | --- | --- |
| 登录 | `http://<host>:8000/login.html` | 首次登录强制改密；审计所有登录 |
| 监控大屏 | `http://<host>:8000/` | 总览 |
| 流量监控 | `http://<host>:8000/traffic.html` | 带宽 / 包速率 / 会话 |
| 威胁告警 | `http://<host>:8000/threat.html` | 可疑流量明细、请求快照、标签、CSV 导出 |
| 封禁管理 | `http://<host>:8000/block.html` | 封禁 / 白名单 / 安全事件报告 |
| 异常端口 | `http://<host>:8000/anomaly.html` | 端口基线、阈值与信号 |
| 规则管理 | `http://<host>:8000/rules.html` | 规则包、档位、匹配引擎状态 |
| 漏洞提醒 | `http://<host>:8000/vuln.html` | CVE 与修复建议 |
| 资产管理 | `http://<host>:8000/asset.html` | 台账与指纹 |
| 云端协同 | `http://<host>:8000/cloud.html` | 云端账号、告警归档、证据文件、AI 值班简报（第 18 章） |
| 兼容跳转 | `http://<host>:8000/response.html` | 自动跳转 `block.html` |
| API 文档 | `http://<host>:8000/docs` | 全部 REST / SSE 接口 |

容器化部署时前缀为 `http://<host>:8080/dashboard/`。

### 16.1 在线演示（可选加分项）

| 项 | 内容 |
| --- | --- |
| **演示地址** | **<https://secops-traffic-guard.app.workbuddy.host/?sharecode=I55BLJHGXB>** |
| 可用时段 | 评审期间保持在线（服务由托管沙箱常驻，无需评审自行部署） |
| 采集模式 | 演示模式（`CAPTURE_MODE=demo`，仿真流量 + 真实检测/告警/封禁链路，不触碰任何真实网络） |
| 数据说明 | 大屏与列表中的数据由仿真攻击剧本实时生成，用于展示完整链路；右上角显示「演示数据」标识 |
| 安全说明 | `DRY_RUN=true`：封禁动作会完整留痕但不真正下发防火墙规则；未配置真实 Webhook 与 LLM 密钥 |

> 首访会带上 `sharecode` 参数完成一次校验，之后浏览器会记住，可直接访问各页面。

### 16.2 评审访问方式

| 项 | 说明 |
| --- | --- |
| 是否需要登录 | **不需要**。演示环境设置 `AUTH_ENABLED=false`，打开链接即为监控大屏，避免多评委互相改密导致账号失效 |
| 建议浏览顺序 | 监控大屏 → 威胁告警（点「详情」看请求快照）→ 异常端口（点「AI 流量研判」）→ 封禁管理 → 漏洞提醒（点「AI 建议」）→ 规则管理 |
| 想体验登录与审计 | 本地部署时把 `AUTH_ENABLED` 设为 `true`（默认值），首启会生成一次性管理员密码并打印在启动日志，登录后强制改密；该流程在演示视频中有完整展示 |

### 16.3 演示环境的部署方式

演示站点由托管沙箱以单端口 HTTP 服务方式运行（源码上传 → 安装依赖 → `python serve.py` 启动，端口由 `PORT` 注入）：

```bash
CAPTURE_MODE=demo        # 演示环境不抓真实流量
AUTH_ENABLED=false       # 演示环境免登录，避免多评委互改密码
DRY_RUN=true             # 封禁只留痕不落地
AUTO_BLOCK_ENABLED=true  # 保留自动封禁链路，便于演示闭环
LLM_ENABLED=true         # 未配置 LLM_API_KEY 时按设计降级，界面标注来源
```

> 需要登录版演示或接入真实业务流量时，按第 5 / 6 章在本机或自有服务器部署即可，参数与上表一致，仅把
> `AUTH_ENABLED` 改回 `true`。

---

## 17. v6 落地范围与边界

本次按“可验证、可回退、不破坏既有链路”的原则采纳 v6：

| v6 项 | 落地状态 |
| --- | --- |
| 资源开销表述 | ✅ 已去掉“几十 MB / CPU < 5%”等绝对承诺，改为分档 + 实测口径 |
| 登录管理 | ✅ 服务端会话、scrypt、CSRF、三角色、限流/锁定、审计、用户管理（规则管理页内） |
| 页面拆分 | ✅ `threat.html` 管证据、`block.html` 管处置；`response.html` 自动跳转 |
| 威胁告警 | ✅ 聚合前落库、L0/L1 保真度、标签、筛选、四页签详情、流式 CSV |
| 封禁报告 | ✅ 九章自包含 HTML、证据 SHA-256、在线查看/下载 |
| 规则库扩容 | ✅ 入侵包 HTTP 部分按 core/extended/lab 接入；研判执行器已实现（默认关）；病毒扫描/流级见后续批次 |
| 多模式引擎 | ✅ `RulePlan` 预编译 + 可选 RE2（只减候选不改判定）；未装 RE2 自动回落 python |
| 响应兜底 | ✅ 五道闸门保留；DB 封禁审计；nftables 补建 `@blocklist` / `@blocklist_cidr` drop 规则（CIDR 用 interval 集合） |
| 流级 109 条入侵规则（P3） | ⏳ 后续批次；执行器保持 `FLOW_RULES_ENABLED=false`，HTTP 规则已可用 |
| 防火墙/镜像采集（P4） | ⏳ 后续批次；`PROTECTED_CIDRS` 方向判定已可用；当前请用访问日志/代理采集，不要设 `CAPTURE_MODE=firewall` |
| 自定义规则上传/回滚（P5） | ⏳ 后续批次；规则管理页只读展示，不提供假入口 |

> 详细操作步骤见 [`docs/部署操作手册.md`](docs/部署操作手册.md)；
> 方案原文为《系统更新方案-v6》（设计文档，不代表全部已上线）。

---

## 18. 云端协同（WorkBuddy 云服务）

### 18.1 定位：云端只做"协作"，不做"检测"

检测、评分、封禁判定、AI 研判降级链全部留在本地后端，云端不参与任何判定。这样设计的原因是：
把检测逻辑搬到云上，一来演示环境与生产环境的判定口径会分叉，二来告警原文里带攻击载荷，
出网就会触发云端 WAF。因此云端只承载三件本地做不好的事 —— **跨设备可追溯的归档**、
**可分享的证据文件**、**免密钥的模型调用**。

| 云服务模块 | 在系统里的落点 | 代码位置 |
| --- | --- | --- |
| Database | `secops_archive` 表：告警 / 封禁处置归档，按操作员隔离 | `dashboard/js/cloud.js` → `archiveInsert/archiveList/archiveDelete` |
| Auth | 云端账号（邮箱验证码，免密码），归档与文件的归属主体 | `dashboard/js/cloud.js` → `sendEmailCode/verifyEmailCode` |
| Storage | 把「封禁管理」生成的九章证据报告上传云端，签发 10 分钟有效链接 | `dashboard/js/cloud.js` → `uploadReport/reportUrl` |
| LLM | AI 值班简报：把大屏统计口径交给云端模型做中文研判，无需 `LLM_API_KEY` | `dashboard/js/cloud.js` → `generate` |

页面为 `dashboard/cloud.html` + `dashboard/js/page-cloud.js`，导航第 9 项「3.7 云端协同」。
SDK 走 **CDN 形态**（`@tencent-ai/workbuddy-cloud-sdk@dev` 的 IIFE 包），懒加载：
本项目没有构建链，为了一个 SDK 引入 `package.json` 会破坏"双击 index.html 也能跑"的演示形态。
客户端只用 `publicConfig`（资源 id / 发布域名 / OAuth Relay / publishableKey）初始化，
真实环境凭证与模型密钥留在服务端，前端拿不到也不需要。

### 18.2 数据模型与隔离

```sql
CREATE TABLE secops_archive (
  id          BIGINT      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  owner_id    TEXT        NOT NULL DEFAULT auth.uid(),   -- 服务端填充，前端永不传
  owner_name  TEXT,
  kind        TEXT        NOT NULL DEFAULT 'alert',      -- alert | block
  title       TEXT        NOT NULL,
  severity    TEXT,
  category    TEXT,
  source_ip   TEXT,
  target      TEXT,
  score       NUMERIC(6,2),
  detail      TEXT,
  observed_at TIMESTAMPTZ,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
)
```

隔离由数据库而不是前端保证：`ENABLE ROW LEVEL SECURITY` + 四条策略
（`SELECT/INSERT/UPDATE/DELETE ... USING (owner_id = auth.uid())`，`INSERT` 用 `WITH CHECK` 防伪造归属），
并对 `authenticated, anon` 显式 `GRANT`（漏了 GRANT 会得到一个"长得像 RLS 失效"的 `42501`）。
删除操作即使被 RLS 过滤掉也不会报错、只返回空数组，所以前端把"空数组"当成"没删掉"提示，
不静默当成功。文件同理：`users/<uid>/reports/...`，只有本人可读写。

### 18.3 三个安全约束（踩过才知道）

| 约束 | 现象 | 处理 |
| --- | --- | --- |
| **WAF 拦请求体** | 告警原文含「命中片段：`<payload>`」，归档与简报的 POST 被云端 WAF 直接 403 拦截页，请求到不了数据库 | 归档只同步结构化字段（类型/级别/来源/目标/评分/规则），自由文本过 `safeText()`；简报只上传统计口径（类型分布、级别分布、脱敏来源），**不上传任何告警原文** |
| **IP 脱敏** | 内网拓扑不应原文出网 | 送模型的来源 IP 统一掩成 `a.b.*.*`，与后端 AI 研判的脱敏口径一致；归档因需追溯处置，保留真实 IP 但仅本人可见 |
| **短时链接** | 签名地址等于短时凭证 | 600 秒有效，只在点击时生成并直接打开，不落盘、不写日志 |
| **直链只下纯文本** | 平台对用户上传内容一律以 `Content-Type: text/plain` 下发（防止共享域名上的存储型 XSS），浏览器直接打开签名链接只会显示 HTML 源码 | 「查看」改为前端取回文本后按 `text/html` 写进新窗口（窗口必须在点击的同一轮事件里同步 `window.open`，否则异步回调里的开窗会被弹窗拦截）；签名链接保留给「复制链接」与外部分享/curl 取件 |

### 18.4 实测记录（发布域名下）

| 能力 | 验证方式 | 结果 |
| --- | --- | --- |
| 云端登录 | 真实邮箱收码 → 校验 | 收码成功，`getSession()` 返回 uid，页面切到「已登录」 |
| 归档写入 | 归档最近 20 条告警 | `已写入云端归档 20 条`，`owner_id` 由 `DEFAULT auth.uid()` 自动填充，与当前账号一致 |
| 归档读回 | 刷新云端归档 | 计数 20，列表按 `created_at` 倒序，RLS 只返回本人行 |
| 文件往返 | 上传 → 列表 → 签名链接 → 删除 | 上传返回 `fullPath`；列表 1 个对象（`text/html`，98 B）；签名链接 HTTP 200 且内容匹配；删除后剩余 0 |
| 在线查看 | 上传九章报告 → 点「查看」 | 新标签页按 HTML 渲染：标题「安全事件报告 · 45.33.32.156」、7 个二级章节、7 张表格、正文 12,172 字，页面文本中**无**源码泄漏（签名直链本身仍是 `text/plain`） |
| 下载另存 | 点「下载」 | 触发浏览器下载，建议文件名 `report-1.html`（取对象键末段；不再把 `users/<uid>/reports/...` 整段塞进 `download` 属性） |
| 复制链接 | 点「复制链接」 | 生成 600 秒签名地址；浏览器拒绝写剪贴板时退到弹窗手动复制，不静默失败 |
| 覆盖上传 | 同一份报告再传一次 | 平台不认 `upsert`，返回 `STORAGE_KEY_ALREADY_EXISTS`；客户端自动「先删后传」完成覆盖，不报错给用户 |
| 模型调用 | 生成值班简报 | `deepseek-v4.1-flash` 流式返回，约 590 字中文研判，941 tokens |
| 未登录闸门 | 未登录时打开页面 | 归档/文件两块显示「登录云端账号后显示」，不发起任何写请求，也不降级到 localStorage |

### 18.5 降级与关闭

* **云端不可用**（SDK 的 CDN 不可达、未登录、额度用尽、WAF 拦截）→ 每一块各自显示明确原因，
  其余模块照常工作；**不会**把本地 localStorage 伪装成云端存储。
* **关闭云服务**：云环境没有前端关停接口，需在 **设置 → 数据管理 → 应用** 中管理该应用
  （删除会一并释放云服务且不可恢复）；只下线站点则保留环境、链接失效。
* 云端不可达时系统功能不受影响 —— 第 1～12 章的检测链路完全不依赖云。

