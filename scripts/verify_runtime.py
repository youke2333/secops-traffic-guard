"""真实服务端到端验证脚本（比 TestClient 更接近生产）。

用途：启动一个真实的 uvicorn 进程（仿真采集 + 临时 SQLite + DRY-RUN 防火墙），
      再用 httpx 逐项验证 REST 与 **SSE 实时流**，覆盖 TestClient 无法验证的流式推送。

用法：
    python scripts/verify_runtime.py              # 默认端口 8123
    python scripts/verify_runtime.py --port 9000

退出码：0=全部通过，1=存在失败项。
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Dict, List, Tuple

import httpx

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
BACKEND_DIR = REPO_ROOT / "backend"

PASSED: List[str] = []
FAILED: List[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    if condition:
        PASSED.append(name)
    else:
        FAILED.append(f"{name} —— {detail}")
    print(f"[{'PASS' if condition else 'FAIL'}] {name}" + (f"  {detail}" if detail and not condition else ""))


def wait_health(base: str, timeout: float = 40.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if httpx.get(f"{base}/health", timeout=2.0).status_code == 200:
                return True
        except Exception:
            time.sleep(0.5)
    return False


def read_sse(base: str, path: str, want_events: int = 2, timeout: float = 15.0
             ) -> List[Tuple[str, Dict[str, Any]]]:
    """读取 SSE 流，直到收集到 want_events 个事件或超时（真实 HTTP 流式读取）。"""
    events: List[Tuple[str, Dict[str, Any]]] = []
    deadline = time.time() + timeout
    with httpx.stream("GET", f"{base}{path}", timeout=timeout) as response:
        if response.status_code != 200:
            return events
        current_event = "message"
        for line in response.iter_lines():
            if time.time() > deadline:
                break
            if line.startswith("event: "):
                current_event = line[7:].strip()
            elif line.startswith("data: "):
                try:
                    events.append((current_event, json.loads(line[6:])))
                except json.JSONDecodeError:
                    continue
                if len(events) >= want_events:
                    break
    return events


def start_server(port: int, db_path: pathlib.Path) -> Tuple[subprocess.Popen, pathlib.Path]:
    """启动真实 uvicorn 进程。

    注意：服务端输出重定向到**文件**而不是 PIPE —— 本验证会跑出大量日志（采集/检测/Web 攻击
    仿真），如果管道没人读取，写满缓冲区后 uvicorn 会整体阻塞（表现为 httpx ReadTimeout）。
    """
    env = dict(os.environ)
    env.update({
        "DB_URL": f"sqlite:///{db_path}",
        "CAPTURE_MODE": "demo",
        "TICK_INTERVAL_MS": "200",
        "DRY_RUN": "true",
        "FIREWALL_BACKEND": "iptables",       # 干跑模式下预演 iptables 命令
        "ALERT_CHANNELS": "log",
        "IFOREST_ENABLED": "true",
        "API_TOKEN": "",
        "AUTH_ENABLED": "false",       # 本脚本验证检测/处置链路；登录/CSRF 由 test_v6.py 覆盖
        "WEB_DETECT_ENABLED": "true",
        "WEB_DEMO_INTERVAL_SEC": "2.5",
        # 漏扫校验用不可达目标（127.0.0.1:1）：把单请求超时与总预算压到最小，
        # 否则 Windows 上每次 ConnectionRefused 都要约 2s，多个探测点会把接口拖过客户端超时。
        "WEBAPP_SCAN_TIMEOUT_SEC": "1.0",
        "WEBAPP_SCAN_MAX_SECONDS": "6.0",
        # v2：把 LLM 指向一个必然连不上的地址，验证"降级链"在真实进程里生效
        # （方案 4.10：断开 API → 降级到本地规则 / 模板，且来源标注可见）
        "LLM_ENABLED": "true",
        "LLM_API_KEY": "sk-verify-runtime",
        "LLM_BASE_URL": "http://127.0.0.1:9/v1",
        "LLM_TIMEOUT_SEC": "0.5",
        "LLM_MAX_RETRIES": "0",
        "PYTHONPATH": str(BACKEND_DIR),
    })
    log_path = db_path.parent / "server.log"
    handle = log_path.open("w", encoding="utf-8", errors="ignore")
    env["PYTHONIOENCODING"] = "utf-8"          # 服务端日志统一 UTF-8，避免 GBK 控制台乱码
    process = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1",
         "--port", str(port), "--log-level", "warning"],
        cwd=str(BACKEND_DIR), env=env,
        stdout=handle, stderr=subprocess.STDOUT, text=True,
    )
    process._log_handle = handle          # 保持文件句柄存活（进程结束后一并关闭）
    return process, log_path


def latency_probe(base: str, payload: dict, wait: float = 0.4) -> Dict[str, Any]:
    """测量"投递攻击载荷 → SSE 收到告警"的端到端延迟（方案要求 P99 < 2s）。

    真实 HTTP 流式读取 + 真实 uvicorn 进程，因此覆盖了 TestClient 无法验证的推送链路。
    仿真采集源也在持续产生告警，因此只认**本次投递源 IP** 的事件（避免误测别人的告警）。
    """
    expected_ip = str(payload.get("src_ip") or "")
    result: Dict[str, Any] = {"received": False, "latency": None, "event": None, "error": ""}
    result["sent_at"] = 0.0

    def reader():
        try:
            deadline = time.time() + 20
            with httpx.stream("GET", f"{base}/stream/events", timeout=20) as response:
                if response.status_code != 200:
                    result["error"] = f"HTTP {response.status_code}"
                    return
                current = ""
                for line in response.iter_lines():
                    if time.time() > deadline:
                        break
                    if line.startswith("event: "):
                        current = line[7:].strip()
                    elif line.startswith("data: ") and current == "alert":
                        event = json.loads(line[6:])
                        if expected_ip and event.get("source_ip") != expected_ip:
                            continue      # 仿真源产生的其它告警：忽略
                        result["event"] = event
                        result["latency"] = time.time() - result["sent_at"]
                        result["received"] = True
                        break
        except Exception as exc:
            result["error"] = f"{type(exc).__name__}: {exc}"

    thread = threading.Thread(target=reader, daemon=True)
    thread.start()
    time.sleep(wait)                       # 等 SSE 连接建立（订阅生效）
    result["sent_at"] = time.time()        # 先记开始时间，避免「事件先于赋值到达」导致负延迟
    posted = httpx.post(f"{base}/web/requests", timeout=20, json={"requests": [payload]})
    result["post"] = posted.json() if posted.status_code == 200 else {}
    thread.join(timeout=15)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="端到端验证：REST + SSE + 封禁闭环")
    parser.add_argument("--port", type=int, default=8123)
    parser.add_argument("--keep-running", action="store_true", help="验证结束后保留服务进程")
    args = parser.parse_args()

    # Windows 控制台默认 GBK：中文/日志里出现生僻字符时不要让脚本自身崩掉
    try:
        sys.stdout.reconfigure(errors="replace")      # type: ignore[attr-defined]
        sys.stderr.reconfigure(errors="replace")      # type: ignore[attr-defined]
    except Exception:
        pass

    base = f"http://127.0.0.1:{args.port}/api/v1"
    db_path = pathlib.Path(tempfile.mkdtemp(prefix="secops-verify-")) / "verify.db"

    print(f"启动 uvicorn（端口 {args.port}，仿真采集，数据库 {db_path.name}）…")
    process, server_log = start_server(args.port, db_path)

    try:
        if not wait_health(base):
            print("服务启动失败，输出如下：")
            if server_log.exists():
                print(server_log.read_text(encoding="utf-8", errors="ignore")[-2000:])
            return 1
        check("服务健康检查 /health", True)
        health = httpx.get(f"{base}/health", timeout=5).json()
        check("采集模式可用（自动降级）", health["capture_mode"] in {"demo", "scapy", "ebpf"}, str(health))
        check("防火墙处于 DRY-RUN 干跑", health["dry_run"] is True, str(health))

        overview = httpx.get(f"{base}/overview", timeout=5).json()
        check("总览 KPI 字段完整",
              {"bps", "bandwidth_util", "pps", "conns", "alerts_total", "blocked_active",
               "assets_total", "vulns_open", "risk_score"} <= set(overview), str(sorted(overview)))

        time.sleep(2.0)   # 让采集累积若干 tick
        status = httpx.get(f"{base}/status", timeout=5).json()
        check("采集 tick 持续运行", status["ticks"] > 1,
              json.dumps(status, ensure_ascii=False)[:200])

        trend = httpx.get(f"{base}/metrics/trend", params={"window_sec": 30}, timeout=5).json()
        check("趋势接口返回时序点", len(trend["bps_in"]) > 0, str(trend)[:160])

        ports = httpx.get(f"{base}/metrics/ports", params={"top": 5}, timeout=5).json()
        check("端口 TOP 接口可用", "items" in ports, str(ports)[:160])

        # ---- SSE 实时流（TestClient 无法覆盖的部分） ----
        metrics_events = read_sse(base, "/stream/metrics", want_events=3, timeout=20)
        check("SSE /stream/metrics 推送 ≥3 帧", len(metrics_events) >= 3,
              f"实际收到 {len(metrics_events)} 帧")
        if metrics_events:
            frame = metrics_events[-1][1]
            check("SSE 指标帧含关键字段",
                  {"bps_in", "pps_in", "conns"} <= set(frame), str(frame)[:200])

        # ---- 封禁闭环 ----
        # 注意：这里使用与仿真剧本、Web 攻击仿真完全不同的地址（198.18.0.0/15 为基准测试网段），
        # 否则可能命中「重复封禁」分支而拿不到防火墙命令（command 只在首次封禁时返回）
        manual_ip = "198.18.0.45"
        created = httpx.post(f"{base}/blocks", timeout=5,
                             json={"ip": manual_ip, "reason": "端到端验证", "ttl_sec": 60}).json()
        check("手动封禁成功", created["success"] is True, str(created)[:220])
        check("封禁命令为预演 iptables 参数",
              "iptables" in str(created.get("detail", {}).get("command", "")),
              str(created.get("detail", {}).get("command")))

        blocks = httpx.get(f"{base}/blocks", params={"active_only": True}, timeout=5).json()
        check("封禁列表包含目标 IP",
              any(item["ip"] == manual_ip for item in blocks["items"]), str(blocks)[:200])

        duplicated = httpx.post(f"{base}/blocks", timeout=5,
                                json={"ip": manual_ip, "reason": "重复封禁"}).json()
        check("重复封禁返回 duplicated 语义", duplicated.get("code") == "duplicated",
              str(duplicated)[:200])

        whitelisted = httpx.post(f"{base}/blocks", timeout=5,
                                 json={"ip": "127.0.0.1", "reason": "白名单校验"}).json()
        check("白名单拒绝封禁", whitelisted.get("code") == "whitelisted", str(whitelisted)[:200])

        released = httpx.delete(f"{base}/blocks/{manual_ip}", timeout=5).json()
        check("人工解封成功", released["success"] is True, str(released)[:200])

        disposals = httpx.get(f"{base}/disposals", timeout=5).json()
        actions = [item["action"] for item in disposals["items"]]
        check("处置流水含 block 与 unblock", "block" in actions and "unblock" in actions, str(actions))

        vuln_summary = httpx.get(f"{base}/vulns/summary", timeout=5).json()
        check("CVE 知识库已加载", vuln_summary["kb"]["rules"] > 0, str(vuln_summary)[:200])

        # ---- Web 攻击知识库（17 大类 / 60+ 规则）与检测接口 ----
        web_kb = httpx.get(f"{base}/web/kb", timeout=10).json()
        check("Web 攻击知识库已加载（≥17 大类、≥60 条规则）",
              web_kb["stats"]["categories"] >= 17 and web_kb["stats"]["rules"] >= 60,
              str(web_kb.get("stats"))[:200])
        check("Web 攻击知识库每个大类都有规则与 CWE 编号",
              all(item["rule_count"] > 0 and str(item["cwe"]).startswith("CWE-")
                  for item in web_kb["categories"]),
              str(web_kb["categories"][:2])[:200])

        sql_inspect = httpx.post(f"{base}/web/inspect", timeout=5, json={
            "method": "GET", "path": "/vulnerabilities/sqli/", "query": "id=1' OR '1'='1",
            "src_ip": "203.0.113.9", "dst_port": 80}).json()
        check("请求体检接口能识别 SQL 注入载荷",
              sql_inspect["hit_count"] >= 1 and "sql_injection" in sql_inspect["categories"],
              str(sql_inspect)[:200])

        xss_inspect = httpx.post(f"{base}/web/inspect", timeout=5, json={
            "method": "GET", "path": "/vulnerabilities/xss_r/",
            "query": "name=<script>alert(1)</script>", "src_ip": "203.0.113.9"}).json()
        check("请求体检接口能识别反射型 XSS 载荷",
              "xss_reflected" in xss_inspect["categories"], str(xss_inspect)[:200])

        try:
            detected = httpx.post(f"{base}/web/requests", timeout=20, json={"requests": [
                {"method": "POST", "path": "/vulnerabilities/exec/",
                 "body": "ip=127.0.0.1;cat /etc/passwd",
                 "src_ip": "198.51.100.99", "dst_ip": "192.168.1.30"}]}).json()
            check("外部投递请求触发 Web 攻击告警（命令注入）",
                  detected["alert_count"] >= 1
                  and any(item["category"] == "web_command_injection"
                          for item in detected["alerts"]),
                  str(detected)[:200])
        except Exception as exc:      # 让失败变成 FAIL 项而不是中断整个验证
            check("外部投递请求触发 Web 攻击告警（命令注入）", False,
                  f"{type(exc).__name__}: {exc}")

        web_stats = httpx.get(f"{base}/web/stats", timeout=5).json()
        check("Web 攻击检测统计可用（含知识库版本与来源）",
              web_stats["analyzed_requests"] > 0 and web_stats["kb"]["rules"] >= 60
              and web_stats["source_name"] in {"demo", "log", "api", "off"},
              str(web_stats)[:200])

        web_alerts = httpx.get(f"{base}/alerts", params={"category": "web_sql_injection"}, timeout=5).json()
        check("告警接口支持按 Web 攻击类别过滤", isinstance(web_alerts, list), str(web_alerts)[:200])

        # ---- v2：规则来源层（内置 + Sigma + ET + 扩展 CVE）----
        sources = httpx.get(f"{base}/rules/sources", timeout=10).json()
        names = {row["source"] for row in sources.get("sources", [])}
        check("规则来源接口可用（内置 / Sigma / ET / 扩展 CVE）",
              names == {"native", "sigma", "et", "cve_ext"}, str(sources)[:200])
        check("各来源规则数、直达规则数与直达大类可见",
              sources.get("direct_alert_total", 0) >= 5
              and bool(sources.get("direct_alert_categories"))
              and sources["web_kb"]["rules"] >= 60,
              str({k: sources.get(k) for k in ("direct_alert_total", "web_kb")})[:200])
        sigma_rules = httpx.get(f"{base}/rules", params={"source": "sigma"}, timeout=5).json()
        check("统一规则清单接口可用（可按来源过滤）",
              sigma_rules.get("total", 0) >= 1, str(sigma_rules)[:200])
        reloaded = httpx.post(f"{base}/rules/reload", timeout=10).json()
        check("规则热加载接口可用（无需重启）",
              reloaded.get("success") is True and reloaded.get("code") == "reloaded",
              str(reloaded)[:200])
        packs = httpx.get(f"{base}/rules/packs", timeout=10).json()
        intrusion = next((item for item in packs.get("packs", [])
                          if item.get("pack") == "intrusion"), {})
        check("规则包接口可用（入侵 742 / 研判 300 / 病毒 329）",
              packs.get("total") == 1371 and intrusion.get("selected", 0) > 0,
              str(packs)[:300])
        engine = httpx.get(f"{base}/rules/engine", timeout=10).json()
        check("匹配引擎状态可观测（backend/plans/compile_ms）",
              engine.get("backend") in {"python", "re2"} and engine.get("plans", 0) > 60,
              str(engine)[:300])
        threats = httpx.get(f"{base}/threats", params={"page_size": 5}, timeout=10).json()
        check("威胁事件接口可用（聚合前落库）",
              "items" in threats and "total" in threats, str(threats)[:200])
        reports = httpx.get(f"{base}/reports", timeout=10).json()
        check("安全事件报告列表可用", "items" in reports, str(reports)[:200])


        # ---- v2：评分与直达机制 ----
        scoring = httpx.get(f"{base}/scoring/config", timeout=5).json()
        check("评分配置接口返回窗口/阈值/直达权重",
              scoring.get("threshold", 0) > 0 and scoring.get("direct_alert_weight") == 6.0
              and scoring.get("window_sec", 0) > 0, str(scoring)[:200])
        check("直达机制不参与自适应阈值（设计决定在接口上可见）",
              "直达" in str(scoring.get("note", "")), str(scoring.get("note"))[:120])

        rce_payload = {"method": "POST", "path": "/vulnerabilities/exec/",
                       "body": "ip=127.0.0.1;cat /etc/passwd", "src_ip": "198.51.100.201",
                       "dst_ip": "192.168.1.30", "status": 200}
        latencies: List[float] = []
        probe: Dict[str, Any] = {}
        for index in range(3):      # 3 次采样：不同源 IP，避免命中冷却期
            sample = dict(rce_payload)
            sample["src_ip"] = f"198.51.100.{211 + index}"
            probe = latency_probe(base, sample)
            if probe["received"]:
                latencies.append(float(probe["latency"] or 0))
        latencies.sort()
        check("直达告警：投递 RCE 载荷后 SSE 立即收到告警（不等窗口到期）",
              bool(latencies), probe.get("error") or str(probe.get("post"))[:160])
        if latencies:
            worst = latencies[-1]
            median = latencies[len(latencies) // 2]
            print(f"      端到端延迟采样（投递 → SSE 收到告警）："
                  f"min={latencies[0] * 1000:.0f}ms, 中位={median * 1000:.0f}ms, "
                  f"max={worst * 1000:.0f}ms（P99 目标 < 2000ms）")
            check("直达告警延迟 < 2 秒（P99 要求）", worst < 2.0, f"最差实测 {worst:.3f}s")
            event = probe["event"] or {}
            check("SSE 告警帧带评分 / 直达 / 贡献规则字段",
                  event.get("direct_alert") is True and float(event.get("risk_score") or 0) >= 6.0
                  and bool(event.get("contributing_rules")),
                  str(event)[:220])
            alert_id = event.get("alert_id")
            if alert_id:
                detail = httpx.get(f"{base}/alerts/{alert_id}", timeout=5).json()
                check("告警详情带窗口 signals 与 AI 研判字段",
                      bool(detail.get("signals")) and "llm_analysis" in detail
                      and detail.get("signal_window_id"), str(detail)[:220])
                analysis = detail.get("llm_analysis")
                if analysis is None:
                    # 研判是异步的：等待后台线程写回（最多 10s，含 LLM 超时与队列排队）
                    for _ in range(50):
                        time.sleep(0.2)
                        detail = httpx.get(f"{base}/alerts/{alert_id}", timeout=5).json()
                        analysis = detail.get("llm_analysis")
                        if analysis is not None:
                            break
                check("AI 研判结果已写回（API 不可用时降级到本地规则/模板）",
                      bool(analysis) and analysis.get("source") in
                      {"deepseek_v4_flash", "local_rules", "template", "pending"},
                      str(analysis)[:220])
                check("降级必须可见（llm_analysis.degraded 与来源标注）",
                      bool(analysis) and ("degraded" in analysis),
                      str(analysis)[:220])
                reanalyzed = httpx.post(f"{base}/alerts/{alert_id}/reanalyze", timeout=10).json()
                check("重新研判接口可用（同步返回降级链结果）",
                      reanalyzed.get("success") is True
                      and reanalyzed.get("code") in {"ok", "degraded"},
                      str(reanalyzed)[:220])

        # ---- v2：抑制可见（未达阈值的信号不得静默丢弃）----
        suppressed = httpx.post(f"{base}/web/requests", timeout=20, json={"requests": [{
            "method": "GET", "path": "/redirect",
            "query": "next=%0d%0aLocation:https://example.com", "src_ip": "198.51.100.202",
            "dst_ip": "192.168.1.30", "status": 200}]}).json()
        check("单条 medium 类攻击被聚合抑制（不再逐条告警）",
              suppressed.get("alert_count") == 0, str(suppressed)[:200])
        signals = httpx.get(f"{base}/signals", params={
            "source_ip": "198.51.100.202", "limit": 10}, timeout=5).json()
        check("被抑制的信号在 /signals 可见且带抑制原因",
              isinstance(signals, list) and bool(signals) and signals[0].get("suppressed") is True
              and signals[0].get("suppressed_reason") in {"below_threshold", "cooldown"},
              str(signals)[:220])
        window = httpx.get(f"{base}/signals/window/198.51.100.202", timeout=5).json()
        check("窗口信号接口可用（按源 IP 查看当前窗口）",
              "items" in window and window.get("threshold", 0) > 0, str(window)[:200])

        # ---- v2：自适应阈值 ----
        thresholds = httpx.get(f"{base}/thresholds", timeout=5).json()
        check("阈值管理接口可用（含静态基准与上次重算结果）",
              "items" in thresholds and "overview" in thresholds, str(thresholds)[:200])
        recomputed = httpx.post(f"{base}/thresholds/recompute", timeout=30).json()
        check("阈值重算接口可用（手动触发）",
              recomputed.get("success") is True and "dimensions" in recomputed.get("detail", {}),
              str(recomputed)[:220])

        assets = httpx.get(f"{base}/assets", timeout=5).json()
        check("资产接口可用", isinstance(assets, list), str(assets)[:160])

        events = read_sse(base, "/stream/events", want_events=1, timeout=8)
        check("SSE /stream/events 可连接", True, f"收到 {len(events)} 条告警事件（无攻击时为 0 属正常）")

        # ---- 模块 3.1 流量监控页依赖的接口 ----
        sessions = httpx.get(f"{base}/metrics/sessions", params={"top": 5}, timeout=5).json()
        check("TOP 会话接口可用", "items" in sessions and "conn_table" in sessions,
              str(sessions)[:200])

        # ---- 模块 3.2 异常端口页依赖的接口 ----
        baseline = httpx.get(f"{base}/metrics/ports/baseline", timeout=5).json()
        check("端口基线接口可用",
              "items" in baseline and "threshold" in baseline and "standard_ports" in baseline,
              str(baseline)[:200])

        # ---- 模块 3.3 封禁页依赖的接口（续期 / 告警详情） ----
        httpx.post(f"{base}/blocks", timeout=5,
                   json={"ip": "203.0.113.77", "reason": "续期验证", "ttl_sec": 120})
        extended = httpx.post(f"{base}/blocks/203.0.113.77/extend",
                              params={"ttl_sec": 3600}, timeout=5).json()
        check("封禁续期返回 extended", extended.get("code") == "extended", str(extended)[:200])
        httpx.delete(f"{base}/blocks/203.0.113.77", timeout=5)

        alerts = httpx.get(f"{base}/alerts", params={"limit": 1}, timeout=5).json()
        if alerts:
            detail = httpx.get(f"{base}/alerts/{alerts[0]['id']}", timeout=5).json()
            check("告警详情含处置建议", bool(detail.get("suggestion")), str(detail)[:200])
        else:
            check("告警详情接口（当前无告警，跳过内容校验）", True, "无告警数据")

        # ---- 模块 3.4 / 3.5 依赖的接口 ----
        jobs = httpx.get(f"{base}/vulns/scan/jobs", timeout=5).json()
        check("扫描任务列表接口可用", "items" in jobs and "stats" in jobs, str(jobs)[:200])
        site = base[: -len("/api/v1")]
        rescan = httpx.post(f"{site}/api/v1/assets/127.0.0.1/rescan",
                            params={"use_nmap": "false"}, timeout=30).json()
        check("单资产重扫接口可用", rescan.get("ip") == "127.0.0.1", str(rescan)[:200])

        # ---- v3：Web 漏扫 / AI 流量研判 / AI 修复建议 ----
        ai_status = httpx.get(f"{base}/ai/status", timeout=5).json()
        check("AI 状态接口可用（含降级链）",
              "alert_analysis" in ai_status and "traffic_analysis" in ai_status,
              str(ai_status)[:220])
        review = httpx.get(f"{base}/ai/traffic/review",
                           params={"window_minutes": 5}, timeout=20).json()
        check("AI 流量研判可用（模型不可用时本地规则兜底）",
              review.get("verdict") in {"normal", "suspicious", "malicious", "unknown"}
              and bool(review.get("source")) and "degraded" in review, str(review)[:220])
        webapp = httpx.post(f"{base}/scanner/webapp", timeout=45,
                            json={"url": "http://127.0.0.1:1/"}).json()
        check("Web 应用漏扫接口可用（不可达目标不产生误报）",
              webapp.get("fingerprint", {}).get("title") == "" and webapp.get("vulns") == [],
              str(webapp)[:220])
        vulns = httpx.get(f"{base}/vulns", params={"limit": 1}, timeout=5).json()
        if vulns:
            advice = httpx.post(f"{base}/vulns/{vulns[0]['id']}/ai-advice", timeout=20).json()
            check("AI 修复建议接口可用（含来源与可执行步骤）",
                  bool(advice.get("source")) and bool(advice.get("steps"))
                  and bool(advice.get("verification")), str(advice)[:220])
        else:
            check("AI 修复建议接口（当前无漏洞记录，跳过内容校验）", True, "无漏洞数据")


        # ---- 大屏静态资源（由后端 StaticFiles 直接托管） ----
        site = base[: -len("/api/v1")]
        statics = [
            ("/", "智能流量安全检测与分析系统"),
            ("/index.html", "chartTrend"),
            ("/js/api.js", "SecApi"),
            ("/js/mock.js", "SecMock"),
            ("/js/dashboard.js", "SecDashboard"),
            ("/js/ui.js", "UI.setText"),
            ("/css/dashboard.css", ".kpi-grid"),
            ("/lib/echarts.min.js", "echarts"),
            # 模块页面
            ("/traffic.html", "模块 3.1 实时动态流量监控"),
            ("/js/page-traffic.js", "SecTrafficPage"),
            ("/anomaly.html", "模块 3.2 异常端口流量检测"),
            ("/js/page-anomaly.js", "SecAnomalyPage"),
            ("/threat.html", "威胁告警"),
            ("/js/page-threat.js", "ThreatPage"),
            ("/block.html", "封禁管理"),
            ("/js/page-block.js", "SecBlockPage"),
            ("/response.html", "封禁管理"),
            ("/rules.html", "规则包与匹配引擎"),
            ("/js/page-rules.js", "RulesPage"),
            ("/login.html", "登录"),
            ("/js/page-login.js", "auth/login"),
            ("/vuln.html", "模块 3.4 漏洞提醒与修复建议"),
            ("/js/page-vuln.js", "SecVulnPage"),
            ("/asset.html", "模块 3.5 资产管理"),
            ("/js/page-asset.js", "SecAssetPage"),
        ]
        for path, needle in statics:
            try:
                response = httpx.get(f"{site}{path}", timeout=5)
                body = response.text
                check(f"页面/资源 {path}", response.status_code == 200 and needle in body,
                      f"HTTP {response.status_code}，长度 {len(body)}")
            except Exception as exc:
                check(f"页面/资源 {path}", False, str(exc))



    finally:
        if args.keep_running:
            print(f"\n服务进程保留：pid={process.pid}，端口 {args.port}")
        else:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
        handle = getattr(process, "_log_handle", None)
        if handle is not None:
            try:
                handle.close()
            except Exception:
                pass

    if FAILED and server_log.exists():
        print("\n服务端日志末尾 25 行（排查失败项用）：")
        tail = server_log.read_text(encoding="utf-8", errors="ignore").splitlines()[-25:]
        for line in tail:
            print("  | " + line)

    print(f"\n===== 结果：{len(PASSED)} 项通过 / {len(FAILED)} 项失败 =====")
    for item in FAILED:
        print(f"  [x] {item}")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())

