#!/usr/bin/env bash
# ============================================================================
# Web 业务接入预检（在 Ubuntu 虚拟机内执行）
#   sudo bash scripts/web_healthcheck.sh
# 检查：业务站点可达、监听端口、访问日志可读、抓包/防火墙能力、服务健康
#
# 说明：脚本不假设被测 Web 应用是任何特定产品。默认探测本机 8080，
#       可用 WEB_CHECK_URL 指定任意地址，例如：
#         WEB_CHECK_URL=http://127.0.0.1:8080/app/ bash scripts/web_healthcheck.sh
# ============================================================================
set -u

WEB_CHECK_URL="${WEB_CHECK_URL:-http://127.0.0.1:8080/}"
ENV_FILE="${ENV_FILE:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/.env}"
if [[ -z "${WEB_LOG_PATH:-}" && -f "${ENV_FILE}" ]]; then
  WEB_LOG_PATH="$(grep -E '^WEB_LOG_PATH=' "${ENV_FILE}" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d '[:space:]')"
fi
WEB_LOG_PATH="${WEB_LOG_PATH:-/var/log/apache2/access.log}"
API_BASE="${API_BASE:-http://127.0.0.1:8000/api/v1}"
if [[ -z "${API_TOKEN:-}" && -f "${ENV_FILE}" ]]; then
  API_TOKEN="$(grep -E '^API_TOKEN=' "${ENV_FILE}" 2>/dev/null | tail -1 | cut -d= -f2- | cut -d'#' -f1 | tr -d '[:space:]')"
fi
AUTH_HEADER=()
[[ -n "${API_TOKEN:-}" ]] && AUTH_HEADER=(-H "X-API-Token: ${API_TOKEN}")
FAILED=0

ok()   { printf '\033[1;32m[OK]\033[0m   %s\n' "$*"; }
bad()  { printf '\033[1;31m[FAIL]\033[0m %s\n' "$*"; FAILED=$((FAILED + 1)); }
warn() { printf '\033[1;33m[WARN]\033[0m %s\n' "$*"; }

# 从 URL 解析主机端口（默认 80/443）
HOSTPORT="${WEB_CHECK_URL#*://}"
HOSTPORT="${HOSTPORT%%/*}"
CHECK_HOST="${HOSTPORT%%:*}"
CHECK_PORT="${HOSTPORT##*:}"
[[ "${CHECK_PORT}" == "${HOSTPORT}" ]] && CHECK_PORT=80

echo "== 1. Web 业务站点（${WEB_CHECK_URL}） =="
if systemctl is-active --quiet apache2 2>/dev/null; then
  ok "apache2 服务运行中"
elif systemctl is-active --quiet nginx 2>/dev/null; then
  ok "nginx 服务运行中"
else
  warn "未检测到运行中的 apache2/nginx（若业务用其它容器/进程托管可忽略）"
fi

if ss -ltn 2>/dev/null | grep -q ":${CHECK_PORT} "; then
  ok "${CHECK_PORT} 端口已监听"
else
  bad "${CHECK_PORT} 未监听（检查业务站点配置与监听端口）"
fi

CODE="$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "${WEB_CHECK_URL}" 2>/dev/null || echo 000)"
if [[ "${CODE}" =~ ^(200|301|302|401|403)$ ]]; then
  ok "站点可达（HTTP ${CODE}）：${WEB_CHECK_URL}"
else
  bad "站点不可达（HTTP ${CODE}）：${WEB_CHECK_URL}"
fi

TITLE="$(curl -s --max-time 3 "${WEB_CHECK_URL}" 2>/dev/null | grep -o -i '<title>[^<]*' | head -1 | sed 's/<title>//I')"
if [[ -n "${TITLE}" ]]; then
  ok "页面标题：${TITLE:0:80}（漏扫据此记录指纹，与产品无关）"
else
  warn "页面无 <title> 或需要登录：漏扫将按通用检查项（响应头/敏感文件/版本/目录）评估"
fi

echo "== 2. 访问日志（Web 攻击检测输入） =="
if [[ -r "${WEB_LOG_PATH}" ]]; then
  ok "访问日志可读：${WEB_LOG_PATH}"
  tail -n 1 "${WEB_LOG_PATH}" 2>/dev/null | cut -c1-160
else
  bad "访问日志不可读：${WEB_LOG_PATH}（当前用户 $(id -un)，文件权限 $(stat -c '%U:%G %a' "${WEB_LOG_PATH}" 2>/dev/null || echo '不存在')）"
  echo "     修复：sudo usermod -aG adm $(id -un) 后重新登录；或以 root 运行后端。"
  echo "     另请确认 WEB_LOG_PATH 与业务站点的 CustomLog/access_log 一致。"
fi

DETECT_SOURCE="$(grep -E '^WEB_DETECT_SOURCE=' "${ENV_FILE}" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d '[:space:]')"
if systemctl is-active --quiet secops-http-proxy 2>/dev/null; then
  ok "高保真代理运行中（8080 → 业务站点 8081）：POST body 也能进入检测"
elif [[ "${DETECT_SOURCE}" == "api" ]]; then
  warn "WEB_DETECT_SOURCE=api，但代理服务未运行：将收不到请求投递（systemctl status secops-http-proxy）"
elif [[ "${DETECT_SOURCE}" == "log" && ! -r "${WEB_LOG_PATH}" ]]; then
  bad "日志检测模式下访问日志不可读"
else
  warn "当前为日志模式：URL/查询类攻击可检出；命令注入/文件上传等 POST body 建议启用 --http-proxy"
fi

echo "== 3. 抓包 / 防火墙能力 =="
if command -v nmap >/dev/null 2>&1; then ok "nmap 已安装：$(nmap --version 2>/dev/null | head -1)"; else warn "未安装 nmap（自动降级为 banner 抓取）"; fi
if command -v iptables >/dev/null 2>&1; then ok "iptables 可用"; else warn "iptables 不可用（FIREWALL_BACKEND=none 时只记录不封禁）"; fi
if [[ "$(id -u)" -ne 0 ]]; then warn "当前非 root：抓包/封禁可能因权限失败（建议 sudo 或 setcap）"; fi

echo "== 4. 检测服务 =="
HEALTH="$(curl -s --max-time 3 "${API_BASE}/health" 2>/dev/null || true)"
if [[ -n "${HEALTH}" ]]; then
  ok "服务健康：${HEALTH}"
else
  bad "服务未就绪：${API_BASE}/health（sudo systemctl status secops-traffic-guard）"
fi
AI="$(curl -s --max-time 3 "${AUTH_HEADER[@]}" "${API_BASE}/ai/status" 2>/dev/null || true)"
if [[ -n "${AI}" ]]; then ok "AI 状态接口可用：${AI:0:120}…"; else warn "AI 状态接口不可用（旧版本或服务未启动）"; fi
if [[ -n "${AI}" ]] && echo "${AI}" | grep -q '"client_available":true'; then
  ok "LLM API 已配置（AI 研判走真实模型）"
else
  warn "LLM 未配置/不可用：自动降级到本地规则与知识库（功能仍可用）"
fi

echo
if [[ "${FAILED}" -eq 0 ]]; then
  printf '\033[1;32m预检通过（0 项失败）\033[0m\n'
else
  printf '\033[1;31m预检失败：%d 项，请按提示修复\033[0m\n' "${FAILED}"
fi
exit "${FAILED}"
