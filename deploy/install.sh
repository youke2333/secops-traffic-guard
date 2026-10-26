#!/usr/bin/env bash
# ============================================================================
# 智能流量安全检测与分析系统 —— 裸机（非容器）安装脚本
#
# 适用：CentOS7+ / Ubuntu20.04+ / openEuler / Kylin，需要 root 权限
# 做四件事：
#   1. 安装系统依赖（python3、libpcap、nmap、iptables/nft、nginx 可选）
#   2. 创建 Python 虚拟环境并安装依赖
#   3. 赋予 Python 二进制 CAP_NET_RAW / CAP_NET_ADMIN（免 root 抓包与封禁）
#   4. 生成 .env、注册 systemd 服务、启动并自检
#
# 用法：sudo bash deploy/install.sh [--with-nginx] [--live-firewall] [--web-profile] [--http-proxy]
#   --with-nginx      额外用 nginx 托管大屏（否则由后端直接托管 8000 端口）
#   --live-firewall   把 DRY_RUN 置为 false（★ 会真正修改防火墙，请确认白名单！）
#   --web-profile     使用单机 Web 业务（Apache 8080）推荐配置模板
#   --http-proxy      高保真接入：代理占用 8080，业务站点改 8081，完整请求（含 POST body）投递检测
# ============================================================================
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY_BIN="${PY_BIN:-python3}"
VENV_DIR="${REPO_DIR}/.venv"
WITH_NGINX=0
LIVE_FIREWALL=0
WEB_PROFILE=0
HTTP_PROXY=0

for arg in "$@"; do
  case "${arg}" in
    --with-nginx) WITH_NGINX=1 ;;
    --live-firewall) LIVE_FIREWALL=1 ;;
    --web-profile) WEB_PROFILE=1 ;;
    --http-proxy) WEB_PROFILE=1; HTTP_PROXY=1 ;;
    *) echo "未知参数: ${arg}"; exit 1 ;;
  esac
done

log() { printf '\033[1;36m[install]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*"; }

if [[ "${EUID}" -ne 0 ]]; then
  echo "请以 root 运行：sudo bash deploy/install.sh" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# 1. 系统依赖
# ---------------------------------------------------------------------------
log "安装系统依赖…"
if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y python3 python3-venv python3-pip libpcap-dev nmap iptables nftables iproute2 curl
  [[ "${WITH_NGINX}" -eq 1 ]] && apt-get install -y nginx
elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
  PKG="$(command -v dnf || command -v yum)"
  ${PKG} install -y python3 python3-pip libpcap nmap iptables nftables iproute curl
  [[ "${WITH_NGINX}" -eq 1 ]] && ${PKG} install -y nginx
else
  warn "未识别的包管理器，请手动安装：python3 libpcap nmap iptables"
fi

# ---------------------------------------------------------------------------
# 2. Python 环境
# ---------------------------------------------------------------------------
log "创建虚拟环境：${VENV_DIR}"
${PY_BIN} -m venv "${VENV_DIR}"
"${VENV_DIR}/bin/pip" install --upgrade pip
"${VENV_DIR}/bin/pip" install -r "${REPO_DIR}/backend/requirements.txt"
# 可选依赖：RE2 多模式预筛（离线环境可直接跳过；未安装时自动回落 python 后端）
if ! "${VENV_DIR}/bin/pip" install google-re2; then
  warn "google-re2 安装失败（离线/架构不支持）：MATCH_BACKEND=auto 将回落 python 后端"
fi

# ---------------------------------------------------------------------------
# 3. 抓包/封禁能力（免 root）
# ---------------------------------------------------------------------------
# 注意：给 /usr/bin/pythonX.Y 打 setcap 后，某些环境下 systemd 再以
# AmbientCapabilities 启动会出现 `Failed to execute ...: Operation not permitted`
# （status=203/EXEC）。本服务的 unit 已以 root 运行并带 AmbientCapabilities，
# root 天然具备 CAP_NET_RAW/CAP_NET_ADMIN，因此**默认跳过 setcap**。
# 确有「以非 root 用户运行」的需求时，显式 SETCAP_ENABLE=1 再执行本脚本。
if [[ "${SETCAP_ENABLE:-0}" == "1" ]]; then
  PY_REAL="$(readlink -f "${VENV_DIR}/bin/python3" || readlink -f "${VENV_DIR}/bin/python")"
  log "为 Python 二进制授予 CAP_NET_RAW / CAP_NET_ADMIN：${PY_REAL}"
  if command -v setcap >/dev/null 2>&1; then
    setcap 'cap_net_raw,cap_net_admin,cap_net_bind_service+eip' "${PY_REAL}" || \
      warn "setcap 失败，若抓包报权限错误，请改用 root 运行服务"
  else
    warn "未找到 setcap（libcap 未安装），将以 root 运行服务"
  fi
else
  log "跳过 setcap（服务以 root + AmbientCapabilities 运行，无需文件能力）"
fi

# ---------------------------------------------------------------------------
# 4. 配置与 systemd
# ---------------------------------------------------------------------------
ENV_FILE="${REPO_DIR}/.env"
if [[ ! -f "${ENV_FILE}" ]]; then
  if [[ "${WEB_PROFILE}" -eq 1 ]]; then
    log "使用单机 Web 业务配置模板：deploy/env.web.example"
    cp "${REPO_DIR}/deploy/env.web.example" "${ENV_FILE}"
    IFACE="$(ip -o route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
    if [[ -n "${IFACE}" ]]; then
      sed -i "s|^CAPTURE_IFACE=.*|CAPTURE_IFACE=${IFACE}|" "${ENV_FILE}"
      log "自动识别采集网卡：${IFACE}"
    fi
    if [[ -f /var/log/apache2/access.log ]]; then
      log "检测到 Apache 访问日志：/var/log/apache2/access.log"
    else
      warn "未找到 /var/log/apache2/access.log：请确认业务站点已启用（a2ensite）并产生访问"
    fi
    HOST_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
    if [[ -n "${HOST_IP}" ]]; then
      sed -i "s|^WEB_DEFAULT_DST_IP=.*|WEB_DEFAULT_DST_IP=${HOST_IP}|" "${ENV_FILE}"
      log "业务地址（日志缺省目的 IP）：${HOST_IP}"
    fi
  else
    log "生成 ${ENV_FILE}"
    cp "${REPO_DIR}/backend/.env.example" "${ENV_FILE}"
  fi

  # 首次生成配置时可预先指定管理员初始密码。
  # 必须在首次启动**之前**写入：ensure_initial_admin() 只在用户表为空时创建 admin，
  # 一旦以随机密码建过号，事后再改这个配置不会生效（表现为"照着文档填密码却登不上"）。
  if [[ -n "${SECOPS_ADMIN_PASSWORD:-}" ]]; then
    # 密码里的 & 在 sed 替换串中代表"整个匹配"，必须先转义；分隔符因此用 |，
    # 所以密码本身不要包含 | 字符。
    ADMIN_PW_ESC="$(printf '%s' "${SECOPS_ADMIN_PASSWORD}" | sed 's/[&|]/\\&/g')"
    if grep -q '^ADMIN_INITIAL_PASSWORD=' "${ENV_FILE}"; then
      sed -i "s|^ADMIN_INITIAL_PASSWORD=.*|ADMIN_INITIAL_PASSWORD=${ADMIN_PW_ESC}|" "${ENV_FILE}"
    else
      printf 'ADMIN_INITIAL_PASSWORD=%s\n' "${SECOPS_ADMIN_PASSWORD}" >> "${ENV_FILE}"
    fi
    log "已写入管理员初始密码（首次登录账号 admin）"
  fi
  sed -i "s|^DB_URL=.*|DB_URL=sqlite:///${REPO_DIR}/backend/data/secops.db|" "${ENV_FILE}"
  sed -i "s|^DASHBOARD_DIR=.*|DASHBOARD_DIR=${REPO_DIR}/dashboard|" "${ENV_FILE}"
fi

# 登录启用时，为机器调用（HTTP 代理 / WAF / 脚本）生成 API_TOKEN；否则 /web/requests 会被 401 拒绝。
if ! grep -q '^AUTH_ENABLED=false' "${ENV_FILE}" 2>/dev/null; then
  if grep -Eq '^API_TOKEN=[[:space:]]*(#.*)?$' "${ENV_FILE}" 2>/dev/null; then
    MACHINE_TOKEN="$(openssl rand -hex 24 2>/dev/null || date +%s%N | sha256sum | cut -c1-48)"
    sed -i "s|^API_TOKEN=.*|API_TOKEN=${MACHINE_TOKEN}|" "${ENV_FILE}"
    log "已生成机器调用 API_TOKEN（代理/WAF/脚本使用；浏览器仍走登录会话）"
  fi
fi
if [[ "${LIVE_FIREWALL}" -eq 1 ]]; then
  warn "DRY_RUN=false：将真正下发防火墙规则，请确认 WHITELIST_CIDRS 不含业务网段！"
  sed -i 's/^DRY_RUN=.*/DRY_RUN=false/' "${ENV_FILE}"
fi

if [[ "${HTTP_PROXY}" -eq 1 ]]; then
  # 高保真模式：代理占 8080，Apache 退到 8081；POST body 才能进入检测链路
  if grep -q '^Listen 8080' /etc/apache2/ports.conf 2>/dev/null; then
    sed -i 's/^Listen 8080/Listen 8081/' /etc/apache2/ports.conf
    log "Apache 端口 8080 → 8081"
  fi
  # 8081 只绑回环：它是业务站点的"内部端口"，外部直连会完全绕过高保真代理，
  # 检测链路失效（威胁事件页一条都不会有）。防火墙封端口不如直接不监听。
  SITE_BIND="${SITE_BIND:-127.0.0.1}"
  sed -i -E '/^[[:space:]]*[Ll][Ii][Ss][Tt][Ee][Nn][[:space:]].*8081[[:space:]]*$/d' \
    /etc/apache2/ports.conf
  printf 'Listen %s:8081\n' "${SITE_BIND}" >> /etc/apache2/ports.conf
  log "8081 监听：${SITE_BIND}:8081（外部只能经 8080 代理访问）"
  while IFS= read -r site; do
    sed -i 's/<VirtualHost \*:8080>/<VirtualHost *:8081>/' "${site}"
  done < <(grep -rl '<VirtualHost \*:8080>' /etc/apache2/sites-available 2>/dev/null || true)
  systemctl restart apache2 2>/dev/null || warn "Apache 重启失败，请检查配置"
  sed -i 's/^WEB_DETECT_SOURCE=.*/WEB_DETECT_SOURCE=api/' "${ENV_FILE}"
  PROXY_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
  PROXY_UNIT="/etc/systemd/system/secops-http-proxy.service"
  cat > "${PROXY_UNIT}" <<EOF
[Unit]
Description=SecOps HTTP Access Proxy (完整请求投递)
After=network-online.target apache2.service
Requires=apache2.service

[Service]
Type=simple
EnvironmentFile=${ENV_FILE}
ExecStart=${VENV_DIR}/bin/python ${REPO_DIR}/scripts/http_proxy.py --listen 0.0.0.0:8080 --upstream 127.0.0.1:8081 --api http://127.0.0.1:8000/api/v1 --dst-ip ${PROXY_IP:-127.0.0.1}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
  log "写入代理服务：${PROXY_UNIT}（8080 → Apache 8081，完整请求投递检测）"
fi



SERVICE_FILE="/etc/systemd/system/secops-traffic-guard.service"
log "写入 systemd 服务：${SERVICE_FILE}"
cat > "${SERVICE_FILE}" <<EOF
[Unit]
Description=SecOps Traffic Guard (智能流量安全检测与分析系统)
After=network-online.target apache2.service
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${REPO_DIR}/backend
EnvironmentFile=${ENV_FILE}
ExecStart=${VENV_DIR}/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 1
Restart=always
RestartSec=5
# 抓包与防火墙能力（对应安装步骤 3 的 setcap；两者取其一即可）
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN CAP_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN CAP_BIND_SERVICE
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now secops-traffic-guard.service

if [[ "${HTTP_PROXY}" -eq 1 ]]; then
  systemctl enable --now secops-http-proxy.service 2>/dev/null || \
    warn "代理启动失败（端口 8080 可能被占用）：journalctl -u secops-http-proxy -n 50"
  sleep 1
  if curl -fsS --max-time 3 http://127.0.0.1:8080/ >/dev/null 2>&1; then
    log "高保真接入自检通过：http://127.0.0.1:8080/"
  else
    warn "高保真接入自检失败：检查 secops-http-proxy 与业务站点 8081 监听"
  fi
  log "高保真接入已启用：访问 http://<VM-IP>:8080/ 的请求会被完整检测"
fi

if [[ "${WITH_NGINX}" -eq 1 ]]; then
  log "配置 nginx 托管大屏…"
  cat > /etc/nginx/conf.d/secops.conf <<EOF
server {
    listen 80;
    server_name _;
    root ${REPO_DIR};
    index dashboard/index.html;
    location = / { return 302 /dashboard/; }
    location /dashboard/ { alias ${REPO_DIR}/dashboard/; try_files \$uri \$uri/ /dashboard/index.html; }
    location /api/v1/stream/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_buffering off;
        proxy_read_timeout 24h;
        add_header X-Accel-Buffering no;
    }
    location /api/ { proxy_pass http://127.0.0.1:8000; proxy_set_header Host \$host; proxy_read_timeout 300s; proxy_buffering off; }
    location /docs { proxy_pass http://127.0.0.1:8000; }
    location /openapi.json { proxy_pass http://127.0.0.1:8000; }
}
EOF
  nginx -t && systemctl reload nginx
fi

# ---------------------------------------------------------------------------
# 5. 自检
# ---------------------------------------------------------------------------
log "等待服务就绪…"
for _ in $(seq 1 20); do
  if curl -fsS http://127.0.0.1:8000/api/v1/health >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

if curl -fsS http://127.0.0.1:8000/api/v1/health >/dev/null 2>&1; then
  log "部署成功 ✅"
  curl -s http://127.0.0.1:8000/api/v1/health
  echo
  if [[ "${WITH_NGINX}" -eq 1 ]]; then
    echo "  大屏地址：http://$(hostname -I | awk '{print $1}')/dashboard/"
  else
    echo "  大屏地址：http://$(hostname -I | awk '{print $1}'):8000/"
  fi
  echo "  API 文档：/docs ｜ 状态自检：/api/v1/status"
  echo "  登录页：http://$(hostname -I | awk '{print $1}'):8000/login.html"
  if ! grep -q '^AUTH_ENABLED=false' "${ENV_FILE}" 2>/dev/null; then
    if grep -q '^ADMIN_INITIAL_PASSWORD=$' "${ENV_FILE}" 2>/dev/null; then
      echo "  首次登录密码（仅本次安装生成）："
      journalctl -u secops-traffic-guard -n 200 --no-pager 2>/dev/null | grep -A2 "一次性密码" | tail -3 || true
      echo "  若已滚动：journalctl -u secops-traffic-guard | grep 一次性密码"
    else
      echo "  首次登录账号：admin（密码为 .env 中的 ADMIN_INITIAL_PASSWORD）"
    fi
  fi
  echo "  日志查看：journalctl -u secops-traffic-guard -f"

  # Web 业务预检放在所有服务启动之后：此时端口已完成 8080/8081 的重新分配，
  # 代理与后端都已拉起，检查结果才是真实状态。
  # （此前的顺序是"先预检后搬端口"，会固定产出 8080 未监听 / 站点不可达 / 服务未就绪
  #   三个假失败，让人误以为部署坏了。）
  if [[ "${WEB_PROFILE}" -eq 1 ]]; then
    SITE_PORT=8080
    [[ "${HTTP_PROXY}" -eq 1 ]] && SITE_PORT=8081
    echo
    log "Web 业务预检（Apache / ${SITE_PORT} / 访问日志 / 服务）…"
    WEB_CHECK_URL="http://127.0.0.1:${SITE_PORT}/" \
      bash "${REPO_DIR}/scripts/web_healthcheck.sh" || \
      warn "预检存在失败项：请按提示修复后再做攻击验证"
  fi
else
  warn "服务未通过健康检查，请查看日志：journalctl -u secops-traffic-guard -n 100"
  exit 1
fi
