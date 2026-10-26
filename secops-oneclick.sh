#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# 0. 自愈：文件若是从 Windows 拷来的 CRLF，就地转 LF 后重新执行自身。
#    只有把行尾的 \r 落在注释里，这一行才能在 CRLF 状态下也被正常解析；
#    转换必须放在任何 set / 多行结构之前，否则 \r 会让它们直接报语法错。
grep -qaU $'\r' "$0" 2>/dev/null && sed -i 's/\r$//' "$0" && exec bash "$0" "$@"  # self-heal-crlf
# -----------------------------------------------------------------------------
# =============================================================================
# secops-oneclick.sh  智能流量安全检测系统 一键部署
#   VMware Ubuntu + Apache 被测站点(8080) + 高保真代理 + 漏洞靶场(DVWA 等)
#
# 用法（root）：
#     bash secops-oneclick.sh
#   首次请用 bash 调用（CRLF 文件的内核 shebang 解析会失败，脚本无法自救）；
#   脚本会先把自身转成 LF，之后 ./secops-oneclick.sh 也能直接跑。
#
# 前提：Ubuntu 已安装 Apache + PHP（被测站点需要数据库时另装 MySQL/MariaDB），
#       被测站点位于 /var/www/html —— 放根目录或子目录（如 /var/www/html/dvwa）都可以，
#       脚本会自动识别入口并给出正确访问地址。
#
# 本脚本幂等，可重复执行。它会依次完成：
#   1) .sh/.py/.js/.css/.html/.json/.example/.env 换行符 CRLF -> LF
#   2) 归一化站点目录大小写，自动识别站点入口（支持子目录部署）
#   3) 收敛 Apache 到 8081：禁用其它抢占端口的 vhost，写入唯一 vhost（含关闭 gzip）
#   4) 清理 env 模板中的行内注释
#   5) 调用 deploy/install.sh --web-profile --http-proxy
#   6) 写入运行配置（网段/白名单/采集/防火墙/降噪/忽略自扫描来源）
#   7) 重启并做全链路自检（服务/端口/健康检查/代理转发/跳转地址/Cookie 域）
#

set -euo pipefail

log()  { printf '\033[1;36m[oneclick]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }

[ "${EUID}" -eq 0 ] || die "请用 root 运行：sudo bash secops-oneclick.sh"

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -f "${REPO_DIR}/deploy/install.sh" ] || \
  die "请把本脚本放在仓库根目录（与 deploy/ 同级，通常是 /opt/secops）"

# -----------------------------------------------------------------------------
# 0. 自动探测环境
# -----------------------------------------------------------------------------
HOST_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
[ -n "${HOST_IP}" ] || die "未探测到本机 IP（hostname -I 为空），请检查网卡"
PREFIX="$(echo "${HOST_IP}" | cut -d. -f1-3)"
PROTECTED="${PREFIX}.0/24"
ADMIN_HOST="${PREFIX}.1/32"
IFACE="$(ip -o route get 1.1.1.1 2>/dev/null \
  | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
IFACE="${IFACE:-ens33}"
log "探测结果：本机IP=${HOST_IP} 网卡=${IFACE} 受保护网段=${PROTECTED} 网关白名单=${ADMIN_HOST}"
# 管理员初始密码：可用环境变量覆盖，例如 SECOPS_ADMIN_PASSWORD='Xxx@12345' bash secops-oneclick.sh
ADMIN_PASSWORD="${SECOPS_ADMIN_PASSWORD:-SecOps@2026Lab}"

# -----------------------------------------------------------------------------
# 1. 换行符 CRLF -> LF
# -----------------------------------------------------------------------------
log "转换 .sh/.py/.example/.env/.js/.css/.html/.json 换行符（CRLF -> LF）…"
find "${REPO_DIR}" -type f \
  \( -name '*.sh' -o -name '*.py' -o -name '*.example' -o -name '*.env' \
     -o -name '*.js' -o -name '*.css' -o -name '*.html' -o -name '*.json' \) \
  -exec sed -i 's/\r$//' {} +
chmod +x "${REPO_DIR}/deploy/install.sh" 2>/dev/null || true
chmod +x "${REPO_DIR}"/scripts/*.sh 2>/dev/null || true

# -----------------------------------------------------------------------------
# 2. 被测站点：目录归一化 + 入口识别
# -----------------------------------------------------------------------------
command -v apache2 >/dev/null 2>&1 || \
  die "未安装 apache2。请先准备 Web 站点：apt install -y apache2 php libapache2-mod-php"

SITE_ROOT="/var/www/html"
[ -d "${SITE_ROOT}" ] || die "未发现 ${SITE_ROOT}：请先部署被测 Web 站点"

# 2.1 顶层目录大小写归一（例如 DVWA -> dvwa），避免 vhost 指向大小写不一致的路径
for upper in $(find "${SITE_ROOT}" -maxdepth 1 -type d 2>/dev/null); do
  base="$(basename "${upper}")"
  lower="$(echo "${base}" | tr '[:upper:]' '[:lower:]')"
  if [ "${base}" != "${lower}" ] && [ ! -e "${SITE_ROOT}/${lower}" ]; then
    log "统一站点目录大小写：${base} -> ${lower}"
    mv "${SITE_ROOT}/${base}" "${SITE_ROOT}/${lower}"
  fi
done

# 2.2 入口识别：根目录有入口就用根；否则找第一个带 login.php/index.php 的子目录
SITE_PREFIX="/"
SITE_ENTRY=""
if [ -f "${SITE_ROOT}/index.php" ] || [ -f "${SITE_ROOT}/index.html" ]; then
  SITE_PREFIX="/"
  SITE_ENTRY="index.php 或 index.html"
else
  for d in "${SITE_ROOT}"/*/; do
    [ -d "${d}" ] || continue
    if [ -f "${d}login.php" ]; then
      SITE_PREFIX="/$(basename "${d}")/"
      SITE_ENTRY="login.php"
      break
    elif [ -f "${d}index.php" ]; then
      SITE_PREFIX="/$(basename "${d}")/"
      SITE_ENTRY="index.php"
      break
    fi
  done
fi
if [ -n "${SITE_ENTRY}" ]; then
  log "站点入口：${SITE_ROOT}${SITE_PREFIX}${SITE_ENTRY}（对外路径 ${SITE_PREFIX}）"
else
  warn "${SITE_ROOT} 下未发现 index.php/index.html/login.php：请确认被测站点已部署"
fi

# -----------------------------------------------------------------------------
# 3. Apache 收敛到 8081，把 8080 让给高保真代理
# -----------------------------------------------------------------------------
log "收敛 Apache：8080 让给高保真代理，站点固定在 8081 …"
systemctl stop secops-http-proxy 2>/dev/null || true

# 3.1 ports.conf：8080 让给代理；8081 只绑回环，禁止从网络直连
#     8081 是业务站点的"内部端口"，任何直连都会完全绕过高保真代理，检测链路失效。
#     需要临时从外部直连 8081 调试时：SITE_BIND=0.0.0.0 bash secops-oneclick.sh
SITE_BIND="${SITE_BIND:-127.0.0.1}"
sed -i -E 's|^[[:space:]]*[Ll][Ii][Ss][Tt][Ee][Nn][[:space:]]+8080[[:space:]]*$|# 8080 reserved for secops-http-proxy|' \
  /etc/apache2/ports.conf
# 先清掉历史遗留的 8081 监听行（裸 8081 / 绑 0.0.0.0 / 上一轮的绑定地址），再写唯一一条。
# 否则会同时监听两个地址，Apache 重启时直接 Address already in use。
sed -i -E '/^[[:space:]]*[Ll][Ii][Ss][Tt][Ee][Nn][[:space:]].*8081[[:space:]]*$/d' \
  /etc/apache2/ports.conf
printf 'Listen %s:8081\n' "${SITE_BIND}" >> /etc/apache2/ports.conf
log "8081 监听地址：${SITE_BIND}（默认仅本机，外部必须经 8080 代理访问）"

# 3.2 禁用除本脚本 vhost 之外的所有站点：避免 default server 抢 8081 导致整站 404
if [ -d /etc/apache2/sites-enabled ]; then
  for site_link in /etc/apache2/sites-enabled/*.conf; do
    [ -e "${site_link}" ] || continue
    site_name="$(basename "${site_link}")"
    [ "${site_name}" = "secops-webapp.conf" ] && continue
    log "禁用站点：${site_name}"
    a2dissite "${site_name}" >/dev/null 2>&1 || rm -f "${site_link}"
  done
fi

# 3.3 写入唯一 vhost；SetEnv no-gzip 保证检测系统留存的响应体是可读文本
cat > /etc/apache2/sites-available/secops-webapp.conf <<EOF
<VirtualHost *:8081>
    ServerName localhost
    DocumentRoot ${SITE_ROOT}
    DirectoryIndex index.php index.html
    <Directory ${SITE_ROOT}>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
    ErrorLog \${APACHE_LOG_DIR}/webapp_error.log
    CustomLog \${APACHE_LOG_DIR}/access.log combined

    # 关闭压缩：否则检测系统留存的响应快照是 gzip 字节流，详情页显示为乱码
    SetEnv no-gzip 1
</VirtualHost>
EOF

a2ensite secops-webapp.conf >/dev/null
a2enmod rewrite >/dev/null 2>&1 || true
a2enmod headers >/dev/null 2>&1 || true
apache2ctl configtest >/dev/null 2>&1 || die "apache2ctl configtest 失败，请检查 /etc/apache2 配置"
systemctl restart apache2
sleep 1

# -----------------------------------------------------------------------------
# 4. 清理 env 模板行内注释（systemd EnvironmentFile 会把 # 之后的内容当成值）
# -----------------------------------------------------------------------------
log "清理 env 模板/配置中的行内注释…"
strip_inline() {
  local f="$1"
  [ -f "$f" ] || return 0
  sed -i -E '/^[A-Za-z]/ { s/[[:space:]]*#.*$//; s/[[:space:]]+$// }' "$f"
}
strip_inline "${REPO_DIR}/deploy/env.web.example"
strip_inline "${REPO_DIR}/backend/.env.example"

# -----------------------------------------------------------------------------
# 5. 运行官方安装脚本：依赖 / venv / systemd / 高保真代理
# -----------------------------------------------------------------------------
log "运行 deploy/install.sh --web-profile --http-proxy（约 3-8 分钟，需联网下载 apt/pip）…"
# 初始密码必须在**首次启动前**交给 install.sh：admin 只在用户表为空时创建，
# 建号之后 .env 里再怎么写都不会生效。
SECOPS_ADMIN_PASSWORD="${ADMIN_PASSWORD}" \
  bash "${REPO_DIR}/deploy/install.sh" --web-profile --http-proxy

# -----------------------------------------------------------------------------
# 6. 最终 .env：清注释 + 写入定制配置（幂等）
# -----------------------------------------------------------------------------
ENV_FILE="${REPO_DIR}/.env"
[ -f "${ENV_FILE}" ] || die "安装后未生成 ${ENV_FILE}"
strip_inline "${ENV_FILE}"

set_env() {
  local key="$1" val="$2"
  if grep -qE "^${key}=" "${ENV_FILE}"; then
    sed -i "s|^${key}=.*|${key}=${val}|" "${ENV_FILE}"
  else
    printf '%s=%s\n' "${key}" "${val}" >> "${ENV_FILE}"
  fi
}

log "写入定制配置：网段/白名单/采集/防火墙/降噪/忽略自扫描来源 …"
set_env CAPTURE_MODE scapy
set_env CAPTURE_IFACE "${IFACE}"
set_env FIREWALL_BACKEND iptables
set_env FIREWALL_CHAIN INPUT
set_env BLOCK_TTL_SEC 300
set_env DRY_RUN true
set_env AUTO_BLOCK_ENABLED true
set_env AUTO_BLOCK_MIN_SEVERITY high
set_env WEB_AUTO_BLOCK_REQUIRES_DIRECT true
set_env WEB_DETECT_SOURCE api
set_env WEB_DEFAULT_DST_IP "${HOST_IP}"
set_env WEB_DEFAULT_DST_PORT 8080
# 本机自访问（含漏洞扫描器）不作为攻击来源，避免 SSRF/目录穿越/资产侦察误报
set_env WEB_IGNORE_IPS "127.0.0.1,::1,${HOST_IP}"
set_env DETECT_IGNORE_IPS "127.0.0.1,::1,${HOST_IP}"
set_env PROTECTED_CIDRS "${PROTECTED}"
# 白名单只保留系统必留地址；把整个业务网段加进来会让攻击方永远无法被封禁
set_env WHITELIST_CIDRS "127.0.0.1/32,::1/128,169.254.0.0/16,224.0.0.0/4,${ADMIN_HOST}"
set_env LLM_MODEL deepseek-chat
set_env COOKIE_SECURE false
# 实验环境默认关闭"整机流量突发"：基线只有几十 Kbps，一次下载即误报。
# 需要演示该能力时改成 true；告警基线 100Mbps 起报，200Mbps 直达 critical。
set_env SPIKE_DETECT_ENABLED false
set_env SPIKE_MIN_ABS_BPS 104857600
set_env SPIKE_BPS_THRESHOLD 209715200

# 首次部署给一个确定的管理员密码，避免去日志里翻随机串
if ! grep -qE '^ADMIN_INITIAL_PASSWORD=.+' "${ENV_FILE}"; then
  set_env ADMIN_INITIAL_PASSWORD "${ADMIN_PASSWORD}"
fi

# -----------------------------------------------------------------------------
# 7. 重启并自检
# -----------------------------------------------------------------------------
log "重启服务并自检 …"
systemctl daemon-reload
systemctl restart secops-traffic-guard
systemctl restart secops-http-proxy
sleep 6

echo
log "================ 服务状态 ================"
for s in secops-traffic-guard secops-http-proxy apache2; do
  printf '  %-24s %s\n' "$s" "$(systemctl is-active "$s" 2>/dev/null)"
done

echo "---------- 端口（期望 8000=uvicorn / 8080=代理 / 8081=apache2 仅回环）----------"
ss -ltnp | grep -E ':8000|:8080|:8081' || warn "端口未全部监听"

# 8081 若绑到 0.0.0.0 或 *，外部可以直连业务站点，整条检测链路被绕过
BIND8081="$(ss -ltn 2>/dev/null | awk '$4 ~ /:8081$/ {print $4; exit}' || true)"
case "${BIND8081}" in
  127.0.0.1:8081|"[::1]:8081")
    log "8081 仅本机回环监听（${BIND8081}）：外部无法直连，攻击必须经 8080 代理" ;;
  "")
    warn "8081 未监听：检查 apache2 状态与 /etc/apache2/ports.conf" ;;
  *)
    warn "8081 对外监听（${BIND8081}）：外部可直连并绕过检测"
    warn "  -> 把 ports.conf 改成 Listen 127.0.0.1:8081 后 systemctl restart apache2" ;;
esac

echo "---------- 后端健康检查 ----------"
curl -s --max-time 5 http://127.0.0.1:8000/api/v1/health \
  || die "后端 8000 健康检查失败，请查 journalctl -u secops-traffic-guard -n 60"
echo

echo "---------- 代理 -> 被测站点 ----------"
SITE_CODE="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
  "http://127.0.0.1:8080${SITE_PREFIX}" || echo 000)"
echo "  http://127.0.0.1:8080${SITE_PREFIX} -> ${SITE_CODE}"
case "${SITE_CODE}" in
  200|301|302) log "代理链路正常" ;;
  *) warn "代理链路异常（${SITE_CODE}）：systemctl status secops-http-proxy；检查 8081 站点配置" ;;
esac

# 7.1 以"外部客户端"的 Host 头验证跳转地址与 Cookie 域
echo "---------- 跳转地址 / Cookie 域（以 ${HOST_IP}:8080 身份访问）----------"
LOCATION="$(curl -sI --max-time 5 -H "Host: ${HOST_IP}:8080" \
  "http://127.0.0.1:8080${SITE_PREFIX}" 2>/dev/null \
  | tr -d '\r' | awk 'BEGIN{IGNORECASE=1} /^location:/{print $2}' | head -1)"
if [ -n "${LOCATION}" ]; then
  echo "  Location: ${LOCATION}"
  case "${LOCATION}" in
    *127.0.0.1*|*localhost*) warn "跳转指回内网地址，请确认使用最新部署包（代理需透传原始 Host）" ;;
    *) log "跳转地址正确" ;;
  esac
else
  echo "  无跳转（站点直接返回内容）"
fi

COOKIE_LINE="$(curl -si --max-time 5 -H "Host: ${HOST_IP}:8080" \
  "http://127.0.0.1:8080${SITE_PREFIX}" 2>/dev/null \
  | tr -d '\r' | grep -i '^set-cookie' | head -3)"
if echo "${COOKIE_LINE}" | grep -qi 'domain=127.0.0.1'; then
  warn "Cookie 域为 127.0.0.1：外部浏览器会丢弃该 Cookie，表现为登录无反应"
  warn "  -> 请确认使用最新部署包（代理需透传原始 Host）"
elif [ -n "${COOKIE_LINE}" ]; then
  log "Cookie 域正常"
fi

# -----------------------------------------------------------------------------
# 8. 输出访问信息
# -----------------------------------------------------------------------------
echo
log "================ 部署完成 ================"
echo "  大屏地址 : http://${HOST_IP}:8000/"
echo "  被测站点 : http://${HOST_IP}:8080${SITE_PREFIX}   （攻击测试必须走 8080；8081 只绑 127.0.0.1，外部直连不通）"
echo "  首次密码 : 见 .env 的 ADMIN_INITIAL_PASSWORD（默认 SecOps@2026Lab）"
echo "            若库中已存在 admin，该配置不生效，请用原密码登录"
echo "  当前模式 : DRY_RUN=true（只记录封禁，不改内核防火墙）；真封见手册第 5 章"
echo "  AI 状态  : 未填 LLM_API_KEY 时自动降级出结论（degraded=true）"
echo "  流量突发 : 已关闭（SPIKE_DETECT_ENABLED=false），需要时在 .env 打开"
echo
echo "  下一步（被测站点为 DVWA 时）："
echo "    1) 浏览器打开 http://${HOST_IP}:8080${SITE_PREFIX}setup.php 点 Create/Reset Database"
echo "    2) 用 admin / password 登录，DVWA Security 改为 Low"
echo "    3) 从攻击机执行手册 8.3~8.6 节的验证用例"
