#!/usr/bin/env bash
# ============================================================================
# 通用攻击验证脚本（仅限授权测试环境！）
#
# 作用：按顺序发送 SQLi / XSS / 命令注入 / 文件包含 / 上传 / 暴破 请求，
#       用于验证「检测 → 告警 → 封禁」闭环。不依赖任何特定应用，按普通业务路径发送。
#
# 重要：
#   * 在**另一台虚拟机/宿主机**上执行，源 IP 才是真实攻击 IP，才能验证自动封禁；
#     在本机执行时源 IP 是 127.0.0.1（白名单），只会检测告警、不会封禁自己。
#   * 首次部署请保持 DRY_RUN=true，确认告警无误报后再改 false。
#   * 路径是占位业务路径，目标站点不存在这些路径时依然能验证检测（检测看的是载荷）。
#
# 用法：
#   bash scripts/web_attack_test.sh [--target http://127.0.0.1:8080/] [--normal-only]
# ============================================================================
set -u

TARGET="${WEB_TARGET:-http://127.0.0.1:8080/}"
NORMAL_ONLY=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) TARGET="$2"; shift 2 ;;
    --normal-only) NORMAL_ONLY=1; shift ;;
    *) echo "未知参数：$1"; exit 1 ;;
  esac
done
TARGET="${TARGET%/}/"
UA_ATTACK="sqlmap/1.8.4#stable (https://sqlmap.org)"
UA_BROWSER="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

echo "[*] 目标：${TARGET}"

if [[ "${NORMAL_ONLY}" -eq 1 ]]; then
  echo "[*] 正常访问（用于验证不产生误报）"
  for path in "" "product/detail?id=1024" "search?q=keyboard" "help/view?page=help.html"; do
    curl -s -A "${UA_BROWSER}" --max-time 5 -o /dev/null "${TARGET}${path}"
    echo "    正常请求：${TARGET}${path}"
    sleep 1
  done
  echo "[*] 完成：请在「异常端口流量检测」页确认没有新增告警。"
  exit 0
fi

send() {   # send <说明> <curl 参数...>
  local desc="$1"; shift
  echo "[>] ${desc}"
  curl -s --max-time 8 -o /dev/null "$@" || true
  sleep 1.2
}

send "SQL 注入（UNION）" -A "${UA_ATTACK}" \
  --get --data-urlencode "id=1' UNION SELECT user,password FROM users-- -" \
  --data-urlencode "Submit=Submit" "${TARGET}product/detail"
send "SQL 盲注（SLEEP）" -A "${UA_ATTACK}" \
  --get --data-urlencode "id=1' AND SLEEP(5)-- -" "${TARGET}product/list"
send "反射型 XSS" -A "${UA_BROWSER}" \
  --get --data-urlencode "name=<script>alert(document.cookie)</script>" \
  "${TARGET}search"
send "命令注入" -A "curl/8.5.0" \
  --data-urlencode "ip=127.0.0.1;cat /etc/passwd" --data "Submit=Submit" \
  "${TARGET}tools/ping"
send "文件包含（LFI）" -A "${UA_BROWSER}" \
  --get --data-urlencode "page=../../../../etc/passwd" "${TARGET}help/view"

echo "[>] 恶意文件上传（shell.php）"
PAYLOAD="$(mktemp --suffix=.php 2>/dev/null || mktemp)"
printf '%s\n' '<?php echo "secops-test"; ?>' > "${PAYLOAD}"
curl -s -A "python-requests/2.31" --max-time 8 -o /dev/null \
  -F "file=@${PAYLOAD};filename=shell.php;type=image/jpeg" \
  -F "upload=Upload" "${TARGET}upload/avatar" || true
rm -f "${PAYLOAD}"
sleep 1.2

echo "[>] 登录暴力破解（12 次，超过阈值 10）"
for i in $(seq 1 12); do
  curl -s -A "hydra/9.5" --max-time 5 -o /dev/null \
    --get --data-urlencode "username=admin" --data-urlencode "password=pass${i}" \
    --data-urlencode "Login=Login" "${TARGET}login" || true
done

echo
echo "[*] 攻击序列完成。请检查："
echo "    1) 大屏「异常端口流量检测」：应出现 web_sql_injection / web_command_injection /"
echo "       web_file_inclusion / web_file_upload / web_brute_force 等直达告警；"
echo "    2) 「风险 IP 封禁」：AUTO_BLOCK_ENABLED=true 且源 IP 非回环时出现自动封禁记录；"
echo "    3) 服务器执行：iptables -L INPUT -n | grep SECOPS   （DRY_RUN=false 时可见）"
echo "    4) 正常流量：bash scripts/web_attack_test.sh --normal-only 不应产生告警。"
