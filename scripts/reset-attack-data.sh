#!/usr/bin/env bash
# 清空测试期间产生的攻击数据（告警 / 信号 / 威胁事件 / 封禁记录 / 审计 / 会话），
# 保留账号、白名单、资产、规则库与 .env。不改动任何业务代码，只操作数据库与系统状态。
#
# 用法：
#   bash scripts/reset-attack-data.sh                      # 交互确认后清理
#   bash scripts/reset-attack-data.sh -y                   # 免确认（脚本化 / 复测流水线）
#   bash scripts/reset-attack-data.sh -y --with-reports --with-firewall
#
# 选项：
#   -y, --yes        跳过二次确认
#   --with-reports   同时清空 backend/data/reports 下的报告文件
#   --with-firewall  同时删除 iptables 中带 SECOPS_BLOCK 注释的封禁规则
#   --with-baseline  同时清空 threshold_configs（自适应基线重新学习，前 30 分钟可能偏敏感）
#   -h, --help       显示本帮助
#
# 保留：users（账号）、whitelist（白名单）、assets（资产）、规则库 JSON、.env
set -uo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# 兼容两种放置位置：<部署根>/scripts/reset-attack-data.sh，或直接丢在部署根目录
resolve_app_dir() {
  local candidate
  for candidate in "${APP_DIR:-}" "${SCRIPT_DIR}" "$(dirname "$SCRIPT_DIR")" /opt/secops "${PWD}"; do
    if [[ -n "$candidate" && -f "${candidate}/.env" ]]; then
      printf '%s' "$candidate"
      return 0
    fi
  done
  return 1
}

if ! APP_DIR=$(resolve_app_dir); then
  printf '\033[31m[失败]\033[0m 未找到含 .env 的部署目录，请显式指定：APP_DIR=/opt/secops bash %s\n' "$0" >&2
  exit 1
fi

ASSUME_YES=0
WITH_REPORTS=0
WITH_FIREWALL=0
WITH_BASELINE=0

usage() { sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    -y|--yes) ASSUME_YES=1 ;;
    --with-reports) WITH_REPORTS=1 ;;
    --with-firewall) WITH_FIREWALL=1 ;;
    --with-baseline) WITH_BASELINE=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "未知参数：$1（用 -h 查看用法）"; exit 2 ;;
  esac
  shift
done

log()  { printf '\033[36m[清理]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[注意]\033[0m %s\n' "$*"; }
die()  { printf '\033[31m[失败]\033[0m %s\n' "$*" >&2; exit 1; }

[[ $(id -u) -eq 0 ]] || die "请用 root 执行（需要停/启 systemd 服务）"
[[ -f "${APP_DIR}/.env" ]] || die "未找到 ${APP_DIR}/.env；可用 APP_DIR=/opt/secops bash $0 指定部署根目录"

# ---------------------------------------------------------------- #
# 1. 定位数据库（以 .env 的 DB_URL 为准，避免猜错路径）
# ---------------------------------------------------------------- #
DB_URL=$(grep -E '^DB_URL=' "${APP_DIR}/.env" | tail -n 1 | cut -d= -f2- | tr -d '[:space:]')
DB_PATH=""

if [[ -n "$DB_URL" && "$DB_URL" == sqlite* ]]; then
  DB_PATH=${DB_URL#sqlite:///}
fi

if [[ -z "$DB_PATH" ]]; then
  for candidate in "${APP_DIR}/backend/data/secops.db" "${APP_DIR}/data/secops.db"; do
    if [[ -f "$candidate" ]]; then DB_PATH="$candidate"; break; fi
  done
fi

if [[ -n "$DB_PATH" && "$DB_PATH" != /* ]]; then
  for candidate in "${APP_DIR}/backend/${DB_PATH}" "${APP_DIR}/${DB_PATH}"; do
    if [[ -f "$candidate" ]]; then DB_PATH="$candidate"; break; fi
  done
fi

[[ -n "$DB_PATH" ]] || die "无法从 .env 解析数据库位置（DB_URL=${DB_URL:-空}）"
[[ -f "$DB_PATH" ]] || die "数据库文件不存在：$DB_PATH"

# ---------------------------------------------------------------- #
# 2. 选择解释器（优先 venv，其次系统 python3）
# ---------------------------------------------------------------- #
PY=""
for candidate in "${APP_DIR}/.venv/bin/python" "${APP_DIR}/backend/.venv/bin/python"; do
  if [[ -x "$candidate" ]]; then PY="$candidate"; break; fi
done
[[ -n "$PY" ]] || PY=$(command -v python3 || true)
[[ -n "$PY" ]] || die "未找到可用 python3"

# ---------------------------------------------------------------- #
# 3. 二次确认
# ---------------------------------------------------------------- #
echo
echo "  部署目录 : ${APP_DIR}"
echo "  数据库   : ${DB_PATH}"
echo "  将清空   : 告警 / 检测信号 / 威胁事件 / 封禁记录 / 处置日志 / 漏洞记录 / 审计日志 / 登录会话"
echo "  将保留   : 账号、白名单、资产、规则库 JSON、.env"
[[ $WITH_BASELINE -eq 1 ]] && echo "  额外清空 : 自适应阈值基线 threshold_configs"
[[ $WITH_REPORTS -eq 1 ]] && echo "  额外清空 : 报告目录 backend/data/reports"
[[ $WITH_FIREWALL -eq 1 ]] && echo "  额外清理 : iptables SECOPS_BLOCK 规则"
echo

if [[ $ASSUME_YES -eq 0 ]]; then
  read -r -p "确认继续？输入 YES 回车：" answer
  [[ "$answer" == "YES" ]] || { echo "已取消，未做任何改动"; exit 0; }
fi

# ---------------------------------------------------------------- #
# 4. 完整性预检（库损坏时立即中止，不碰服务与数据）
# ---------------------------------------------------------------- #
log "数据库完整性预检…"
"$PY" - "$DB_PATH" <<'PYEOF'
import sqlite3
import sys

try:
    conn = sqlite3.connect(sys.argv[1], timeout=30)
    rows = conn.execute("PRAGMA quick_check").fetchall()
    conn.close()
except sqlite3.DatabaseError as exc:
    print(f"  quick_check 无法执行：{exc}")
    sys.exit(1)

bad = [str(row[0]) for row in rows if str(row[0]).lower() != "ok"]
if bad:
    print("  quick_check 异常：" + "；".join(bad[:5]))
    sys.exit(1)
print("  quick_check 通过")
PYEOF
PREFLIGHT_RC=$?
if [[ $PREFLIGHT_RC -ne 0 ]]; then
  printf '\033[31m[失败]\033[0m 数据库文件已损坏，已中止：未停服务、未改动任何数据。\n' >&2
  printf '  修复请见手册 14.7（sqlite3 .recover 重建），或确认可丢数据后按 14.3 删库重建。\n' >&2
  exit 1
fi

# ---------------------------------------------------------------- #
# 5. 停服务（SQLite 被进程持有期间不能动文件/做大事务）
# ---------------------------------------------------------------- #
log "停止服务…"
for unit in secops-traffic-guard secops-http-proxy; do
  if systemctl is-active --quiet "$unit"; then
    systemctl stop "$unit" && echo "  - 已停止 ${unit}"
  fi
done

# ---------------------------------------------------------------- #
# 6. 备份（失败即中止，不做无备份的破坏性操作）
# ---------------------------------------------------------------- #
BACKUP_DIR=${BACKUP_DIR:-/root/secops-backups}
mkdir -p "$BACKUP_DIR" || die "无法创建备份目录 $BACKUP_DIR"
BACKUP_FILE="${BACKUP_DIR}/secops-$(date +%Y%m%d-%H%M%S).db"
cp -a "$DB_PATH" "$BACKUP_FILE" || die "备份失败，已中止"
log "已备份：${BACKUP_FILE}"

# ---------------------------------------------------------------- #
# 7. 清表 + VACUUM
# ---------------------------------------------------------------- #
log "清理攻击数据…"
"$PY" - "$DB_PATH" "$WITH_BASELINE" <<'PYEOF'
import sqlite3
import sys

db_path, with_baseline = sys.argv[1], sys.argv[2] == "1"

tables = [
    ("threat_tags", "威胁标签"),
    ("threat_events", "威胁事件"),
    ("alerts", "告警"),
    ("signals", "检测信号"),
    ("block_reports", "封禁记录"),
    ("disposal_logs", "处置时间线"),
    ("vulnerabilities", "漏洞记录"),
    ("traffic_samples", "流量采样"),
    ("port_traffic_samples", "端口流量采样"),
    ("block_rules", "封禁规则"),
    ("audit_logs", "审计日志"),
    ("sessions", "登录会话"),
]
if with_baseline:
    tables.append(("threshold_configs", "自适应阈值基线"))

conn = sqlite3.connect(db_path, timeout=30)
conn.execute("PRAGMA foreign_keys=OFF")
cur = conn.cursor()
existing = {row[0] for row in cur.execute(
    "SELECT name FROM sqlite_master WHERE type='table'")}

removed = 0
for name, label in tables:
    if name not in existing:
        print(f"  - {label}({name})：表不存在，跳过")
        continue
    try:
        count = cur.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0]
        cur.execute(f"DELETE FROM {name}")
    except sqlite3.DatabaseError as exc:
        print(f"  - {label}({name})：读取/删除失败（{exc}）")
        conn.rollback()
        conn.close()
        print("  事务已回滚：本次删除全部撤销，原有数据未被清除。")
        sys.exit(2)
    removed += count
    print(f"  - {label}({name})：删除 {count} 行")

conn.commit()
try:
    cur.execute("VACUUM")
    conn.commit()
except sqlite3.DatabaseError as exc:
    print(f"  - VACUUM 跳过（{exc}），数据已删除，不影响结果")
conn.close()
print(f"  合计删除 {removed} 行")
PYEOF
CLEAN_RC=$?
if [[ $CLEAN_RC -ne 0 ]]; then
  printf '\033[31m[失败]\033[0m 清理未完成（退出码 %s），事务已回滚。\n' "$CLEAN_RC" >&2
  printf '  数据库文件疑似损坏，请按手册 14.7 修复（sqlite3 .recover），不要对损坏库执行 VACUUM。\n' >&2
  printf '  服务当前处于停止状态；确认无误后手动启动：systemctl start secops-traffic-guard secops-http-proxy\n' >&2
  exit 1
fi

# ---------------------------------------------------------------- #
# 8. 可选：报告文件 / 防火墙规则
# ---------------------------------------------------------------- #
if [[ $WITH_REPORTS -eq 1 ]]; then
  for dir in "${APP_DIR}/backend/data/reports" "${APP_DIR}/data/reports"; do
    if [[ -d "$dir" ]]; then
      find "$dir" -mindepth 1 -delete 2>/dev/null
      log "已清空报告目录 ${dir}"
    fi
  done
fi

if [[ $WITH_FIREWALL -eq 1 ]]; then
  if command -v iptables >/dev/null 2>&1; then
    count=$(iptables -S INPUT 2>/dev/null | grep -c SECOPS_BLOCK || true)
    iptables -S INPUT 2>/dev/null | grep SECOPS_BLOCK | sed 's/^-A /-D /' \
      | while read -r rule; do iptables $rule; done
    log "已移除 ${count} 条 SECOPS_BLOCK 封禁规则"
  else
    warn "未找到 iptables，跳过防火墙清理"
  fi
fi

# ---------------------------------------------------------------- #
# 9. 起服务并自检
# ---------------------------------------------------------------- #
log "启动服务…"
systemctl start secops-traffic-guard
if [[ -f /etc/systemd/system/secops-http-proxy.service ]]; then
  systemctl start secops-http-proxy
fi

healthy=0
for _ in $(seq 1 20); do
  if curl -fsS -m 2 http://127.0.0.1:8000/api/v1/health >/dev/null 2>&1; then
    healthy=1
    break
  fi
  sleep 1
done
[[ $healthy -eq 1 ]] && log "后端健康检查通过（/api/v1/health）" || warn "健康检查未通过，请执行：journalctl -u secops-traffic-guard -n 80"

echo
log "剩余记录核对："
"$PY" - "$DB_PATH" <<'PYEOF'
import sqlite3
import sys

total = 0
conn = sqlite3.connect(sys.argv[1], timeout=30)
cur = conn.cursor()
for name in ("alerts", "signals", "threat_events", "block_reports",
             "block_rules", "audit_logs", "vulnerabilities"):
    try:
        count = cur.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0]
    except sqlite3.DatabaseError as exc:
        print(f"  - {name}: 读取失败（{exc}）")
        total += 1
        continue
    print(f"  - {name}: {count}")
    total += count
conn.close()
sys.exit(1 if total else 0)
PYEOF
VERIFY_RC=$?

if [[ $VERIFY_RC -ne 0 ]]; then
  warn "仍有残留记录：清理没有真正生效，请检查是否清到了正确的库（对照 .env 的 DB_URL 与 systemctl show -p EnvironmentFiles）"
  exit 1
fi

echo
log "清理完成。请在浏览器强制刷新（Ctrl+F5）后复查各页面是否已归零。"
log "如需回滚到清理前状态：systemctl stop secops-traffic-guard secops-http-proxy && cp -a ${BACKUP_FILE} ${DB_PATH} && systemctl start secops-traffic-guard secops-http-proxy"
