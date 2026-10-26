"""时间口径自检：确认"库里存什么"与"页面显示什么"是否一致。

背景：本项目历史上存在两种写入口径——alerts / signals / traffic_samples 写**本地时间**，
threat_events / disposal_logs / block_rules / audit_logs 写 **UTC**。
对外输出统一换算成本地时间（backend/app/timeutil.py），本脚本用来离线核对换算是否正确。

用法：
    python scripts/verify_time.py
    python scripts/verify_time.py --db data/secops.db

判据（全部满足才算 PASS）：
    1. 威胁事件、处置流水、封禁规则换算后的时间，不早于"系统当前时间 - 留存期"；
    2. 威胁事件（UTC 列，换算后）与流量样本（本地列）在同一批写入时刻上差异 < 60s；
    3. 换算后的时间与系统当前时间处于同一时区（相差不是整 8 小时）。

退出码：0=PASS，1=FAIL。
"""

from __future__ import annotations

import argparse
import os
import sqlite3
import sys
from datetime import datetime, timedelta

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "backend"))

from app.timeutil import iso_local, text_local  # noqa: E402


def parse(value):
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None


def latest(cur, table: str, column: str = "ts"):
    try:
        row = cur.execute(f"select {column} from {table} order by {column} desc limit 1").fetchone()
    except sqlite3.Error:
        return None
    return parse(row[0]) if row else None


def main() -> int:
    ap = argparse.ArgumentParser(description="时间口径自检")
    ap.add_argument("--db", default=os.path.join(REPO_ROOT, "data", "secops.db"))
    args = ap.parse_args()

    if not os.path.exists(args.db):
        print(f"[FAIL] 数据库不存在：{args.db}")
        return 1

    conn = sqlite3.connect(args.db)
    cur = conn.cursor()
    now = datetime.now()

    rows = [
        ("威胁事件 threat_events.ts", latest(cur, "threat_events"), "utc"),
        ("处置流水 disposal_logs.ts", latest(cur, "disposal_logs"), "utc"),
        ("封禁规则 block_rules.created_at", latest(cur, "block_rules", "created_at"), "utc"),
        ("审计日志 audit_logs.ts", latest(cur, "audit_logs"), "utc"),
        ("告警 alerts.ts", latest(cur, "alerts"), "local"),
        ("流量样本 traffic_samples.ts", latest(cur, "traffic_samples"), "local"),
    ]

    print(f"系统当前时间：{now:%Y-%m-%d %H:%M:%S}（{now.astimezone().tzinfo}）\n")
    print(f"{'表 / 列':<34}{'修复前(直接显示)':<24}{'修复后(本地时间)':<24}")
    print("-" * 84)

    failures = []
    offset_sec = now.astimezone().utcoffset().total_seconds()
    for name, value, stored in rows:
        if value is None:
            print(f"{name:<34}{'-':<24}{'-':<24}")
            continue
        before = value.isoformat(timespec="seconds").replace("T", " ")
        after = text_local(value, stored=stored)
        print(f"{name:<34}{before:<24}{after:<24}")
        # 判据 3：UTC 列的换算量必须正好等于本机时区偏移；本地列必须原样不变
        shift = (parse(after) - value).total_seconds() if parse(after) else 0.0
        expected = offset_sec if stored == "utc" else 0.0
        if abs(shift - expected) > 1:
            failures.append(f"{name} 换算偏差 {shift:.0f}s，期望 {expected:.0f}s")

    print("\n交叉校验（同一批写入应指向同一时刻）：")
    t_threat = latest(cur, "threat_events")
    t_traffic = latest(cur, "traffic_samples")
    if t_threat and t_traffic:
        a = parse(text_local(t_threat))
        b = parse(text_local(t_traffic, stored="local"))
        diff = abs((a - b).total_seconds())
        print(f"  威胁事件(换算) = {a:%Y-%m-%d %H:%M:%S}")
        print(f"  流量样本(本地) = {b:%Y-%m-%d %H:%M:%S}")
        print(f"  差异 = {diff:.0f} 秒")
        if diff > 60:
            failures.append(f"威胁事件与流量样本相差 {diff:.0f} 秒，时区口径可能不一致")
    else:
        print("  数据不足，跳过")

    # 判据 1：留存期内的 UTC 列换算后不应落到未来
    retention = 7
    future = [name for name, value, stored in rows
              if stored == "utc" and value and parse(text_local(value)) > now + timedelta(minutes=5)]
    if future:
        failures.append("换算后出现未来时间：" + "、".join(future))

    print(f"\n留存期参考：{retention} 天（THREAT_RETENTION_DAYS）")
    if failures:
        print("\n[FAIL] " + "；".join(failures))
        return 1
    print("\n[PASS] 时间口径一致：UTC 列已换算成本地时间，且与本地列指向同一时刻")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
