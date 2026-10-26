"""旧库结构补齐脚本（v2 起沿用，幂等）。

与其他脚本的关系：**正常情况下不需要跑这个脚本**。服务启动时 `init_db()` 已经会
`create_all()` + 自动补列（见 `backend/app/database.py::plan_missing_columns`）。
本脚本只在这些场景用得上：

1. 想在**启动服务之前**先看看会改什么（`--dry-run` 只打印 SQL，不执行）；
2. 服务因别的原因起不来，但需要先把库结构补齐；
3. 换库（SQLite → PostgreSQL）后核对两边列是否一致。

    python scripts/migrate_v2.py                 # 使用 .env / 环境变量里的 DB_URL
    python scripts/migrate_v2.py --db sqlite:///./data/secops.db
    python scripts/migrate_v2.py --dry-run       # 只打印将要执行的 SQL

行为：
1. 幂等（可重复执行）：已存在的列会被跳过；
2. 只做 **新增**（ADD COLUMN）与**新建表**，绝不删列/改列，保证可回滚；
3. 补列语句由 `app.database._column_ddl` 统一生成，与服务启动时的自动补列完全一致。
"""

from __future__ import annotations

import argparse
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))


def collect_plan(engine):
    """返回 (需要执行的 ALTER 语句, 需要新建的表名)。"""
    from sqlalchemy import inspect

    from app import models  # noqa: F401  —— 触发模型注册
    from app.database import Base, plan_missing_columns

    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())
    pending_tables = [table.name for table in Base.metadata.sorted_tables
                      if table.name not in existing_tables]
    return plan_missing_columns(engine), pending_tables


def main() -> int:
    parser = argparse.ArgumentParser(description="补齐旧库结构：补列 + 建新表（幂等）")
    parser.add_argument("--db", default="", help="覆盖 DB_URL，如 sqlite:///./data/secops.db")
    parser.add_argument("--dry-run", action="store_true", help="只打印计划，不执行")
    args = parser.parse_args()

    if args.db:
        import os

        os.environ["DB_URL"] = args.db

    from app.config import reload_settings
    from app.database import get_engine, init_db

    reload_settings()
    engine = get_engine()
    print(f"目标数据库：{engine.url}")

    statements, pending_tables = collect_plan(engine)
    if not statements and not pending_tables:
        print("无需迁移：结构与当前模型一致")
        return 0

    for table in pending_tables:
        print(f"[新表] {table}")
    for statement in statements:
        print(f"[补列] {statement}")

    if args.dry_run:
        print("（dry-run：未执行任何改动）")
        return 0

    init_db()                      # 建表 + 补列（幂等，与进程启动走同一条路径）
    print(f"迁移完成：新建 {len(pending_tables)} 张表、补充 {len(statements)} 个列")
    return 0


if __name__ == "__main__":
    sys.exit(main())
