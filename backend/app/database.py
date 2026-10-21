"""数据库连接与会话管理（SQLAlchemy 2.0）。

默认 SQLite 便于单机轻量部署；生产通过 DB_URL 指向 PostgreSQL，代码零改动。
"""

from __future__ import annotations

import logging
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import get_settings

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    """所有 ORM 模型的基类。"""


_engine: Optional[Engine] = None
_session_factory: Optional[sessionmaker] = None


def _prepare_sqlite_dir(url: str) -> None:
    if url.startswith("sqlite"):
        path = url.split("///")[-1]
        if path and path != ":memory:":
            Path(path).resolve().parent.mkdir(parents=True, exist_ok=True)


def get_engine() -> Engine:
    global _engine
    if _engine is None:
        url = get_settings().db_url
        _prepare_sqlite_dir(url)
        connect_args = {"check_same_thread": False, "timeout": 30} if url.startswith("sqlite") else {}
        _engine = create_engine(url, future=True, pool_pre_ping=True, connect_args=connect_args)
        if url.startswith("sqlite"):
            # SQLite 并发写入优化：WAL + 放宽同步（本地单机场景足够安全）
            @event.listens_for(_engine, "connect")
            def _set_sqlite_pragma(dbapi_conn, _record):  # pragma: no cover - 依赖 sqlite3
                cursor = dbapi_conn.cursor()
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA synchronous=NORMAL")
                cursor.close()

    return _engine


def get_session_factory() -> sessionmaker:
    global _session_factory
    if _session_factory is None:
        _session_factory = sessionmaker(bind=get_engine(), autoflush=False, expire_on_commit=False, future=True)
    return _session_factory


@contextmanager
def session_scope() -> Iterator[Session]:
    """脚本 / 后台线程使用的事务上下文。"""
    session = get_session_factory()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_db() -> Iterator[Session]:
    """FastAPI 依赖注入使用的会话。"""
    session = get_session_factory()()
    try:
        yield session
    finally:
        session.close()


def init_db() -> None:
    """建表 + 补列（幂等）。

    `create_all()` 只创建缺失的表，**不会给已存在的表补列**。本项目是单机部署、
    升级包直接覆盖，若要求运维手工跑迁移脚本，忘一次就会在查询时炸「no such column」。
    因此启动时顺手做一次「只加列、不删改」的补齐：
    新增列必须可空或带常量默认值，旧版本代码读到新库也不会异常。
    """
    from . import models  # noqa: F401  —— 触发模型注册

    engine = get_engine()
    Base.metadata.create_all(bind=engine)
    _add_missing_columns(engine)


def plan_missing_columns(engine) -> list[str]:
    """算出「已存在的表缺哪些列」，返回待执行的 ADD COLUMN 语句（不执行）。

    与 :func:`_add_missing_columns` 共用同一套 DDL 生成逻辑，`scripts/migrate_v2.py`
    的 dry-run 也走这里，避免两处实现各写一套、慢慢跑偏。
    """
    from sqlalchemy import inspect

    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())
    statements: list[str] = []
    for table in Base.metadata.sorted_tables:
        if table.name not in existing_tables:
            continue
        present = {column["name"] for column in inspector.get_columns(table.name)}
        for column in table.columns:
            if column.name in present:
                continue
            ddl = _column_ddl(column, engine.dialect)
            if ddl:
                statements.append(f"ALTER TABLE {table.name} ADD COLUMN {ddl}")
    return statements


def _add_missing_columns(engine) -> None:
    """给已存在的表补上模型里新增的列（失败只记日志，绝不阻断启动）。"""
    from sqlalchemy import text

    try:
        statements = plan_missing_columns(engine)
        if not statements:
            return
        with engine.begin() as connection:
            for statement in statements:
                connection.execute(text(statement))
        logger.info("数据库补列完成：%s", "; ".join(statements))
    except Exception:      # pragma: no cover - 补列失败不应影响服务启动
        logger.exception("数据库补列失败（可手工执行 scripts/migrate_v2.py）")


def _column_ddl(column, dialect) -> str:
    """拼一条 ADD COLUMN 用的列定义（类型 + 常量默认值）。"""
    try:
        column_type = column.type.compile(dialect=dialect)
    except Exception:
        return ""
    ddl = f"{column.name} {column_type}"
    default = getattr(column, "default", None)
    literal = None
    if default is not None:
        value = getattr(default, "arg", None)
        if getattr(default, "is_scalar", False) and isinstance(value, (str, int, float, bool)):
            literal = value
    if literal is None:
        return ddl
    if isinstance(literal, bool):
        literal = int(literal)
    if isinstance(literal, str):
        escaped = literal.replace("'", "''")
        return f"{ddl} DEFAULT '{escaped}'"
    return f"{ddl} DEFAULT {literal}"


def reset_state() -> None:
    """测试用：销毁引擎与工厂，便于切换 DB_URL。"""
    global _engine, _session_factory
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _session_factory = None
