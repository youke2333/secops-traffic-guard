"""pytest 全局夹具：隔离测试环境（临时 SQLite + 仿真采集 + DRY-RUN 防火墙）。"""

from __future__ import annotations

import os
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))


@pytest.fixture(scope="session", autouse=True)
def isolated_env(tmp_path_factory: pytest.TempPathFactory) -> None:
    """在任何 app 模块被导入前，注入隔离配置。"""
    db_path = tmp_path_factory.mktemp("secops-db") / "test.db"
    os.environ.update({
        "DB_URL": f"sqlite:///{db_path}",
        "CAPTURE_MODE": "demo",
        "TICK_INTERVAL_MS": "100",
        "DRY_RUN": "true",
        "FIREWALL_BACKEND": "none",
        "AUTO_BLOCK_ENABLED": "true",
        "ALERT_CHANNELS": "log",
        "IFOREST_ENABLED": "false",
        "TREND_POINTS": "120",
        "CVE_RULES_FILE": str(ROOT / "backend" / "data" / "cve_rules.json"),
        "WEB_ATTACK_RULES_FILE": str(ROOT / "backend" / "data" / "web_attack_rules.json"),
        "WEB_DETECT_ENABLED": "true",
        "WEB_DETECT_SOURCE": "demo",
        "WEB_DEMO_INTERVAL_SEC": "30",       # 测试期间降低仿真频率，避免用例相互干扰
        "WHITELIST_CIDRS": "127.0.0.1/32",
        "AUTH_ENABLED": "false",       # 既有用例聚焦检测链路；登录鉴权由 test_auth.py 单独覆盖
    })
    from app.config import reload_settings
    from app.database import init_db

    reload_settings()
    init_db()


@pytest.fixture(scope="session")
def settings():
    from app.config import get_settings

    return get_settings()


@pytest.fixture()
def engine(settings):
    from app.detection.engine import DetectionEngine

    return DetectionEngine(settings)
