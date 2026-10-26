#!/usr/bin/env python3
"""高保真接入代理启动脚本（见 backend/app/collector/http_proxy.py）。"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "backend"))

from app.collector.http_proxy import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
