"""在线演示启动入口。

与 `uvicorn app.main:app --app-dir backend` 等价，但从环境变量 `PORT` 读取端口并绑定 0.0.0.0，
便于在只注入 PORT、不经过 shell 展开的托管环境中启动。

用法：
    python serve.py                 # 默认 8000
    PORT=8080 python serve.py       # 指定端口
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import uvicorn

ROOT = Path(__file__).resolve().parent


def main() -> None:
    port = int(os.environ.get("PORT", "8000"))
    host = os.environ.get("HOST", "0.0.0.0")
    # 让 backend 目录可被 import（等价于 --app-dir backend）
    sys.path.insert(0, str(ROOT / "backend"))
    print(f"[serve] starting on http://{host}:{port}", flush=True)
    uvicorn.run("app.main:app", host=host, port=port, log_level="info", access_log=False)


if __name__ == "__main__":
    main()
