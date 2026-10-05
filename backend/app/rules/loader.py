"""规则加载分发器：按文件扩展名 / 目录约定分发到具体加载器。

约定（与 `backend/data/` 目录结构一一对应）：

    backend/data/
    ├── web_attack_rules.json        → native_loader（HTTP 侧知识库）
    ├── cve_rules.json               → native_loader（内置 CVE）
    ├── cve_rules_extended.json      → cve_ext_loader（扩展 CVE）
    ├── sigma_rules/*.yml            → sigma_loader
    └── et_rules/*.rules             → et_loader

`load_path()` 供运维/测试把"任意路径"丢进来即可得到统一 `Rule` 列表，
新来源（如未来接入 YARA-L、nuclei 模板）只需在此登记扩展名。
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Optional

from .base import Rule
from .cve_ext_loader import load_extended_rules
from .et_loader import load_et_rules
from .native_loader import load_cve_rules, load_web_rules
from .sigma_loader import load_sigma_rules

logger = logging.getLogger(__name__)

SIGMA_SUFFIXES = {".yml", ".yaml"}
ET_SUFFIXES = {".rules", ".txt"}
JSON_SUFFIX = ".json"


def load_path(path: Path) -> List[Rule]:
    """按扩展名分发加载；目录则递归（Sigma / ET 各自处理子目录）。"""
    target = Path(path)
    if not target.exists():
        logger.info("规则路径不存在，跳过：%s", target)
        return []
    if target.is_dir():
        if target.name == "sigma_rules":
            return load_sigma_rules(target)
        if target.name == "et_rules":
            return load_et_rules(target)
        rules: List[Rule] = []
        for child in sorted(target.iterdir()):
            rules.extend(load_path(child))
        return rules
    suffix = target.suffix.lower()
    if suffix in SIGMA_SUFFIXES:
        return load_sigma_rules(target.parent) if _looks_like_sigma(target) else []
    if suffix in ET_SUFFIXES:
        return load_et_rules(target.parent)
    if suffix == JSON_SUFFIX:
        return _load_json(target)
    logger.debug("未知规则文件类型，已跳过：%s", target)
    return []


def _looks_like_sigma(path: Path) -> bool:
    """仅当该目录里确实存在本文件时才加载（避免把父目录整体重复加载）。"""
    return path.exists()


def _load_json(path: Path) -> List[Rule]:
    name = path.name.lower()
    if "cve" in name and "extend" in name:
        return load_extended_rules(path)
    if "cve" in name:
        return load_cve_rules(path)
    if "web" in name:
        return load_web_rules(path)
    return _sniff(path)


def _sniff(path: Path) -> Optional[List[Rule]]:
    """无法从文件名判断时，按内容特征嗅探（含 categories 视为 Web 知识库，含 cve 视为 CVE）。"""
    try:
        text = path.read_text(encoding="utf-8")[:4096]
    except Exception:
        return []
    if '"categories"' in text:
        return load_web_rules(path)
    if '"cve"' in text:
        return load_cve_rules(path)
    return []
