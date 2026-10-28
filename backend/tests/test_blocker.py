"""封禁编排测试：白名单闸门、去重、TTL 自动解封、防火墙命令构造。

全部在 DRY_RUN + 无防火墙命令（NullFirewallBackend）环境下运行，
不触碰宿主机内核表，保证测试可安全重复执行。
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from app.database import session_scope
from app.models import BlockRule, DisposalLog, utcnow
from app.response.blocker import Blocker
from app.response.firewall import (
    FirewallError,
    IptablesBackend,
    NftablesBackend,
    NullFirewallBackend,
    build_backend,
    validate_target,
)


@pytest.fixture()
def blocker(settings):
    instance = Blocker(settings, backend=NullFirewallBackend(dry_run=True))
    return instance


# --------------------------------------------------------------------------- #
# 输入校验（防命令注入）
# --------------------------------------------------------------------------- #
def test_validate_target_rejects_injection():
    assert validate_target("192.168.1.10") == "192.168.1.10"
    assert validate_target("10.0.0.0/8") == "10.0.0.0/8"
    for bad in ["192.168.1.10; rm -rf /", "$(reboot)", "1.2.3.4 -j ACCEPT", "", "300.1.1.1"]:
        with pytest.raises(FirewallError):
            validate_target(bad)


def test_iptables_command_is_argument_list():
    backend = IptablesBackend(dry_run=True)
    ok, _message, args = backend.block("203.0.113.66", ttl_sec=60)
    assert ok
    assert args[0] == "iptables" and "-s" in args and "DROP" in args
    assert all(isinstance(item, str) for item in args)     # 列表参数 → 无 shell 解析


def test_nftables_set_element_command():
    backend = NftablesBackend(dry_run=True)
    ok, _message, args = backend.block("203.0.113.77", ttl_sec=120)
    assert ok
    assert "secops" in args and "timeout" in " ".join(args)


def test_build_backend_autodetect_returns_usable_backend(settings):
    backend = build_backend("auto", dry_run=True)
    assert backend.name in {"iptables", "nftables", "firewalld", "none"}
    assert backend.describe()


# --------------------------------------------------------------------------- #
# 封禁流程
# --------------------------------------------------------------------------- #
def test_block_records_rule(blocker):
    result = blocker.block("203.0.113.90", reason="单测：端口扫描", category="port_scan",
                           severity="high", ttl_sec=120)
    assert result["success"] and result["block_id"]
    active = [item for item in blocker.active_blocks() if item["ip"] == "203.0.113.90"]
    assert active and active[0]["remaining_sec"] is not None


def test_duplicate_block_only_increments_hits(blocker):
    first = blocker.block("203.0.113.91", reason="重复封禁测试", category="port_scan", ttl_sec=300)
    second = blocker.block("203.0.113.91", reason="重复封禁测试", category="port_scan", ttl_sec=300)
    assert second.get("duplicated") is True
    assert second["block_id"] == first["block_id"]


def test_whitelist_blocks_auto_ban(blocker):
    blocker.whitelist.add("203.0.113.100/32", "单测白名单")
    result = blocker.block("203.0.113.100", reason="不应被封禁", category="port_scan", ttl_sec=60)
    assert result["success"] is False
    assert result.get("whitelisted") is True


def test_unblock_releases_rule(blocker):
    blocker.block("203.0.113.92", reason="解封测试", category="brute_force", ttl_sec=600)
    result = blocker.unblock("203.0.113.92", operator="tester")
    assert result["success"] and result["released"] >= 1
    assert not [item for item in blocker.active_blocks() if item["ip"] == "203.0.113.92"]


def test_release_expired_rules(blocker):
    result = blocker.block("203.0.113.93", reason="TTL 测试", category="traffic_spike", ttl_sec=60)
    with session_scope() as session:
        rule = session.get(BlockRule, result["block_id"])
        rule.expires_at = utcnow() - timedelta(seconds=5)
    assert blocker.release_expired() >= 1
    assert not [item for item in blocker.active_blocks() if item["ip"] == "203.0.113.93"]


def test_disposal_logs_written(blocker):
    blocker.block("203.0.113.94", reason="处置日志测试", category="manual", ttl_sec=60)
    logs = blocker.disposal_logs(limit=50)
    assert any(item["target"] == "203.0.113.94" for item in logs)
    with session_scope() as session:
        assert session.query(DisposalLog).count() >= 1
