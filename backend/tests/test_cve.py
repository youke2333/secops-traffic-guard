"""CVE 知识库匹配与资产风险评级测试。"""

from __future__ import annotations

from app.scanner.cve import CveKnowledgeBase, version_tuple
from app.scanner.fingerprint import Fingerprinter, HostFingerprint, ServiceInfo


def test_version_tuple_ordering():
    assert version_tuple("2.4.57") > version_tuple("2.4.9")
    assert version_tuple("9.3p2") == (9, 3, 2)
    assert version_tuple("") == (0,)


def test_knowledge_base_matches_openssh_vulnerabilities(settings):
    kb = CveKnowledgeBase(settings.cve_rules_path)
    assert kb.rules, "CVE 规则库应当被加载"
    # 8.9 同时落在 CVE-2024-6387 的区间 8.5~9.7 与 CVE-2023-38408 的 <9.3 之内
    matches = kb.match(product="OpenSSH", version="8.9", port=22, service="ssh")
    cves = {item.cve for item in matches}
    assert "CVE-2024-6387" in cves
    assert "CVE-2023-38408" in cves
    assert all(item.recommendation for item in matches), "每条命中都必须带修复建议"


def test_knowledge_base_respects_version_range_boundaries(settings):
    """区间比较必须双向正确：低于区间下界不命中，高于上界也不命中。"""
    kb = CveKnowledgeBase(settings.cve_rules_path)

    below = {item.cve for item in kb.match(product="OpenSSH", version="8.2", port=22, service="ssh")}
    assert "CVE-2024-6387" not in below, "8.2 低于受影响区间下界 8.5，不应命中"
    assert "CVE-2023-38408" in below, "8.2 低于 9.3，应命中"

    above = {item.cve for item in kb.match(product="OpenSSH", version="9.8", port=22, service="ssh")}
    assert not above & {"CVE-2024-6387", "CVE-2023-38408"}, "9.8 已修复，不应命中"


def test_knowledge_base_skips_patched_version(settings):
    kb = CveKnowledgeBase(settings.cve_rules_path)
    matches = kb.match(product="OpenSSH", version="10.0", port=22, service="ssh")
    assert not {item.cve for item in matches} & {"CVE-2024-6387", "CVE-2023-38408"}


def test_knowledge_base_detects_misconfiguration(settings):
    kb = CveKnowledgeBase(settings.cve_rules_path)
    docker = kb.match(product="", version="", port=2375, service="docker", banner="HTTP/1.1 200 OK")
    assert any(item.cve.startswith("MISCONF") for item in docker)

    redis = kb.match(product="", version="", port=6379, service="redis", banner="redis_version:6.0.9")
    assert {"CVE-2022-0543", "MISCONF-REDIS-UNAUTH"} & {item.cve for item in redis}


def test_banner_parser_extracts_product_and_version():
    product, version = Fingerprinter._parse_banner(22, "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5")
    assert product == "OpenSSH" and version.startswith("8.2")

    product, version = Fingerprinter._parse_banner(80, "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0")
    assert product == "nginx" and version == "1.18.0"


def test_asset_risk_evaluation(settings):
    from app.models import Asset
    from app.scanner.assets import AssetManager

    asset = Asset(ip="192.168.1.10", open_ports=[22, 80], vuln_count=0, alert_count=0)
    assert AssetManager.evaluate_risk(asset) == "low"

    risky = Asset(ip="192.168.1.30", open_ports=[22, 2375, 6379], vuln_count=2, alert_count=3)
    assert AssetManager.evaluate_risk(risky) in {"high", "critical"}


def test_fingerprint_serialization():
    fingerprint = HostFingerprint(ip="192.168.1.10", os_guess="Linux", services=[
        ServiceInfo(port=22, name="ssh", product="OpenSSH", version="8.2"),
        ServiceInfo(port=80, name="http", product="nginx", version="1.18.0"),
    ])
    assert fingerprint.open_ports == [22, 80]
    assert fingerprint.services[0].to_dict()["product"] == "OpenSSH"
