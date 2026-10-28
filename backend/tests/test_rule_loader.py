"""统一规则加载层测试（方案第 1 层）。

覆盖：
1. 内置知识库 → 统一 Schema，且**直达标记按类别白名单自动注入**；
2. Sigma YAML 解析（含 `|contains|all` → match_all 语义还原、不支持字段跳过）；
3. Suricata/ET 解析（只取入向 http 规则、content AND 语义、hex 字节块跳过）；
4. 扩展 CVE 合并（同编号以扩展为准）与"CVE 永不直达"；
5. 注册表索引 / 热加载 / 来源统计 / 无法映射类别的跳过策略。
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from app.rules import (
    DIRECT_ALERT_CATEGORIES,
    Rule,
    RuleRegistry,
    load_cve_rules,
    load_et_rules,
    load_extended_rules,
    load_path,
    load_sigma_rules,
    load_web_rules,
    merge_cve_rules,
    reset_registry,
    should_inject_direct_alert,
)

SIGMA_SAMPLE = textwrap.dedent("""
    title: SQL Injection Attempt - Union Select Pattern
    id: SIGMA-TEST-SQLI-1
    logsource:
        category: webserver
    detection:
        selection:
            cs-uri-query|contains|all:
                - union
                - select
        condition: selection
    level: high
    ---
    title: Suspicious Process Creation
    id: SIGMA-TEST-PROC-1
    logsource:
        category: process_creation
        product: windows
    detection:
        selection:
            CommandLine|contains: 'whoami'
        condition: selection
    level: medium
""").strip()

ET_SAMPLE = "\n".join([
    'alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET TEST SQL Injection"; '
    'flow:established,to_server; content:"union"; http_uri; nocase; content:"select"; '
    'http_uri; nocase; classtype:web-application-attack; sid:9001001; rev:1;)',
    'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TEST Response Direction"; '
    'flow:established,to_client; content:"uid="; file_data; nocase; sid:9001002; rev:1;)',
    'alert dns $HOME_NET any -> any 53 (msg:"ET TEST DNS Query"; content:"evil"; sid:9001003; rev:1;)',
    'alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET TEST Webshell Access"; '
    'flow:established,to_server; content:".php"; http_uri; nocase; content:"cmd="; http_uri; '
    'nocase; classtype:web-application-attack; sid:9001004; rev:1;)',
])


# --------------------------------------------------------------------------- #
# 1. 内置知识库与直达标记注入
# --------------------------------------------------------------------------- #
def test_web_rules_loaded_from_native_knowledge_base(settings):
    rules = load_web_rules(settings.web_attack_rules_path)
    assert len(rules) >= 60
    assert all(isinstance(rule, Rule) for rule in rules)
    assert all(rule.patterns and rule.match_targets for rule in rules)
    assert {rule.source for rule in rules} == {"native"}


def test_direct_alert_injected_by_category_whitelist(settings):
    """命令注入 / Webshell / SSTI / 文件上传 / XXE 必须自动直达，其余类别不直达。"""
    rules = {rule.id: rule for rule in load_web_rules(settings.web_attack_rules_path)}
    for rule in rules.values():
        expected = rule.category in DIRECT_ALERT_CATEGORIES
        if rule.category == "xxe":
            expected = rule.confidence == "high"      # XXE 需高置信度才直达
        assert rule.direct_alert is expected, f"{rule.id}（{rule.category}）直达标记不符预期"
    assert rules["WEB-CMDI-001"].direct_alert and rules["WEB-WS-001"].direct_alert
    assert notes_not_direct(rules)


def notes_not_direct(rules) -> bool:
    """明确不直达的类别（旧接口拼接易误报 / 依赖频次阈值）必须保持聚合路径。"""
    return all(not rules[rid].direct_alert for rid in ("WEB-SQLI-002", "WEB-XSSR-001"))


def test_should_inject_direct_alert_rules():
    assert should_inject_direct_alert("webshell", "high", "high") is True
    assert should_inject_direct_alert("sql_injection", "critical", "high") is False
    assert should_inject_direct_alert("port_scan", "critical", "high") is False
    assert should_inject_direct_alert("custom_category", "critical", "high", "sigma") is True
    assert should_inject_direct_alert("custom_category", "critical", "medium", "sigma") is False
    assert should_inject_direct_alert("command_injection", "critical", "high", "cve_ext") is False


def test_cve_rules_never_direct(settings):
    rules = load_cve_rules(settings.cve_rules_path)
    assert rules and all(rule.direct_alert is False for rule in rules)


# --------------------------------------------------------------------------- #
# 2. Sigma YAML
# --------------------------------------------------------------------------- #
def test_sigma_loader_converts_http_rules(tmp_path: Path):
    directory = tmp_path / "sigma_rules"
    directory.mkdir()
    (directory / "sample.yml").write_text(SIGMA_SAMPLE, encoding="utf-8")
    rules = load_sigma_rules(directory)
    assert len(rules) == 1, "非流量侧（process_creation）规则必须被跳过"
    rule = rules[0]
    assert rule.id == "SIGMA-TEST-SQLI-1"
    assert rule.category == "sql_injection"
    assert rule.match_targets == ["query"]
    # `|contains|all` 语义：union 与 select 必须同时命中
    assert rule.match_all is True
    assert sorted(rule.patterns) == ["select", "union"]
    assert rule.source == "sigma" and rule.remediation and rule.references


def test_sigma_loader_skips_unsupported_modifiers(tmp_path: Path):
    directory = tmp_path / "sigma_rules"
    directory.mkdir()
    (directory / "base64.yml").write_text(textwrap.dedent("""
        title: Webshell Access With Base64 Payload
        logsource:
            category: webserver
        detection:
            selection:
                cs-uri-query|base64offset|contains: 'whoami'
            condition: selection
        level: high
    """).strip(), encoding="utf-8")
    assert load_sigma_rules(directory) == []


def test_sigma_loader_handles_missing_directory(tmp_path: Path):
    assert load_sigma_rules(tmp_path / "not-exists") == []


# --------------------------------------------------------------------------- #
# 3. Suricata / ET
# --------------------------------------------------------------------------- #
def test_et_loader_parses_inbound_http_rules(tmp_path: Path):
    directory = tmp_path / "et_rules"
    directory.mkdir()
    (directory / "sample.rules").write_text(ET_SAMPLE + "\n", encoding="utf-8")
    rules = {rule.id: rule for rule in load_et_rules(directory)}
    # dns 规则与响应方向（to_client）规则都必须被跳过
    assert set(rules) == {"ET-9001001", "ET-9001004"}
    sql = rules["ET-9001001"]
    assert sql.category == "sql_injection"
    assert sql.match_all is True, "Suricata 多个 content 之间是 AND 语义"
    assert sorted(sql.patterns) == ["select", "union"]
    assert sql.severity == "high" and sql.direct_alert is False
    shell = rules["ET-9001004"]
    assert shell.category == "webshell" and shell.direct_alert is True


def test_et_loader_skips_hex_byte_blocks(tmp_path: Path):
    directory = tmp_path / "et_rules"
    directory.mkdir()
    (directory / "hex.rules").write_text(
        'alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET TEST Hex Only"; '
        'flow:established,to_server; content:"|0a 0d|"|"skip"; http_uri; sid:9002001; rev:1;)',
        encoding="utf-8")
    rules = load_et_rules(directory)
    assert all("\\x00" not in pattern for rule in rules for pattern in rule.patterns)


def test_et_loader_parses_threshold(tmp_path: Path):
    directory = tmp_path / "et_rules"
    directory.mkdir()
    (directory / "thr.rules").write_text(
        'alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET TEST Login Brute Force"; '
        'flow:established,to_server; content:"login"; http_uri; '
        'threshold: type both, track by_src, count 12, seconds 60; '
        'classtype:web-application-activity; sid:9003001; rev:1;)', encoding="utf-8")
    rules = load_et_rules(directory)
    assert rules and rules[0].threshold == {"window_sec": 60, "count": 12}


# --------------------------------------------------------------------------- #
# 4. 扩展 CVE
# --------------------------------------------------------------------------- #
def test_cve_ext_merging_prefers_extended(tmp_path: Path):
    base = tmp_path / "cve_rules.json"
    base.write_text('{"version": "t", "rules": [{"cve": "CVE-0000-1", "title": "base", '
                    '"severity": "high", "cvss": 1.0, "product_regex": "demo", '
                    '"version_lt": "1.0"}]}', encoding="utf-8")
    extended = tmp_path / "cve_rules_extended.json"
    extended.write_text('{"version": "t2", "rules": [{"cve": "CVE-0000-1", "title": "extended", '
                        '"severity": "critical", "cvss": 9.9, "product_regex": "demo", '
                        '"version_lt": "2.0", "recommendation": "升级"}]}', encoding="utf-8")

    native = load_cve_rules(base)
    extra = load_extended_rules(extended)
    merged = merge_cve_rules(native, extra)
    assert len(merged) == 1 and merged[0].title == "extended"
    assert merged[0].source == "cve_ext" and merged[0].direct_alert is False


def test_shipped_extended_cve_file_loads():
    path = Path(__file__).resolve().parents[1] / "data" / "cve_rules_extended.json"
    rules = load_extended_rules(path)
    assert len(rules) >= 5
    assert all(rule.cve and rule.remediation and rule.references for rule in rules)


# --------------------------------------------------------------------------- #
# 5. 注册表（索引 / 热加载 / 来源统计）
# --------------------------------------------------------------------------- #
def test_registry_indexes_and_stats(settings):
    registry = RuleRegistry(settings)
    report = registry.load_all()
    assert report["native_web"] >= 60
    assert report["sigma"] >= 1 and report["et"] >= 1 and report["cve_ext"] >= 5
    assert report["direct_alert"] >= 5
    assert registry.get_rules(category="sql_injection")
    assert registry.get_rules(source="sigma")
    assert all(rule.direct_alert for rule in registry.get_rules(category="webshell"))
    assert registry.rule("WEB-CMDI-001") is not None
    assert registry.is_direct("WEB-CMDI-001") is True
    assert registry.is_direct("WEB-SQLI-002") is False
    assert "sql_injection" in registry.categories()
    stats = registry.stats()
    assert stats["by_source"]["sigma"] >= 1 and stats["by_target"]["query"]


def test_registry_sources_payload_shape(settings):
    registry = RuleRegistry(settings)
    registry.load_all()
    payload = registry.sources(web_categories=["sql_injection", "webshell"])
    sources = {row["source"]: row for row in payload["sources"]}
    assert set(sources) == {"native", "sigma", "et", "cve_ext"}
    assert sources["native"]["enabled"] is True
    assert sources["sigma"]["rules"] >= 1
    assert payload["direct_alert_total"] >= 5
    assert payload["errors"] == []


def test_registry_reload_is_idempotent(settings):
    registry = RuleRegistry(settings)
    first = registry.load_all()
    second = registry.reload()
    assert first["sigma"] == second["sigma"] and first["et"] == second["et"]


def test_registry_hot_reload_picks_up_new_files(settings, tmp_path: Path):
    """把 RULES_DIR 指向临时目录：热加载后新规则应立即出现在注册表里。"""
    rules_dir = tmp_path / "data"
    (rules_dir / "et_rules").mkdir(parents=True)
    scoped = settings.model_copy(update={"rules_dir": str(rules_dir)})
    registry = RuleRegistry(scoped)
    before = registry.load_all()
    assert before["et"] == 0
    (rules_dir / "et_rules" / "new.rules").write_text(ET_SAMPLE + "\n", encoding="utf-8")
    after = registry.reload()
    assert after["et"] == 2


def test_registry_skips_unmappable_external_rules(settings, tmp_path: Path):
    """无法映射到内置大类的规则不得进入 Web 检测器（避免污染告警统计）。"""
    directory = tmp_path / "sigma_rules"
    directory.mkdir()
    (directory / "unknown.yml").write_text(textwrap.dedent("""
        title: Something We Cannot Map
        logsource:
            category: webserver
        detection:
            selection:
                cs-uri-query|contains: 'totally-unmapped-keyword'
            condition: selection
        level: high
    """).strip(), encoding="utf-8")
    assert load_sigma_rules(directory) == []


def test_load_path_dispatch(tmp_path: Path):
    directory = tmp_path / "et_rules"
    directory.mkdir()
    (directory / "one.rules").write_text(ET_SAMPLE + "\n", encoding="utf-8")
    assert load_path(directory)
    assert load_path(tmp_path / "missing") == []


def test_web_knowledge_base_merges_external_rules(settings):
    """知识库合并外部规则后：规则数增加、类别仍在 17 大类内、直达标记可读。"""
    from app.detection.web_knowledge import WebAttackKnowledgeBase

    registry = RuleRegistry(settings)
    registry.load_all()
    kb = WebAttackKnowledgeBase(settings.web_attack_rules_path,
                                extra_rules=registry.extras_for_web(),
                                direct_alert_ids=registry.direct_alert_ids)
    assert kb.external_loaded >= 2
    assert len(kb.rules) > 63
    known = {item["key"] for item in kb.categories}
    assert all(rule["category"] in known for rule in kb.rules)
    assert kb.stats["external_rules"] >= 2 and kb.stats["direct_alert_rules"] >= 5


def test_reset_registry_clears_singleton(settings):
    from app.rules import get_registry

    first = get_registry(settings)
    reset_registry()
    second = get_registry(settings)
    assert first is not second
