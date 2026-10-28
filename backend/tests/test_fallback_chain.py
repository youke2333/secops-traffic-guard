"""AI 研判降级链测试（方案第 4 / 5 层）。

覆盖：
1. 四级降级顺序：LLM → 本地规则 → 静态模板 → 待人工（每级来源标注正确）；
2. schema 校验：非法枚举/置信度一律视为不可用并降级；
3. Prompt 安全：只发结构化摘要、内网 IP 脱敏、绝不携带原始 payload / URL / UA；
4. 异步执行器：研判结果写回 alerts.llm_analysis 并推送 alert_enriched 事件。
"""

from __future__ import annotations

import time
from datetime import datetime

import pytest

from app.analysis.enricher import AlertEnricher
from app.analysis.fallback_chain import (
    SOURCE_LLM,
    SOURCE_LOCAL,
    SOURCE_PENDING,
    SOURCE_TEMPLATE,
    AnalysisFallbackChain,
)
from app.analysis.llm_client import DeepSeekClient, LLMUnavailable, validate_result
from app.analysis.prompts import build_alert_digest, build_messages, mask_ip
from app.database import session_scope
from app.models import Alert
from app.bus import EventBus

ALERT = {
    "id": 1,
    "category": "web_command_injection",
    "severity": "critical",
    "score": 0.95,
    "risk_score": 6.0,
    "direct_alert": True,
    "contributing_rules": ["WEB-CMDI-001"],
    "source_ip": "10.20.30.40",
    "dest_port": 80,
    "protocol": "TCP",
    "detector": "web-kb",
    "evidence": {"hits": 1, "rule_ids": ["WEB-CMDI-001"],
                 "request": {"path": "/exec/", "query": "ip=1.1.1.1;cat /etc/passwd"}},
    "message": "源 10.20.30.40 POST /exec/ 命中「命令注入」",
}


class StubClient:
    """可编程的 LLM 客户端桩：用于逐一触发降级链的每一级。"""

    def __init__(self, available: bool = True, result: dict | None = None,
                 error: Exception | None = None) -> None:
        self._available = available
        self._result = result or {"verdict": "confirm", "confidence": 0.9,
                                  "suggestion": "block", "reason": "命中 RCE 规则"}
        self._error = error
        self.calls = 0

    @property
    def available(self) -> bool:
        return self._available

    def analyze(self, alert: dict) -> dict:
        self.calls += 1
        if self._error is not None:
            raise self._error
        return validate_result(self._result)


# --------------------------------------------------------------------------- #
# 降级链四级
# --------------------------------------------------------------------------- #
def test_llm_available_uses_model_result(settings):
    client = StubClient()
    chain = AnalysisFallbackChain(settings, client=client)
    result = chain.analyze(ALERT)
    assert result["source"] == SOURCE_LLM and result["degraded"] is False
    assert result["verdict"] == "confirm" and result["direct_alert"] is True
    assert client.calls == 1
    assert chain.stats["sources"][SOURCE_LLM] == 1


def test_llm_failure_degrades_to_local_rules(settings):
    client = StubClient(error=LLMUnavailable("超时"))
    chain = AnalysisFallbackChain(settings, client=client)
    result = chain.analyze(ALERT)
    assert result["source"] == SOURCE_LOCAL and result["degraded"] is True
    assert result["suggestion"] == "block"
    assert "本地规则" in result["reason"]
    assert chain.stats["sources"]["llm_unavailable"] == 1


def test_llm_unavailable_falls_back_to_template(settings):
    alert = {**ALERT, "risk_score": 1.0, "direct_alert": False}
    chain = AnalysisFallbackChain(settings, client=StubClient(available=False))
    result = chain.analyze(alert)
    assert result["source"] == SOURCE_TEMPLATE and result["degraded"] is True
    # 模板理由里会插入检测证据（"hits=1"）
    assert "命中" in result["reason"] and result["verdict"] == "confirm"


def test_no_template_falls_back_to_pending(settings):
    alert = {**ALERT, "category": "not_a_known_category", "risk_score": 0.5,
             "direct_alert": False, "contributing_rules": []}
    chain = AnalysisFallbackChain(settings, client=StubClient(available=False))
    result = chain.analyze(alert)
    assert result["source"] == SOURCE_PENDING
    assert result["verdict"] == "unknown" and result["suggestion"] == "watch"
    assert "人工核查" in result["reason"]


def test_aggregated_alert_without_direct_goes_to_template(settings):
    """聚合告警（非直达）在 API 不可用且评分不高时走模板，而不是本地规则强判。"""
    alert = {**ALERT, "direct_alert": False, "risk_score": 1.5, "category": "port_scan",
             "severity": "high", "evidence": {"unique_dst_ports": 120, "port_entropy": 6.5}}
    chain = AnalysisFallbackChain(settings, client=StubClient(available=False))
    result = chain.analyze(alert)
    assert result["source"] == SOURCE_TEMPLATE and result["verdict"] == "suspect"


def test_chain_stats_shape(settings):
    chain = AnalysisFallbackChain(settings, client=StubClient(available=False))
    chain.analyze(ALERT)
    stats = chain.stats
    assert stats["enabled"] is True and "sources" in stats
    assert stats["sources"]["total"] == 1
    assert "model" in stats


# --------------------------------------------------------------------------- #
# Prompt 安全与 schema 校验
# --------------------------------------------------------------------------- #
def test_validate_result_rejects_illegal_values():
    assert validate_result({"verdict": "confirm", "confidence": 1.5,
                            "suggestion": "block", "reason": "ok"})["confidence"] == 1.0
    for bad in ({"verdict": "hack", "confidence": 0.5, "suggestion": "block"},
                {"verdict": "confirm", "confidence": 0.5, "suggestion": "nuke"},
                {"verdict": "confirm", "confidence": "高", "suggestion": "block"}):
        with pytest.raises(LLMUnavailable):
            validate_result(bad)


def test_prompt_digest_excludes_raw_payload_and_masks_ip():
    """注入防护：原始 URL / query / UA 绝不进入 Prompt，内网 IP 必须脱敏。"""
    digest = build_alert_digest(ALERT, mask_internal_ip=True)
    assert digest["source_ip"] == "10.20.0.0"
    text = str(digest)
    assert "cat /etc/passwd" not in text, "原始载荷不得进入 Prompt"
    assert "/exec/" not in text
    assert digest["evidence_summary"]["hits"] == 1
    assert mask_ip("192.168.1.30") == "192.168.0.0"
    assert mask_ip("203.0.113.9") == "203.0.113.9"


def test_prompt_carries_direct_alert_and_rules():
    messages = build_messages(ALERT, mask_internal_ip=True)
    assert len(messages) == 2 and messages[0]["role"] == "system"
    assert "direct_alert" in messages[0]["content"], "系统提示必须解释直达机制语义"
    body = messages[1]["content"]
    assert "WEB-CMDI-001" in body and "risk_score" in body


def test_client_unavailable_without_api_key(settings):
    scoped = settings.model_copy(update={"llm_api_key": "", "llm_enabled": True})
    client = DeepSeekClient(scoped)
    assert client.available is False
    with pytest.raises(LLMUnavailable):
        client.analyze(ALERT)


def test_client_disabled_by_switch(settings):
    scoped = settings.model_copy(update={"llm_api_key": "sk-test", "llm_enabled": False})
    assert DeepSeekClient(scoped).available is False


# --------------------------------------------------------------------------- #
# 异步执行器
# --------------------------------------------------------------------------- #
@pytest.fixture()
def stored_alert():
    with session_scope() as session:
        row = Alert(ts=datetime.fromtimestamp(time.time()),
                    source_ip="203.0.113.240", dest_port=80, category="web_command_injection",
                    severity="critical", score=0.95, risk_score=6.0, direct_alert=True,
                    contributing_rules=["WEB-CMDI-001"], message="测试研判", status="open")
        session.add(row)
        session.flush()
        alert_id = row.id
    yield alert_id
    with session_scope() as session:
        target = session.get(Alert, alert_id)
        if target is not None:
            session.delete(target)


def test_enricher_writes_back_and_publishes_event(settings, stored_alert):
    bus = EventBus(maxlen=16)
    subscriber = bus.subscribe()
    enricher = AlertEnricher(settings, chain=AnalysisFallbackChain(
        settings, client=StubClient(available=False)), event_bus=bus)

    result = enricher.enrich(stored_alert)
    assert result is not None and result["source"] in {SOURCE_LOCAL, SOURCE_TEMPLATE}
    with session_scope() as session:
        row = session.get(Alert, stored_alert)
        assert row.llm_analysis and row.llm_analysis["source"] == result["source"]
        assert row.llm_analysis["degraded"] is True
    events = bus.drain(subscriber, "alert_enriched")
    assert events and events[0]["data"]["alert_id"] == stored_alert


def test_enricher_caches_same_source_category(settings, stored_alert):
    enricher = AlertEnricher(settings, chain=AnalysisFallbackChain(
        settings, client=StubClient(available=False)))
    first = enricher.enrich(stored_alert)
    second = enricher.enrich(stored_alert)
    assert second is not None and second.get("cached") is True
    assert enricher.stats["cached"] == 1
    assert first["verdict"] == second["verdict"]


def test_enricher_submit_queue_and_missing_alert(settings, stored_alert):
    enricher = AlertEnricher(settings, chain=AnalysisFallbackChain(
        settings, client=StubClient(available=False)))
    assert enricher.submit(stored_alert) is True
    assert enricher.submit(None) is False
    enricher.start()
    deadline = time.time() + 5
    while enricher.stats["done"] < 1 and time.time() < deadline:
        time.sleep(0.05)
    enricher.stop()
    assert enricher.stats["done"] >= 1
    assert enricher.enrich(999999) is None


def test_enricher_stats_shape(settings):
    enricher = AlertEnricher(settings, chain=AnalysisFallbackChain(
        settings, client=StubClient(available=False)))
    stats = enricher.stats
    assert stats["queued"] == 0 and stats["submitted"] == 0
    assert stats["chain"]["enabled"] is True
