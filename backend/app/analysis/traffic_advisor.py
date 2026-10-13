"""AI 流量研判（窗口摘要 → 判定 + 建议），本地规则兜底。

注意：只把**聚合后的统计摘要**交给模型（bps/pps/端口 Top/告警类别计数），
不发送原始报文、URL、Payload；AI 结论只作为"研判建议"，不会直接触发封禁 ——
自动封禁仍然只由确定性规则（直达规则 + 严重度门槛 + 白名单）决定。
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ..config import Settings, get_settings
from .llm_client import DeepSeekClient, LLMUnavailable

logger = logging.getLogger(__name__)

SOURCE_LLM = "deepseek_v4_flash"
SOURCE_LOCAL = "local_rules"
VERDICTS = {"normal", "suspicious", "malicious", "unknown"}

SYSTEM_PROMPT = """你是流量安全分析助手。你会收到一段**聚合后的流量窗口摘要**（JSON），
请判断是否存在异常/攻击，并给出运营建议。

字段说明：window（bps/pps/连接数）、ports（端口 Top）、alerts（窗口内已产生告警的类别计数）、
signals（未达阈值的检测信号类别计数）、thresholds（当前生效阈值）。

只输出 JSON（不要解释文本），格式：
{"verdict": "normal|suspicious|malicious|unknown",
 "confidence": 0.0-1.0,
 "summary": "一句话结论（<=120字）",
 "findings": ["发现1", "发现2"],
 "recommendations": ["建议1", "建议2"]}

判定要求：
1. 无告警且各项指标接近基线 → normal；
2. 出现直达告警（direct_alert）或多类攻击信号 → malicious；
3. 仅有少量弱信号或单一异常 → suspicious；
4. 证据不足 → unknown，不要臆测。"""


class TrafficAdvisor:
    """把 `CollectorService.ai_traffic_digest()` 的摘要变成研判结论。"""

    def __init__(self, settings: Optional[Settings] = None,
                 client: Optional[DeepSeekClient] = None) -> None:
        self.settings = settings or get_settings()
        self.client = client or DeepSeekClient(self.settings)
        self.counters: Dict[str, int] = {"total": 0, SOURCE_LLM: 0, SOURCE_LOCAL: 0,
                                         "llm_unavailable": 0}

    def review(self, digest: Dict[str, Any]) -> Dict[str, Any]:
        self.counters["total"] += 1
        if self.client.available:
            try:
                raw = self.client.chat_json(self._messages(digest), max_tokens=700)
                return self._payload(self._validate(raw), SOURCE_LLM, degraded=False)
            except LLMUnavailable as exc:
                self.counters["llm_unavailable"] += 1
                logger.warning("AI 流量研判不可用，降级到本地规则：%s", exc)
        return self._payload(self._heuristic(digest), SOURCE_LOCAL, degraded=True)

    @staticmethod
    def _messages(digest: Dict[str, Any]) -> List[Dict[str, str]]:
        return [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": "请研判以下流量窗口：\n"
                                        + json.dumps(digest, ensure_ascii=False)},
        ]

    @staticmethod
    def _validate(raw: Dict[str, Any]) -> Dict[str, Any]:
        verdict = str(raw.get("verdict") or "").strip().lower()
        if verdict not in VERDICTS:
            raise LLMUnavailable(f"非法 verdict：{verdict!r}")
        try:
            confidence = min(1.0, max(0.0, float(raw.get("confidence"))))
        except (TypeError, ValueError) as exc:
            raise LLMUnavailable("confidence 非数值") from exc
        summary = str(raw.get("summary") or "").strip()[:300]
        findings = [str(item).strip()[:200] for item in
                    (raw.get("findings") or []) if str(item).strip()][:6]
        recommendations = [str(item).strip()[:200] for item in
                           (raw.get("recommendations") or []) if str(item).strip()][:6]
        if not summary:
            raise LLMUnavailable("summary 为空")
        return {"verdict": verdict, "confidence": round(confidence, 3), "summary": summary,
                "findings": findings, "recommendations": recommendations}

    @staticmethod
    def _heuristic(digest: Dict[str, Any]) -> Dict[str, Any]:
        """本地规则兜底：只依据窗口内已经落库的告警/信号，不猜测。"""
        window = digest.get("window") or {}
        alerts = digest.get("alerts") or {}
        signals = digest.get("signals") or {}
        threshold = float(digest.get("threshold") or 6.0)
        direct = int(alerts.get("direct_count") or 0)
        high = int(alerts.get("high_count") or 0)
        max_risk = float(alerts.get("max_risk_score") or 0.0)
        categories = alerts.get("categories") or {}
        findings: List[str] = []
        for name, count in sorted(categories.items(), key=lambda item: -int(item[1]))[:4]:
            findings.append(f"窗口内「{name}」类告警 {count} 条")
        if signals:
            findings.append("未达阈值的信号：" + "、".join(
                f"{name}×{count}" for name, count in list(signals.items())[:5]))
        if not findings:
            findings.append("窗口内无告警与异常信号，流量指标位于正常区间")

        if direct or (high and max_risk >= threshold):
            verdict, confidence = "malicious", 0.85
            summary = (f"窗口内出现直达/高危告警（direct={direct}，"
                       f"max_risk={max_risk}），疑似正在遭受攻击。")
            recommendations = [
                "在「风险 IP 封禁」页确认自动封禁结果，未封禁的来源立即人工封禁。",
                "核对 Web 访问日志与业务日志，确认攻击是否成功（状态码/响应体/异常文件）。",
                "对命中规则对应的业务接口做加固：参数化查询、输出编码、上传目录禁执行。",
            ]
        elif max_risk > 0 or alerts.get("total") or signals:
            verdict, confidence = "suspicious", 0.6
            summary = "窗口内存在少量异常信号但证据不足以判定攻击，建议持续观察并人工复核。"
            recommendations = [
                "复核 /signals 与 /alerts 中的证据字段（端口熵、命中次数、规则 ID）。",
                "对可疑来源做限速或加入观察名单，暂不自动封禁。",
                "确认是否为业务高峰、备份窗口或授权扫描。",
            ]
        else:
            verdict, confidence = "normal", 0.7
            summary = (f"窗口内未发现异常：{window.get('bps_in', 0)} bps in / "
                       f"{window.get('conns', 0)} 连接，无告警与信号。")
            recommendations = ["保持监控；如需更高灵敏度可下调 ZSCORE_THRESHOLD 或在阈值页调整。"]

        return {"verdict": verdict, "confidence": confidence, "summary": summary,
                "findings": findings, "recommendations": recommendations}

    def _payload(self, result: Dict[str, Any], source: str, degraded: bool) -> Dict[str, Any]:
        self.counters[source] = self.counters.get(source, 0) + 1
        return {
            "source": source,
            "degraded": bool(degraded),
            "verdict": result["verdict"],
            "confidence": result["confidence"],
            "summary": result["summary"],
            "findings": list(result["findings"]),
            "recommendations": list(result["recommendations"]),
            "generated_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z",
        }

    @property
    def stats(self) -> Dict[str, Any]:
        return {"client_available": self.client.available, **self.counters}

