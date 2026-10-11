"""告警通道：Webhook（钉钉/企业微信/通用）、邮件、Syslog、本地日志。

设计要点：

* 通道失败**不影响**主流程（异常全部吞掉并记录 last_error），避免告警系统拖垮检测链路；
* 所有外呼带超时，且默认只在严重程度达阈值时触发（由 Notifier 统一控制）；
* 通道可插拔：新增通道只需实现 ``AlertChannel.send``。
"""

from __future__ import annotations

import json
import logging
import smtplib
import socket
from abc import ABC, abstractmethod
from email.message import EmailMessage
from email.utils import formatdate
from typing import Dict, List, Tuple

import httpx

from ..config import Settings

logger = logging.getLogger(__name__)

SEVERITY_EMOJI = {"critical": "🚨", "high": "🔥", "medium": "⚠️", "low": "ℹ️"}


def format_markdown(anomaly: Dict[str, object]) -> str:
    """统一的 Markdown 告警文案（钉钉 / 企业微信均支持）。"""
    severity = str(anomaly.get("severity", "medium"))
    emoji = SEVERITY_EMOJI.get(severity, "⚠️")
    lines = [
        f"## {emoji} 流量安全告警：{anomaly.get('category_text', anomaly.get('category', ''))}",
        f"- **级别**：{anomaly.get('severity_text', severity)}（score={anomaly.get('score')}）",
        f"- **时间**：{anomaly.get('ts_text', '')}",
        f"- **源 IP**：{anomaly.get('source_ip') or '未知'}",
        f"- **目标**：{anomaly.get('dest_ip') or '-'}:{anomaly.get('dest_port') or '-'}",
        f"- **检测器**：{anomaly.get('detector', '-')}",
        f"- **详情**：{anomaly.get('message', '')}",
    ]
    evidence = anomaly.get("evidence") or {}
    if evidence:
        preview = json.dumps(evidence, ensure_ascii=False)[:500]
        lines.append(f"- **证据**：`{preview}`")
    lines.append(f"- **处置**：{'已自动封禁' if anomaly.get('blocked') else '待人工确认'}")
    return "\n".join(lines)


class AlertChannel(ABC):
    name = "base"
    kind = "generic"

    def __init__(self, min_severity: str = "medium") -> None:
        self.min_severity = min_severity
        self.last_error = ""

    @abstractmethod
    def send(self, anomaly: Dict[str, object]) -> Tuple[bool, str]:
        """返回 (是否成功, 说明)。"""

    def build_text(self, anomaly: Dict[str, object]) -> str:
        return format_markdown(anomaly)


class LogChannel(AlertChannel):
    """本地日志通道：始终启用，作为审计兜底。"""

    name = "log"
    kind = "log"

    def send(self, anomaly: Dict[str, object]) -> Tuple[bool, str]:
        logger.warning("[ALERT] %s | %s | %s", anomaly.get("category"),
                       anomaly.get("source_ip"), anomaly.get("message"))
        return True, "logged"


class WebhookChannel(AlertChannel):
    """Webhook 通道：支持钉钉机器人、企业微信机器人、通用 JSON 回调。"""

    def __init__(self, url: str, kind: str = "generic", timeout: float = 5.0,
                 min_severity: str = "medium") -> None:
        super().__init__(min_severity=min_severity)
        self.url = url
        self.kind = kind
        self.timeout = timeout
        self._name = f"webhook:{kind}"

    @property
    def name(self) -> str:  # type: ignore[override]
        return self._name

    def _payload(self, anomaly: Dict[str, object]) -> Dict[str, object]:
        text = self.build_text(anomaly)
        title = f"流量安全告警：{anomaly.get('category_text', anomaly.get('category', ''))}"
        if self.kind == "dingtalk":
            return {"msgtype": "markdown", "markdown": {"title": title, "text": text}}
        if self.kind == "wecom":
            return {"msgtype": "markdown", "markdown": {"content": text}}
        return {"title": title, "severity": anomaly.get("severity"), "text": text,
                "source_ip": anomaly.get("source_ip"), "evidence": anomaly.get("evidence")}

    def send(self, anomaly: Dict[str, object]) -> Tuple[bool, str]:
        if not self.url:
            return False, "未配置 URL"
        try:
            response = httpx.post(self.url, json=self._payload(anomaly), timeout=self.timeout)
            body = response.text[:200]
            if response.status_code >= 400:
                self.last_error = f"HTTP {response.status_code}: {body}"
                return False, self.last_error
            compact = body.replace(" ", "")
            if '"errcode":0' in compact or self.kind == "generic":
                return True, f"HTTP {response.status_code}"
            self.last_error = body
            return False, body
        except Exception as exc:
            self.last_error = str(exc)
            logger.warning("Webhook 告警发送失败: %s", exc)
            return False, self.last_error


class EmailChannel(AlertChannel):
    """SMTP 邮件通道（支持 SSL 465 与 STARTTLS 587 两种模式）。"""

    name = "email"
    kind = "email"

    def __init__(self, settings: Settings) -> None:
        super().__init__(min_severity="high")
        self.settings = settings

    def send(self, anomaly: Dict[str, object]) -> Tuple[bool, str]:
        cfg = self.settings
        if not (cfg.smtp_host and cfg.smtp_recipients):
            return False, "未配置 SMTP_HOST / SMTP_RECIPIENTS"
        message = EmailMessage()
        message["Subject"] = (
            f"[流量安全告警] {anomaly.get('category_text', anomaly.get('category'))} "
            f"- {anomaly.get('source_ip')}"
        )
        message["From"] = cfg.smtp_sender or cfg.smtp_user
        message["To"] = ", ".join(cfg.smtp_recipients)
        message["Date"] = formatdate(localtime=True)
        message.set_content(self.build_text(anomaly).replace("**", "").replace("##", ""))
        try:
            if cfg.smtp_ssl:
                server: smtplib.SMTP = smtplib.SMTP_SSL(cfg.smtp_host, cfg.smtp_port, timeout=10)
            else:
                server = smtplib.SMTP(cfg.smtp_host, cfg.smtp_port, timeout=10)
                server.starttls()
            with server:
                if cfg.smtp_user:
                    server.login(cfg.smtp_user, cfg.smtp_password)
                server.send_message(message)
            return True, f"已发送至 {len(cfg.smtp_recipients)} 个收件人"
        except Exception as exc:
            self.last_error = str(exc)
            logger.warning("邮件告警发送失败: %s", exc)
            return False, self.last_error


class SyslogChannel(AlertChannel):
    """Syslog 通道：把告警以 RFC5424 推送给集中日志平台（SIEM/SOC）。"""

    name = "syslog"
    kind = "syslog"

    def __init__(self, address: str, min_severity: str = "medium") -> None:
        super().__init__(min_severity=min_severity)
        self.address = address
        host, _, port = address.partition(":")
        self.host = host
        self.port = int(port or 514)

    def send(self, anomaly: Dict[str, object]) -> Tuple[bool, str]:
        if not self.host:
            return False, "未配置 SYSLOG_ADDRESS"
        payload = json.dumps(anomaly, ensure_ascii=False, default=str)
        # facility=13(local0)*8 + severity(3=err / 5=notice)
        priority = 13 * 8 + (3 if anomaly.get("severity") in ("critical", "high") else 5)
        message = f"<{priority}>1 - secops traffic-guard - - - {payload}".encode("utf-8")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.settimeout(3)
                sock.sendto(message, (self.host, self.port))
            finally:
                sock.close()
            return True, f"UDP -> {self.address}"
        except Exception as exc:
            self.last_error = str(exc)
            return False, self.last_error


def build_channels(settings: Settings) -> List[AlertChannel]:
    """按配置装配通道；未配置的通道自动跳过。"""
    wanted = {item.strip().lower() for item in settings.alert_channels if item.strip()}
    channels: List[AlertChannel] = []
    if "log" in wanted or not wanted:
        channels.append(LogChannel())
    if "webhook" in wanted or settings.dingtalk_webhook or settings.wecom_webhook or settings.generic_webhook:
        if settings.dingtalk_webhook:
            channels.append(WebhookChannel(settings.dingtalk_webhook, kind="dingtalk"))
        if settings.wecom_webhook:
            channels.append(WebhookChannel(settings.wecom_webhook, kind="wecom"))
        if settings.generic_webhook:
            channels.append(WebhookChannel(settings.generic_webhook, kind="generic"))
    if "email" in wanted and settings.smtp_host:
        channels.append(EmailChannel(settings))
    if "syslog" in wanted and settings.syslog_address:
        channels.append(SyslogChannel(settings.syslog_address))
    return channels

