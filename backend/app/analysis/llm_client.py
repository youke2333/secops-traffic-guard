"""LLM 研判客户端（DeepSeek / 任意 OpenAI 兼容接口）。

硬约束（方案 4.3 节）：
* 单次调用超时默认 3s（`LLM_TIMEOUT_SEC`），且**在后台线程执行**，绝不阻塞 500ms 的 tick 节奏；
* 输出必须通过 schema 校验（verdict / suggestion 枚举 + confidence 值域），非法值视为不可用并降级；
* 只发送结构化摘要（见 `prompts.build_alert_digest`），禁止发送原始 payload / URL / UA；
* 任何网络/解析异常都抛 `LLMUnavailable`，由降级链接管 —— 不在这里做重试风暴。
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional

import httpx

from ..config import Settings, get_settings
from .prompts import build_messages

logger = logging.getLogger(__name__)

VERDICTS = {"confirm", "suspect", "dismiss", "unknown"}
SUGGESTIONS = {"block", "watch", "ignore"}
_FENCE_RE = re.compile(r"^```(?:json)?|```$", re.MULTILINE)


class LLMUnavailable(Exception):
    """LLM 不可用（未配置 / 超时 / 非 2xx / 输出非法）——降级链的触发信号。"""


class DeepSeekClient:
    """OpenAI 兼容 Chat Completions 客户端（DeepSeek V4-Flash 默认）。"""

    def __init__(self, settings: Optional[Settings] = None) -> None:
        cfg = settings or get_settings()
        self.settings = cfg
        self.enabled = bool(cfg.llm_enabled)
        self.api_key = cfg.llm_api_key
        self.base_url = (cfg.llm_base_url or "").rstrip("/")
        self.model = cfg.llm_model
        self.timeout = float(cfg.llm_timeout_sec)
        self.max_retries = int(cfg.llm_max_retries)

    @property
    def available(self) -> bool:
        """能否发起真实调用（缺 Key 时视为不可用，直接走降级）。"""
        return bool(self.enabled and self.api_key and self.base_url)

    # ------------------------------------------------------------------ #
    def chat_json(self, messages: List[Dict[str, str]], max_tokens: int = 512,
                  temperature: float = 0.0) -> Dict[str, Any]:
        """调用 Chat Completions 并解析出 JSON 对象（供告警/漏洞/流量三类研判复用）。"""
        if not self.available:
            raise LLMUnavailable("LLM 未启用或未配置 API Key")
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": False,
        }
        attempts = max(1, self.max_retries + 1)
        last_error = ""
        for attempt in range(attempts):
            try:
                response = httpx.post(
                    f"{self.base_url}/chat/completions",
                    headers={"Authorization": f"Bearer {self.api_key}",
                             "Content-Type": "application/json"},
                    json=payload, timeout=self.timeout,
                )
                if response.status_code >= 400:
                    last_error = f"HTTP {response.status_code}"
                    continue
                content = (response.json().get("choices") or [{}])[0].get("message", {}).get(
                    "content", "")
                return _extract_json(content)
            except LLMUnavailable:
                raise
            except Exception as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                logger.warning("LLM 调用失败（第 %d/%d 次）：%s", attempt + 1, attempts, last_error)
        raise LLMUnavailable(last_error or "LLM 调用失败")

    def analyze(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """请求告警研判；返回已校验的结果字典。失败抛 `LLMUnavailable`。"""
        if not self.available:
            raise LLMUnavailable("LLM 未启用或未配置 API Key")
        return validate_result(self.chat_json(
            build_messages(alert, bool(self.settings.llm_mask_internal_ip))))


def _extract_json(content: str) -> Dict[str, Any]:
    text = _FENCE_RE.sub("", str(content or "")).strip()
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        raise LLMUnavailable(f"LLM 输出不含 JSON 对象：{text[:120]}")
    try:
        return json.loads(text[start:end + 1])
    except json.JSONDecodeError as exc:
        raise LLMUnavailable(f"LLM 输出 JSON 解析失败：{exc}") from exc


def validate_result(raw: Dict[str, Any]) -> Dict[str, Any]:
    """schema 校验：枚举值 + 置信度值域，任一不合法即视为不可用（走降级）。"""
    verdict = str(raw.get("verdict") or "").strip().lower()
    suggestion = str(raw.get("suggestion") or "").strip().lower()
    if verdict not in VERDICTS:
        raise LLMUnavailable(f"非法 verdict：{verdict!r}")
    if suggestion not in SUGGESTIONS:
        raise LLMUnavailable(f"非法 suggestion：{suggestion!r}")
    try:
        confidence = float(raw.get("confidence"))
    except (TypeError, ValueError) as exc:
        raise LLMUnavailable("confidence 非数值") from exc
    confidence = min(1.0, max(0.0, confidence))
    reason = str(raw.get("reason") or "").strip()[:200] or "模型未给出理由"
    return {
        "verdict": verdict,
        "confidence": round(confidence, 3),
        "suggestion": suggestion,
        "reason": reason,
    }
