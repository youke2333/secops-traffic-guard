"""漏洞修复建议（AI 优先 + 知识库模板降级）。

约束：
* 只发送结构化漏洞字段（CVE/标题/级别/CVSS/产品版本/端口/已有建议），不发送扫描原始响应；
* 输出必须通过 schema 校验（summary / steps / verification / risk），否则降级；
* API 不可用时用知识库建议生成可执行步骤，并标记 ``degraded=True``（前端显示来源）。
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ..config import Settings, get_settings
from .llm_client import DeepSeekClient, LLMUnavailable
from .prompts import mask_ip

logger = logging.getLogger(__name__)

SOURCE_LLM = "deepseek_v4_flash"
SOURCE_TEMPLATE = "knowledge_base"

SYSTEM_PROMPT = """你是企业漏洞管理与修复助手。你会收到一条结构化漏洞记录（JSON）。
请给出可执行的修复建议，必须基于给定字段，禁止臆造未提供的版本号或漏洞细节。

只输出 JSON（不要解释文本），格式：
{"summary": "一句话说明风险（<=120字）",
 "steps": ["步骤1", "步骤2", "步骤3"],
 "verification": "修复后的验证方法（<=100字）",
 "risk": "high|medium|low"}

要求：
1. steps 3~6 条，包含备份/回滚与变更窗口提示；
2. Web 配置/暴露面类问题优先建议收敛暴露面，而不是仅升级版本；
3. 不得输出删除数据、关闭安全设备等破坏性操作。"""


class VulnAdvisor:
    """单一漏洞的修复建议生成器（供 `POST /vulns/{id}/ai-advice` 使用）。"""

    def __init__(self, settings: Optional[Settings] = None,
                 client: Optional[DeepSeekClient] = None) -> None:
        self.settings = settings or get_settings()
        self.client = client or DeepSeekClient(self.settings)
        self.counters: Dict[str, int] = {"total": 0, SOURCE_LLM: 0, SOURCE_TEMPLATE: 0,
                                         "llm_unavailable": 0}

    def advise(self, vuln: Dict[str, Any], force: bool = False) -> Dict[str, Any]:
        """生成修复建议；``force=True`` 表示用户点了"重新生成"。

        这里必须区分两条路径，否则"重新生成"是个摆设：常规生成用 ``temperature=0``
        求稳定；重新生成把温度抬到 0.7 并明确再打一次模型，否则同样的输入会拿回
        逐字相同的结果，用户看到内容没变会认为请求根本没发出去。

        另外每次调用都会真实发起 HTTP 请求——本模块不做结果缓存（缓存只存在于
        告警研判的 enricher 里），所以不存在"命中缓存导致不请求"的情况。
        """
        self.counters["total"] += 1
        fallback = self._template(vuln)
        if self.client.available:
            try:
                raw = self.client.chat_json(
                    self._messages(vuln), max_tokens=700,
                    temperature=0.7 if force else 0.0)
                result = self._validate(raw)
                return self._payload(result, SOURCE_LLM, degraded=False, regenerated=force)
            except LLMUnavailable as exc:
                self.counters["llm_unavailable"] += 1
                logger.warning("漏洞修复建议 AI 不可用，降级到知识库：%s", exc)
        return self._payload(fallback, SOURCE_TEMPLATE, degraded=True, regenerated=force)

    # ------------------------------------------------------------------ #
    def _messages(self, vuln: Dict[str, Any]) -> List[Dict[str, str]]:
        digest = {
            "cve": str(vuln.get("cve") or ""),
            "title": str(vuln.get("title") or "")[:200],
            "severity": str(vuln.get("severity") or ""),
            "cvss": vuln.get("cvss") or 0,
            "asset_ip": mask_ip(vuln.get("asset_ip"), True),
            "port": vuln.get("port") or 0,
            "service": str(vuln.get("service") or "")[:120],
            "evidence": str(vuln.get("evidence") or "")[:300],
            "fixed_version": str(vuln.get("fixed_version") or "")[:80],
            "existing_recommendation": str(vuln.get("recommendation") or "")[:300],
        }
        import json

        return [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": "请为以下漏洞生成修复建议：\n"
                                        + json.dumps(digest, ensure_ascii=False)},
        ]

    @staticmethod
    def _validate(raw: Dict[str, Any]) -> Dict[str, Any]:
        summary = str(raw.get("summary") or "").strip()[:300]
        steps = [str(item).strip()[:300] for item in (raw.get("steps") or [])
                 if str(item).strip()][:8]
        verification = str(raw.get("verification") or "").strip()[:200]
        risk = str(raw.get("risk") or "").strip().lower()
        if not summary or len(steps) < 2 or not verification:
            raise LLMUnavailable("漏洞建议字段不完整")
        if risk not in {"high", "medium", "low"}:
            risk = "medium"
        return {"summary": summary, "steps": steps, "verification": verification, "risk": risk}

    @staticmethod
    def _template(vuln: Dict[str, Any]) -> Dict[str, Any]:
        """知识库兜底：用已有 recommendation / fixed_version 生成可执行步骤。"""
        cve = str(vuln.get("cve") or "")
        title = str(vuln.get("title") or "该漏洞")
        target = f"{vuln.get('asset_ip') or '-'}:{vuln.get('port') or '-'}"
        fixed = str(vuln.get("fixed_version") or "").strip()
        recommendation = str(vuln.get("recommendation") or "").strip()
        is_web_check = cve.startswith("WEB-")
        if is_web_check:
            steps = [
                f"确认 {target} 上该暴露面/配置项是否为业务必需；非必需的直接下线或加访问控制。",
                recommendation or "按扫描证据逐项加固：关闭目录列举、移除调试与安装脚本、补齐安全响应头。",
                "在 Web 服务器或网关层统一配置，避免逐个站点遗漏，并纳入上线基线检查。",
                "变更后重新扫描该地址，确认该编号不再出现；保留变更记录与扫描证据。",
            ]
            summary = f"{title}：属于 Web 应用配置与暴露面类风险，单项影响有限，叠加会显著扩大攻击面。"
        else:
            steps = [
                f"确认受影响资产 {target} 的业务重要性与变更窗口，先备份配置与数据。",
                (f"按厂商公告升级到 {fixed} 或安装对应安全补丁；升级前准备回滚包。"
                 if fixed else "按厂商公告安装安全补丁；若暂无补丁，先实施临时缓解措施。"),
                recommendation or "收紧服务暴露面（仅内网/白名单访问），关闭不必要端口与组件。",
                "在维护窗口执行变更，变更后观察业务指标与错误日志 30 分钟。",
                "重新扫描该资产确认漏洞关闭；若未关闭，保留记录并升级处理。",
            ]
            summary = f"{title}（{cve or '无编号'}，CVSS {vuln.get('cvss') or 0}）影响 {target}，建议按步骤修复。"
        return {
            "summary": summary,
            "steps": steps,
            "verification": "调用 POST /api/v1/vulns/scan（或单资产 rescan）重新扫描，确认该记录不再出现。",
            "risk": "high" if str(vuln.get("severity")) in ("critical", "high") else "medium",
        }

    def _payload(self, result: Dict[str, Any], source: str, degraded: bool,
                 regenerated: bool = False) -> Dict[str, Any]:
        self.counters[source] = self.counters.get(source, 0) + 1
        return {
            "source": source,
            "degraded": bool(degraded),
            "regenerated": bool(regenerated),
            "summary": result["summary"],
            "steps": list(result["steps"]),
            "verification": result["verification"],
            "risk": result["risk"],
            "generated_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z",
        }

    @property
    def stats(self) -> Dict[str, Any]:
        return {"client_available": self.client.available, **self.counters}
