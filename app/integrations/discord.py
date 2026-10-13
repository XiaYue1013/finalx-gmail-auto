from __future__ import annotations

import logging

import httpx

from app.config import settings
from app.models import ScanDecision


logger = logging.getLogger("finalx_gmail.discord")

RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


class DiscordNotifier:
    def __init__(self, webhook_url: str | None = None) -> None:
        self.webhook_url = webhook_url or settings.discord_webhook_url

    def notify_decision(self, decision: ScanDecision) -> bool:
        if not self.webhook_url or decision.action in {"skipped", "dry_run_mark", "error"}:
            return False
        if not self._passes_threshold(decision.risk_level):
            return False
        payload = self._payload(decision)
        try:
            response = httpx.post(self.webhook_url, json=payload, timeout=settings.discord_timeout_seconds)
            if response.status_code >= 400:
                logger.warning("Discord webhook failed status=%s body=%s", response.status_code, response.text[:300])
                return False
            return True
        except Exception as exc:
            logger.warning("Discord webhook exception: %s", exc)
            return False

    def _passes_threshold(self, risk_level: str) -> bool:
        threshold = RISK_ORDER.get(settings.discord_notify_min_risk_level, RISK_ORDER["high"])
        return RISK_ORDER.get(risk_level, 0) >= threshold

    def _payload(self, decision: ScanDecision) -> dict:
        color = {
            "critical": 0xDC2626,
            "high": 0xEF4444,
            "medium": 0xF59E0B,
            "low": 0x10B981,
        }.get(decision.risk_level, 0x64748B)
        evidence = [
            f"- {item.title}: {item.detail[:120]}"
            for item in decision.evidence
            if item.score_delta > 0 or item.status in {"malicious", "suspicious"}
        ][:4]
        return {
            "username": "Inbox Sentry",
            "content": f"Inbox Sentry 偵測到 {decision.risk_level.upper()} 風險郵件",
            "embeds": [
                {
                    "title": decision.subject or "(無主旨)",
                    "description": decision.summary,
                    "color": color,
                    "fields": [
                        {"name": "寄件者", "value": decision.sender or decision.sender_email or "unknown", "inline": False},
                        {"name": "分數 / 理由", "value": f"{decision.risk_score} / {decision.label_reason}", "inline": True},
                        {"name": "動作", "value": decision.action, "inline": True},
                        {"name": "證據摘要", "value": "\n".join(evidence) if evidence else "無高分證據", "inline": False},
                    ],
                    "footer": {"text": f"Gmail ID: {decision.gmail_id or 'unknown'}"},
                }
            ],
        }
