from __future__ import annotations

import json
import logging
from typing import Any

import httpx

from app.config import settings
from app.models import EvidenceItem, RiskReport


logger = logging.getLogger("finalx_gmail.llm_intent_classifier")


class LlmIntentClassifierService:
    RATE_LIMIT_STATUS_CODES = {429}
    RATE_LIMIT_MARKERS = (
        "rate limit",
        "rate_limit",
        "ratelimit",
        "quota",
        "resource_exhausted",
    )

    def collect(self, text: str, *, preliminary_report: RiskReport, evidence: list[EvidenceItem]) -> list[EvidenceItem]:
        if not self.should_analyze(preliminary_report=preliminary_report, evidence=evidence):
            return []
        result = self.analyze(text)
        return [result] if result else []

    def should_analyze(self, *, preliminary_report: RiskReport, evidence: list[EvidenceItem]) -> bool:
        if not settings.enable_llm_intent_classifier or not settings.gemini_api_key:
            return False
        if any(item.status == "malicious" and item.source in {"urlhaus", "google_safe_browsing"} for item in evidence):
            return False

        score = preliminary_report.risk_score
        has_risk_signal = bool(preliminary_report.risk_level != "low" or any(item.score_delta > 0 for item in evidence))
        return has_risk_signal and settings.llm_intent_min_score <= score <= settings.llm_intent_max_score

    def analyze(self, text: str) -> EvidenceItem | None:
        prompt = self._prompt(text[: settings.llm_intent_max_text_chars])
        endpoint = f"{settings.gemini_vision_base_url.rstrip('/')}/models/{settings.gemini_intent_model}:generateContent"
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "responseMimeType": "application/json",
                "responseSchema": self._response_schema(),
                "temperature": 0.1,
            },
        }

        try:
            with httpx.Client(timeout=settings.gemini_vision_timeout_seconds) as client:
                response = client.post(
                    endpoint,
                    headers={"x-goog-api-key": settings.gemini_api_key, "Content-Type": "application/json"},
                    json=payload,
            )
            if response.status_code >= 400:
                logger.warning("LLM intent classifier HTTP error: %s %s", response.status_code, response.text[:300])
                if self._is_rate_limited(response.status_code, response.text):
                    self._disable_after_rate_limit(response.status_code, response.text)
                    return self._error(f"HTTP {response.status_code}; LLM disabled after rate limit.")
                return self._error(f"HTTP {response.status_code}")

            data = response.json()
            text_result = self._extract_text(data)
            if not text_result:
                return self._error("Gemini returned empty intent output.")
            parsed = json.loads(text_result)
            return self._to_evidence(parsed)
        except Exception as exc:
            logger.warning("LLM intent classifier failed: %s", exc)
            if self._is_rate_limited(None, str(exc)):
                self._disable_after_rate_limit(None, str(exc))
                return self._error("LLM disabled after rate limit.")
            return self._error(str(exc))

    def _is_rate_limited(self, status_code: int | None, detail: str) -> bool:
        if status_code in self.RATE_LIMIT_STATUS_CODES:
            return True
        normalized = detail.lower()
        return any(marker in normalized for marker in self.RATE_LIMIT_MARKERS)

    def _disable_after_rate_limit(self, status_code: int | None, detail: str) -> None:
        settings.enable_llm_intent_classifier = False
        logger.warning(
            "LLM intent classifier disabled for this process after rate limit: status=%s detail=%s",
            status_code or "unknown",
            detail[:300],
        )

    def _to_evidence(self, parsed: dict[str, Any]) -> EvidenceItem:
        is_scam_like = bool(parsed.get("is_scam_like"))
        should_label_high_risk = bool(parsed.get("should_label_high_risk"))
        confidence = self._bounded_float(parsed.get("confidence"), default=0.0)
        scam_type = str(parsed.get("scam_type") or "unknown")
        intent = str(parsed.get("intent") or "unknown")
        urgency_level = str(parsed.get("urgency_level") or "unknown")
        reasons = parsed.get("reasons") if isinstance(parsed.get("reasons"), list) else []
        score_delta = self._score_delta(
            is_scam_like=is_scam_like,
            should_label_high_risk=should_label_high_risk,
            confidence=confidence,
        )
        status = "suspicious" if score_delta > 0 else "safe" if score_delta < 0 else "info"
        detail = (
            f"is_scam_like={is_scam_like}, should_label_high_risk={should_label_high_risk}, confidence={confidence:.2f}, "
            f"scam_type={scam_type}, intent={intent}, urgency_level={urgency_level}, "
            f"reasons={'; '.join(str(item)[:80] for item in reasons[:5]) or 'none'}。"
        )
        return EvidenceItem(
            source="llm_intent_classifier",
            indicator_type="unknown",
            indicator="message",
            status=status,
            score_delta=score_delta,
            title="LLM 結構化意圖萃取",
            detail=detail,
        )

    def _score_delta(self, *, is_scam_like: bool, should_label_high_risk: bool, confidence: float) -> int:
        if should_label_high_risk and confidence >= 0.7:
            return 15
        if is_scam_like:
            if confidence >= 0.85:
                return 15
            if confidence >= 0.7:
                return 10
            if confidence >= 0.55:
                return 6
            return 0
        if confidence >= 0.85:
            return -8
        return 0

    def _prompt(self, text: str) -> str:
        return f"""
You are an anti-scam intent extraction engine.
Analyze the user-provided email and return only JSON matching the schema.
Extract observable scam intent signals and decide whether the email should receive a high-risk label.
Prefer semantic intent over exact wording; do not require exact keyword matches.

Classify based on social-engineering intent, not exact wording.
Supported scam_type examples: phishing, payment_scam, investment_scam, delivery_scam,
government_impersonation, support_scam, harassment, grey_market_lure, benign, unknown.
Supported intent examples: credential_theft, money_transfer, personal_data_theft,
malware_delivery, platform_account_takeover, harassment, benign, unknown.
Supported urgency_level values: none, low, medium, high.

Set should_label_high_risk=true when the email combines a plausible impersonation or service notice
with a requested action that can steal money, credentials, or personal data. Examples:
- parcel/delivery failure + fee/payment + deadline
- account/security warning + login/verification link
- government/bank notice + payment, verification, or personal data request

Email:
---
{text}
---
"""

    def _response_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "is_scam_like": {"type": "boolean"},
                "should_label_high_risk": {"type": "boolean"},
                "scam_type": {"type": "string"},
                "intent": {"type": "string"},
                "urgency_level": {"type": "string"},
                "confidence": {"type": "number"},
                "reasons": {"type": "array", "items": {"type": "string"}},
            },
            "required": [
                "is_scam_like",
                "should_label_high_risk",
                "scam_type",
                "intent",
                "urgency_level",
                "confidence",
                "reasons",
            ],
        }

    def _extract_text(self, data: dict) -> str:
        candidates = data.get("candidates") or []
        if not candidates:
            return ""
        parts = candidates[0].get("content", {}).get("parts", [])
        if not parts:
            return ""
        return str(parts[0].get("text") or "")

    def _error(self, detail: str) -> EvidenceItem:
        return EvidenceItem(
            source="llm_intent_classifier",
            indicator_type="unknown",
            indicator="message",
            status="error",
            score_delta=0,
            title="LLM 意圖萃取失敗",
            detail=detail[:500],
        )

    def _bounded_float(self, value: Any, *, default: float) -> float:
        try:
            parsed = float(value)
        except Exception:
            return default
        return max(0.0, min(1.0, parsed))
