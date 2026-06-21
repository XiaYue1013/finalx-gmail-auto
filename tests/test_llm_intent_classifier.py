from app.analysis.llm_intent_classifier import LlmIntentClassifierService
from app.config import settings
from app.models import EvidenceItem, RiskReport


class RateLimitedResponse:
    status_code = 429
    text = '{"error":{"status":"RESOURCE_EXHAUSTED","message":"Quota exceeded"}}'


class RateLimitedClient:
    calls = 0

    def __init__(self, *args, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def post(self, *args, **kwargs):
        RateLimitedClient.calls += 1
        return RateLimitedResponse()


def test_llm_rate_limit_disables_later_calls(monkeypatch):
    original_enabled = settings.enable_llm_intent_classifier
    original_key = settings.gemini_api_key
    RateLimitedClient.calls = 0

    try:
        settings.enable_llm_intent_classifier = True
        settings.gemini_api_key = "test-key"
        monkeypatch.setattr("app.analysis.llm_intent_classifier.httpx.Client", RateLimitedClient)

        service = LlmIntentClassifierService()
        report = RiskReport(risk_score=45, risk_level="medium", summary="test")
        evidence = [
            EvidenceItem(
                source="local_rule",
                indicator_type="unknown",
                indicator="message",
                status="suspicious",
                score_delta=10,
                title="test",
                detail="test",
            )
        ]

        first = service.collect("可疑信件內容", preliminary_report=report, evidence=evidence)
        second = service.collect("另一封可疑信件", preliminary_report=report, evidence=evidence)

        assert RateLimitedClient.calls == 1
        assert settings.enable_llm_intent_classifier is False
        assert first[0].status == "error"
        assert "disabled after rate limit" in first[0].detail
        assert second == []
    finally:
        settings.enable_llm_intent_classifier = original_enabled
        settings.gemini_api_key = original_key
