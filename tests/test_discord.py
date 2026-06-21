from app.config import settings
from app.integrations.discord import DiscordNotifier
from app.models import EvidenceItem, ScanDecision


class FakeResponse:
    status_code = 204
    text = ""


def test_discord_notifier_posts_high_risk_payload(monkeypatch):
    calls = []

    def fake_post(url, json, timeout):
        calls.append({"url": url, "json": json, "timeout": timeout})
        return FakeResponse()

    monkeypatch.setattr("app.integrations.discord.httpx.post", fake_post)
    original_url = settings.discord_webhook_url
    original_min = settings.discord_notify_min_risk_level
    try:
        settings.discord_webhook_url = "https://discord.example/webhook"
        settings.discord_notify_min_risk_level = "high"
        decision = ScanDecision(
            gmail_id="gmail-1",
            subject="Security alert",
            sender="Fake Google <alert@example.test>",
            sender_email="alert@example.test",
            high_risk=True,
            action="marked",
            risk_score=72,
            risk_level="high",
            confidence_score=80,
            summary="高風險",
            label_reason="釣魚驗證",
            evidence=[
                EvidenceItem(
                    source="local_url_analysis",
                    indicator_type="url",
                    indicator="https://example.test/login",
                    status="suspicious",
                    score_delta=20,
                    title="可疑網址",
                    detail="login path",
                )
            ],
        )

        assert DiscordNotifier().notify_decision(decision) is True
    finally:
        settings.discord_webhook_url = original_url
        settings.discord_notify_min_risk_level = original_min

    assert calls
    assert calls[0]["url"] == "https://discord.example/webhook"
    assert calls[0]["json"]["embeds"][0]["fields"][1]["value"] == "72 / 釣魚驗證"


def test_discord_notifier_skips_without_webhook():
    original_url = settings.discord_webhook_url
    try:
        settings.discord_webhook_url = None
        notifier = DiscordNotifier()
        decision = ScanDecision(
            high_risk=True,
            action="marked",
            risk_score=72,
            risk_level="high",
            confidence_score=80,
            summary="高風險",
            label_reason="釣魚驗證",
        )
        assert notifier.notify_decision(decision) is False
    finally:
        settings.discord_webhook_url = original_url
