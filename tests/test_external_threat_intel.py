from app.analysis.external_threat_intel import ExternalThreatIntelService
from app.config import settings
from app.models import EvidenceItem


class FakeResponse:
    status_code = 200

    def json(self):
        return {"data": {"attributes": {"last_analysis_stats": {"malicious": 1, "suspicious": 0, "harmless": 50}}}}


class FakeClient:
    def get(self, *args, **kwargs):
        return FakeResponse()


def test_external_threat_intel_can_be_disabled_without_network():
    original = settings.enable_external_threat_lookups
    settings.enable_external_threat_lookups = False
    try:
        evidence = ExternalThreatIntelService().collect("hello", [])
    finally:
        settings.enable_external_threat_lookups = original

    assert evidence[0].source == "external_threat_lookups"
    assert evidence[0].status == "skipped"


def test_virustotal_domain_reputation_is_downweighted_for_common_platforms():
    original_key = settings.virustotal_api_key
    settings.virustotal_api_key = "test-key"
    try:
        evidence = ExternalThreatIntelService()._virustotal_domain(FakeClient(), "t.me")
    finally:
        settings.virustotal_api_key = original_key

    assert evidence.status == "info"
    assert evidence.score_delta == 0


def test_virustotal_domain_reputation_is_downweighted_for_line_platform():
    original_key = settings.virustotal_api_key
    settings.virustotal_api_key = "test-key"
    try:
        evidence = ExternalThreatIntelService()._virustotal_domain(FakeClient(), "line.me")
    finally:
        settings.virustotal_api_key = original_key

    assert evidence.status == "info"
    assert evidence.score_delta == 0


def test_single_virustotal_engine_vote_does_not_add_risk_score():
    original_key = settings.virustotal_api_key
    settings.virustotal_api_key = "test-key"
    try:
        evidence = ExternalThreatIntelService()._virustotal_url(FakeClient(), "https://help.steampowered.com")
    finally:
        settings.virustotal_api_key = original_key

    assert evidence.status == "info"
    assert evidence.score_delta == 0
    assert "單一引擎" in evidence.title


def test_external_lookup_skips_reserved_and_file_like_domains():
    service = ExternalThreatIntelService()

    assert service._url_is_external_lookup_candidate("https://security-check.example.invalid/verify") is False
    assert service._url_is_external_lookup_candidate("https://package-lock.json") is False
    assert service._url_is_external_lookup_candidate("https://example.com/login") is True


class FakeCacheStore:
    def __init__(self):
        self.saved = None
        self.hits = 0
        self.queued = []

    def get_cached_evidence(self, **kwargs):
        self.hits += 1
        return self.saved

    def save_cached_evidence(self, item):
        self.saved = item

    def queue_threat_lookup(self, **kwargs):
        self.queued.append(kwargs)


def test_cached_lookup_reuses_saved_evidence():
    store = FakeCacheStore()
    service = ExternalThreatIntelService(cache_store=store)
    calls = {"count": 0}

    def producer():
        calls["count"] += 1
        return EvidenceItem(
            source="urlhaus",
            indicator_type="url",
            indicator="https://example.com/login",
            status="safe",
            title="URLhaus 未命中",
            detail="safe",
        )

    first = service._cached_lookup("urlhaus", "url", "https://example.com/login", producer)
    second = service._cached_lookup("urlhaus", "url", "https://example.com/login", producer)

    assert first.status == "safe"
    assert second.status == "safe"
    assert second.raw_ref == "cache"
    assert calls["count"] == 1
    assert store.hits == 2


def test_cached_single_virustotal_vote_is_normalized_without_waiting_for_expiry():
    store = FakeCacheStore()
    store.saved = EvidenceItem(
        source="virustotal_url",
        indicator_type="url",
        indicator="https://help.steampowered.com",
        status="malicious",
        score_delta=8,
        title="VirusTotal URL reputation",
        detail="malicious=1, suspicious=0, harmless=58。",
    )
    service = ExternalThreatIntelService(cache_store=store)

    evidence = service._cached_lookup(
        "virustotal_url",
        "url",
        "https://help.steampowered.com",
        lambda: None,
    )

    assert evidence.status == "info"
    assert evidence.score_delta == 0
    assert evidence.raw_ref == "cache"


def test_rate_limited_lookup_is_queued_for_retry():
    store = FakeCacheStore()
    service = ExternalThreatIntelService(cache_store=store)

    def producer():
        return EvidenceItem(
            source="urlscan",
            indicator_type="url",
            indicator="https://example.com/login",
            status="skipped",
            title="外部資料來源未查詢",
            detail="urlscan.io 服務暫時無法使用或達請求上限 (HTTP 429)。",
        )

    evidence = service._cached_lookup("urlscan", "url", "https://example.com/login", producer)

    assert evidence.status == "skipped"
    assert len(store.queued) == 1
    assert store.queued[0]["source"] == "urlscan"
