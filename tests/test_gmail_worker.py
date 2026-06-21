from app.config import settings
from app.gmail.worker import GmailRiskWorker
from app.models import ScanBatchResult, ScanDecision


class FakeGmail:
    def __init__(self):
        self.created_labels = []

    def ensure_label(self, name: str) -> str:
        self.created_labels.append(name)
        return f"label:{name}"


def test_medium_risk_decision_uses_medium_label_without_system_flags():
    settings.gmail_warning_label = "FINALX 中風險"
    settings.enable_reason_labels = True
    settings.mark_starred = False
    settings.mark_important = False
    gmail = FakeGmail()
    worker = GmailRiskWorker(gmail=gmail, store=object())
    decision = ScanDecision(
        high_risk=False,
        action="skipped",
        risk_score=35,
        risk_level="medium",
        confidence_score=80,
        summary="中風險",
        label_reason="可疑網址",
    )

    assert worker._should_warn(decision) is True
    label_ids = worker._warning_label_ids_for_decision(decision)

    assert "label:FINALX 中風險" in label_ids
    assert "label:FINALX 理由 - 可疑網址" in label_ids
    assert "STARRED" not in label_ids
    assert "IMPORTANT" not in label_ids


class FakeNotFoundGmail(FakeGmail):
    def get_message(self, message_id: str):
        raise FakeHttpError404("Requested entity was not found.")


class FakeHttpError404(Exception):
    resp = type("Resp", (), {"status": 404})()


class FakeStore:
    def __init__(self):
        self.processed = []
        self.events = []

    def is_processed(self, message_id: str) -> bool:
        return False

    def mark_processed(self, message_id: str) -> None:
        self.processed.append(message_id)

    def append_event(self, event: ScanDecision) -> None:
        self.events.append(event)


def test_missing_gmail_message_is_skipped_without_error_event():
    store = FakeStore()
    worker = GmailRiskWorker(gmail=FakeNotFoundGmail(), analyzer=object(), store=store)
    batch = ScanBatchResult()

    worker._process_message_id("missing-message-id", batch=batch, dry_run=False, include_processed=False)

    assert batch.skipped == 1
    assert batch.errors == 0
    assert store.processed == ["missing-message-id"]
    assert store.events == []
