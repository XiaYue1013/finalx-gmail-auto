import base64
import json

import pytest

from app.gmail.push import GmailPushDecodeError, decode_pubsub_push


def _encode(value: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(value).encode("utf-8")).decode("ascii").rstrip("=")


def test_decode_pubsub_push_payload():
    payload = {
        "message": {
            "data": _encode({"emailAddress": "admin@example.test", "historyId": "12345"}),
            "messageId": "pubsub-1",
        },
        "subscription": "projects/demo/subscriptions/gmail-push",
    }

    decoded = decode_pubsub_push(payload)

    assert decoded["emailAddress"] == "admin@example.test"
    assert decoded["historyId"] == "12345"
    assert decoded["messageId"] == "pubsub-1"


def test_decode_pubsub_push_rejects_missing_history_id():
    payload = {"message": {"data": _encode({"emailAddress": "admin@example.test"})}}

    with pytest.raises(GmailPushDecodeError):
        decode_pubsub_push(payload)

