from __future__ import annotations

import base64
import json
from typing import Any


class GmailPushDecodeError(ValueError):
    pass


def decode_pubsub_push(payload: dict[str, Any]) -> dict[str, str]:
    message = payload.get("message")
    if not isinstance(message, dict):
        raise GmailPushDecodeError("Pub/Sub payload missing message object.")

    encoded = message.get("data")
    if not isinstance(encoded, str) or not encoded:
        raise GmailPushDecodeError("Pub/Sub message missing data field.")

    padded = encoded + "=" * (-len(encoded) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
        data = json.loads(decoded)
    except Exception as exc:
        raise GmailPushDecodeError("Pub/Sub message data is not valid base64url JSON.") from exc

    email_address = str(data.get("emailAddress") or "")
    history_id = str(data.get("historyId") or "")
    if not history_id:
        raise GmailPushDecodeError("Gmail push payload missing historyId.")
    return {
        "emailAddress": email_address,
        "historyId": history_id,
        "messageId": str(message.get("messageId") or ""),
        "publishTime": str(message.get("publishTime") or ""),
        "subscription": str(payload.get("subscription") or ""),
    }

