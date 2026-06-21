import base64

from app.gmail.message_parser import parse_gmail_message


def _b64(value: str) -> str:
    return base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii").rstrip("=")


def test_parse_plain_text_gmail_message():
    raw = {
        "id": "abc123",
        "threadId": "thread123",
        "labelIds": ["INBOX", "UNREAD"],
        "snippet": "snippet",
        "internalDate": "1710000000000",
        "payload": {
            "mimeType": "multipart/alternative",
            "headers": [
                {"name": "From", "value": "Security <security@example.com>"},
                {"name": "Reply-To", "value": "help@evil.example"},
                {"name": "Subject", "value": "Account verification"},
                {"name": "Authentication-Results", "value": "mx.google.com; spf=fail"},
            ],
            "parts": [
                {
                    "mimeType": "text/plain",
                    "body": {"data": _b64("Please verify your account.")},
                },
                {
                    "filename": "invoice.xlsm",
                    "mimeType": "application/vnd.ms-excel.sheet.macroEnabled.12",
                    "body": {"attachmentId": "att1"},
                },
            ],
        },
    }

    message = parse_gmail_message(raw)

    assert message.gmail_id == "abc123"
    assert message.sender_email == "security@example.com"
    assert message.reply_to == "help@evil.example"
    assert message.subject == "Account verification"
    assert "verify your account" in message.body_text
    assert message.attachment_filenames == ["invoice.xlsm"]
    assert "spf=fail" in message.authentication_results


def test_parse_html_message_keeps_link_href():
    raw = {
        "id": "html123",
        "payload": {
            "mimeType": "text/html",
            "headers": [
                {"name": "From", "value": "Service <service@example.com>"},
                {"name": "Subject", "value": "Verify account"},
            ],
            "body": {"data": _b64('<a href="http://example.test/login">Verify now</a>')},
        },
    }

    message = parse_gmail_message(raw)

    assert "http://example.test/login" in message.body_text
    assert "Verify now" in message.body_text
