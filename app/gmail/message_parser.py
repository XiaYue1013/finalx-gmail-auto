from __future__ import annotations

import base64
import re
from email.header import decode_header, make_header
from email.utils import parseaddr
from html.parser import HTMLParser
from typing import Any

from app.models import GmailMessage


class _HtmlTextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a":
            return
        for name, value in attrs:
            if name.lower() == "href" and value and value.lower().startswith(("http://", "https://")):
                self.parts.append(value)

    def handle_data(self, data: str) -> None:
        text = " ".join(data.split())
        if text:
            self.parts.append(text)

    def text(self) -> str:
        return " ".join(self.parts)


def parse_gmail_message(raw: dict[str, Any]) -> GmailMessage:
    payload = raw.get("payload") or {}
    headers = _headers(payload)
    sender = _decode_mime_header(headers.get("from", ""))
    _, sender_email = parseaddr(sender)
    subject = _decode_mime_header(headers.get("subject", ""))
    plain_parts: list[str] = []
    html_parts: list[str] = []
    attachment_filenames: list[str] = []
    _collect_parts(payload, plain_parts, html_parts, attachment_filenames)

    body_parts = [part for part in plain_parts if part.strip()]
    body_parts.extend(_html_to_text(part) for part in html_parts if part.strip())
    body_text = "\n".join(part for part in body_parts if part.strip()).strip()

    return GmailMessage(
        gmail_id=str(raw.get("id") or ""),
        thread_id=raw.get("threadId"),
        label_ids=list(raw.get("labelIds") or []),
        subject=subject,
        sender=sender,
        sender_email=sender_email.lower(),
        reply_to=_decode_mime_header(headers.get("reply-to", "")),
        to=_decode_mime_header(headers.get("to", "")),
        date=_decode_mime_header(headers.get("date", "")),
        snippet=str(raw.get("snippet") or ""),
        body_text=_normalize_text(body_text),
        authentication_results=headers.get("authentication-results", ""),
        received_spf=headers.get("received-spf", ""),
        attachment_filenames=attachment_filenames,
        internal_date_ms=int(raw["internalDate"]) if str(raw.get("internalDate") or "").isdigit() else None,
    )


def _headers(payload: dict[str, Any]) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in payload.get("headers") or []:
        name = str(item.get("name") or "").lower()
        value = str(item.get("value") or "")
        if name:
            result[name] = value
    return result


def _collect_parts(payload: dict[str, Any], plain_parts: list[str], html_parts: list[str], attachment_filenames: list[str]) -> None:
    filename = _decode_mime_header(str(payload.get("filename") or "")).strip()
    if filename:
        attachment_filenames.append(filename)

    mime_type = str(payload.get("mimeType") or "").lower()
    data = (payload.get("body") or {}).get("data")
    if data:
        decoded = _decode_body(data)
        if mime_type == "text/plain":
            plain_parts.append(decoded)
        elif mime_type == "text/html":
            html_parts.append(decoded)

    for part in payload.get("parts") or []:
        if isinstance(part, dict):
            _collect_parts(part, plain_parts, html_parts, attachment_filenames)


def _decode_body(data: str) -> str:
    padded = data + "=" * (-len(data) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8", errors="replace")
    except Exception:
        return ""


def _decode_mime_header(value: str) -> str:
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def _html_to_text(html: str) -> str:
    parser = _HtmlTextExtractor()
    try:
        parser.feed(html)
        return parser.text()
    except Exception:
        return re.sub(r"<[^>]+>", " ", html)


def _normalize_text(value: str) -> str:
    return re.sub(r"[ \t\r\f\v]+", " ", value).strip()
