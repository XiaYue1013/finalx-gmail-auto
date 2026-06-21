from __future__ import annotations

import re
from urllib.parse import parse_qsl, unquote, urlparse

from app.analysis.domain_utils import is_probable_domain
from app.models import ExtractedIndicator


URL_PATTERN = re.compile(
    r"(?P<url>"
    r"https?://[^\s<>'\"，。！？、)）\]]+"
    r"|(?<![@\w.-])(?:[a-z0-9-]+\.)+[a-z]{2,}(?:/[^\s<>'\"，。！？、)）\]]*)?"
    r")",
    re.IGNORECASE,
)
EMAIL_PATTERN = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
PHONE_PATTERN = re.compile(
    r"(?<![\w-])(?:\+?886[-\s]?)?0?9\d{2}[-\s]?\d{3}[-\s]?\d{3}(?![\w-])|"
    r"(?<![\w-])(?:\+?886[-\s]?)?0\d{1,2}[-\s]?\d{3,4}[-\s]?\d{4}(?![\w-])"
)
LINE_ID_PATTERN = re.compile(r"(?:line\s*id|line帳號|line\s*帳號|加入line|加line)[:：\s@]*([a-zA-Z0-9._-]{4,32})", re.IGNORECASE)
CRYPTO_PATTERN = re.compile(r"\b(?:bc1[ac-hj-np-z02-9]{25,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40})\b")
LONG_DIGIT_PATTERN = re.compile(r"(?<!\d)(\d[\d\s-]{7,24}\d)(?!\d)")

BANK_CONTEXT_PATTERN = re.compile(r"(銀行|帳號|匯款|轉帳|ATM|提款機|收款|入金|保證金|手續費|bank|wire|transfer)", re.IGNORECASE)
REDIRECT_QUERY_KEYS = {
    "continue",
    "dest",
    "destination",
    "link",
    "next",
    "q",
    "r",
    "redirect",
    "redirect_uri",
    "target",
    "to",
    "u",
    "url",
}


class IndicatorExtractor:
    def extract(self, text: str) -> list[ExtractedIndicator]:
        text = text or ""
        indicators: list[ExtractedIndicator] = []
        seen: set[tuple[str, str]] = set()

        def add(indicator: ExtractedIndicator) -> None:
            key = (indicator.type, indicator.value)
            if key in seen:
                return
            seen.add(key)
            indicators.append(indicator)

        def add_url(raw_url: str, *, depth: int = 0) -> None:
            raw_url = raw_url.rstrip(".,;")
            normalized = self._normalize_url(raw_url)
            domain = self._domain_from_url(normalized)
            has_explicit_scheme = bool(re.match(r"^https?://", raw_url, re.IGNORECASE))
            if not has_explicit_scheme and not is_probable_domain(domain):
                return
            add(
                ExtractedIndicator(
                    type="url",
                    value=raw_url,
                    normalized=normalized,
                    label="網址",
                    confidence=0.98,
                )
            )
            if domain and is_probable_domain(domain):
                add(
                    ExtractedIndicator(
                        type="domain",
                        value=domain,
                        normalized=domain,
                        label="網域",
                        confidence=0.95,
                    )
                )
            if depth >= 2:
                return
            for nested_url in self._nested_urls(normalized):
                add_url(nested_url, depth=depth + 1)

        for match in URL_PATTERN.finditer(text):
            add_url(match.group("url"))

        for match in EMAIL_PATTERN.finditer(text):
            value = match.group(0)
            add(
                ExtractedIndicator(
                    type="email",
                    value=value,
                    normalized=value.lower(),
                    label="Email",
                    confidence=0.95,
                )
            )

        for match in PHONE_PATTERN.finditer(text):
            value = match.group(0)
            normalized = re.sub(r"\D", "", value)
            add(
                ExtractedIndicator(
                    type="phone",
                    value=value,
                    normalized=normalized,
                    label="電話",
                    confidence=0.86,
                )
            )

        for match in LINE_ID_PATTERN.finditer(text):
            value = match.group(1)
            add(
                ExtractedIndicator(
                    type="line_id",
                    value=value,
                    normalized=value.lower(),
                    label="LINE ID",
                    confidence=0.82,
                )
            )

        for match in CRYPTO_PATTERN.finditer(text):
            value = match.group(0)
            add(
                ExtractedIndicator(
                    type="crypto_address",
                    value=value,
                    normalized=value,
                    label="加密貨幣地址",
                    confidence=0.9,
                )
            )

        for match in LONG_DIGIT_PATTERN.finditer(text):
            value = match.group(1)
            normalized = re.sub(r"\D", "", value)
            if not (8 <= len(normalized) <= 18):
                continue
            start = max(0, match.start() - 24)
            end = min(len(text), match.end() + 24)
            context = text[start:end]
            if not BANK_CONTEXT_PATTERN.search(context):
                continue
            add(
                ExtractedIndicator(
                    type="bank_account",
                    value=value,
                    normalized=normalized,
                    label="疑似匯款帳號",
                    confidence=0.76,
                )
            )

        return indicators

    def _normalize_url(self, value: str) -> str:
        value = value.strip()
        if not re.match(r"^https?://", value, re.IGNORECASE):
            value = f"https://{value}"
        return value

    def _domain_from_url(self, value: str) -> str | None:
        parsed = urlparse(value)
        hostname = (parsed.hostname or "").lower().strip(".")
        return hostname or None

    def _nested_urls(self, value: str) -> list[str]:
        parsed = urlparse(value)
        nested: list[str] = []
        for key, query_value in parse_qsl(parsed.query, keep_blank_values=False):
            if key.lower() not in REDIRECT_QUERY_KEYS:
                continue
            decoded = unquote(query_value)
            for match in URL_PATTERN.finditer(decoded):
                nested.append(match.group("url").rstrip(".,;"))
        return list(dict.fromkeys(nested))
