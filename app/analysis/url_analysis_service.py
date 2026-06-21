from __future__ import annotations

import difflib
import re
from urllib.parse import urlparse
from urllib.parse import parse_qsl, unquote

from app.analysis.domain_utils import same_org_domain
from app.models import EvidenceItem, ExtractedIndicator


SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "reurl.cc",
    "lihi.cc",
    "is.gd",
    "cutt.ly",
    "shorturl.at",
    "ow.ly",
}

SUSPICIOUS_TLDS = {
    "xyz",
    "top",
    "click",
    "work",
    "support",
    "monster",
    "quest",
    "icu",
    "vip",
    "shop",
    "zip",
    "mov",
    "win",
}

OFFICIAL_BRANDS = {
    "line": {"line.me", "linecorp.com", "lin.ee"},
    "paypal": {"paypal.com"},
    "apple": {"apple.com"},
    "google": {"google.com", "gmail.com"},
    "github": {"github.com"},
    "slack": {"slack.com"},
    "netflix": {"netflix.com"},
    "microsoft": {"microsoft.com", "office.com", "office365.com", "outlook.com", "live.com"},
    "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
    "shopee": {"shopee.tw", "shopee.com"},
    "momo": {"momo.com.tw"},
    "post": {"post.gov.tw"},
    "cht": {"cht.com.tw", "cht.tw"},
    "esunbank": {"esunbank.com", "esunbank.com.tw"},
    "cathaybk": {"cathaybk.com.tw"},
}

RISKY_PATH_WORDS = (
    "login",
    "verify",
    "verification",
    "security",
    "account",
    "bonus",
    "gift",
    "claim",
    "wallet",
    "otp",
    "bank",
    "safe",
    "update",
    "unlock",
    "password",
)

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

MESSAGING_DOMAINS = {"t.me", "telegram.me", "telegram.org"}


class UrlAnalysisService:
    def analyze(self, indicators: list[ExtractedIndicator]) -> list[EvidenceItem]:
        evidence: list[EvidenceItem] = []
        urls = [item for item in indicators if item.type == "url"]
        domains = {item.value for item in indicators if item.type == "domain"}

        for indicator in urls:
            url = indicator.normalized or indicator.value
            parsed = urlparse(url)
            domain = (parsed.hostname or "").lower().strip(".")
            if domain:
                domains.add(domain)

            if parsed.scheme != "https":
                evidence.append(
                    EvidenceItem(
                        source="local_url_analysis",
                        indicator_type="url",
                        indicator=url,
                        status="suspicious",
                        score_delta=8,
                        title="網址未使用 HTTPS",
                        detail="登入、付款或帳戶驗證頁面若未使用 HTTPS，風險較高。",
                    )
                )

            path = f"{parsed.path or ''}?{parsed.query or ''}".lower()
            matched_words = [word for word in RISKY_PATH_WORDS if word in path]
            if matched_words:
                evidence.append(
                    EvidenceItem(
                        source="local_url_analysis",
                        indicator_type="url",
                        indicator=url,
                        status="info",
                        score_delta=5,
                        title="網址路徑含高風險關鍵字",
                        detail=f"命中關鍵字：{', '.join(matched_words[:5])}。",
                    )
                )

            redirect_target = self._redirect_target(parsed)
            if redirect_target:
                evidence.append(
                    EvidenceItem(
                        source="local_url_analysis",
                        indicator_type="url",
                        indicator=url,
                        status="suspicious",
                        score_delta=18,
                        title="網址含外部跳轉目標",
                        detail=f"查到 redirect 類參數，目的地指向 {redirect_target}。",
                    )
                )

        for domain in sorted(domains):
            evidence.extend(self._analyze_domain(domain))

        return evidence

    def _analyze_domain(self, domain: str) -> list[EvidenceItem]:
        evidence: list[EvidenceItem] = []
        tld = domain.rsplit(".", 1)[-1] if "." in domain else ""

        if domain in SHORTENER_DOMAINS:
            evidence.append(
                EvidenceItem(
                    source="local_url_analysis",
                    indicator_type="domain",
                    indicator=domain,
                    status="suspicious",
                    score_delta=12,
                    title="偵測到短網址服務",
                    detail="短網址會隱藏真實目的地，詐騙信件常用來降低使用者警覺。",
                )
            )

        if domain in MESSAGING_DOMAINS:
            evidence.append(
                EvidenceItem(
                    source="local_url_analysis",
                    indicator_type="domain",
                    indicator=domain,
                    status="info",
                    score_delta=8,
                    title="導向即時通訊平台",
                    detail="導流到 Telegram 等即時通訊平台時，需搭配信件內容確認是否為假客服或求職詐騙。",
                )
            )

        if tld in SUSPICIOUS_TLDS:
            score_delta = 18 if tld in {"zip", "mov"} else 5
            status = "suspicious" if score_delta >= 10 else "info"
            evidence.append(
                EvidenceItem(
                    source="local_url_analysis",
                    indicator_type="domain",
                    indicator=domain,
                    status=status,
                    score_delta=score_delta,
                    title="網域使用高風險常見 TLD",
                    detail=f".{tld} 常出現在短期活動頁或一次性釣魚站，需搭配其他證據判斷。",
                )
            )

        if domain.startswith("xn--"):
            evidence.append(
                EvidenceItem(
                    source="local_url_analysis",
                    indicator_type="domain",
                    indicator=domain,
                    status="suspicious",
                    score_delta=16,
                    title="網域使用 punycode",
                    detail="punycode 可能被用於視覺混淆與仿冒官方網域。",
                )
            )

        brand_hit = self._brand_impersonation(domain)
        if brand_hit:
            brand, official = brand_hit
            evidence.append(
                EvidenceItem(
                    source="local_url_analysis",
                    indicator_type="domain",
                    indicator=domain,
                    status="suspicious",
                    score_delta=20,
                    title="疑似品牌仿冒網域",
                    detail=f"網域看起來接近 {brand}，但不在官方網域清單：{', '.join(sorted(official))}。",
                )
            )

        return evidence

    def _brand_impersonation(self, domain: str) -> tuple[str, set[str]] | None:
        lowered = domain.lower()
        skeleton = self._domain_skeleton(lowered)
        for brand, official_domains in OFFICIAL_BRANDS.items():
            if lowered in official_domains or any(lowered.endswith(f".{official}") for official in official_domains):
                continue
            if brand in lowered:
                return brand, official_domains
            compact = re.sub(r"[^a-z0-9]", "", lowered)
            similarity = difflib.SequenceMatcher(None, skeleton, brand).ratio()
            if similarity >= 0.78 or brand in compact:
                return brand, official_domains
        return None

    def _domain_skeleton(self, value: str) -> str:
        host = value.split(".")[0]
        return (
            host.replace("0", "o")
            .replace("1", "l")
            .replace("3", "e")
            .replace("5", "s")
            .replace("-", "")
            .replace("_", "")
        )

    def _redirect_target(self, parsed) -> str | None:
        source_domain = (parsed.hostname or "").lower().strip(".")
        for key, value in parse_qsl(parsed.query or "", keep_blank_values=False):
            if key.lower() not in REDIRECT_QUERY_KEYS:
                continue
            decoded = unquote(value).strip()
            if not self._looks_like_redirect_location(decoded):
                continue
            nested = urlparse(decoded if decoded.startswith(("http://", "https://")) else f"https://{decoded}")
            target_domain = (nested.hostname or "").lower().strip(".")
            if target_domain and not self._related_domain(source_domain, target_domain):
                return target_domain
        return None

    def _looks_like_redirect_location(self, value: str) -> bool:
        if value.startswith(("http://", "https://")):
            return True
        return bool(re.match(r"^(?:[a-z0-9-]+\.)+[a-z]{2,}(?:[/:?#].*)?$", value, re.IGNORECASE))

    def _related_domain(self, left: str, right: str) -> bool:
        if not left or not right:
            return False
        return left == right or left.endswith(f".{right}") or right.endswith(f".{left}") or same_org_domain(left, right)
