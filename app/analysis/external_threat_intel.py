from __future__ import annotations

import base64
import json
import logging
import re
from urllib.parse import quote, urlparse

import httpx

from app.analysis.domain_utils import is_external_lookup_domain
from app.config import settings
from app.models import EvidenceItem, ExtractedIndicator


logger = logging.getLogger("finalx_gmail.threat_intel")

LOW_SIGNAL_DOMAIN_REPUTATION = {
    "t.me",
    "telegram.me",
    "telegram.org",
    "line.me",
    "lin.ee",
    "gmail.com",
    "google.com",
    "github.com",
    "slack.com",
    "medium.com",
    "paypal.com",
    "netflix.com",
    "facebook.com",
    "instagram.com",
    "youtube.com",
}


class ExternalThreatIntelService:
    def __init__(self, cache_store=None) -> None:
        self.timeout = settings.external_lookup_timeout_seconds
        self.force_ipv4 = settings.threat_lookup_force_ipv4
        self.cache_store = cache_store

    def collect(self, text: str, indicators: list[ExtractedIndicator]) -> list[EvidenceItem]:
        if not settings.enable_external_threat_lookups:
            return [
                EvidenceItem(
                    source="external_threat_lookups",
                    indicator_type="unknown",
                    indicator="all",
                    status="skipped",
                    title="外部查核已停用",
                    detail="ENABLE_EXTERNAL_THREAT_LOOKUPS=false，因此只使用本地規則、郵件標頭與 URL 結構分析。",
                )
            ]

        urls = [
            item.normalized or item.value
            for item in indicators
            if item.type == "url" and self._url_is_external_lookup_candidate(item.normalized or item.value)
        ]
        domain_values = {
            item.value
            for item in indicators
            if item.type == "domain" and is_external_lookup_domain(item.value)
        }
        domain_values.update(
            email_value.rsplit("@", 1)[-1].lower().strip(".")
            for email_value in (item.value for item in indicators if item.type == "email" and "@" in item.value)
            if is_external_lookup_domain(email_value.rsplit("@", 1)[-1])
        )
        domains = sorted(domain_values)
        evidence: list[EvidenceItem] = []

        client_kwargs: dict = {"timeout": self.timeout, "follow_redirects": True}
        if self.force_ipv4:
            client_kwargs["transport"] = httpx.HTTPTransport(local_address="0.0.0.0")

        with httpx.Client(**client_kwargs) as client:
            for url in urls[:3]:
                evidence.append(self._cached_lookup("google_safe_browsing", "url", url, lambda: self._safe_browsing(client, url)))
                evidence.append(self._cached_lookup("urlhaus", "url", url, lambda: self._urlhaus(client, url)))
                evidence.append(self._cached_lookup("virustotal_url", "url", url, lambda: self._virustotal_url(client, url)))
                evidence.append(self._cached_lookup("urlscan", "url", url, lambda: self._urlscan_search(client, url)))
            for domain in domains[:3]:
                evidence.append(self._cached_lookup("virustotal_domain", "domain", domain, lambda: self._virustotal_domain(client, domain)))
            serp_indicator = urls[0] if urls else domains[0] if domains else (text[:80] or "message")
            evidence.append(self._cached_lookup("serpapi", "unknown", serp_indicator, lambda: self._serpapi(client, text, urls, domains)))
            fact_indicator = " ".join((text or "").split())[:180] or "message"
            evidence.append(self._cached_lookup("google_fact_check", "unknown", fact_indicator, lambda: self._fact_check(client, text)))

        return evidence

    def _cached_lookup(self, source: str, indicator_type: str, indicator: str, producer):
        if self.cache_store is not None:
            getter = getattr(self.cache_store, "get_cached_evidence", None)
            if callable(getter):
                cached = getter(source=source, indicator_type=indicator_type, indicator=indicator)
                if cached is not None:
                    cached.raw_ref = "cache"
                    return self._normalize_cached_evidence(cached)
        item = producer()
        if self.cache_store is not None:
            saver = getattr(self.cache_store, "save_cached_evidence", None)
            if callable(saver):
                try:
                    saver(item)
                except Exception:
                    logger.exception("failed to save threat intel cache source=%s indicator=%s", source, indicator)
            self._queue_lookup_if_needed(item)
        return item

    def _normalize_cached_evidence(self, item: EvidenceItem) -> EvidenceItem:
        if item.source not in {"virustotal_url", "virustotal_domain"} or item.score_delta <= 0:
            return item
        malicious_match = re.search(r"\bmalicious=(\d+)", item.detail)
        suspicious_match = re.search(r"\bsuspicious=(\d+)", item.detail)
        harmless_match = re.search(r"\bharmless=(\d+)", item.detail)
        malicious = int(malicious_match.group(1)) if malicious_match else 0
        suspicious = int(suspicious_match.group(1)) if suspicious_match else 0
        harmless = int(harmless_match.group(1)) if harmless_match else 0
        if malicious + suspicious >= 2:
            return item
        item.status = "info"
        item.score_delta = 0
        item.title = (
            "VirusTotal URL 單一引擎命中已降權"
            if item.source == "virustotal_url"
            else "VirusTotal domain 單一引擎命中已降權"
        )
        item.detail = (
            f"malicious={malicious}, suspicious={suspicious}, harmless={harmless}；"
            "舊快取未達多引擎共識，已在讀取時取消風險分數。"
        )
        return item

    def _queue_lookup_if_needed(self, item: EvidenceItem) -> None:
        if self.cache_store is None or not self._should_queue_lookup(item):
            return
        queue = getattr(self.cache_store, "queue_threat_lookup", None)
        if not callable(queue):
            return
        try:
            queue(
                source=item.source,
                indicator_type=str(item.indicator_type),
                indicator=item.indicator,
                reason=item.detail,
            )
        except Exception:
            logger.exception("failed to queue threat intel lookup source=%s indicator=%s", item.source, item.indicator)

    def _should_queue_lookup(self, item: EvidenceItem) -> bool:
        if item.status not in {"error", "skipped"}:
            return False
        detail = item.detail.lower()
        retryable_signals = (
            "429",
            "rate",
            "limit",
            "timeout",
            "timed out",
            "temporarily",
            "unavailable",
            "暫時",
            "請求上限",
        )
        return any(signal in detail for signal in retryable_signals)

    def _url_is_external_lookup_candidate(self, url: str) -> bool:
        hostname = (urlparse(url).hostname or "").lower().strip(".")
        return is_external_lookup_domain(hostname)

    def _safe_browsing(self, client: httpx.Client, url: str) -> EvidenceItem:
        if not settings.google_safe_browsing_api_key:
            return self._skipped("google_safe_browsing", "url", url, "未設定 GOOGLE_SAFE_BROWSING_API_KEY。")

        endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        payload = {
            "client": {"clientId": "finalx-gmail-auto", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        try:
            response = client.post(endpoint, params={"key": settings.google_safe_browsing_api_key}, json=payload)
            if response.status_code >= 400:
                return self._response_error("google_safe_browsing", "url", url, response)
            matches = response.json().get("matches") or []
            if matches:
                threat_types = ", ".join(sorted({str(item.get("threatType")) for item in matches if item.get("threatType")}))
                return EvidenceItem(
                    source="google_safe_browsing",
                    indicator_type="url",
                    indicator=url,
                    status="malicious",
                    score_delta=35,
                    title="Safe Browsing 命中威脅清單",
                    detail=f"命中 threat types：{threat_types or 'unknown'}。",
                    reference_url="https://developers.google.com/safe-browsing/v4",
                )
            return EvidenceItem(
                source="google_safe_browsing",
                indicator_type="url",
                indicator=url,
                status="safe",
                score_delta=0,
                title="Safe Browsing 未命中",
                detail="此 URL 未命中 Google Safe Browsing 回傳的威脅清單。",
                reference_url="https://developers.google.com/safe-browsing/v4",
            )
        except Exception as exc:
            return self._error("google_safe_browsing", "url", url, exc)

    def _urlhaus(self, client: httpx.Client, url: str) -> EvidenceItem:
        if not settings.enable_urlhaus_lookup:
            return self._skipped("urlhaus", "url", url, "ENABLE_URLHAUS_LOOKUP=false。")
        if not settings.urlhaus_auth_key:
            return self._skipped("urlhaus", "url", url, "未設定 URLHAUS_AUTH_KEY。")

        try:
            response = client.post(
                "https://urlhaus-api.abuse.ch/v1/url/",
                data={"url": url},
                headers={"Auth-Key": settings.urlhaus_auth_key},
            )
            if response.status_code == 401:
                return self._skipped("urlhaus", "url", url, "URLhaus API Key 認證失敗 (HTTP 401)。")
            if response.status_code in {429, 502, 503, 504}:
                return self._skipped("urlhaus", "url", url, f"URLhaus 服務暫時無法使用或達請求上限 (HTTP {response.status_code})。")
            if response.status_code >= 400:
                return self._response_error("urlhaus", "url", url, response)
            data = response.json()
            query_status = str(data.get("query_status") or "")
            if query_status == "ok":
                threat = str(data.get("threat") or "malware_or_phishing")
                url_status = str(data.get("url_status") or "unknown")
                return EvidenceItem(
                    source="urlhaus",
                    indicator_type="url",
                    indicator=url,
                    status="malicious",
                    score_delta=40,
                    title="URLhaus 命中惡意 URL",
                    detail=f"query_status=ok, threat={threat}, url_status={url_status}。",
                    reference_url=str(data.get("urlhaus_reference") or "https://urlhaus-api.abuse.ch/"),
                )
            return EvidenceItem(
                source="urlhaus",
                indicator_type="url",
                indicator=url,
                status="safe",
                score_delta=0,
                title="URLhaus 未命中",
                detail=f"query_status={query_status or 'unknown'}。",
                reference_url="https://urlhaus-api.abuse.ch/",
            )
        except Exception as exc:
            return self._error("urlhaus", "url", url, exc)

    def _virustotal_url(self, client: httpx.Client, url: str) -> EvidenceItem:
        if not settings.virustotal_api_key:
            return self._skipped("virustotal_url", "url", url, "未設定 VIRUSTOTAL_API_KEY。")

        url_id = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        try:
            response = client.get(endpoint, headers={"x-apikey": settings.virustotal_api_key})
            if response.status_code == 404:
                return EvidenceItem(
                    source="virustotal_url",
                    indicator_type="url",
                    indicator=url,
                    status="unknown",
                    score_delta=0,
                    title="VirusTotal 無既有 URL 報告",
                    detail="VirusTotal 查無此 URL 的既有分析報告，未主動提交掃描以避免送出敏感 URL。",
                    reference_url="https://docs.virustotal.com/reference/overview",
                )
            if response.status_code >= 400:
                return self._response_error("virustotal_url", "url", url, response)
            stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = int(stats.get("malicious") or 0)
            suspicious = int(stats.get("suspicious") or 0)
            harmless = int(stats.get("harmless") or 0)
            if malicious + suspicious < 2:
                return EvidenceItem(
                    source="virustotal_url",
                    indicator_type="url",
                    indicator=url,
                    status="info",
                    score_delta=0,
                    title="VirusTotal URL 單一引擎命中已降權",
                    detail=f"malicious={malicious}, suspicious={suspicious}, harmless={harmless}；未達多引擎共識，不計入風險分數。",
                    reference_url="https://docs.virustotal.com/reference/overview",
                )
            score_delta = min(35, malicious * 8 + suspicious * 4)
            status = "malicious" if malicious else "suspicious" if suspicious else "safe"
            return EvidenceItem(
                source="virustotal_url",
                indicator_type="url",
                indicator=url,
                status=status,
                score_delta=score_delta,
                title="VirusTotal URL reputation",
                detail=f"malicious={malicious}, suspicious={suspicious}, harmless={stats.get('harmless', 0)}。",
                reference_url="https://docs.virustotal.com/reference/overview",
            )
        except Exception as exc:
            return self._error("virustotal_url", "url", url, exc)

    def _virustotal_domain(self, client: httpx.Client, domain: str) -> EvidenceItem:
        if not settings.virustotal_api_key:
            return self._skipped("virustotal_domain", "domain", domain, "未設定 VIRUSTOTAL_API_KEY。")

        endpoint = f"https://www.virustotal.com/api/v3/domains/{quote(domain, safe='')}"
        try:
            response = client.get(endpoint, headers={"x-apikey": settings.virustotal_api_key})
            if response.status_code == 404:
                return EvidenceItem(
                    source="virustotal_domain",
                    indicator_type="domain",
                    indicator=domain,
                    status="unknown",
                    score_delta=0,
                    title="VirusTotal 無 domain 報告",
                    detail="VirusTotal 查無此 domain 的既有分析報告。",
                    reference_url="https://docs.virustotal.com/reference/overview",
                )
            if response.status_code >= 400:
                return self._response_error("virustotal_domain", "domain", domain, response)
            stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = int(stats.get("malicious") or 0)
            suspicious = int(stats.get("suspicious") or 0)
            harmless = int(stats.get("harmless") or 0)
            if domain in LOW_SIGNAL_DOMAIN_REPUTATION and (malicious or suspicious):
                return EvidenceItem(
                    source="virustotal_domain",
                    indicator_type="domain",
                    indicator=domain,
                    status="info",
                    score_delta=0,
                    title="VirusTotal domain reputation 已降權",
                    detail=(
                        f"{domain} 是常見平台網域；domain 層級 malicious={malicious}, suspicious={suspicious} "
                        "不單獨作為惡意判定，需以具體 URL 或其他證據佐證。"
                    ),
                    reference_url="https://docs.virustotal.com/reference/overview",
                )
            if malicious + suspicious < 2:
                return EvidenceItem(
                    source="virustotal_domain",
                    indicator_type="domain",
                    indicator=domain,
                    status="info",
                    score_delta=0,
                    title="VirusTotal domain 單一引擎命中已降權",
                    detail=f"malicious={malicious}, suspicious={suspicious}, harmless={harmless}；未達多引擎共識，不計入風險分數。",
                    reference_url="https://docs.virustotal.com/reference/overview",
                )
            score_delta = min(30, malicious * 7 + suspicious * 4)
            status = "malicious" if malicious else "suspicious" if suspicious else "safe"
            return EvidenceItem(
                source="virustotal_domain",
                indicator_type="domain",
                indicator=domain,
                status=status,
                score_delta=score_delta,
                title="VirusTotal domain reputation",
                detail=f"malicious={malicious}, suspicious={suspicious}, harmless={stats.get('harmless', 0)}。",
                reference_url="https://docs.virustotal.com/reference/overview",
            )
        except Exception as exc:
            return self._error("virustotal_domain", "domain", domain, exc)

    def _urlscan_search(self, client: httpx.Client, url: str) -> EvidenceItem:
        if not settings.urlscan_api_key:
            return self._skipped("urlscan", "url", url, "未設定 URLSCAN_API_KEY。")

        domain = urlparse(url).hostname or url
        try:
            response = client.get(
                "https://urlscan.io/api/v1/search/",
                params={"q": f"domain:{domain}", "size": 3},
                headers={"API-Key": settings.urlscan_api_key},
            )
            if response.status_code == 401:
                return self._skipped("urlscan", "url", url, "urlscan.io API Key 認證失敗 (HTTP 401)。")
            if response.status_code in {429, 502, 503, 504}:
                return self._skipped("urlscan", "url", url, f"urlscan.io 服務暫時無法使用或達請求上限 (HTTP {response.status_code})。")
            if response.status_code >= 400:
                return self._response_error("urlscan", "url", url, response)
            results = response.json().get("results") or []
            verdicts = [item.get("verdicts", {}) for item in results if isinstance(item, dict)]
            malicious = any((verdict.get("overall") or {}).get("malicious") for verdict in verdicts)
            return EvidenceItem(
                source="urlscan",
                indicator_type="url",
                indicator=url,
                status="suspicious" if malicious else "info",
                score_delta=20 if malicious else 0,
                title="urlscan.io 既有掃描查詢",
                detail=f"找到 {len(results)} 筆既有掃描；overall malicious={malicious}。",
                reference_url="https://urlscan.io/docs/api/",
            )
        except Exception as exc:
            return self._error("urlscan", "url", url, exc)

    def _serpapi(self, client: httpx.Client, text: str, urls: list[str], domains: list[str]) -> EvidenceItem:
        indicator = urls[0] if urls else domains[0] if domains else (text[:80] or "message")
        if not settings.serpapi_api_key:
            return self._skipped("serpapi", "unknown", indicator, "未設定 SERPAPI_API_KEY。")

        search_target = domains[0] if domains else urls[0] if urls else text[:120]
        try:
            response = client.get(
                "https://serpapi.com/search.json",
                params={"engine": "google", "q": f'"{search_target}"', "api_key": settings.serpapi_api_key, "num": 5, "hl": "zh-tw"},
            )
            if response.status_code >= 400:
                return self._response_error("serpapi", "unknown", indicator, response)
            results = response.json().get("organic_results") or []
            combined = " ".join(
                f"{item.get('title', '')} {item.get('snippet', '')}"
                for item in results[:5]
                if isinstance(item, dict)
            ).lower()
            risky_hits = sum(keyword in combined for keyword in ("詐騙", "釣魚", "phishing", "scam", "fake", "fraud"))
            return EvidenceItem(
                source="serpapi",
                indicator_type="unknown",
                indicator=search_target,
                status="suspicious" if risky_hits else "info",
                score_delta=12 if risky_hits else 0,
                title="搜尋結果佐證",
                detail=f"搜尋前 {len(results[:5])} 筆結果中，風險關鍵字命中 {risky_hits} 類。",
                reference_url="https://serpapi.com/search-api",
            )
        except Exception as exc:
            return self._error("serpapi", "unknown", indicator, exc)

    def _fact_check(self, client: httpx.Client, text: str) -> EvidenceItem:
        query = " ".join((text or "").split())[:180]
        if not settings.google_fact_check_api_key:
            return self._skipped("google_fact_check", "unknown", query or "message", "未設定 GOOGLE_FACT_CHECK_API_KEY。")
        if not query:
            return self._skipped("google_fact_check", "unknown", "message", "沒有足夠文字可查詢 fact-check。")

        try:
            response = client.get(
                "https://factchecktools.googleapis.com/v1alpha1/claims:search",
                params={"query": query, "key": settings.google_fact_check_api_key, "languageCode": "zh"},
            )
            if response.status_code >= 400:
                return self._response_error("google_fact_check", "unknown", query[:80] or "message", response)
            claims = response.json().get("claims") or []
            return EvidenceItem(
                source="google_fact_check",
                indicator_type="unknown",
                indicator=query[:80],
                status="info",
                score_delta=8 if claims else 0,
                title="Fact Check Tools 查核結果",
                detail=f"找到 {len(claims)} 筆可能相關的 fact-check claim。",
                reference_url="https://developers.google.com/fact-check/tools/api/reference/rest/v1alpha1/claims/search",
            )
        except Exception as exc:
            return self._error("google_fact_check", "unknown", query[:80] or "message", exc)

    def _skipped(self, source: str, indicator_type: str, indicator: str, detail: str) -> EvidenceItem:
        return EvidenceItem(
            source=source,
            indicator_type=indicator_type,
            indicator=indicator,
            status="skipped",
            score_delta=0,
            title="外部資料來源未查詢",
            detail=detail,
        )

    def _error(self, source: str, indicator_type: str, indicator: str, exc: Exception) -> EvidenceItem:
        detail = self._redact_secret_query(str(exc))
        logger.warning("Threat intel lookup exception source=%s indicator_type=%s detail=%s", source, indicator_type, detail)
        return EvidenceItem(
            source=source,
            indicator_type=indicator_type,
            indicator=indicator,
            status="error",
            score_delta=0,
            title="外部資料來源查詢失敗",
            detail=detail[:500],
        )

    def _response_error(self, source: str, indicator_type: str, indicator: str, response: httpx.Response) -> EvidenceItem:
        detail = self._response_error_detail(response)
        logger.warning(
            "Threat intel lookup HTTP error source=%s status=%s indicator_type=%s detail=%s",
            source,
            response.status_code,
            indicator_type,
            detail,
        )
        return EvidenceItem(
            source=source,
            indicator_type=indicator_type,
            indicator=indicator,
            status="error",
            score_delta=0,
            title="外部資料來源查詢失敗",
            detail=detail,
        )

    def _response_error_detail(self, response: httpx.Response) -> str:
        parts = [f"HTTP {response.status_code}"]
        try:
            payload = response.json()
        except Exception:
            body = self._redact_secret_query(response.text[:600])
            return " | ".join(parts + ([body] if body else []))

        if isinstance(payload, dict) and isinstance(payload.get("error"), dict):
            error = payload["error"]
            status = error.get("status")
            message = error.get("message")
            if status:
                parts.append(f"status={status}")
            if message:
                parts.append(f"message={self._redact_secret_query(str(message))}")
            reasons = []
            for item in error.get("details") or []:
                if not isinstance(item, dict):
                    continue
                reason = item.get("reason")
                metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
                caller_ip = metadata.get("callerIp")
                service = metadata.get("service")
                if reason:
                    reasons.append(str(reason))
                if caller_ip:
                    parts.append(f"caller_ip={caller_ip}")
                if service:
                    parts.append(f"service={service}")
            if reasons:
                parts.append("reason=" + ",".join(dict.fromkeys(reasons)))
            return " | ".join(parts)

        return " | ".join(parts + [self._redact_secret_query(json.dumps(payload, ensure_ascii=False)[:600])])

    def _redact_secret_query(self, detail: str) -> str:
        return re.sub(
            r"(?i)([?&])(?:key|api_key|apikey|token|access_token)=[^&\s'\"<>]+",
            r"\1[redacted_query]",
            detail,
        )
