from __future__ import annotations

import re
import unicodedata
from email.utils import parseaddr
from typing import Any

from app.analysis.domain_utils import email_domain, org_domain, same_org_domain
from app.analysis.external_threat_intel import ExternalThreatIntelService
from app.analysis.indicator_extractor import IndicatorExtractor
from app.analysis.llm_intent_classifier import LlmIntentClassifierService
from app.analysis.risk_scoring_service import RiskScoringService
from app.analysis.scam_rules import ScamRuleEngine
from app.analysis.setfit_classifier import SetFitEmailClassifierService, build_model_input
from app.analysis.url_analysis_service import OFFICIAL_BRANDS, UrlAnalysisService
from app.config import settings
from app.models import EvidenceItem, GmailMessage, ScanDecision


DANGEROUS_ATTACHMENT_EXTENSIONS = {
    ".exe",
    ".scr",
    ".js",
    ".jse",
    ".vbs",
    ".vbe",
    ".wsf",
    ".bat",
    ".cmd",
    ".ps1",
    ".lnk",
    ".iso",
    ".img",
    ".apk",
    ".jar",
}

MACRO_ATTACHMENT_EXTENSIONS = {".docm", ".xlsm", ".pptm"}
SUSPICIOUS_ATTACHMENT_EXTENSIONS = {".zip", ".rar", ".7z", ".html", ".htm"}
SENSITIVE_WORDS = re.compile(
    r"(verify|verification|password|login|account|security|payment|transaction|refund|purchase|付款|轉帳|驗證|登入|帳戶|密碼|銀行|信用卡)",
    re.IGNORECASE,
)
EINVOICE_NOTICE_SUPPRESSED_RULE_IDS = {
    "dangerous_attachment_lure",
    "government_refund_phishing",
    "law_enforcement_impersonation",
    "payment_request",
    "urgency_pressure",
}
SEED_TRUSTED_SENDER_DOMAINS = {
    "einvoice.nat.gov.tw",
    "mail.fisc.com.tw",
    "post.gov.tw",
    "github.com",
    "slack.com",
    "medium.com",
    "uptime-robot.com",
}


class RiskAnalyzer:
    def __init__(
        self,
        reputation_store: Any | None = None,
        setfit_classifier: SetFitEmailClassifierService | None = None,
    ) -> None:
        self.extractor = IndicatorExtractor()
        self.rules = ScamRuleEngine()
        self.url_analysis = UrlAnalysisService()
        self.threat_intel = ExternalThreatIntelService(cache_store=reputation_store)
        self.llm_intent = LlmIntentClassifierService()
        self.setfit_classifier = setfit_classifier or SetFitEmailClassifierService()
        self.scoring = RiskScoringService()
        self.reputation_store = reputation_store

    def analyze_email(self, message: GmailMessage) -> ScanDecision:
        text = message.combined_text(max_body_chars=settings.max_body_chars)
        model_input_text = build_model_input(message)
        indicators = self.extractor.extract(text)
        rule_hits = self.rules.match(text)
        evidence = self.url_analysis.analyze(indicators)
        evidence.extend(self._email_header_evidence(message))
        rule_hits = self._filter_contextual_rule_hits(rule_hits, message, evidence)
        evidence.extend(self._sender_reputation_evidence(message))
        evidence.extend(self._attachment_evidence(message))
        evidence.extend(self._content_obfuscation_evidence(text))
        evidence.extend(self.threat_intel.collect(text, indicators))
        evidence.extend(self.setfit_classifier.collect(model_input_text))

        report = self.scoring.score(indicators=indicators, evidence=evidence, rule_hits=rule_hits)
        llm_evidence = self.llm_intent.collect(model_input_text, preliminary_report=report, evidence=evidence)
        if llm_evidence:
            evidence.extend(llm_evidence)
            report = self.scoring.score(indicators=indicators, evidence=evidence, rule_hits=rule_hits)
        reasons = self._reasons(rule_hits, evidence, report.summary)
        high_risk = report.risk_score >= settings.high_risk_threshold
        action = "marked" if high_risk else "skipped"

        return ScanDecision(
            gmail_id=message.gmail_id,
            subject=message.subject,
            sender=message.sender,
            sender_email=message.sender_email,
            high_risk=high_risk,
            action=action,  # type: ignore[arg-type]
            risk_score=report.risk_score,
            risk_level=report.risk_level,
            score_breakdown=report.score_breakdown,
            confidence_score=report.confidence_score,
            summary=report.summary,
            uncertainty_notes=report.uncertainty_notes,
            label_reason=self._label_reason(rule_hits, evidence, report.risk_level),
            reasons=reasons,
            recommendations=report.recommendations,
            indicators=indicators,
            evidence=evidence,
            rule_hits=rule_hits,
            model_input_text=model_input_text,
        )

    def analyze_text(self, text: str) -> ScanDecision:
        message = GmailMessage(
            gmail_id="manual",
            subject="manual text",
            sender="manual",
            sender_email="",
            body_text=text,
        )
        decision = self.analyze_email(message)
        if decision.high_risk:
            decision.action = "dry_run_mark"
        return decision

    def _email_header_evidence(self, message: GmailMessage) -> list[EvidenceItem]:
        evidence: list[EvidenceItem] = []
        sender_domain = email_domain(message.sender_email)
        reply_name, reply_email = parseaddr(message.reply_to or "")
        reply_domain = email_domain(reply_email)

        if sender_domain and reply_domain and not same_org_domain(sender_domain, reply_domain):
            evidence.append(
                EvidenceItem(
                    source="email_header_analysis",
                    indicator_type="email",
                    indicator=message.reply_to,
                    status="suspicious",
                    score_delta=12,
                    title="Reply-To 與寄件者網域不一致",
                    detail=f"From 網域為 {sender_domain}，但 Reply-To 指向 {reply_domain}，可能導向冒名回覆。",
                )
            )

        auth_text = f"{message.authentication_results}\n{message.received_spf}".lower()
        failed_checks = sorted(set(re.findall(r"\b(spf|dkim|dmarc)\s*=\s*(?:fail|softfail|temperror|permerror)", auth_text)))
        if failed_checks:
            evidence.append(
                EvidenceItem(
                    source="email_header_analysis",
                    indicator_type="email",
                    indicator=message.sender_email or message.sender,
                    status="suspicious",
                    score_delta=20,
                    title="寄件者驗證失敗",
                    detail=f"郵件驗證結果異常：{', '.join(failed_checks)}。這常出現在仿冒寄件者或釣魚信。",
                )
            )
        else:
            auth_evidence = self._authentication_evidence(message, sender_domain)
            if auth_evidence:
                evidence.append(auth_evidence)

        if self._seed_trusted_sender_domain(sender_domain):
            auth_passed = self._auth_passed(message)
            score_delta = -14 if auth_passed else -8
            evidence.append(
                EvidenceItem(
                    source="email_trust_analysis",
                    indicator_type="domain",
                    indicator=sender_domain or message.sender_email or message.sender,
                    status="safe",
                    score_delta=score_delta,
                    title="可信寄件者網域",
                    detail=(
                        "寄件網域在可信清單中"
                        + ("，且 SPF/DKIM/DMARC 至少一項通過。" if auth_passed else "，且未看到明確驗證失敗。")
                    ),
                )
            )

        brand_hit = self._brand_sender_mismatch(message, sender_domain)
        if brand_hit:
            brand, official_domains = brand_hit
            evidence.append(
                EvidenceItem(
                    source="email_header_analysis",
                    indicator_type="domain",
                    indicator=sender_domain or message.sender_email or message.sender,
                    status="suspicious",
                    score_delta=12,
                    title="寄件者疑似仿冒品牌",
                    detail=f"信件主旨或寄件者顯示名稱提到 {brand}，但寄件網域不在官方網域清單：{', '.join(sorted(official_domains))}。",
                )
            )

        return evidence

    def _filter_contextual_rule_hits(
        self,
        rule_hits,
        message: GmailMessage,
        evidence: list[EvidenceItem],
    ):
        filtered = []
        for hit in rule_hits:
            if hit.rule_id == "dangerous_attachment_lure" and not message.attachment_filenames:
                continue
            if hit.rule_id in EINVOICE_NOTICE_SUPPRESSED_RULE_IDS and self._verified_einvoice_notice(message, evidence):
                continue
            filtered.append(hit)
        return filtered

    def _verified_einvoice_notice(self, message: GmailMessage, evidence: list[EvidenceItem]) -> bool:
        target = f"{message.sender} {message.subject} {message.body_text[:1200]}".lower()
        if "電子發票" not in target and "發票號碼" not in target:
            return False
        return any(
            item.source in {"email_authentication_analysis", "email_trust_analysis"}
            and item.status == "safe"
            and item.score_delta < 0
            for item in evidence
        )

    def _authentication_evidence(self, message: GmailMessage, sender_domain: str | None) -> EvidenceItem | None:
        passed_checks = self._passed_auth_checks(message)
        if not passed_checks:
            return None
        auth_domains = self._auth_domains(message)
        aligned_domains = [
            domain
            for domain in auth_domains
            if sender_domain and same_org_domain(sender_domain, domain)
        ]
        aligned = bool(aligned_domains)
        score_delta = -6 if aligned else -3
        checks = ", ".join(sorted(passed_checks))
        detail = f"通過驗證：{checks}。"
        if sender_domain and auth_domains:
            detail += (
                f" 驗證網域與 From 組織網域相符：{', '.join(sorted(aligned_domains))}。"
                if aligned
                else f" 驗證網域未明確對齊 From：{', '.join(sorted(auth_domains))}。"
            )
        return EvidenceItem(
            source="email_authentication_analysis",
            indicator_type="domain",
            indicator=sender_domain or message.sender_email or message.sender,
            status="safe",
            score_delta=score_delta,
            title="寄件者驗證通過",
            detail=detail,
        )

    def _sender_reputation_evidence(self, message: GmailMessage) -> list[EvidenceItem]:
        sender_domain = email_domain(message.sender_email)
        if not sender_domain or not self.reputation_store:
            return []
        getter = getattr(self.reputation_store, "get_sender_reputation", None)
        if not callable(getter):
            return []
        try:
            reputation = getter(sender_domain)
        except Exception:
            return []
        if not reputation:
            return []
        trust_score = int(reputation.get("trust_score") or 0)
        safe_count = int(reputation.get("safe_count") or 0)
        auth_pass_count = int(reputation.get("auth_pass_count") or 0)
        manual_safe_count = int(reputation.get("manual_safe_count") or 0)
        manual_threat_count = int(reputation.get("manual_threat_count") or 0)
        organization = org_domain(sender_domain)
        evidence: list[EvidenceItem] = []
        if manual_threat_count > 0:
            evidence.append(
                EvidenceItem(
                    source="sender_reputation",
                    indicator_type="domain",
                    indicator=organization,
                    status="suspicious",
                    score_delta=16,
                    title="人工回饋：此寄件者曾被確認為威脅",
                    detail=f"同組織寄件者累積 {manual_threat_count} 次人工威脅回饋；後續同來源信件需提高警覺。",
                )
            )
        if trust_score > 0:
            evidence.append(
                EvidenceItem(
                    source="sender_reputation",
                    indicator_type="domain",
                    indicator=organization,
                    status="safe",
                    score_delta=-min(12, trust_score),
                    title="歷史寄件者信譽",
                    detail=(
                        f"同組織寄件網域近期累積 {safe_count} 次低風險、"
                        f"{auth_pass_count} 次驗證通過、{manual_safe_count} 次人工安全回饋；"
                        "以歷史信譽降低單一弱訊號造成的誤判。"
                    ),
                )
            )
        return evidence

    def _attachment_evidence(self, message: GmailMessage) -> list[EvidenceItem]:
        evidence: list[EvidenceItem] = []
        for filename in message.attachment_filenames:
            lowered = filename.lower()
            extension = self._extension(lowered)
            if extension in DANGEROUS_ATTACHMENT_EXTENSIONS:
                evidence.append(
                    EvidenceItem(
                        source="attachment_analysis",
                        indicator_type="unknown",
                        indicator=filename,
                        status="suspicious",
                        score_delta=26,
                        title="附件副檔名高風險",
                        detail=f"{extension} 附件可能直接執行程式或腳本，不應開啟。",
                    )
                )
            elif extension in MACRO_ATTACHMENT_EXTENSIONS:
                evidence.append(
                    EvidenceItem(
                        source="attachment_analysis",
                        indicator_type="unknown",
                        indicator=filename,
                        status="suspicious",
                        score_delta=20,
                        title="Office 巨集附件",
                        detail="含巨集的 Office 檔可能被用來投遞惡意程式。",
                    )
                )
            elif extension in SUSPICIOUS_ATTACHMENT_EXTENSIONS and SENSITIVE_WORDS.search(message.subject + " " + message.body_text[:500]):
                evidence.append(
                    EvidenceItem(
                        source="attachment_analysis",
                        indicator_type="unknown",
                        indicator=filename,
                        status="info",
                        score_delta=8,
                        title="壓縮或 HTML 附件搭配敏感主題",
                        detail="壓縮檔或 HTML 附件若搭配帳戶驗證、付款、發票等主題，需要進一步確認。",
                    )
                )
        return evidence

    def _content_obfuscation_evidence(self, text: str) -> list[EvidenceItem]:
        confusable_chars = [
            char
            for char in text
            if ord(char) > 127 and self._is_confusable_alnum(char)
        ]
        if len(confusable_chars) < 3:
            return []
        sample = "".join(dict.fromkeys(confusable_chars))[:20]
        return [
            EvidenceItem(
                source="content_obfuscation",
                indicator_type="unknown",
                indicator=sample,
                status="info",
                score_delta=8,
                title="文字含 Unicode 混淆字元",
                detail="信件使用外觀接近英數字的 Unicode 字元，常用於繞過簡單關鍵字或降低辨識度。",
            )
        ]

    def _is_confusable_alnum(self, char: str) -> bool:
        if not unicodedata.category(char).startswith(("L", "N")):
            return False
        name = unicodedata.name(char, "")
        return any(token in name for token in ("MATHEMATICAL", "FULLWIDTH", "SMALL CAPITAL"))

    def _brand_sender_mismatch(self, message: GmailMessage, sender_domain: str | None) -> tuple[str, set[str]] | None:
        if not sender_domain:
            return None
        target = f"{message.sender} {message.subject}".lower()
        if not SENSITIVE_WORDS.search(target):
            return None
        for brand, official_domains in OFFICIAL_BRANDS.items():
            if brand not in target:
                continue
            if sender_domain in official_domains or any(sender_domain.endswith(f".{official}") for official in official_domains):
                return None
            return brand, official_domains
        return None

    def _seed_trusted_sender_domain(self, domain: str | None) -> bool:
        if not domain:
            return False
        lowered = domain.lower()
        trusted_domains = SEED_TRUSTED_SENDER_DOMAINS
        return lowered in trusted_domains or any(lowered.endswith(f".{trusted}") for trusted in trusted_domains)

    def _auth_passed(self, message: GmailMessage) -> bool:
        return bool(self._passed_auth_checks(message))

    def _passed_auth_checks(self, message: GmailMessage) -> set[str]:
        auth_text = f"{message.authentication_results}\n{message.received_spf}".lower()
        return set(re.findall(r"\b(spf|dkim|dmarc)\s*=\s*pass\b", auth_text))

    def _auth_domains(self, message: GmailMessage) -> set[str]:
        auth_text = f"{message.authentication_results}\n{message.received_spf}".lower()
        domains = set(
            match.strip(".")
            for match in re.findall(
                r"(?:smtp\.mailfrom|header\.d|header\.from|header\.i)=@?([a-z0-9.-]+\.[a-z]{2,})",
                auth_text,
            )
        )
        domains.update(
            match.strip(".")
            for match in re.findall(r"\bdomain of [^@\s;]+@([a-z0-9.-]+\.[a-z]{2,})", auth_text)
        )
        return {domain for domain in domains if domain}

    def _extension(self, filename: str) -> str:
        if "." not in filename:
            return ""
        return "." + filename.rsplit(".", 1)[-1]

    def _reasons(self, rule_hits, evidence, summary: str) -> list[str]:
        reasons = [summary]
        has_setfit_result = any(
            item.source == "setfit_email_classifier" and item.status not in {"error", "skipped"}
            for item in evidence
        )
        top_rules = [] if has_setfit_result else sorted(rule_hits, key=lambda hit: hit.score_delta, reverse=True)[:3]
        for hit in top_rules:
            reasons.append(f"{hit.name}：{hit.explanation}")

        top_evidence = sorted(
            [item for item in evidence if item.score_delta > 0],
            key=lambda item: item.score_delta,
            reverse=True,
        )[:3]
        for item in top_evidence:
            reasons.append(f"{item.title}：{item.detail}")

        return list(dict.fromkeys(reasons))[:6]

    def _label_reason(self, rule_hits, evidence, risk_level: str = "high") -> str:
        if risk_level == "low":
            return "低風險"
        if any(item.source == "attachment_analysis" and item.score_delta >= 20 for item in evidence):
            return "惡意附件"
        if any(item.source in {"google_safe_browsing", "urlhaus", "virustotal_url", "virustotal_domain", "urlscan"} and item.status in {"malicious", "suspicious"} for item in evidence):
            return "外部情資"
        setfit_item = next((item for item in evidence if item.source == "setfit_email_classifier"), None)
        if setfit_item and setfit_item.status == "suspicious" and setfit_item.score_delta >= 60:
            return "語意威脅"
        if setfit_item and setfit_item.status == "suspicious" and setfit_item.score_delta >= 30:
            return "可疑意圖"
        if any(hit.category == "credential_theft" or hit.rule_id in {"credential_login", "social_account_phishing"} for hit in rule_hits):
            return "釣魚驗證"
        if any(hit.category == "phishing" for hit in rule_hits):
            return "釣魚驗證"
        if any(hit.category == "payment_scam" for hit in rule_hits):
            return "轉帳付款"
        if any(hit.category == "investment_scam" for hit in rule_hits):
            return "投資詐騙"
        if any(hit.category == "impersonation" for hit in rule_hits):
            return "冒名詐騙"
        if any(item.source == "email_header_analysis" for item in evidence):
            return "寄件異常"
        if any(item.source == "local_url_analysis" and item.score_delta > 0 for item in evidence):
            return "可疑網址"
        if rule_hits:
            return "詐騙話術"
        if risk_level in {"high", "critical"}:
            return "高風險"
        if risk_level == "medium":
            return "可疑訊號"
        return "低風險"
