from __future__ import annotations

from app.models import EvidenceItem, ExtractedIndicator, RiskReport, ScamRuleHit, ScoreBreakdown
from app.analysis.setfit_classifier import SETFIT_SOURCE


LOCAL_URL_SOURCES = {"local_url_analysis", "local_tls_probe"}
EMAIL_HEADER_SOURCES = {"email_header_analysis", "attachment_analysis"}
CONTENT_OBFUSCATION_SOURCES = {"content_obfuscation"}
TRUST_SOURCES = {"email_trust_analysis"}
AUTHENTICATION_SOURCES = {"email_authentication_analysis"}
REPUTATION_SOURCES = {"sender_reputation"}
STRONG_REPUTATION_SOURCES = {"google_safe_browsing", "urlhaus", "virustotal_url", "virustotal_domain", "urlscan"}
STRONG_REPUTATION_FLOOR_MIN_SCORE = 20
EXTERNAL_SOURCES = {
    "google_safe_browsing",
    "urlhaus",
    "virustotal_url",
    "virustotal_domain",
    "urlscan",
    "serpapi",
    "google_fact_check",
    "external_threat_lookups",
}
LLM_INTENT_SOURCE = "llm_intent_classifier"

MESSAGE_INTENT_CAP = 45
SETFIT_CLASSIFIER_CAP = 70
URL_STRUCTURE_CAP = 22
EXTERNAL_REPUTATION_CAP = 30
EMAIL_HEADER_CAP = 22
SENSITIVE_INDICATOR_CAP = 10
UNCERTAINTY_CAP = 5


class RiskScoringService:
    def score(
        self,
        *,
        indicators: list[ExtractedIndicator],
        evidence: list[EvidenceItem],
        rule_hits: list[ScamRuleHit],
    ) -> RiskReport:
        score_breakdown = ScoreBreakdown(
            message_intent=self._message_intent_score(rule_hits, evidence),
            url_structure=self._url_structure_score(evidence),
            external_reputation=self._external_reputation_score(evidence),
            ml_classifier=self._source_score(evidence, {SETFIT_SOURCE}, SETFIT_CLASSIFIER_CAP),
            llm_intent=self._source_score(evidence, {LLM_INTENT_SOURCE}, 15),
            sensitive_indicators=self._indicator_bonus(indicators),
            uncertainty=self._uncertainty_score(indicators, evidence),
        )

        header_score = self._source_score(evidence, EMAIL_HEADER_SOURCES, EMAIL_HEADER_CAP)
        score_breakdown.calibration_adjustment += max(0, header_score)
        content_score = self._source_score(evidence, CONTENT_OBFUSCATION_SOURCES, 10)
        score_breakdown.calibration_adjustment += max(0, content_score)
        trust_score = self._source_score(evidence, TRUST_SOURCES, 25)
        score_breakdown.calibration_adjustment += min(0, trust_score)
        authentication_score = self._source_score(evidence, AUTHENTICATION_SOURCES, 8)
        score_breakdown.calibration_adjustment += min(0, authentication_score)
        reputation_score = self._source_score(evidence, REPUTATION_SOURCES, 12)
        score_breakdown.calibration_adjustment += reputation_score

        base_score = self._breakdown_total(score_breakdown)
        risk_floor = self._risk_floor(score_breakdown, evidence, rule_hits)
        if risk_floor > base_score:
            score_breakdown.calibration_adjustment = min(100, score_breakdown.calibration_adjustment + risk_floor - base_score)

        score = max(0, min(100, self._breakdown_total(score_breakdown)))
        risk_level = self._risk_level(score)
        recommendations = self._recommendations(risk_level, indicators, evidence, rule_hits)
        uncertainty_notes = self._uncertainty_notes(evidence)
        summary = self._summary(risk_level, rule_hits, evidence)
        confidence_score = self._confidence_score(indicators, evidence, rule_hits)

        return RiskReport(
            risk_score=score,
            risk_level=risk_level,
            score_breakdown=score_breakdown,
            confidence_score=confidence_score,
            summary=summary,
            recommendations=recommendations,
            uncertainty_notes=uncertainty_notes,
        )

    def _message_intent_score(self, rule_hits: list[ScamRuleHit], evidence: list[EvidenceItem]) -> int:
        if self._has_setfit_result(evidence):
            return 0
        raw_score = sum(max(0, hit.score_delta) for hit in rule_hits)
        if raw_score <= 0:
            return 0

        categories = {hit.category for hit in rule_hits}
        has_critical = any(hit.severity == "critical" for hit in rule_hits)
        category_bonus = min(8, max(0, len(categories) - 1) * 3)
        severity_bonus = 6 if has_critical else 0
        weighted_score = round(raw_score * 0.65) + category_bonus + severity_bonus
        return min(MESSAGE_INTENT_CAP, weighted_score)

    def _url_structure_score(self, evidence: list[EvidenceItem]) -> int:
        score = sum(max(0, item.score_delta) for item in evidence if item.source in LOCAL_URL_SOURCES)
        return min(URL_STRUCTURE_CAP, score)

    def _external_reputation_score(self, evidence: list[EvidenceItem]) -> int:
        score = sum(max(0, item.score_delta) for item in evidence if item.source in EXTERNAL_SOURCES)
        return min(EXTERNAL_REPUTATION_CAP, score)

    def _source_score(self, evidence: list[EvidenceItem], sources: set[str], cap: int) -> int:
        score = sum(item.score_delta for item in evidence if item.source in sources)
        return max(-cap, min(cap, score))

    def _indicator_bonus(self, indicators: list[ExtractedIndicator]) -> int:
        types = {item.type for item in indicators}
        score = 0
        if "url" in types:
            score += 2
        if "bank_account" in types:
            score += 5
        if "crypto_address" in types:
            score += 5
        if "line_id" in types:
            score += 3
        if "email" in types:
            score += 2
        if "phone" in types:
            score += 2
        return min(SENSITIVE_INDICATOR_CAP, score)

    def _uncertainty_score(self, indicators: list[ExtractedIndicator], evidence: list[EvidenceItem]) -> int:
        has_network_indicator = any(item.type in {"url", "domain"} for item in indicators)
        if has_network_indicator and not any(item.source in STRONG_REPUTATION_SOURCES for item in evidence):
            return min(UNCERTAINTY_CAP, 2)
        return 0

    def _risk_floor(
        self,
        score_breakdown: ScoreBreakdown,
        evidence: list[EvidenceItem],
        rule_hits: list[ScamRuleHit],
    ) -> int:
        floor = 0
        if any(self._strong_reputation_floor_evidence(item, "malicious") for item in evidence):
            floor = max(floor, 85)
        if any(self._strong_reputation_floor_evidence(item, "suspicious") for item in evidence):
            floor = max(floor, 60)
        if any(item.status == "suspicious" and item.score_delta >= 20 and item.source in EMAIL_HEADER_SOURCES for item in evidence):
            floor = max(floor, 60)
        setfit_item = self._setfit_evidence(evidence)
        if setfit_item and setfit_item.status == "suspicious":
            if setfit_item.score_delta >= 60:
                floor = max(floor, 60)
            elif setfit_item.score_delta >= 30:
                floor = max(floor, 30)
        trust_signal = self._has_trust_signal(evidence)
        authenticated_sender = self._has_authenticated_sender(evidence)
        ml_safe = self._has_safe_setfit_classification(evidence)
        if (
            not trust_signal
            and not (authenticated_sender and (self._has_only_redirect_url_signal(evidence) or ml_safe))
            and any(item.source in LOCAL_URL_SOURCES and item.score_delta >= 18 for item in evidence)
        ):
            floor = max(floor, 30)
        if not self._has_setfit_result(evidence):
            categories = {hit.category for hit in rule_hits}
            rule_ids = {hit.rule_id for hit in rule_hits}
            has_delivery_payment = "parcel_delivery" in rule_ids and "payment_request" in rule_ids
            if score_breakdown.message_intent >= 40 and (len(categories) >= 2 or len(rule_hits) >= 3):
                floor = max(floor, 60)
            if score_breakdown.message_intent >= 35 and any(hit.severity == "critical" for hit in rule_hits):
                floor = max(floor, 60)
            if has_delivery_payment and ("urgency_pressure" in rule_ids or self._has_suspicious_url_signal(evidence)):
                floor = max(floor, 60)
        return min(100, floor)

    def _setfit_evidence(self, evidence: list[EvidenceItem]) -> EvidenceItem | None:
        return next((item for item in evidence if item.source == SETFIT_SOURCE), None)

    def _has_setfit_result(self, evidence: list[EvidenceItem]) -> bool:
        item = self._setfit_evidence(evidence)
        return bool(item and item.status not in {"error", "skipped"})

    def _has_safe_setfit_classification(self, evidence: list[EvidenceItem]) -> bool:
        item = self._setfit_evidence(evidence)
        return bool(
            item
            and item.status == "safe"
            and item.score_delta < 0
            and (self._has_authenticated_sender(evidence) or self._has_trust_signal(evidence))
        )

    def _has_trust_signal(self, evidence: list[EvidenceItem]) -> bool:
        return any(item.source in TRUST_SOURCES | REPUTATION_SOURCES and item.status == "safe" and item.score_delta < 0 for item in evidence)

    def _has_authenticated_sender(self, evidence: list[EvidenceItem]) -> bool:
        return any(item.source in AUTHENTICATION_SOURCES and item.status == "safe" and item.score_delta < 0 for item in evidence)

    def _has_only_redirect_url_signal(self, evidence: list[EvidenceItem]) -> bool:
        positive_local = [
            item
            for item in evidence
            if item.source in LOCAL_URL_SOURCES and item.score_delta > 0 and item.status in {"info", "suspicious", "malicious"}
        ]
        return bool(positive_local) and all(item.title == "網址含外部跳轉目標" for item in positive_local)

    def _strong_reputation_floor_evidence(self, item: EvidenceItem, status: str) -> bool:
        return (
            item.status == status
            and item.source in STRONG_REPUTATION_SOURCES
            and item.score_delta >= STRONG_REPUTATION_FLOOR_MIN_SCORE
        )

    def _has_suspicious_url_signal(self, evidence: list[EvidenceItem]) -> bool:
        return any(
            item.source in LOCAL_URL_SOURCES
            and item.indicator_type in {"url", "domain"}
            and item.score_delta > 0
            and item.status in {"info", "suspicious", "malicious"}
            for item in evidence
        )

    def _confidence_score(
        self,
        indicators: list[ExtractedIndicator],
        evidence: list[EvidenceItem],
        rule_hits: list[ScamRuleHit],
    ) -> int:
        score = 35
        if self._has_setfit_result(evidence):
            score += 20
        else:
            score += min(20, len(rule_hits) * 4)
        score += min(15, len(indicators) * 2)
        if any(item.source in LOCAL_URL_SOURCES for item in evidence):
            score += 8
        if any(item.source in EMAIL_HEADER_SOURCES for item in evidence):
            score += 12
        if any(item.source in EXTERNAL_SOURCES and item.status not in {"skipped", "error"} for item in evidence):
            score += 15
        if any(item.source == LLM_INTENT_SOURCE and item.status not in {"skipped", "error"} for item in evidence):
            score += 10
        if any(item.status in {"malicious", "suspicious"} and item.score_delta > 0 for item in evidence):
            score += 10
        if not rule_hits and not indicators:
            score -= 15
        return max(0, min(100, score))

    def _breakdown_total(self, score_breakdown: ScoreBreakdown) -> int:
        return (
            score_breakdown.message_intent
            + score_breakdown.url_structure
            + score_breakdown.external_reputation
            + score_breakdown.case_similarity
            + score_breakdown.ml_classifier
            + score_breakdown.llm_intent
            + score_breakdown.sensitive_indicators
            + score_breakdown.uncertainty
            + score_breakdown.calibration_adjustment
        )

    def _risk_level(self, score: int):
        if score >= 80:
            return "critical"
        if score >= 60:
            return "high"
        if score >= 30:
            return "medium"
        return "low"

    def _summary(self, risk_level: str, rule_hits: list[ScamRuleHit], evidence: list[EvidenceItem]) -> str:
        if risk_level == "critical":
            return "極高風險：此信件同時命中多個詐騙特徵或強烈的郵件/網址風險證據。"
        if risk_level == "high":
            return "高風險：此信件有明顯釣魚、詐騙或惡意附件特徵，已達自動標記門檻。"
        if risk_level == "medium":
            return "中風險：此信件有可疑元素，系統會記錄但預設不標記 Gmail。"
        setfit_item = self._setfit_evidence(evidence)
        if setfit_item and setfit_item.status == "safe" and setfit_item.score_delta < 0:
            return "低風險：SetFit 語意模型判定為正常通知，目前沒有足以升級的客觀風險證據。"
        if setfit_item and setfit_item.status == "info" and setfit_item.score_delta <= 0:
            return "低風險：SetFit 語意結果未達可疑門檻，其他有限訊號也不足以升級。"
        if rule_hits or any(item.status in {"suspicious", "malicious"} for item in evidence):
            return "低到中風險：目前證據有限，但有部分可疑訊號。"
        return "低風險：目前未命中主要詐騙規則或郵件風險證據。"

    def _recommendations(
        self,
        risk_level: str,
        indicators: list[ExtractedIndicator],
        evidence: list[EvidenceItem],
        rule_hits: list[ScamRuleHit],
    ) -> list[str]:
        recommendations = [
            "不要提供 OTP、驗證碼、密碼或金融卡資訊。",
            "改從官方 App、官方網站或官方客服自行查證。",
        ]
        types = {item.type for item in indicators}
        if "url" in types:
            recommendations.insert(0, "不要直接點擊信件中的連結。")
        if "bank_account" in types or any(hit.category == "payment_scam" for hit in rule_hits):
            recommendations.insert(0, "不要依照信件指示轉帳、匯款或支付保證金。")
        if any(item.source == "attachment_analysis" and item.status == "suspicious" for item in evidence):
            recommendations.insert(0, "不要下載或開啟此信件附件。")
        if any(self._strong_reputation_floor_evidence(item, "malicious") for item in evidence):
            recommendations.insert(0, "此連結或網域已被外部威脅來源標記，請立即停止操作。")
        if risk_level in {"high", "critical"}:
            recommendations.append("若已輸入帳密或轉帳，請立即聯繫銀行與 165 反詐騙專線。")
        return list(dict.fromkeys(recommendations))

    def _uncertainty_notes(self, evidence: list[EvidenceItem]) -> list[str]:
        notes: list[str] = []
        skipped_sources = sorted({item.source for item in evidence if item.source in EXTERNAL_SOURCES and item.status == "skipped"})
        error_sources = sorted({item.source for item in evidence if item.source in EXTERNAL_SOURCES and item.status == "error"})
        if skipped_sources:
            notes.append(f"下列外部來源尚未設定或未查詢：{', '.join(skipped_sources)}。")
        if error_sources:
            notes.append(f"下列外部來源查詢失敗：{', '.join(error_sources)}。")
        if not any(item.source in EXTERNAL_SOURCES and item.status not in {"skipped", "error"} for item in evidence):
            notes.append("未取得外部威脅情資有效結果時，仍需搭配內容與官方管道查證。")
        setfit_item = self._setfit_evidence(evidence)
        if setfit_item and "out_of_distribution" in setfit_item.detail:
            notes.append("此郵件與目前訓練樣本相似度偏低，模型不會提供安全降分，需依客觀證據或人工回饋判斷。")
        elif setfit_item and setfit_item.status == "info" and setfit_item.score_delta == 0:
            notes.append("SetFit 對此郵件信心不足，因此未用模型結果降低風險。")
        return notes
