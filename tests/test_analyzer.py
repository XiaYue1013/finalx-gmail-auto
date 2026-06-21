from app.analysis.risk_analyzer import EINVOICE_NOTICE_SUPPRESSED_RULE_IDS, RiskAnalyzer
from app.analysis.risk_scoring_service import RiskScoringService
from app.config import settings
from app.models import EvidenceItem, ExtractedIndicator, GmailMessage, ScamRuleHit
from app.analysis.setfit_classifier import SETFIT_SOURCE
from app.analysis.setfit_classifier import SetFitEmailClassifierService, build_model_input


def disable_api_features():
    settings.enable_external_threat_lookups = False
    settings.enable_llm_intent_classifier = False
    settings.enable_setfit_classifier = False


class FakeSafeSetFitClassifier:
    def collect(self, model_input: str):
        return [
            EvidenceItem(
                source=SETFIT_SOURCE,
                indicator_type="unknown",
                indicator="message",
                status="safe",
                score_delta=-30,
                title="SetFit 多語郵件語意分類",
                detail="predicted=legitimate, confidence=0.95。",
            )
        ]


class FakeThreatSetFitClassifier:
    def collect(self, model_input: str):
        return [
            EvidenceItem(
                source=SETFIT_SOURCE,
                indicator_type="unknown",
                indicator="message",
                status="suspicious",
                score_delta=60,
                title="SetFit 多語郵件語意分類",
                detail=(
                    "predicted=threat, confidence=0.70, legitimate=0.20, suspicious=0.10, "
                    "threat=0.70, nearest_similarity=0.80, distribution=known。"
                ),
            )
        ]


def test_manual_structured_text_is_not_wrapped_twice_for_setfit():
    message = GmailMessage(
        gmail_id="manual",
        subject="manual text",
        sender="manual",
        body_text=(
            "Sender: security@example.test\n"
            "Subject: Verify account\n"
            "Authentication: spf=fail\n"
            "Body: Enter your password."
        ),
    )

    model_input = build_model_input(message)

    assert model_input.startswith("Sender: security@example.test")
    assert "Subject: manual text" not in model_input


def test_high_risk_phishing_email_is_marked():
    disable_api_features()
    text = """
    Google Security final notice: your account will be suspended within 24 hours.
    Please verify your account and enter your verification code at
    https://g00gle-security.top/login/verify
    """

    decision = RiskAnalyzer().analyze_text(text)

    assert decision.high_risk is True
    assert decision.risk_score >= 60
    assert decision.score_breakdown.message_intent > 0
    assert decision.score_breakdown.url_structure > 0
    assert decision.label_reason in {"釣魚驗證", "可疑網址", "詐騙話術", "寄件異常"}
    assert decision.reasons


def test_low_risk_normal_email_is_skipped():
    disable_api_features()
    text = "明天下午三點開會，附件是上週討論事項，沒有登入連結或付款要求。"

    decision = RiskAnalyzer().analyze_text(text)

    assert decision.high_risk is False
    assert decision.action == "skipped"
    assert decision.risk_level == "low"


class FakeThreatFeedbackStore:
    def get_sender_reputation(self, sender_domain: str):
        return {
            "org_domain": sender_domain,
            "safe_count": 0,
            "auth_pass_count": 0,
            "manual_safe_count": 0,
            "manual_threat_count": 1,
            "trust_score": 0,
        }


def test_manual_threat_feedback_adds_sender_reputation_evidence():
    disable_api_features()
    message = GmailMessage(
        gmail_id="manual-threat",
        subject="一般通知",
        sender="notice@example-mail.test",
        sender_email="notice@example-mail.test",
        body_text="這是一封一般通知，請查看最新消息。",
    )

    decision = RiskAnalyzer(reputation_store=FakeThreatFeedbackStore()).analyze_email(message)

    assert any(
        item.source == "sender_reputation"
        and item.status == "suspicious"
        and item.score_delta > 0
        for item in decision.evidence
    )
    assert decision.risk_score > 0


def test_trusted_einvoice_notice_is_not_marked_high_risk():
    disable_api_features()
    message = GmailMessage(
        gmail_id="trusted-einvoice",
        subject="財政部電子發票整合服務平台 – 115年03-04月期雲端發票中獎獎金匯款成功通知",
        sender="einvoice@einvoice.nat.gov.tw",
        sender_email="einvoice@einvoice.nat.gov.tw",
        body_text="財政部電子發票整合服務平台通知您雲端發票中獎獎金匯款成功。請勿將本通知轉寄他人，刑事警察局提醒防詐。",
        authentication_results="mx.google.com; spf=pass smtp.mailfrom=einvoice.nat.gov.tw; dkim=pass header.d=einvoice.nat.gov.tw; dmarc=pass",
    )

    decision = RiskAnalyzer().analyze_email(message)

    assert decision.high_risk is False
    assert decision.risk_score < settings.high_risk_threshold
    assert "payment_request" not in {hit.rule_id for hit in decision.rule_hits}
    assert "law_enforcement_impersonation" not in {hit.rule_id for hit in decision.rule_hits}
    assert any(item.source == "email_trust_analysis" and item.score_delta < 0 for item in decision.evidence)


def test_tradevan_invoice_notice_with_app_link_stays_low_risk():
    disable_api_features()
    message = GmailMessage(
        gmail_id="tradevan-invoice",
        subject="電子發票開立作業通知",
        sender='"麥當勞雲端發票" <b2ceci@ecimail2.tradevan.com.tw>',
        sender_email="b2ceci@ecimail2.tradevan.com.tw",
        body_text=(
            "電子發票已開立，請查看發票明細。"
            "https://dg95h.app.goo.gl/?link=https%3A%2F%2Fwww.mcdonalds.com%2Ftw%2Fzh-tw%2Fdigital%2Fmcdapp.html"
        ),
        authentication_results=(
            "mx.google.com; spf=pass smtp.mailfrom=ecimail2.tradevan.com.tw; "
            "dkim=pass header.d=tradevan.com.tw"
        ),
    )

    decision = RiskAnalyzer().analyze_email(message)

    assert decision.high_risk is False
    assert decision.risk_level == "low"
    assert decision.risk_score < settings.medium_risk_threshold
    assert "dangerous_attachment_lure" not in {hit.rule_id for hit in decision.rule_hits}
    assert any(item.source == "email_authentication_analysis" and item.score_delta < 0 for item in decision.evidence)
    assert not any(item.source == "email_trust_analysis" for item in decision.evidence)


def test_verified_invoice_notice_without_attachment_does_not_match_attachment_lure():
    disable_api_features()
    message = GmailMessage(
        gmail_id="cht-invoice",
        subject="中華電信115年06月電子發票通知函 [發票號碼：AM64905242]",
        sender='"中華電信電子發票" <invoice@cht.com.tw>',
        sender_email="invoice@cht.com.tw",
        body_text="本信為電子發票通知，請至會員中心查看發票資訊。提醒您勿依陌生指示轉帳。",
        authentication_results="mx.google.com; spf=pass smtp.mailfrom=cht.com.tw; dkim=pass header.d=cht.com.tw",
    )

    decision = RiskAnalyzer().analyze_email(message)

    assert decision.high_risk is False
    assert decision.risk_level == "low"
    assert not {hit.rule_id for hit in decision.rule_hits} & EINVOICE_NOTICE_SUPPRESSED_RULE_IDS


def test_subscription_billing_phishing_reaches_high_risk_without_llm():
    disable_api_features()
    text = """
    Netflix Account Update
    We were unable to process your monthly membership payment.
    To continue enjoying Netflix, please update your credit card details immediately.
    Verify your details at https://netflix-payment-update.example.test/login.
    Failure to update your payment information will result in immediate termination of your subscription.
    """

    decision = RiskAnalyzer().analyze_text(text)

    assert decision.high_risk is True
    assert decision.risk_score >= settings.high_risk_threshold
    assert "subscription_billing_phishing" in {hit.rule_id for hit in decision.rule_hits}


def test_business_email_compromise_wire_request_reaches_high_risk_without_llm():
    disable_api_features()
    text = """
    From: ceo-office@ceo-corporate-example.test
    Subject: URGENT REQUEST: Immediate wire transfer needed for project acquisition
    I am currently attending a confidential board meeting and cannot take any calls.
    Please prepare a wire transfer of $25,000 USD to the escrow bank account details attached in the file.
    Speed is critical.
    """

    decision = RiskAnalyzer().analyze_text(text)

    assert decision.high_risk is True
    assert decision.risk_score >= settings.high_risk_threshold
    assert "business_email_compromise_wire" in {hit.rule_id for hit in decision.rule_hits}


def test_fullwidth_punctuation_is_not_unicode_obfuscation_signal():
    evidence = RiskAnalyzer()._content_obfuscation_evidence("退款通知：您好，這是一封一般中文通知。")

    assert evidence == []


def test_delivery_fee_deadline_email_is_high_risk():
    disable_api_features()
    text = """
    【物流通知】您的包裹配送失敗，請重新確認收件資訊（追蹤碼：TW948573）
    由於您提供的收件地址不完整，今日無法順利投遞。
    請於 24 小時內更新地址並支付手續費新台幣 15 元：
    https://www.google.com/search?q=http://www.tw-logistics-update-fee.com/pay
    """

    decision = RiskAnalyzer().analyze_text(text)

    assert decision.high_risk is True
    assert decision.risk_score >= settings.high_risk_threshold
    assert "delivery_scam" in {hit.category for hit in decision.rule_hits}
    assert any(indicator.value == "http://www.tw-logistics-update-fee.com/pay" for indicator in decision.indicators)


def test_llm_evidence_does_not_force_medium_delivery_notice_to_high_risk():
    report = RiskScoringService().score(
        indicators=[
            ExtractedIndicator(type="url", value="http://shorturl.at/xyz789", normalized="http://shorturl.at/xyz789", label="網址"),
            ExtractedIndicator(type="domain", value="shorturl.at", normalized="shorturl.at", label="網域"),
        ],
        evidence=[
            EvidenceItem(
                source="local_url_analysis",
                indicator_type="url",
                indicator="http://shorturl.at/xyz789",
                status="suspicious",
                score_delta=8,
                title="網址未使用 HTTPS",
                detail="登入、付款或帳戶驗證頁面若未使用 HTTPS，風險較高。",
            ),
            EvidenceItem(
                source="local_url_analysis",
                indicator_type="domain",
                indicator="shorturl.at",
                status="suspicious",
                score_delta=12,
                title="偵測到短網址服務",
                detail="短網址會隱藏真實目的地，詐騙信件常用來降低使用者警覺。",
            ),
            EvidenceItem(
                source="llm_intent_classifier",
                indicator_type="unknown",
                indicator="message",
                status="suspicious",
                score_delta=15,
                title="LLM 結構化意圖萃取",
                detail="LLM 認為有可疑配送通知意圖，但沒有付款或憑證竊取的強證據。",
            ),
        ],
        rule_hits=[
            ScamRuleHit(
                rule_id="parcel_delivery",
                name="假包裹或物流通知",
                category="delivery_scam",
                severity="medium",
                score_delta=16,
                matched_text="包裹配送失敗通知，請確認您的收件地址",
                explanation="假包裹通知常誘導使用者點擊付款或登入連結。",
            )
        ],
    )

    assert report.risk_score < settings.high_risk_threshold
    assert report.risk_level == "medium"


def test_low_vote_domain_reputation_does_not_force_high_risk():
    report = RiskScoringService().score(
        indicators=[
            ExtractedIndicator(type="url", value="https://line.me/R/ti/p/example", normalized="https://line.me/R/ti/p/example", label="網址"),
            ExtractedIndicator(type="domain", value="line.me", normalized="line.me", label="網域"),
        ],
        evidence=[
            EvidenceItem(
                source="virustotal_domain",
                indicator_type="domain",
                indicator="line.me",
                status="malicious",
                score_delta=7,
                title="VirusTotal domain reputation",
                detail="malicious=1, suspicious=0, harmless=59。",
            )
        ],
        rule_hits=[],
    )

    assert report.risk_score < settings.high_risk_threshold
    assert report.risk_level == "low"


class FakeReputationStore:
    def get_sender_reputation(self, sender_domain: str):
        return {
            "org_domain": "example.com",
            "safe_count": 4,
            "auth_pass_count": 4,
            "trust_score": 12,
        }


def test_sender_reputation_adds_history_based_trust_signal():
    disable_api_features()
    message = GmailMessage(
        gmail_id="repeated-safe-sender",
        subject="Monthly account digest",
        sender="alerts@example.com",
        sender_email="alerts@example.com",
        body_text="Your monthly digest is ready: https://tracker.example/click?url=https%3A%2F%2Fpromo.example.com%2Fdigest",
        authentication_results="mx.google.com; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com",
    )

    decision = RiskAnalyzer(reputation_store=FakeReputationStore()).analyze_email(message)

    assert decision.high_risk is False
    assert decision.risk_level == "low"
    assert any(item.source == "sender_reputation" and item.score_delta < 0 for item in decision.evidence)


def test_sender_reputation_does_not_override_phishing_rules():
    disable_api_features()
    message = GmailMessage(
        gmail_id="trusted-sender-compromised",
        subject="帳戶登入異常，請立即完成身分驗證避免帳戶凍結",
        sender="alerts@example.com",
        sender_email="alerts@example.com",
        body_text="您的帳戶偵測到異常登入，請立即驗證帳戶，否則將限制使用：https://secure-verify-update-account.top/login",
        authentication_results="mx.google.com; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com",
    )

    decision = RiskAnalyzer(reputation_store=FakeReputationStore()).analyze_email(message)

    assert decision.high_risk is True
    assert decision.risk_score >= settings.high_risk_threshold
    assert any(item.source == "sender_reputation" and item.score_delta < 0 for item in decision.evidence)


def test_setfit_safe_classification_suppresses_false_positive_bank_notice():
    settings.enable_external_threat_lookups = False
    settings.enable_llm_intent_classifier = False
    settings.enable_setfit_classifier = True
    message = GmailMessage(
        gmail_id="taishin-cardless-withdrawal",
        subject="台新銀行無卡提款設定通知",
        sender="webmaster@taishinbank.com.tw",
        sender_email="webmaster@taishinbank.com.tw",
        body_text=(
            "您的無卡提款設定通知。無卡提款帳號：00288****83381。"
            "若非本人操作，請開啟官方 App 或聯絡客服。"
            "https://www.taishinbank.com.tw/TSB/personal/digital/Digital-Platform/mobile-banking/nocard-withdrawal/"
        ),
        authentication_results=(
            "mx.google.com; spf=pass smtp.mailfrom=taishinbank.com.tw; "
            "dkim=pass header.d=taishinbank.com.tw; dmarc=pass header.from=taishinbank.com.tw"
        ),
    )

    decision = RiskAnalyzer(setfit_classifier=FakeSafeSetFitClassifier()).analyze_email(message)

    assert decision.risk_level == "low"
    assert decision.high_risk is False
    assert decision.score_breakdown.ml_classifier == -30
    assert decision.score_breakdown.message_intent == 0
    assert decision.label_reason == "低風險"
    assert decision.summary.startswith("低風險：SetFit")
    assert "crypto_casino_withdrawal" not in {hit.rule_id for hit in decision.rule_hits}


def test_setfit_safe_classification_keeps_legitimate_security_notice_low():
    settings.enable_external_threat_lookups = False
    settings.enable_llm_intent_classifier = False
    settings.enable_setfit_classifier = True
    message = GmailMessage(
        gmail_id="steam-new-sign-in",
        subject="New sign in to Steam",
        sender="noreply@steampowered.com",
        sender_email="noreply@steampowered.com",
        body_text=(
            "Steam Guard authenticator confirmation. If the details look familiar, safely ignore this email. "
            "If not, visit https://help.steampowered.com/en/wizard/HelpWithLogin"
        ),
        authentication_results=(
            "mx.google.com; spf=pass smtp.mailfrom=steampowered.com; "
            "dkim=pass header.d=steampowered.com; dmarc=pass header.from=steampowered.com"
        ),
    )

    decision = RiskAnalyzer(setfit_classifier=FakeSafeSetFitClassifier()).analyze_email(message)

    assert decision.risk_level == "low"
    assert decision.high_risk is False
    assert decision.score_breakdown.message_intent == 0


def test_setfit_threat_classification_reaches_high_without_custom_rule_score():
    settings.enable_external_threat_lookups = False
    settings.enable_llm_intent_classifier = False
    settings.enable_setfit_classifier = True
    message = GmailMessage(
        gmail_id="semantic-threat",
        subject="A private request",
        sender="outside@example.test",
        sender_email="outside@example.test",
        body_text="Please follow the confidential instructions in this message.",
        authentication_results="spf=pass dkim=pass dmarc=pass",
    )

    decision = RiskAnalyzer(setfit_classifier=FakeThreatSetFitClassifier()).analyze_email(message)

    assert decision.high_risk is True
    assert decision.risk_level == "high"
    assert decision.risk_score >= settings.high_risk_threshold
    assert decision.score_breakdown.ml_classifier == 60
    assert decision.score_breakdown.message_intent == 0
    assert decision.label_reason == "語意威脅"


def test_setfit_out_of_distribution_legitimate_prediction_does_not_lower_risk():
    classifier = SetFitEmailClassifierService()

    evidence = classifier._to_evidence(
        {"legitimate": 0.95, "suspicious": 0.03, "threat": 0.02},
        nearest_similarity=settings.setfit_ood_min_similarity - 0.01,
    )

    assert evidence.status == "info"
    assert evidence.score_delta == 0
    assert "distribution=out_of_distribution" in evidence.detail


def test_setfit_probability_calibration_separates_borderline_notice_from_suspicious_mail():
    classifier = SetFitEmailClassifierService()

    borderline = classifier._to_evidence(
        {"legitimate": 0.354, "suspicious": 0.553, "threat": 0.093},
        nearest_similarity=0.89,
    )
    suspicious = classifier._to_evidence(
        {"legitimate": 0.25, "suspicious": 0.61, "threat": 0.14},
        nearest_similarity=0.80,
    )

    assert borderline.status == "info"
    assert borderline.score_delta == 0
    assert suspicious.status == "suspicious"
    assert suspicious.score_delta == 30


def test_delivery_address_update_uses_model_and_objective_evidence_without_rule_score():
    report = RiskScoringService().score(
        indicators=[
            ExtractedIndicator(
                type="url",
                value="http://shorturl.at/xyz789",
                normalized="http://shorturl.at/xyz789",
                label="網址",
            ),
            ExtractedIndicator(type="domain", value="shorturl.at", normalized="shorturl.at", label="網域"),
        ],
        evidence=[
            EvidenceItem(
                source="local_url_analysis",
                indicator_type="url",
                indicator="http://shorturl.at/xyz789",
                status="suspicious",
                score_delta=8,
                title="網址未使用 HTTPS",
                detail="HTTP",
            ),
            EvidenceItem(
                source="local_url_analysis",
                indicator_type="domain",
                indicator="shorturl.at",
                status="suspicious",
                score_delta=12,
                title="偵測到短網址服務",
                detail="shortener",
            ),
            EvidenceItem(
                source="serpapi",
                indicator_type="domain",
                indicator="shorturl.at",
                status="suspicious",
                score_delta=12,
                title="搜尋結果佐證",
                detail="generic search result",
            ),
            EvidenceItem(
                source=SETFIT_SOURCE,
                indicator_type="unknown",
                indicator="message",
                status="info",
                score_delta=0,
                title="SetFit 多語郵件語意分類",
                detail="predicted=suspicious",
            ),
            EvidenceItem(
                source="llm_intent_classifier",
                indicator_type="unknown",
                indicator="message",
                status="suspicious",
                score_delta=15,
                title="LLM 結構化意圖萃取",
                detail="delivery address update",
            ),
        ],
        rule_hits=[
            ScamRuleHit(
                rule_id="parcel_delivery",
                name="假包裹或物流通知",
                category="delivery_scam",
                severity="medium",
                score_delta=16,
                matched_text="包裹配送失敗",
                explanation="delivery",
            )
        ],
    )

    assert report.score_breakdown.message_intent == 0
    assert report.risk_score == 51
    assert report.risk_level == "medium"
