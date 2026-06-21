from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, Field


RiskLevel = Literal["low", "medium", "high", "critical"]
IndicatorType = Literal["url", "domain", "email", "phone", "bank_account", "crypto_address", "line_id", "unknown"]
EvidenceStatus = Literal["malicious", "suspicious", "safe", "info", "skipped", "error", "unknown"]
FeedbackVerdict = Literal["false_positive", "confirmed_threat", "false_negative", "safe", "threat"]
FeedbackReviewStatus = Literal["pending", "approved", "rejected"]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ExtractedIndicator(BaseModel):
    type: IndicatorType
    value: str
    normalized: str | None = None
    label: str
    confidence: float = Field(default=1.0, ge=0, le=1)


class EvidenceItem(BaseModel):
    source: str
    indicator_type: IndicatorType | str
    indicator: str
    status: EvidenceStatus
    score_delta: int = 0
    title: str
    detail: str
    reference_url: str | None = None
    raw_ref: str | None = None


class ScamRuleHit(BaseModel):
    rule_id: str
    name: str
    category: str
    severity: RiskLevel
    score_delta: int
    matched_text: str
    explanation: str


class ScoreBreakdown(BaseModel):
    message_intent: int = Field(default=0, ge=0, le=100)
    url_structure: int = Field(default=0, ge=0, le=100)
    external_reputation: int = Field(default=0, ge=0, le=100)
    case_similarity: int = Field(default=0, ge=-100, le=100)
    ml_classifier: int = Field(default=0, ge=-100, le=100)
    llm_intent: int = Field(default=0, ge=-100, le=100)
    sensitive_indicators: int = Field(default=0, ge=0, le=100)
    uncertainty: int = Field(default=0, ge=0, le=100)
    calibration_adjustment: int = Field(default=0, ge=-100, le=100)


class RiskReport(BaseModel):
    risk_score: int = Field(..., ge=0, le=100)
    risk_level: RiskLevel
    score_breakdown: ScoreBreakdown = Field(default_factory=ScoreBreakdown)
    confidence_score: int = Field(default=0, ge=0, le=100)
    summary: str
    recommendations: list[str] = Field(default_factory=list)
    uncertainty_notes: list[str] = Field(default_factory=list)


class GmailMessage(BaseModel):
    gmail_id: str
    thread_id: str | None = None
    label_ids: list[str] = Field(default_factory=list)
    subject: str = ""
    sender: str = ""
    sender_email: str = ""
    reply_to: str = ""
    to: str = ""
    date: str = ""
    snippet: str = ""
    body_text: str = ""
    authentication_results: str = ""
    received_spf: str = ""
    attachment_filenames: list[str] = Field(default_factory=list)
    internal_date_ms: int | None = None

    def combined_text(self, max_body_chars: int = 10000) -> str:
        body = self.body_text[:max_body_chars]
        attachments = ", ".join(self.attachment_filenames)
        return "\n".join(
            part
            for part in (
                f"寄件者: {self.sender}",
                f"寄件者信箱: {self.sender_email}",
                f"Reply-To: {self.reply_to}" if self.reply_to else "",
                f"收件者: {self.to}" if self.to else "",
                f"主旨: {self.subject}",
                f"附件: {attachments}" if attachments else "",
                f"內容: {body or self.snippet}",
            )
            if part.strip()
        )


class ScanDecision(BaseModel):
    gmail_id: str | None = None
    subject: str = ""
    sender: str = ""
    sender_email: str = ""
    high_risk: bool
    action: Literal["marked", "warned", "skipped", "dry_run_mark", "error"]
    risk_score: int
    risk_level: RiskLevel
    score_breakdown: ScoreBreakdown = Field(default_factory=ScoreBreakdown)
    confidence_score: int
    summary: str
    uncertainty_notes: list[str] = Field(default_factory=list)
    label_reason: str
    reasons: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    indicators: list[ExtractedIndicator] = Field(default_factory=list)
    evidence: list[EvidenceItem] = Field(default_factory=list)
    rule_hits: list[ScamRuleHit] = Field(default_factory=list)
    model_input_text: str = ""
    created_at: datetime = Field(default_factory=utc_now)
    error: str | None = None


class ScanBatchResult(BaseModel):
    scanned: int = 0
    marked: int = 0
    warned: int = 0
    skipped: int = 0
    already_processed: int = 0
    errors: int = 0
    dry_run: bool = False
    events: list[ScanDecision] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=utc_now)
    finished_at: datetime | None = None


class FeedbackRequest(BaseModel):
    gmail_id: str = Field(..., min_length=1, max_length=256)
    verdict: FeedbackVerdict
    notes: str = Field(default="", max_length=2000)
    actor: str = Field(default="dashboard", max_length=120)


class FeedbackReviewRequest(BaseModel):
    review_status: Literal["approved", "rejected"]
    reviewer: str = Field(default="dashboard", max_length=120)
    review_notes: str = Field(default="", max_length=2000)


class FeedbackRecord(FeedbackRequest):
    feedback_id: str = Field(default_factory=lambda: uuid4().hex)
    subject: str = ""
    sender: str = ""
    sender_email: str = ""
    sender_domain: str = ""
    org_domain: str = ""
    previous_action: str = ""
    previous_risk_score: int | None = None
    previous_risk_level: RiskLevel | None = None
    model_input_text: str = ""
    review_status: FeedbackReviewStatus = "pending"
    reviewer: str = ""
    review_notes: str = ""
    reviewed_at: datetime | None = None
    created_at: datetime = Field(default_factory=utc_now)
