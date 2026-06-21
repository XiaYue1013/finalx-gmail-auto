from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "FINALX Gmail Auto Risk Marker"
    api_prefix: str = "/api"
    api_token: str | None = None

    data_dir: Path = Path("data")
    credentials_file: Path = Path("credentials.json")
    token_file: Path = Path("token.json")
    mongodb_uri: str | None = None
    mongodb_database: str = "finalx_gmail_auto"
    mongodb_state_collection: str = "gmail_state"
    mongodb_events_collection: str = "scan_events"
    mongodb_reputation_collection: str = "sender_reputation"
    mongodb_feedback_collection: str = "feedback"
    mongodb_threat_cache_collection: str = "threat_cache"
    mongodb_threat_queue_collection: str = "threat_queue"
    mongodb_labeled_dataset_collection: str = "labeled_dataset"

    gmail_query: str = "in:inbox newer_than:1d -in:drafts"
    gmail_batch_size: int = Field(default=20, ge=1, le=100)
    gmail_scan_pages: int = Field(default=5, ge=1, le=20)
    gmail_poll_seconds: int = Field(default=15, ge=15)
    gmail_history_max_results: int = Field(default=100, ge=1, le=500)
    gmail_history_max_pages: int = Field(default=10, ge=1, le=50)
    gmail_watch_topic_name: str | None = None
    gmail_watch_label_ids: str = "INBOX"
    gmail_watch_label_filter_behavior: str = "INCLUDE"
    gmail_auto_register_watch: bool = False
    gmail_push_token: str | None = None

    high_risk_threshold: int = Field(default=60, ge=1, le=100)
    medium_risk_threshold: int = Field(default=30, ge=1, le=100)
    gmail_high_risk_label: str = "FINALX 高風險"
    gmail_warning_label: str = "FINALX 中風險"
    gmail_reason_label_prefix: str = "FINALX 理由"
    label_medium_risk: bool = True
    enable_reason_labels: bool = True
    mark_starred: bool = False
    mark_important: bool = False
    save_safe_events: bool = False
    enable_background_worker: bool = False
    max_body_chars: int = Field(default=10000, ge=1000, le=50000)
    max_processed_ids: int = Field(default=5000, ge=100, le=50000)

    google_safe_browsing_api_key: str | None = None
    virustotal_api_key: str | None = None
    urlhaus_auth_key: str | None = None
    urlscan_api_key: str | None = None
    serpapi_api_key: str | None = None
    google_fact_check_api_key: str | None = None
    enable_external_threat_lookups: bool = True
    enable_urlhaus_lookup: bool = True
    enable_threat_intel_cache: bool = True
    threat_intel_cache_ttl_hours: int = Field(default=168, ge=1, le=8760)
    threat_intel_cache_max_entries: int = Field(default=2000, ge=100, le=100000)
    threat_intel_queue_max_entries: int = Field(default=1000, ge=100, le=100000)
    threat_lookup_force_ipv4: bool = True
    external_lookup_timeout_seconds: float = Field(default=12.0, gt=0)

    gemini_api_key: str | None = None
    gemini_vision_base_url: str = "https://generativelanguage.googleapis.com/v1beta"
    gemini_vision_timeout_seconds: float = Field(default=15.0, gt=0)
    enable_llm_intent_classifier: bool = False
    gemini_intent_model: str = "gemini-2.5-flash"
    llm_intent_min_score: int = Field(default=30, ge=0, le=100)
    llm_intent_max_score: int = Field(default=75, ge=0, le=100)
    llm_intent_max_text_chars: int = Field(default=2500, ge=200, le=12000)

    enable_setfit_classifier: bool = True
    setfit_model_dir: Path = Path("data/models/setfit-email-risk")
    setfit_base_model: str = "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"
    setfit_device: str = "cpu"
    setfit_max_text_chars: int = Field(default=3500, ge=500, le=12000)
    setfit_training_epochs: int = Field(default=1, ge=1, le=10)
    setfit_training_iterations: int = Field(default=2, ge=1, le=50)
    setfit_threat_probability: float = Field(default=0.52, ge=0, le=1)
    setfit_threat_high_probability: float = Field(default=0.72, ge=0, le=1)
    setfit_threat_critical_probability: float = Field(default=0.85, ge=0, le=1)
    setfit_suspicious_probability: float = Field(default=0.60, ge=0, le=1)
    setfit_legitimate_probability: float = Field(default=0.65, ge=0, le=1)
    setfit_legitimate_high_probability: float = Field(default=0.80, ge=0, le=1)
    setfit_ood_min_similarity: float = Field(default=0.35, ge=-1, le=1)

    dashboard_recent_events_limit: int = Field(default=25, ge=5, le=200)
    feedback_auto_approve: bool = False
    discord_webhook_url: str | None = None
    discord_notify_min_risk_level: str = "high"
    discord_timeout_seconds: float = Field(default=6.0, gt=0)

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    def ensure_directories(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.ensure_directories()
    return settings


settings = get_settings()
