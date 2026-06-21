from __future__ import annotations

import json
import logging
import re
import threading
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import numpy as np

from app.config import settings
from app.models import EvidenceItem, GmailMessage


logger = logging.getLogger("finalx_gmail.setfit_classifier")

SETFIT_SOURCE = "setfit_email_classifier"
MODEL_METADATA_FILENAME = "finalx_metadata.json"
REFERENCE_EMBEDDINGS_FILENAME = "reference_embeddings.npz"
DEFAULT_LABELS = ["legitimate", "suspicious", "threat"]

URL_RE = re.compile(r"https?://[^\s<>'\"，。！？、)）\]]+", re.IGNORECASE)
LONG_TOKEN_RE = re.compile(r"\b[A-Za-z0-9_-]{32,}\b")
LONG_NUMBER_RE = re.compile(r"(?<!\d)\d{8,}(?!\d)")
AUTH_RESULT_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.IGNORECASE)
MISTRAL_MODEL_TYPES = {"mistral", "mistral3", "voxtral", "ministral", "pixtral"}


class _FalseMistralRegexWarningFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return "with an incorrect regex pattern:" not in record.getMessage()


@contextmanager
def suppress_false_mistral_regex_warning(model_path: str | Path):
    """Suppress a Transformers 4.57.x false positive for local, non-Mistral large vocab tokenizers."""

    config_path = Path(model_path) / "config.json"
    try:
        model_type = str(json.loads(config_path.read_text(encoding="utf-8")).get("model_type") or "")
    except (OSError, ValueError, TypeError):
        model_type = ""
    if not model_type or model_type in MISTRAL_MODEL_TYPES:
        yield
        return

    tokenizer_logger = logging.getLogger("transformers.tokenization_utils_base")
    warning_filter = _FalseMistralRegexWarningFilter()
    tokenizer_logger.addFilter(warning_filter)
    try:
        yield
    finally:
        tokenizer_logger.removeFilter(warning_filter)


def build_model_input(message: GmailMessage, *, max_chars: int | None = None) -> str:
    """Build a stable, privacy-reduced text representation for ML and LLM classification."""

    max_chars = max_chars or settings.setfit_max_text_chars
    if (
        message.gmail_id == "manual"
        and message.subject == "manual text"
        and message.sender == "manual"
        and re.search(r"(?im)^\s*(sender|subject|authentication|body)\s*:", message.body_text or "")
    ):
        return _sanitize_text(message.body_text)[:max_chars]
    auth_results = _authentication_summary(message)
    attachments = ", ".join(message.attachment_filenames) or "none"
    body = _sanitize_text(message.body_text or message.snippet)
    sender = message.sender_email or message.sender
    parts = [
        f"Sender: {sender}",
        f"Subject: {message.subject}",
        f"Authentication: {auth_results}",
        f"Attachments: {attachments}",
        f"Body: {body}",
    ]
    return "\n".join(parts)[:max_chars]


def _authentication_summary(message: GmailMessage) -> str:
    auth_text = f"{message.authentication_results}\n{message.received_spf}"
    results: dict[str, str] = {}
    for check, status in AUTH_RESULT_RE.findall(auth_text):
        results[check.lower()] = status.lower()
    if not results:
        return "unknown"
    return " ".join(f"{name}={results[name]}" for name in ("spf", "dkim", "dmarc") if name in results)


def _sanitize_text(value: str) -> str:
    value = URL_RE.sub(_sanitize_url_match, value or "")
    value = LONG_TOKEN_RE.sub("<TOKEN>", value)
    value = LONG_NUMBER_RE.sub("<LONG_NUMBER>", value)
    return " ".join(value.split())


def _sanitize_url_match(match: re.Match[str]) -> str:
    raw_url = match.group(0)
    try:
        parsed = urlsplit(raw_url)
        path = parsed.path[:160]
        return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))
    except Exception:
        return raw_url.split("?", 1)[0][:240]


class SetFitEmailClassifierService:
    _lock = threading.Lock()
    _model = None
    _model_path: Path | None = None
    _model_mtime: float | None = None
    _metadata: dict = {}
    _reference_embeddings = None

    def collect(self, model_input: str) -> list[EvidenceItem]:
        if not settings.enable_setfit_classifier:
            return []
        model = self._load_model()
        if model is None:
            return [
                EvidenceItem(
                    source=SETFIT_SOURCE,
                    indicator_type="unknown",
                    indicator="message",
                    status="skipped",
                    score_delta=0,
                    title="SetFit 郵件分類器尚未載入",
                    detail=f"找不到可用模型：{settings.setfit_model_dir}。請先執行訓練指令。",
                )
            ]

        try:
            embedding = model.encode(
                [model_input],
                show_progress_bar=False,
            )
            probabilities = model.model_head.predict_proba(embedding)[0]
            labels = self._labels(model, len(probabilities))
            scores = {label: float(probabilities[index]) for index, label in enumerate(labels)}
            nearest_similarity = self._nearest_similarity(embedding[0])
            return [self._to_evidence(scores, nearest_similarity=nearest_similarity)]
        except Exception as exc:
            logger.exception("SetFit email classification failed")
            return [
                EvidenceItem(
                    source=SETFIT_SOURCE,
                    indicator_type="unknown",
                    indicator="message",
                    status="error",
                    score_delta=0,
                    title="SetFit 郵件分類失敗",
                    detail=str(exc)[:500],
                )
            ]

    def _load_model(self):
        model_path = Path(settings.setfit_model_dir)
        config_path = model_path / "config.json"
        if not config_path.exists():
            return None
        tracked_paths = [
            config_path,
            model_path / "model_head.pkl",
            model_path / MODEL_METADATA_FILENAME,
            model_path / REFERENCE_EMBEDDINGS_FILENAME,
        ]
        model_mtime = max(path.stat().st_mtime for path in tracked_paths if path.exists())
        if (
            self.__class__._model is not None
            and self.__class__._model_path == model_path
            and self.__class__._model_mtime == model_mtime
        ):
            return self.__class__._model

        with self.__class__._lock:
            if (
                self.__class__._model is not None
                and self.__class__._model_path == model_path
                and self.__class__._model_mtime == model_mtime
            ):
                return self.__class__._model
            try:
                from setfit import SetFitModel

                with suppress_false_mistral_regex_warning(model_path):
                    model = SetFitModel.from_pretrained(
                        str(model_path),
                        local_files_only=True,
                        device=settings.setfit_device,
                    )
                metadata_path = model_path / MODEL_METADATA_FILENAME
                metadata = {}
                if metadata_path.exists():
                    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
                reference_embeddings = None
                reference_path = model_path / REFERENCE_EMBEDDINGS_FILENAME
                if reference_path.exists():
                    with np.load(reference_path) as data:
                        reference_embeddings = np.asarray(data["embeddings"], dtype=np.float32)
                self.__class__._model = model
                self.__class__._model_path = model_path
                self.__class__._model_mtime = model_mtime
                self.__class__._metadata = metadata
                self.__class__._reference_embeddings = reference_embeddings
                logger.info("loaded SetFit email classifier from %s", model_path)
                return model
            except Exception:
                logger.exception("failed to load SetFit email classifier from %s", model_path)
                return None

    def _labels(self, model, probability_count: int) -> list[str]:
        labels = list(getattr(model, "labels", None) or self.__class__._metadata.get("labels") or DEFAULT_LABELS)
        if len(labels) != probability_count:
            return DEFAULT_LABELS[:probability_count]
        return labels

    def _nearest_similarity(self, embedding) -> float | None:
        references = self.__class__._reference_embeddings
        if references is None or not len(references):
            return None
        query = np.asarray(embedding, dtype=np.float32)
        query_norm = float(np.linalg.norm(query))
        if query_norm == 0:
            return None
        normalized_query = query / query_norm
        return float(np.max(references @ normalized_query))

    def _to_evidence(
        self,
        scores: dict[str, float],
        *,
        nearest_similarity: float | None = None,
    ) -> EvidenceItem:
        legitimate = scores.get("legitimate", 0.0)
        suspicious = scores.get("suspicious", 0.0)
        threat = scores.get("threat", 0.0)
        predicted_label = max(scores, key=scores.get) if scores else "unknown"
        confidence = scores.get(predicted_label, 0.0)
        in_distribution = nearest_similarity is None or nearest_similarity >= settings.setfit_ood_min_similarity

        if threat >= settings.setfit_threat_critical_probability:
            score_delta = 70
            status = "suspicious"
        elif threat >= settings.setfit_threat_high_probability:
            score_delta = 65
            status = "suspicious"
        elif threat >= settings.setfit_threat_probability:
            score_delta = 60
            status = "suspicious"
        elif suspicious >= settings.setfit_suspicious_probability:
            score_delta = 30
            status = "suspicious"
        elif suspicious >= 0.30 and confidence < 0.55:
            score_delta = 10
            status = "info"
        elif in_distribution and legitimate >= settings.setfit_legitimate_high_probability:
            score_delta = -30
            status = "safe"
        elif in_distribution and legitimate >= settings.setfit_legitimate_probability:
            score_delta = -20
            status = "safe"
        else:
            score_delta = 0
            status = "info"

        similarity_detail = (
            f", nearest_similarity={nearest_similarity:.3f}, distribution={'known' if in_distribution else 'out_of_distribution'}"
            if nearest_similarity is not None
            else ", nearest_similarity=unavailable"
        )
        detail = (
            f"predicted={predicted_label}, confidence={confidence:.3f}, "
            f"legitimate={legitimate:.3f}, suspicious={suspicious:.3f}, threat={threat:.3f}"
            f"{similarity_detail}。"
        )
        return EvidenceItem(
            source=SETFIT_SOURCE,
            indicator_type="unknown",
            indicator="message",
            status=status,
            score_delta=score_delta,
            title="SetFit 多語郵件語意分類",
            detail=detail,
        )
