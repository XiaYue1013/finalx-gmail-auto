from __future__ import annotations

import logging
import time
from datetime import datetime, timezone

from app.analysis.risk_analyzer import RiskAnalyzer
from app.config import settings
from app.gmail.client import GmailClient
from app.gmail.message_parser import parse_gmail_message
from app.integrations.discord import DiscordNotifier
from app.models import ScanBatchResult, ScanDecision
from app.store import MongoStateStore


logger = logging.getLogger("finalx_gmail.worker")


class GmailRiskWorker:
    def __init__(
        self,
        gmail: GmailClient | None = None,
        analyzer: RiskAnalyzer | None = None,
        store: MongoStateStore | None = None,
    ) -> None:
        self.gmail = gmail or GmailClient()
        self.store = store or MongoStateStore()
        self.analyzer = analyzer or RiskAnalyzer(reputation_store=self.store)
        self.discord = DiscordNotifier()
        self._high_risk_label_id: str | None = None
        self._warning_label_id: str | None = None

    def scan_once(self, dry_run: bool = False, include_processed: bool = False) -> ScanBatchResult:
        batch = ScanBatchResult(dry_run=dry_run)

        messages = self.gmail.list_candidates(settings.gmail_query, settings.gmail_batch_size, settings.gmail_scan_pages)
        for item in messages:
            message_id = str(item.get("id") or "")
            if not message_id:
                continue
            self._process_message_id(message_id, batch=batch, dry_run=dry_run, include_processed=include_processed)

        batch.finished_at = datetime.now(timezone.utc)
        return batch

    def register_watch(self) -> dict:
        topic_name = settings.gmail_watch_topic_name
        if not topic_name:
            raise ValueError("GMAIL_WATCH_TOPIC_NAME is required before registering Gmail push notifications.")
        label_ids = self._watch_label_ids()
        response = self.gmail.watch(topic_name, label_ids, settings.gmail_watch_label_filter_behavior)
        self.store.save_watch(
            history_id=response.get("historyId"),
            expiration_ms=response.get("expiration"),
            topic_name=topic_name,
        )
        return response

    def stop_watch(self) -> None:
        self.gmail.stop_watch()

    def process_history_notification(
        self,
        *,
        notification_history_id: str | int | None,
        email_address: str | None = None,
        dry_run: bool = False,
    ) -> ScanBatchResult:
        self.store.record_push(email_address=email_address, history_id=notification_history_id)
        batch = ScanBatchResult(dry_run=dry_run)
        start_history_id = self.store.get_history_id()

        if not start_history_id:
            self.store.set_history_id(notification_history_id)
            batch.finished_at = datetime.now(timezone.utc)
            return batch

        try:
            history, returned_history_id = self.gmail.list_history(
                start_history_id=start_history_id,
                label_id="INBOX" if "INBOX" in self._watch_label_ids() else None,
                history_types=["messageAdded"],
            )
            for message_id in self._message_ids_from_history(history):
                self._process_message_id(message_id, batch=batch, dry_run=dry_run, include_processed=False)
            self.store.set_history_id(returned_history_id or notification_history_id)
        except Exception as exc:
            if self._is_history_not_found(exc):
                logger.warning("Gmail historyId %s is out of date; running full sync fallback.", start_history_id)
                fallback = self.scan_once(dry_run=dry_run, include_processed=False)
                self.store.set_history_id(notification_history_id)
                return fallback
            logger.exception("failed to process Gmail history from %s", start_history_id)
            batch.errors += 1
            event = ScanDecision(
                high_risk=False,
                action="error",
                risk_score=0,
                risk_level="low",
                confidence_score=0,
                summary="處理 Gmail History API 推播時發生錯誤。",
                label_reason="錯誤",
                error=str(exc),
            )
            self.store.append_event(event)
            batch.events.append(event)

        batch.finished_at = datetime.now(timezone.utc)
        return batch

    def poll_forever(self) -> None:
        logger.info("Gmail worker started; query=%s, interval=%ss", settings.gmail_query, settings.gmail_poll_seconds)
        while True:
            try:
                result = self.scan_once(dry_run=False)
                logger.info(
                    "scan finished: scanned=%s marked=%s warned=%s skipped=%s already_processed=%s errors=%s",
                    result.scanned,
                    result.marked,
                    result.warned,
                    result.skipped,
                    result.already_processed,
                    result.errors,
                )
            except Exception:
                logger.exception("scan loop failed")
            time.sleep(settings.gmail_poll_seconds)

    def _process_message_id(
        self,
        message_id: str,
        *,
        batch: ScanBatchResult,
        dry_run: bool,
        include_processed: bool,
    ) -> None:
        if self.store.is_processed(message_id) and not include_processed:
            batch.already_processed += 1
            return

        try:
            raw = self.gmail.get_message(message_id)
            message = parse_gmail_message(raw)
            if "INBOX" not in message.label_ids and not include_processed:
                batch.skipped += 1
                if not dry_run:
                    self.store.mark_processed(message_id)
                return
            claimed = False
            if not dry_run and not include_processed:
                claimed = self.store.claim_processed(message_id)
                if not claimed:
                    batch.already_processed += 1
                    return

            decision = self.analyzer.analyze_email(message)
            batch.scanned += 1

            if decision.high_risk:
                if dry_run:
                    decision.action = "dry_run_mark"
                else:
                    self.gmail.add_labels(message_id, self._label_ids_for_decision(decision))
                batch.marked += 1
                self.store.append_event(decision)
                batch.events.append(decision)
                if not dry_run:
                    self._notify_discord(decision)
            elif self._should_warn(decision):
                if dry_run:
                    decision.action = "dry_run_mark"
                else:
                    decision.action = "warned"
                    self.gmail.add_labels(message_id, self._warning_label_ids_for_decision(decision))
                batch.warned += 1
                self.store.append_event(decision)
                batch.events.append(decision)
                if not dry_run:
                    self._notify_discord(decision)
            else:
                batch.skipped += 1
                if settings.save_safe_events:
                    self.store.append_event(decision)
                    batch.events.append(decision)

            if not dry_run and (include_processed or not claimed):
                self.store.mark_processed(message_id)
        except Exception as exc:
            if self._is_message_not_found(exc):
                logger.info("gmail message %s no longer exists; skipping.", message_id)
                batch.skipped += 1
                if not dry_run:
                    self.store.mark_processed(message_id)
                return
            logger.exception("failed to scan gmail message %s", message_id)
            batch.errors += 1
            event = ScanDecision(
                gmail_id=message_id,
                high_risk=False,
                action="error",
                risk_score=0,
                risk_level="low",
                confidence_score=0,
                summary="掃描信件時發生錯誤。",
                label_reason="錯誤",
                error=str(exc),
            )
            self.store.append_event(event)
            batch.events.append(event)
            if not dry_run and include_processed:
                self.store.mark_processed(message_id)

    def _label_ids_for_decision(self, decision: ScanDecision) -> list[str]:
        self._high_risk_label_id = self._high_risk_label_id or self.gmail.ensure_label(settings.gmail_high_risk_label)
        label_ids = [self._high_risk_label_id]
        if settings.mark_starred:
            label_ids.append("STARRED")
        if settings.mark_important:
            label_ids.append("IMPORTANT")
        if settings.enable_reason_labels and decision.label_reason:
            label_ids.append(self.gmail.ensure_label(f"{settings.gmail_reason_label_prefix} - {decision.label_reason}"))
        return label_ids

    def _warning_label_ids_for_decision(self, decision: ScanDecision) -> list[str]:
        self._warning_label_id = self._warning_label_id or self.gmail.ensure_label(settings.gmail_warning_label)
        label_ids = [self._warning_label_id]
        if settings.enable_reason_labels and decision.label_reason:
            label_ids.append(self.gmail.ensure_label(f"{settings.gmail_reason_label_prefix} - {decision.label_reason}"))
        return label_ids

    def _should_warn(self, decision: ScanDecision) -> bool:
        return (
            settings.label_medium_risk
            and decision.risk_score >= settings.medium_risk_threshold
            and decision.risk_score < settings.high_risk_threshold
            and decision.action != "error"
        )

    def _watch_label_ids(self) -> list[str]:
        return [item.strip() for item in settings.gmail_watch_label_ids.split(",") if item.strip()]

    def _message_ids_from_history(self, history: list[dict]) -> list[str]:
        ids: list[str] = []
        for item in history:
            for added in item.get("messagesAdded") or []:
                message = added.get("message") if isinstance(added, dict) else None
                message_id = str((message or {}).get("id") or "")
                if message_id:
                    ids.append(message_id)
        return list(dict.fromkeys(ids))

    def _is_history_not_found(self, exc: Exception) -> bool:
        response = getattr(exc, "resp", None)
        status = getattr(response, "status", None)
        if status == 404:
            return True
        return "404" in str(exc) and "history" in str(exc).lower()

    def _is_message_not_found(self, exc: Exception) -> bool:
        response = getattr(exc, "resp", None)
        status = getattr(response, "status", None)
        if status == 404:
            return True
        error_text = str(exc).lower()
        return "404" in error_text and "requested entity was not found" in error_text

    def _notify_discord(self, decision: ScanDecision) -> None:
        try:
            self.discord.notify_decision(decision)
        except Exception:
            logger.exception("failed to send Discord notification")
