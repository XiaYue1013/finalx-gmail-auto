from __future__ import annotations

import json
import logging
import threading
import hashlib
from datetime import datetime, timedelta, timezone
from email.utils import parseaddr
from typing import Any

try:
    from pymongo import ASCENDING, DESCENDING, MongoClient
    from pymongo.collection import Collection
except Exception:  # pragma: no cover - exercised only when dependency is absent
    ASCENDING = 1  # type: ignore[assignment]
    DESCENDING = None  # type: ignore[assignment]
    MongoClient = None  # type: ignore[assignment]
    Collection = Any  # type: ignore[misc, assignment]

from app.config import settings
from app.analysis.domain_utils import email_domain, org_domain
from app.models import EvidenceItem, FeedbackRecord, FeedbackRequest, ScanDecision


STATE_DOC_ID = "gmail_state"
logger = logging.getLogger("finalx_gmail.store")


class MongoStateStore:
    """MongoDB-backed state/event store."""

    def __init__(self) -> None:
        if not settings.mongodb_uri:
            raise RuntimeError("MONGODB_URI is required. JSON state/history fallback has been removed.")
        if MongoClient is None:
            raise RuntimeError("MONGODB_URI is configured, but pymongo is not installed.")

        self._lock = threading.Lock()
        self._mongo_client: Any = MongoClient(
            settings.mongodb_uri,
            serverSelectionTimeoutMS=3000,
            connectTimeoutMS=3000,
            appname="finalx-gmail-auto",
        )
        self._mongo_client.admin.command("ping")
        db = self._mongo_client[settings.mongodb_database]
        self._state_collection: Collection = db[settings.mongodb_state_collection]
        self._events_collection: Collection = db[settings.mongodb_events_collection]
        self._reputation_collection: Collection = db[settings.mongodb_reputation_collection]
        self._feedback_collection: Collection = db[settings.mongodb_feedback_collection]
        self._cache_collection: Collection = db[settings.mongodb_threat_cache_collection]
        self._queue_collection: Collection = db[settings.mongodb_threat_queue_collection]
        self._labels_collection: Collection = db[settings.mongodb_labeled_dataset_collection]
        self._ensure_indexes()
        self._ensure_state_doc()

    def load_state(self) -> dict[str, Any]:
        doc = self._state_collection.find_one({"_id": STATE_DOC_ID}) or {}
        doc.pop("_id", None)
        defaults = self._empty_state()
        for key, value in defaults.items():
            doc.setdefault(key, value)
        return doc

    def save_state(self, state: dict[str, Any]) -> None:
        doc = dict(self._empty_state())
        doc.update(state)
        doc["_id"] = STATE_DOC_ID
        self._state_collection.replace_one({"_id": STATE_DOC_ID}, doc, upsert=True)

    def is_processed(self, gmail_id: str) -> bool:
        return self._state_collection.count_documents(
            {"_id": STATE_DOC_ID, "processed_message_ids": gmail_id},
            limit=1,
        ) > 0

    def mark_processed(self, gmail_id: str) -> None:
        with self._lock:
            state = self.load_state()
            processed = list(dict.fromkeys([gmail_id] + list(state.get("processed_message_ids") or [])))
            state["processed_message_ids"] = processed[: settings.max_processed_ids]
            state["last_scan_at"] = self._now()
            self.save_state(state)

    def claim_processed(self, gmail_id: str) -> bool:
        with self._lock:
            state = self.load_state()
            processed_ids = list(state.get("processed_message_ids") or [])
            if gmail_id in set(processed_ids):
                return False
            processed = list(dict.fromkeys([gmail_id] + processed_ids))
            state["processed_message_ids"] = processed[: settings.max_processed_ids]
            state["last_scan_at"] = self._now()
            self.save_state(state)
            return True

    def get_history_id(self) -> str | None:
        value = self.load_state().get("last_history_id")
        return str(value) if value else None

    def set_history_id(self, history_id: str | int | None) -> None:
        if history_id is None:
            return
        self._state_collection.update_one(
            {"_id": STATE_DOC_ID},
            {
                "$set": {
                    "last_history_id": str(history_id),
                    "last_history_update_at": self._now(),
                }
            },
            upsert=True,
        )

    def save_watch(self, *, history_id: str | int | None, expiration_ms: str | int | None, topic_name: str) -> None:
        updates: dict[str, Any] = {
            "watch_topic_name": topic_name,
            "watch_registered_at": self._now(),
        }
        if history_id is not None:
            updates["last_history_id"] = str(history_id)
        if expiration_ms is not None:
            updates["watch_expiration_ms"] = str(expiration_ms)
        self._state_collection.update_one({"_id": STATE_DOC_ID}, {"$set": updates}, upsert=True)

    def record_push(self, *, email_address: str | None, history_id: str | int | None) -> None:
        updates: dict[str, Any] = {"last_push_at": self._now()}
        if email_address:
            updates["last_push_email_address"] = email_address
        if history_id is not None:
            updates["last_push_history_id"] = str(history_id)
        self._state_collection.update_one({"_id": STATE_DOC_ID}, {"$set": updates}, upsert=True)

    def append_event(self, event: ScanDecision) -> None:
        doc = json.loads(event.model_dump_json())
        if doc.get("gmail_id") and doc.get("action"):
            self._events_collection.replace_one(
                {"gmail_id": doc["gmail_id"], "action": doc["action"]},
                doc,
                upsert=True,
            )
        else:
            self._events_collection.insert_one(doc)
        self._record_sender_reputation(doc)

    def list_events(self, limit: int = 50) -> list[dict[str, Any]]:
        cursor = self._events_collection.find({}, {"_id": False}).sort("created_at", DESCENDING).limit(limit)
        return list(cursor)

    def get_event(self, gmail_id: str) -> dict[str, Any] | None:
        return self._events_collection.find_one({"gmail_id": gmail_id}, {"_id": False}, sort=[("created_at", DESCENDING)])

    def record_feedback(self, feedback: FeedbackRequest) -> dict[str, Any]:
        event = self.get_event(feedback.gmail_id) or {}
        sender_domain = self._sender_domain_from_event(event)
        organization = org_domain(sender_domain) if sender_domain else ""
        auto_approved = settings.feedback_auto_approve
        record = FeedbackRecord(
            gmail_id=feedback.gmail_id,
            verdict=feedback.verdict,
            notes=feedback.notes,
            actor=feedback.actor,
            subject=str(event.get("subject") or ""),
            sender=str(event.get("sender") or ""),
            sender_email=str(event.get("sender_email") or ""),
            sender_domain=sender_domain or "",
            org_domain=organization,
            previous_action=str(event.get("action") or ""),
            previous_risk_score=event.get("risk_score"),
            previous_risk_level=event.get("risk_level"),
            model_input_text=str(event.get("model_input_text") or ""),
            review_status="approved" if auto_approved else "pending",
            reviewer="auto" if auto_approved else "",
            reviewed_at=datetime.now(timezone.utc) if auto_approved else None,
        )
        doc = record.model_dump(mode="json")
        self._feedback_collection.insert_one(doc)
        if auto_approved:
            self._apply_feedback_to_reputation(doc)
            self._upsert_labeled_sample(doc)
        doc.pop("_id", None)
        return doc

    def list_feedback(self, limit: int = 50, review_status: str | None = None) -> list[dict[str, Any]]:
        query = {"review_status": review_status} if review_status else {}
        cursor = self._feedback_collection.find(query, {"_id": False}).sort("created_at", DESCENDING).limit(limit)
        return list(cursor)

    def review_feedback(self, feedback_id: str, *, review_status: str, reviewer: str, review_notes: str = "") -> dict[str, Any] | None:
        if review_status not in {"approved", "rejected"}:
            raise ValueError("review_status must be approved or rejected")
        existing = self._feedback_collection.find_one({"feedback_id": feedback_id}, {"_id": False})
        if not existing:
            return None

        now = self._now()
        updates = {
            "review_status": review_status,
            "reviewer": reviewer,
            "review_notes": review_notes,
            "reviewed_at": now,
        }
        self._feedback_collection.update_one({"feedback_id": feedback_id}, {"$set": updates})
        updated = dict(existing)
        updated.update(updates)
        if review_status == "approved" and existing.get("review_status") != "approved":
            self._apply_feedback_to_reputation(updated)
            self._upsert_labeled_sample(updated)
        return updated

    def list_labeled_samples(self, limit: int = 50) -> list[dict[str, Any]]:
        cursor = self._labels_collection.find({}, {"_id": False}).sort("created_at", DESCENDING).limit(limit)
        return list(cursor)

    def list_threat_queue(self, limit: int = 50) -> list[dict[str, Any]]:
        cursor = self._queue_collection.find({}, {"_id": False}).sort("created_at", ASCENDING).limit(limit)
        return list(cursor)

    def get_cached_evidence(self, *, source: str, indicator_type: str, indicator: str) -> EvidenceItem | None:
        if not settings.enable_threat_intel_cache:
            return None
        key = self._cache_key(source, indicator_type, indicator)
        doc = self._cache_collection.find_one({"_id": key}, {"_id": False})
        if not doc:
            return None
        expires_at = self._parse_datetime(doc.get("expires_at"))
        if expires_at and expires_at <= datetime.now(timezone.utc):
            self._cache_collection.delete_one({"_id": key})
            return None
        evidence = doc.get("evidence")
        if not isinstance(evidence, dict):
            return None
        self._cache_collection.update_one(
            {"_id": key},
            {"$inc": {"hit_count": 1}, "$set": {"last_hit_at": self._now()}},
        )
        return EvidenceItem(**evidence)

    def save_cached_evidence(self, item: EvidenceItem) -> None:
        if not settings.enable_threat_intel_cache or item.status in {"error", "skipped"}:
            return
        key = self._cache_key(item.source, str(item.indicator_type), item.indicator)
        now = datetime.now(timezone.utc)
        self._cache_collection.replace_one(
            {"_id": key},
            {
                "_id": key,
                "source": item.source,
                "indicator_type": item.indicator_type,
                "indicator": item.indicator,
                "evidence": item.model_dump(mode="json"),
                "created_at": now.isoformat(),
                "expires_at": (now + timedelta(hours=settings.threat_intel_cache_ttl_hours)).isoformat(),
                "hit_count": 0,
            },
            upsert=True,
        )
        self._enforce_collection_limit(
            self._cache_collection,
            max_entries=settings.threat_intel_cache_max_entries,
            sort_field="created_at",
        )

    def queue_threat_lookup(self, *, source: str, indicator_type: str, indicator: str, reason: str) -> None:
        key = self._cache_key(source, indicator_type, indicator)
        now = self._now()
        self._queue_collection.update_one(
            {"_id": key},
            {
                "$setOnInsert": {
                    "_id": key,
                    "source": source,
                    "indicator_type": indicator_type,
                    "indicator": indicator,
                    "created_at": now,
                    "status": "pending",
                },
                "$set": {
                    "reason": reason[:500],
                    "last_seen_at": now,
                },
                "$inc": {"seen_count": 1},
            },
            upsert=True,
        )
        self._enforce_collection_limit(
            self._queue_collection,
            max_entries=settings.threat_intel_queue_max_entries,
            sort_field="created_at",
        )

    def dashboard_metrics(self) -> dict[str, Any]:
        events = list(self._events_collection.find({}, {"_id": False}))
        feedback = list(self._feedback_collection.find({}, {"_id": False}))
        state = self.load_state()
        action_counts = self._counter(events, "action")
        risk_counts = self._counter(events, "risk_level")
        reason_counts = self._counter(events, "label_reason")
        feedback_counts = self._counter(feedback, "verdict")
        review_counts = self._counter(feedback, "review_status")
        cache_docs = list(self._cache_collection.find({}, {"_id": False, "hit_count": True, "source": True}))
        queue_docs = list(self._queue_collection.find({}, {"_id": False, "source": True, "status": True, "seen_count": True}))
        labels_total = self._labels_collection.count_documents({})
        approved_feedback = [item for item in feedback if item.get("review_status") == "approved"]
        false_positive_count = sum(1 for item in approved_feedback if item.get("verdict") == "false_positive")
        reviewed_count = len(approved_feedback)
        false_positive_rate = round(false_positive_count / reviewed_count, 4) if reviewed_count else 0
        return {
            "state": {
                "processed_message_ids": len(state.get("processed_message_ids") or []),
                "last_history_id": state.get("last_history_id"),
                "last_push_at": state.get("last_push_at"),
                "watch_expiration_ms": state.get("watch_expiration_ms"),
            },
            "events": {
                "total": len(events),
                "actions": action_counts,
                "risk_levels": risk_counts,
                "label_reasons": reason_counts,
                "errors": sum(1 for item in events if item.get("error")),
            },
            "feedback": {
                "total": len(feedback),
                "verdicts": feedback_counts,
                "review_status": review_counts,
                "pending": review_counts.get("pending", 0),
                "approved": review_counts.get("approved", 0),
                "rejected": review_counts.get("rejected", 0),
                "false_positive_count": false_positive_count,
                "reviewed_count": reviewed_count,
                "false_positive_rate": false_positive_rate,
            },
            "cache": {
                "total": len(cache_docs),
                "max_entries": settings.threat_intel_cache_max_entries,
                "hit_count": sum(int(item.get("hit_count") or 0) for item in cache_docs),
                "sources": self._counter(cache_docs, "source"),
            },
            "queue": {
                "total": len(queue_docs),
                "max_entries": settings.threat_intel_queue_max_entries,
                "statuses": self._counter(queue_docs, "status"),
                "sources": self._counter(queue_docs, "source"),
                "seen_count": sum(int(item.get("seen_count") or 0) for item in queue_docs),
            },
            "labels": {
                "total": labels_total,
            },
            "reputation": {
                "total": self._reputation_collection.count_documents({}),
            },
            "trends": {
                "daily": self._daily_trends(events, feedback, days=14),
            },
        }

    def get_sender_reputation(self, sender_domain: str | None) -> dict[str, Any] | None:
        if not sender_domain:
            return None
        domain = sender_domain.lower().strip(".")
        if not domain:
            return None
        organization = org_domain(domain)
        doc = self._reputation_collection.find_one({"_id": organization}, {"_id": False})
        if doc:
            return doc
        return self._derive_sender_reputation_from_events(organization)

    def _ensure_indexes(self) -> None:
        self._events_collection.create_index([("created_at", DESCENDING)])
        self._events_collection.create_index([("gmail_id", DESCENDING)])
        self._events_collection.create_index([("action", DESCENDING)])
        self._reputation_collection.create_index([("org_domain", DESCENDING)])
        self._reputation_collection.create_index([("trust_score", DESCENDING)])
        self._reputation_collection.create_index([("last_seen_at", DESCENDING)])
        self._feedback_collection.create_index([("created_at", DESCENDING)])
        self._feedback_collection.create_index([("gmail_id", DESCENDING)])
        self._feedback_collection.create_index([("org_domain", DESCENDING)])
        self._feedback_collection.create_index([("verdict", DESCENDING)])
        self._create_index_safely(self._feedback_collection, [("feedback_id", DESCENDING)], unique=True)
        self._feedback_collection.create_index([("review_status", DESCENDING)])
        self._cache_collection.create_index([("expires_at", DESCENDING)])
        self._cache_collection.create_index([("source", DESCENDING)])
        self._queue_collection.create_index([("created_at", ASCENDING)])
        self._queue_collection.create_index([("status", DESCENDING)])
        self._queue_collection.create_index([("source", DESCENDING)])
        self._labels_collection.create_index([("created_at", DESCENDING)])
        self._labels_collection.create_index([("gmail_id", DESCENDING)])
        self._labels_collection.create_index([("label", DESCENDING)])
        self._create_index_safely(self._labels_collection, [("feedback_id", DESCENDING)], unique=True)

    def _create_index_safely(self, collection: Collection, keys: list[tuple[str, Any]], **kwargs: Any) -> None:
        try:
            collection.create_index(keys, **kwargs)
        except Exception as exc:
            logger.warning("skipped MongoDB index creation keys=%s options=%s error=%s", keys, kwargs, exc)

    def _ensure_state_doc(self) -> None:
        doc = self._empty_state()
        doc["_id"] = STATE_DOC_ID
        self._state_collection.update_one({"_id": STATE_DOC_ID}, {"$setOnInsert": doc}, upsert=True)

    def _empty_state(self) -> dict[str, Any]:
        return {
            "processed_message_ids": [],
            "last_scan_at": None,
            "last_history_id": None,
            "watch_expiration_ms": None,
            "watch_topic_name": None,
            "last_push_at": None,
            "watch_registered_at": None,
            "last_push_email_address": None,
            "last_push_history_id": None,
            "last_history_update_at": None,
        }

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _record_sender_reputation(self, doc: dict[str, Any]) -> None:
        try:
            if doc.get("action") == "error":
                return
            sender_domain = self._sender_domain_from_event(doc)
            if not sender_domain:
                return
            organization = org_domain(sender_domain)
            existing = self._reputation_collection.find_one({"_id": organization}) or {
                "_id": organization,
                "org_domain": organization,
                "sender_domains": [],
                "total_count": 0,
                "safe_count": 0,
                "warned_count": 0,
                "high_count": 0,
                "auth_pass_count": 0,
                "manual_safe_count": 0,
                "manual_threat_count": 0,
                "feedback_count": 0,
            }

            sender_domains = set(existing.get("sender_domains") or [])
            sender_domains.add(sender_domain)

            total_count = int(existing.get("total_count") or 0) + 1
            safe_count = int(existing.get("safe_count") or 0)
            warned_count = int(existing.get("warned_count") or 0)
            high_count = int(existing.get("high_count") or 0)
            auth_pass_count = int(existing.get("auth_pass_count") or 0)
            manual_safe_count = int(existing.get("manual_safe_count") or 0)
            manual_threat_count = int(existing.get("manual_threat_count") or 0)
            feedback_count = int(existing.get("feedback_count") or 0)

            if self._event_has_authentication_pass(doc):
                auth_pass_count += 1
            if self._event_is_high_risk(doc):
                high_count += 1
            elif doc.get("action") == "warned" or doc.get("risk_level") == "medium":
                warned_count += 1
            elif self._event_is_safe_low_risk(doc):
                safe_count += 1

            trust_score = self._trust_score(
                safe_count=safe_count,
                warned_count=warned_count,
                high_count=high_count,
                auth_pass_count=auth_pass_count,
                manual_safe_count=manual_safe_count,
                manual_threat_count=manual_threat_count,
            )
            updates = {
                "_id": organization,
                "org_domain": organization,
                "sender_domains": sorted(sender_domains),
                "total_count": total_count,
                "safe_count": safe_count,
                "warned_count": warned_count,
                "high_count": high_count,
                "auth_pass_count": auth_pass_count,
                "manual_safe_count": manual_safe_count,
                "manual_threat_count": manual_threat_count,
                "feedback_count": feedback_count,
                "trust_score": trust_score,
                "last_action": doc.get("action"),
                "last_risk_score": doc.get("risk_score"),
                "last_risk_level": doc.get("risk_level"),
                "last_seen_at": doc.get("created_at") or self._now(),
                "updated_at": self._now(),
                "source": "observed_scan_events",
            }
            self._reputation_collection.replace_one({"_id": organization}, updates, upsert=True)
        except Exception:
            logger.exception("failed to update sender reputation")

    def _derive_sender_reputation_from_events(self, organization: str) -> dict[str, Any] | None:
        cursor = self._events_collection.find(
            {"action": {"$in": ["marked", "warned", "skipped"]}},
            {
                "_id": False,
                "sender": True,
                "sender_email": True,
                "action": True,
                "risk_score": True,
                "risk_level": True,
                "evidence": True,
                "created_at": True,
            },
        ).sort("created_at", DESCENDING).limit(500)
        docs = []
        sender_domains: set[str] = set()
        for doc in cursor:
            sender_domain = self._sender_domain_from_event(doc)
            if not sender_domain or org_domain(sender_domain) != organization:
                continue
            sender_domains.add(sender_domain)
            docs.append(doc)
        if not docs:
            return None

        safe_count = sum(1 for doc in docs if self._event_is_safe_low_risk(doc))
        warned_count = sum(1 for doc in docs if doc.get("action") == "warned" or doc.get("risk_level") == "medium")
        high_count = sum(1 for doc in docs if self._event_is_high_risk(doc))
        auth_pass_count = sum(1 for doc in docs if self._event_has_authentication_pass(doc))
        trust_score = self._trust_score(
            safe_count=safe_count,
            warned_count=warned_count,
            high_count=high_count,
            auth_pass_count=auth_pass_count,
            manual_safe_count=0,
            manual_threat_count=0,
        )
        return {
            "org_domain": organization,
            "sender_domains": sorted(sender_domains),
            "total_count": len(docs),
            "safe_count": safe_count,
            "warned_count": warned_count,
            "high_count": high_count,
            "auth_pass_count": auth_pass_count,
            "trust_score": trust_score,
            "source": "derived_scan_events",
        }

    def _sender_domain_from_event(self, doc: dict[str, Any]) -> str | None:
        sender_email = str(doc.get("sender_email") or "")
        sender_domain = email_domain(sender_email)
        if sender_domain:
            return sender_domain
        _, parsed_email = parseaddr(str(doc.get("sender") or ""))
        return email_domain(parsed_email)

    def _event_is_high_risk(self, doc: dict[str, Any]) -> bool:
        return bool(doc.get("high_risk")) or doc.get("action") == "marked" or int(doc.get("risk_score") or 0) >= settings.high_risk_threshold

    def _event_is_safe_low_risk(self, doc: dict[str, Any]) -> bool:
        return doc.get("action") == "skipped" and int(doc.get("risk_score") or 0) < settings.medium_risk_threshold

    def _event_has_authentication_pass(self, doc: dict[str, Any]) -> bool:
        return any(
            item.get("source") == "email_authentication_analysis"
            and item.get("status") == "safe"
            and int(item.get("score_delta") or 0) < 0
            for item in doc.get("evidence") or []
            if isinstance(item, dict)
        )

    def _trust_score(
        self,
        *,
        safe_count: int,
        warned_count: int,
        high_count: int,
        auth_pass_count: int,
        manual_safe_count: int = 0,
        manual_threat_count: int = 0,
    ) -> int:
        if manual_threat_count > 0:
            return 0
        effective_high_count = max(0, high_count - manual_safe_count)
        if effective_high_count > 0:
            return 0
        if auth_pass_count < 2 and manual_safe_count == 0:
            return 0
        if manual_safe_count > 0:
            return min(18, 6 + manual_safe_count * 5 + safe_count * 2 + min(4, auth_pass_count))
        if safe_count >= 3 and warned_count == 0:
            return min(12, 4 + safe_count * 2)
        if safe_count >= 2 and warned_count == 0:
            return 6
        if safe_count >= 3 and warned_count == 1:
            return 4
        return 0

    def _apply_feedback_to_reputation(self, feedback_doc: dict[str, Any]) -> None:
        organization = str(feedback_doc.get("org_domain") or "")
        sender_domain = str(feedback_doc.get("sender_domain") or "")
        if not organization:
            return
        existing = self._reputation_collection.find_one({"_id": organization}) or {
            "_id": organization,
            "org_domain": organization,
            "sender_domains": [],
            "total_count": 0,
            "safe_count": 0,
            "warned_count": 0,
            "high_count": 0,
            "auth_pass_count": 0,
            "manual_safe_count": 0,
            "manual_threat_count": 0,
            "feedback_count": 0,
        }
        sender_domains = set(existing.get("sender_domains") or [])
        if sender_domain:
            sender_domains.add(sender_domain)
        verdict = str(feedback_doc.get("verdict") or "")
        manual_safe_count = int(existing.get("manual_safe_count") or 0)
        manual_threat_count = int(existing.get("manual_threat_count") or 0)
        if verdict in {"false_positive", "safe"}:
            manual_safe_count += 1
        elif verdict in {"confirmed_threat", "false_negative", "threat"}:
            manual_threat_count += 1

        safe_count = int(existing.get("safe_count") or 0)
        warned_count = int(existing.get("warned_count") or 0)
        high_count = int(existing.get("high_count") or 0)
        auth_pass_count = int(existing.get("auth_pass_count") or 0)
        trust_score = self._trust_score(
            safe_count=safe_count,
            warned_count=warned_count,
            high_count=high_count,
            auth_pass_count=auth_pass_count,
            manual_safe_count=manual_safe_count,
            manual_threat_count=manual_threat_count,
        )
        updates = dict(existing)
        updates.update(
            {
                "_id": organization,
                "org_domain": organization,
                "sender_domains": sorted(sender_domains),
                "manual_safe_count": manual_safe_count,
                "manual_threat_count": manual_threat_count,
                "feedback_count": int(existing.get("feedback_count") or 0) + 1,
                "trust_score": trust_score,
                "last_feedback_verdict": verdict,
                "last_feedback_at": feedback_doc.get("created_at") or self._now(),
                "updated_at": self._now(),
                "source": "feedback_and_observed_scan_events",
            }
        )
        self._reputation_collection.replace_one({"_id": organization}, updates, upsert=True)

    def _upsert_labeled_sample(self, feedback_doc: dict[str, Any]) -> None:
        label = self._feedback_label(str(feedback_doc.get("verdict") or ""))
        if not label:
            return
        feedback_id = str(feedback_doc.get("feedback_id") or "")
        if not feedback_id:
            return
        now = self._now()
        doc = {
            "feedback_id": feedback_id,
            "gmail_id": feedback_doc.get("gmail_id"),
            "label": label,
            "verdict": feedback_doc.get("verdict"),
            "subject": feedback_doc.get("subject"),
            "sender": feedback_doc.get("sender"),
            "sender_email": feedback_doc.get("sender_email"),
            "sender_domain": feedback_doc.get("sender_domain"),
            "org_domain": feedback_doc.get("org_domain"),
            "previous_action": feedback_doc.get("previous_action"),
            "previous_risk_score": feedback_doc.get("previous_risk_score"),
            "previous_risk_level": feedback_doc.get("previous_risk_level"),
            "model_input_text": feedback_doc.get("model_input_text"),
            "notes": feedback_doc.get("notes"),
            "actor": feedback_doc.get("actor"),
            "reviewer": feedback_doc.get("reviewer"),
            "created_at": feedback_doc.get("created_at") or now,
            "approved_at": feedback_doc.get("reviewed_at") or now,
            "source": "approved_feedback",
        }
        self._labels_collection.replace_one({"feedback_id": feedback_id}, doc, upsert=True)

    def _feedback_label(self, verdict: str) -> str | None:
        if verdict in {"false_positive", "safe"}:
            return "safe"
        if verdict in {"confirmed_threat", "false_negative", "threat"}:
            return "threat"
        return None

    def _daily_trends(self, events: list[dict[str, Any]], feedback: list[dict[str, Any]], *, days: int) -> list[dict[str, Any]]:
        today = datetime.now(timezone.utc).date()
        buckets: dict[str, dict[str, Any]] = {}
        for offset in range(days - 1, -1, -1):
            date_key = (today - timedelta(days=offset)).isoformat()
            buckets[date_key] = {
                "date": date_key,
                "total": 0,
                "marked": 0,
                "warned": 0,
                "skipped": 0,
                "error": 0,
                "false_positive": 0,
                "confirmed_threat": 0,
                "false_negative": 0,
            }

        for event in events:
            date_key = self._date_key(event.get("created_at"))
            if date_key not in buckets:
                continue
            buckets[date_key]["total"] += 1
            action = str(event.get("action") or "")
            if action in buckets[date_key]:
                buckets[date_key][action] += 1

        for item in feedback:
            date_key = self._date_key(item.get("created_at"))
            if date_key not in buckets:
                continue
            verdict = str(item.get("verdict") or "")
            if verdict in buckets[date_key]:
                buckets[date_key][verdict] += 1

        return list(buckets.values())

    def _date_key(self, value: Any) -> str | None:
        parsed = self._parse_datetime(value)
        return parsed.date().isoformat() if parsed else None

    def _enforce_collection_limit(self, collection: Collection, *, max_entries: int, sort_field: str) -> None:
        try:
            overflow = collection.count_documents({}) - max_entries
            if overflow <= 0:
                return
            ids = [
                item["_id"]
                for item in collection.find({}, {"_id": True}).sort(sort_field, ASCENDING).limit(overflow)
                if item.get("_id") is not None
            ]
            if ids:
                collection.delete_many({"_id": {"$in": ids}})
        except Exception:
            logger.exception("failed to enforce MongoDB collection limit")

    def _cache_key(self, source: str, indicator_type: str, indicator: str) -> str:
        raw = f"{source}\0{indicator_type}\0{indicator}".encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    def _parse_datetime(self, value: Any) -> datetime | None:
        if isinstance(value, datetime):
            if value.tzinfo is None:
                return value.replace(tzinfo=timezone.utc)
            return value
        if isinstance(value, str):
            try:
                parsed = datetime.fromisoformat(value)
                if parsed.tzinfo is None:
                    return parsed.replace(tzinfo=timezone.utc)
                return parsed
            except ValueError:
                return None
        return None

    def _counter(self, docs: list[dict[str, Any]], field: str) -> dict[str, int]:
        counts: dict[str, int] = {}
        for doc in docs:
            value = str(doc.get(field) or "unknown")
            counts[value] = counts.get(value, 0) + 1
        return dict(sorted(counts.items()))
