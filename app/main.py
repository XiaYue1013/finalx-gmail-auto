from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from app.analysis.risk_analyzer import RiskAnalyzer
from app.config import settings
from app.dashboard import DASHBOARD_HTML
from app.gmail.push import GmailPushDecodeError, decode_pubsub_push
from app.gmail.worker import GmailRiskWorker
from app.models import FeedbackRequest, FeedbackReviewRequest
from app.store import MongoStateStore


logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logger = logging.getLogger("finalx_gmail.api")


class AnalyzeTextRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=50000)


def require_api_token(
    token: str | None = Query(default=None),
    x_finalx_api_token: str | None = Header(default=None),
) -> None:
    if not settings.api_token:
        return
    supplied_token = x_finalx_api_token or token
    if supplied_token != settings.api_token:
        raise HTTPException(status_code=401, detail="Invalid FINALX API token.")


async def _background_worker_loop() -> None:
    try:
        worker = GmailRiskWorker()
    except Exception:
        logger.exception("background worker cannot start")
        return

    while True:
        try:
            await asyncio.to_thread(worker.scan_once, False)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("background scan failed")
        await asyncio.sleep(settings.gmail_poll_seconds)


def _register_watch_if_configured() -> None:
    if not settings.gmail_auto_register_watch or not settings.gmail_watch_topic_name:
        return
    try:
        response = GmailRiskWorker().register_watch()
        logger.info(
            "Gmail watch registered: historyId=%s expiration=%s topic=%s",
            response.get("historyId"),
            response.get("expiration"),
            settings.gmail_watch_topic_name,
        )
    except Exception:
        logger.exception("failed to register Gmail watch on startup")


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings.ensure_directories()
    task: asyncio.Task | None = None
    await asyncio.to_thread(_register_watch_if_configured)
    if settings.enable_background_worker:
        task = asyncio.create_task(_background_worker_loop())
    try:
        yield
    finally:
        if task:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass


app = FastAPI(title=settings.app_name, lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:8008", "http://127.0.0.1:8008"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def root() -> dict[str, str]:
    return {
        "name": settings.app_name,
        "docs": "/docs",
        "status": f"{settings.api_prefix}/status",
        "events": f"{settings.api_prefix}/events",
        "scan_now": f"{settings.api_prefix}/scan-now",
        "gmail_push": f"{settings.api_prefix}/gmail/push",
        "dashboard": "/dashboard",
    }


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard() -> str:
    return DASHBOARD_HTML


@app.get(f"{settings.api_prefix}/status", dependencies=[Depends(require_api_token)])
async def status() -> dict:
    store = MongoStateStore()
    state = store.load_state()
    return {
        "app": settings.app_name,
        "gmail_query": settings.gmail_query,
        "high_risk_threshold": settings.high_risk_threshold,
        "high_risk_label": settings.gmail_high_risk_label,
        "background_worker": settings.enable_background_worker,
        "storage": {
            "mongodb_configured": bool(settings.mongodb_uri),
            "mongodb_database": settings.mongodb_database if settings.mongodb_uri else None,
            "state_collection": settings.mongodb_state_collection if settings.mongodb_uri else None,
            "events_collection": settings.mongodb_events_collection if settings.mongodb_uri else None,
            "reputation_collection": settings.mongodb_reputation_collection if settings.mongodb_uri else None,
            "feedback_collection": settings.mongodb_feedback_collection if settings.mongodb_uri else None,
            "threat_cache_collection": settings.mongodb_threat_cache_collection if settings.mongodb_uri else None,
            "threat_queue_collection": settings.mongodb_threat_queue_collection if settings.mongodb_uri else None,
            "labeled_dataset_collection": settings.mongodb_labeled_dataset_collection if settings.mongodb_uri else None,
        },
        "gmail_push": {
            "topic_name_configured": bool(settings.gmail_watch_topic_name),
            "watch_label_ids": settings.gmail_watch_label_ids,
            "auto_register_watch": settings.gmail_auto_register_watch,
            "push_token_required": bool(settings.gmail_push_token),
            "api_token_required": bool(settings.api_token),
        },
        "external_api_sources": {
            "enabled": settings.enable_external_threat_lookups,
            "google_safe_browsing": bool(settings.google_safe_browsing_api_key),
            "urlhaus": bool(settings.urlhaus_auth_key) and settings.enable_urlhaus_lookup,
            "virustotal": bool(settings.virustotal_api_key),
            "urlscan": bool(settings.urlscan_api_key),
            "serpapi": bool(settings.serpapi_api_key),
            "google_fact_check": bool(settings.google_fact_check_api_key),
            "llm_intent_classifier": settings.enable_llm_intent_classifier and bool(settings.gemini_api_key),
            "setfit_classifier": {
                "enabled": settings.enable_setfit_classifier,
                "model_dir": str(settings.setfit_model_dir),
                "model_ready": (settings.setfit_model_dir / "config.json").exists(),
                "base_model": settings.setfit_base_model,
            },
        },
        "state": state,
    }


@app.get(f"{settings.api_prefix}/events", dependencies=[Depends(require_api_token)])
async def events(limit: int = Query(default=50, ge=1, le=500)) -> dict:
    return {"items": MongoStateStore().list_events(limit=limit)}


@app.get(f"{settings.api_prefix}/dashboard/metrics", dependencies=[Depends(require_api_token)])
async def dashboard_metrics() -> dict:
    return MongoStateStore().dashboard_metrics()


@app.get(f"{settings.api_prefix}/feedback", dependencies=[Depends(require_api_token)])
async def feedback_items(
    limit: int = Query(default=50, ge=1, le=500),
    review_status: str | None = Query(default=None, pattern="^(pending|approved|rejected)$"),
) -> dict:
    return {"items": MongoStateStore().list_feedback(limit=limit, review_status=review_status)}


@app.post(f"{settings.api_prefix}/feedback", dependencies=[Depends(require_api_token)])
async def record_feedback(payload: FeedbackRequest) -> dict:
    return {"ok": True, "item": MongoStateStore().record_feedback(payload)}


@app.post(f"{settings.api_prefix}/feedback/{{feedback_id}}/review", dependencies=[Depends(require_api_token)])
async def review_feedback(feedback_id: str, payload: FeedbackReviewRequest) -> dict:
    try:
        item = MongoStateStore().review_feedback(
            feedback_id,
            review_status=payload.review_status,
            reviewer=payload.reviewer,
            review_notes=payload.review_notes,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if item is None:
        raise HTTPException(status_code=404, detail="Feedback not found.")
    return {"ok": True, "item": item}


@app.get(f"{settings.api_prefix}/labeled-dataset", dependencies=[Depends(require_api_token)])
async def labeled_dataset(limit: int = Query(default=50, ge=1, le=500)) -> dict:
    return {"items": MongoStateStore().list_labeled_samples(limit=limit)}


@app.get(f"{settings.api_prefix}/threat-queue", dependencies=[Depends(require_api_token)])
async def threat_queue(limit: int = Query(default=50, ge=1, le=500)) -> dict:
    return {"items": MongoStateStore().list_threat_queue(limit=limit)}


@app.post(f"{settings.api_prefix}/analyze-text")
async def analyze_text(payload: AnalyzeTextRequest) -> dict:
    decision = RiskAnalyzer().analyze_text(payload.text)
    return decision.model_dump(mode="json")


@app.post(f"{settings.api_prefix}/scan-now", dependencies=[Depends(require_api_token)])
async def scan_now(dry_run: bool = False, include_processed: bool = False) -> dict:
    try:
        result = await asyncio.to_thread(GmailRiskWorker().scan_once, dry_run, include_processed)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return result.model_dump(mode="json")


@app.post(f"{settings.api_prefix}/gmail/watch", dependencies=[Depends(require_api_token)])
async def register_gmail_watch() -> dict:
    try:
        response = await asyncio.to_thread(GmailRiskWorker().register_watch)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return {"ok": True, "watch": response}


@app.post(f"{settings.api_prefix}/gmail/push")
async def gmail_push(
    payload: dict,
    background_tasks: BackgroundTasks,
    token: str | None = Query(default=None),
    x_finalx_push_token: str | None = Header(default=None),
) -> dict:
    if settings.gmail_push_token:
        supplied_token = x_finalx_push_token or token
        if supplied_token != settings.gmail_push_token:
            raise HTTPException(status_code=401, detail="Invalid Gmail push token.")

    try:
        notification = decode_pubsub_push(payload)
    except GmailPushDecodeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    background_tasks.add_task(_process_gmail_push_notification, notification)
    return {"ok": True}


def _process_gmail_push_notification(notification: dict[str, str]) -> None:
    result = GmailRiskWorker().process_history_notification(
        notification_history_id=notification.get("historyId"),
        email_address=notification.get("emailAddress"),
        dry_run=False,
    )
    logger.info(
        "gmail push processed: email=%s historyId=%s scanned=%s marked=%s warned=%s skipped=%s already_processed=%s errors=%s",
        notification.get("emailAddress"),
        notification.get("historyId"),
        result.scanned,
        result.marked,
        result.warned,
        result.skipped,
        result.already_processed,
        result.errors,
    )
