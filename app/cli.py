from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from app.analysis.risk_analyzer import RiskAnalyzer
from app.config import settings
from app.gmail.auth import build_gmail_service
from app.gmail.worker import GmailRiskWorker
from app.store import MongoStateStore


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="FINALX Gmail automatic risk marker")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("auth", help="Run Gmail OAuth flow and store token.json")

    scan_parser = subparsers.add_parser("scan-once", help="Scan Gmail messages once")
    scan_parser.add_argument("--dry-run", action="store_true", help="Analyze only; do not add Gmail labels or update processed state")
    scan_parser.add_argument("--include-processed", action="store_true", help="Also analyze messages already recorded in local state")

    subparsers.add_parser("watch", help="Register Gmail push notifications with users.watch")
    subparsers.add_parser("stop-watch", help="Stop Gmail push notifications with users.stop")
    subparsers.add_parser("poll", help="Fallback mode: keep polling Gmail and mark high-risk emails")
    subparsers.add_parser("worker", help="Alias of poll fallback mode")
    subparsers.add_parser("auto", help="Start the webhook API server; use with Gmail Push + Cloud Pub/Sub")
    subparsers.add_parser("status", help="Print local scanner state")
    subparsers.add_parser("train-setfit", help="Train SetFit with bootstrap samples and approved feedback")

    analyze_parser = subparsers.add_parser("analyze-text", help="Analyze a text sample without Gmail")
    analyze_parser.add_argument("text", nargs="?", help="Text to analyze")
    analyze_parser.add_argument("--file", type=Path, help="Read text from file")

    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")

    if args.command == "auth":
        service = build_gmail_service(allow_interactive=True)
        profile = service.users().getProfile(userId="me").execute()
        print(json.dumps({"authenticated": True, "emailAddress": profile.get("emailAddress")}, ensure_ascii=False, indent=2))
        return 0

    if args.command == "scan-once":
        result = GmailRiskWorker().scan_once(dry_run=args.dry_run, include_processed=args.include_processed)
        print(result.model_dump_json(indent=2))
        return 0

    if args.command == "watch":
        result = GmailRiskWorker().register_watch()
        print(json.dumps({"registered": True, "watch": result}, ensure_ascii=False, indent=2))
        return 0

    if args.command == "stop-watch":
        GmailRiskWorker().stop_watch()
        print(json.dumps({"stopped": True}, ensure_ascii=False, indent=2))
        return 0

    if args.command in {"worker", "poll"}:
        print(
            "FINALX Gmail 輪詢 fallback 已啟動：會持續掃描 Gmail，"
            f"每 {settings.gmail_poll_seconds} 秒掃描一次，"
            f"高風險信件會自動加上「{settings.gmail_high_risk_label}」標籤。"
        )
        GmailRiskWorker().poll_forever()
        return 0

    if args.command == "auto":
        from uvicorn import run

        print("FINALX Gmail Push webhook API 啟動中：請讓 Cloud Pub/Sub push 到 /api/gmail/push。")
        run("app.main:app", host="127.0.0.1", port=8008, reload=False)
        return 0

    if args.command == "status":
        store = MongoStateStore()
        print(
            json.dumps(
                {
                    "settings": {
                        "gmail_query": settings.gmail_query,
                        "gmail_batch_size": settings.gmail_batch_size,
                        "gmail_scan_pages": settings.gmail_scan_pages,
                        "gmail_poll_seconds": settings.gmail_poll_seconds,
                        "automatic_monitoring": True,
                        "push_webhook_path": f"{settings.api_prefix}/gmail/push",
                        "watch_topic_name_configured": bool(settings.gmail_watch_topic_name),
                        "watch_label_ids": settings.gmail_watch_label_ids,
                        "auto_register_watch": settings.gmail_auto_register_watch,
                        "polling_fallback_enabled": settings.enable_background_worker,
                        "external_threat_lookups": settings.enable_external_threat_lookups,
                        "google_safe_browsing": bool(settings.google_safe_browsing_api_key),
                        "urlhaus": bool(settings.urlhaus_auth_key) and settings.enable_urlhaus_lookup,
                        "virustotal": bool(settings.virustotal_api_key),
                        "urlscan": bool(settings.urlscan_api_key),
                        "serpapi": bool(settings.serpapi_api_key),
                        "google_fact_check": bool(settings.google_fact_check_api_key),
                        "llm_intent_classifier": settings.enable_llm_intent_classifier and bool(settings.gemini_api_key),
                        "setfit_classifier": settings.enable_setfit_classifier,
                        "setfit_model_dir": str(settings.setfit_model_dir),
                        "setfit_model_ready": (settings.setfit_model_dir / "config.json").exists(),
                        "high_risk_threshold": settings.high_risk_threshold,
                        "medium_risk_threshold": settings.medium_risk_threshold,
                        "gmail_high_risk_label": settings.gmail_high_risk_label,
                        "gmail_warning_label": settings.gmail_warning_label,
                        "storage": {
                            "mongodb_configured": bool(settings.mongodb_uri),
                            "mongodb_database": settings.mongodb_database if settings.mongodb_uri else None,
                            "state_collection": settings.mongodb_state_collection if settings.mongodb_uri else None,
                            "events_collection": settings.mongodb_events_collection if settings.mongodb_uri else None,
                            "reputation_collection": settings.mongodb_reputation_collection if settings.mongodb_uri else None,
                        },
                    },
                    "state": store.load_state(),
                    "recent_events": store.list_events(limit=10),
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0

    if args.command == "train-setfit":
        from tools.train_setfit_classifier import main as train_setfit

        return train_setfit([])

    if args.command == "analyze-text":
        if args.file:
            text = args.file.read_text(encoding="utf-8")
        elif args.text:
            text = args.text
        else:
            text = sys.stdin.read()
        decision = RiskAnalyzer().analyze_text(text)
        print(decision.model_dump_json(indent=2))
        return 0

    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
