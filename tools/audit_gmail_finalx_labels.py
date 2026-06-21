from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.analysis.risk_analyzer import RiskAnalyzer
from app.config import settings
from app.gmail.client import GmailClient
from app.gmail.message_parser import parse_gmail_message


DEFAULT_QUERY = "in:anywhere after:2026/6/11 -in:drafts"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Audit and reconcile FINALX Gmail labels.")
    parser.add_argument("--query", default=DEFAULT_QUERY, help="Gmail search query.")
    parser.add_argument("--apply", action="store_true", help="Apply label additions/removals.")
    parser.add_argument("--disable-external", action="store_true", help="Disable external threat lookups for this audit run.")
    parser.add_argument("--disable-llm", action="store_true", help="Disable LLM intent classification for this audit run.")
    parser.add_argument("--limit", type=int, default=500, help="Maximum messages to audit.")
    parser.add_argument("--report-dir", default="data", help="Directory for JSON reports.")
    parser.add_argument("--no-report", action="store_true", help="Do not write a JSON report.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.disable_external:
        settings.enable_external_threat_lookups = False
    if args.disable_llm:
        settings.enable_llm_intent_classifier = False
    gmail = GmailClient()
    service = gmail.service
    labels = service.users().labels().list(userId="me").execute().get("labels") or []
    label_by_id = {str(item["id"]): str(item.get("name") or "") for item in labels if item.get("id")}
    id_by_label = {name: label_id for label_id, name in label_by_id.items()}
    finalx_label_ids = {label_id for label_id, name in label_by_id.items() if name.startswith("FINALX")}

    analyzer = RiskAnalyzer()
    message_ids = list_message_ids(service, args.query, args.limit)
    results: list[dict[str, Any]] = []

    for index, message_id in enumerate(message_ids, start=1):
        print(f"[{index}/{len(message_ids)}] auditing {message_id}", flush=True)
        try:
            raw = service.users().messages().get(userId="me", id=message_id, format="full").execute()
            message = parse_gmail_message(raw)
            decision = analyzer.analyze_email(message)
            existing_label_ids = set(raw.get("labelIds") or [])
            existing_finalx_ids = existing_label_ids & finalx_label_ids
            existing_finalx_names = sorted(label_by_id[label_id] for label_id in existing_finalx_ids)
            desired_label_names = desired_finalx_labels(decision)
            desired_label_ids = {ensure_label_id(gmail, id_by_label, name) for name in desired_label_names} if args.apply else {
                id_by_label[name] for name in desired_label_names if name in id_by_label
            }

            missing_label_names = sorted(name for name in desired_label_names if name not in existing_finalx_names)
            remove_label_ids = sorted(existing_finalx_ids - desired_label_ids)
            remove_label_names = sorted(label_by_id[label_id] for label_id in remove_label_ids)

            if args.apply:
                add_label_ids = [ensure_label_id(gmail, id_by_label, name) for name in missing_label_names]
                body: dict[str, list[str]] = {}
                if add_label_ids:
                    body["addLabelIds"] = add_label_ids
                if remove_label_ids:
                    body["removeLabelIds"] = remove_label_ids
                if body:
                    service.users().messages().modify(userId="me", id=message_id, body=body).execute()

            results.append(
                {
                    "gmail_id": message_id,
                    "subject": message.subject,
                    "sender": message.sender,
                    "existing_finalx_labels": existing_finalx_names,
                    "desired_finalx_labels": desired_label_names,
                    "add_labels": missing_label_names,
                    "remove_labels": remove_label_names,
                    "risk_score": decision.risk_score,
                    "risk_level": decision.risk_level,
                    "label_reason": decision.label_reason,
                    "rule_hits": [hit.rule_id for hit in decision.rule_hits],
                    "positive_evidence": [
                        {
                            "source": item.source,
                            "indicator": item.indicator,
                            "status": item.status,
                            "score_delta": item.score_delta,
                            "title": item.title,
                        }
                        for item in decision.evidence
                        if item.score_delta > 0 or item.status in {"malicious", "suspicious"}
                    ],
                    "high_risk": decision.high_risk,
                    "action": decision.action,
                    "changed": bool(missing_label_names or remove_label_names),
                    "error": None,
                }
            )
        except Exception as exc:
            results.append(
                {
                    "gmail_id": message_id,
                    "changed": False,
                    "error": str(exc),
                }
            )

    print_summary(results, applied=args.apply)
    if not args.no_report:
        report_path = write_report(args.report_dir, args.query, args.apply, results)
        print(f"report={report_path}")
    return 0


def list_message_ids(service: Any, query: str, limit: int) -> list[str]:
    ids: list[str] = []
    page_token: str | None = None
    while len(ids) < limit:
        response = (
            service.users()
            .messages()
            .list(
                userId="me",
                q=query,
                maxResults=min(100, limit - len(ids)),
                includeSpamTrash=True,
                pageToken=page_token,
            )
            .execute()
        )
        ids.extend(str(item["id"]) for item in response.get("messages") or [] if item.get("id"))
        page_token = response.get("nextPageToken")
        if not page_token:
            break
    return list(dict.fromkeys(ids))


def desired_finalx_labels(decision) -> list[str]:
    names: list[str] = []
    if decision.high_risk:
        names.append(settings.gmail_high_risk_label)
    elif (
        settings.label_medium_risk
        and settings.medium_risk_threshold <= decision.risk_score < settings.high_risk_threshold
    ):
        names.append(settings.gmail_warning_label)
    if names and settings.enable_reason_labels and decision.label_reason:
        names.append(f"{settings.gmail_reason_label_prefix} - {decision.label_reason}")
    return list(dict.fromkeys(names))


def ensure_label_id(gmail: GmailClient, id_by_label: dict[str, str], name: str) -> str:
    label_id = id_by_label.get(name)
    if label_id:
        return label_id
    label_id = gmail.ensure_label(name)
    id_by_label[name] = label_id
    return label_id


def print_summary(results: list[dict[str, Any]], *, applied: bool) -> None:
    changed = [item for item in results if item.get("changed")]
    errors = [item for item in results if item.get("error")]
    missed = [item for item in changed if item.get("add_labels")]
    mislabels = [item for item in changed if item.get("remove_labels")]
    print(
        json.dumps(
            {
                "mode": "apply" if applied else "dry-run",
                "audited": len(results),
                "changed": len(changed),
                "missed_need_add": len(missed),
                "mislabels_need_remove": len(mislabels),
                "errors": len(errors),
            },
            ensure_ascii=False,
        )
    )
    for item in changed:
        print(
            json.dumps(
                {
                    "gmail_id": item.get("gmail_id"),
                    "subject": item.get("subject"),
                    "risk_score": item.get("risk_score"),
                    "risk_level": item.get("risk_level"),
                    "add": item.get("add_labels"),
                    "remove": item.get("remove_labels"),
                },
                ensure_ascii=False,
            )
        )
    for item in errors:
        print(json.dumps({"gmail_id": item.get("gmail_id"), "error": item.get("error")}, ensure_ascii=False))


def write_report(report_dir: str, query: str, applied: bool, results: list[dict[str, Any]]) -> str:
    path = Path(report_dir)
    path.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    report_path = path / f"gmail_finalx_label_audit_{timestamp}.json"
    report_path.write_text(
        json.dumps(
            {
                "query": query,
                "applied": applied,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "results": results,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    return str(report_path)


if __name__ == "__main__":
    raise SystemExit(main())
