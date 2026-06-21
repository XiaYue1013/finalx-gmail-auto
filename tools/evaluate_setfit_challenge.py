#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from email.utils import parseaddr
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.analysis.risk_analyzer import RiskAnalyzer
from app.config import settings
from app.models import GmailMessage


DEFAULT_DATASET = PROJECT_ROOT / "tests/fixtures/setfit_challenge.json"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate the trained model on held-out challenge emails.")
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--json-output", type=Path, default=Path("data/setfit_challenge_report.json"))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    settings.enable_setfit_classifier = True
    settings.enable_external_threat_lookups = False
    settings.enable_llm_intent_classifier = False

    samples = json.loads(args.dataset.read_text(encoding="utf-8"))
    analyzer = RiskAnalyzer()
    rows = []
    confusion: Counter[tuple[str, str]] = Counter()
    for sample in samples:
        _, sender_email = parseaddr(sample["sender"])
        message = GmailMessage(
            gmail_id=sample["id"],
            subject=sample["subject"],
            sender=sample["sender"],
            sender_email=sender_email or sample["sender"],
            reply_to=sample.get("reply_to", ""),
            body_text=sample["body"],
            authentication_results=sample.get("authentication_results", ""),
            attachment_filenames=[sample["attachment_name"]] if sample.get("attachment_name") else [],
        )
        decision = analyzer.analyze_email(message)
        setfit = next(
            (item for item in decision.evidence if item.source == "setfit_email_classifier"),
            None,
        )
        expected = sample["expected_level"]
        predicted = decision.risk_level
        expected_bucket = _bucket(expected)
        predicted_bucket = _bucket(predicted)
        confusion[(expected_bucket, predicted_bucket)] += 1
        rows.append(
            {
                "id": sample["id"],
                "expected_level": expected,
                "predicted_level": predicted,
                "expected_bucket": expected_bucket,
                "predicted_bucket": predicted_bucket,
                "risk_score": decision.risk_score,
                "setfit": setfit.detail if setfit else "",
                "passed": expected_bucket == predicted_bucket,
            }
        )

    passed = sum(row["passed"] for row in rows)
    summary = {
        "total": len(rows),
        "passed": passed,
        "accuracy": round(passed / len(rows), 4) if rows else 0,
        "confusion": {
            f"{expected}->{predicted}": count
            for (expected, predicted), count in sorted(confusion.items())
        },
    }
    args.json_output.parent.mkdir(parents=True, exist_ok=True)
    args.json_output.write_text(
        json.dumps({"summary": summary, "rows": rows}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    for row in rows:
        if not row["passed"]:
            print(
                f"FAIL {row['id']}: expected={row['expected_level']} "
                f"predicted={row['predicted_level']} score={row['risk_score']} {row['setfit']}"
            )
    return 0 if passed == len(rows) else 1


def _bucket(level: str) -> str:
    if level in {"high", "critical"}:
        return "threat"
    if level == "medium":
        return "suspicious"
    return "legitimate"


if __name__ == "__main__":
    raise SystemExit(main())
