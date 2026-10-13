from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.analysis.risk_analyzer import RiskAnalyzer
from app.config import settings


DEMO_TEXT = (
    "Google Security final notice: your account will be suspended within 24 hours. "
    "Please verify your account at https://g00gle-security.top/login/verify"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check FINALX Gmail Auto demo readiness.")
    parser.add_argument("--api-url", default="", help="Optional running API base URL, e.g. http://127.0.0.1:8008")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    settings.enable_external_threat_lookups = False
    settings.enable_llm_intent_classifier = False

    checks = [
        check_file("README.md"),
        check_file("FINALX Gmail Auto.pptx"),
        check_file("PROJECT_OPERATION_AND_IMPROVEMENTS.md"),
        check_file("PRESENTATION_LLM_OUTLINE.md"),
        check_file(".env.example"),
        check_optional_file(".env"),
        check_credentials(),
        check_optional_file("token.json"),
        check_setting("MONGODB_URI", bool(settings.mongodb_uri)),
        check_setting("GMAIL_WATCH_TOPIC_NAME", bool(settings.gmail_watch_topic_name)),
        check_setting("API_TOKEN", bool(settings.api_token), optional=True),
    ]
    if args.api_url:
        checks.append(check_api(args.api_url))

    decision = RiskAnalyzer().analyze_text(DEMO_TEXT)
    checks.append(
        {
            "name": "baseline analyzer",
            "ok": decision.high_risk and decision.risk_score >= settings.high_risk_threshold,
            "detail": f"{decision.risk_level} / {decision.risk_score} / {decision.label_reason}",
        }
    )

    print("# FINALX Demo Readiness")
    print()
    for check in checks:
        icon = "OK" if check["ok"] else ("WARN" if check.get("optional") else "FAIL")
        print(f"[{icon}] {check['name']}: {check['detail']}")

    blocking_failures = [item for item in checks if not item["ok"] and not item.get("optional")]
    print()
    print("Recommended live demo order:")
    print("1. ./run.sh evaluate")
    print("2. ./run.sh api")
    print("3. Open http://127.0.0.1:8008/dashboard")
    print("4. ./run.sh demo-insert --list")
    print("5. ./run.sh demo-insert --wave 1 --interval 0")
    print("6. Use Dashboard 詳情 and Gmail labels to explain the result")
    print()
    print(json.dumps({"ok": not blocking_failures, "failures": blocking_failures}, ensure_ascii=False))
    return 1 if blocking_failures else 0


def check_file(path: str) -> dict:
    exists = Path(path).exists()
    return {"name": path, "ok": exists, "detail": "exists" if exists else "missing"}


def check_optional_file(path: str) -> dict:
    result = check_file(path)
    result["optional"] = True
    return result


def check_credentials() -> dict:
    matches = list(Path(".").glob("client_secret_*.json"))
    exists = Path("credentials.json").exists() or bool(matches)
    detail = "credentials.json/client_secret found" if exists else "missing until Gmail OAuth demo"
    return {"name": "Gmail OAuth credentials", "ok": exists, "detail": detail, "optional": True}


def check_setting(name: str, ok: bool, optional: bool = False) -> dict:
    return {"name": name, "ok": ok, "detail": "configured" if ok else "not configured", "optional": optional}


def check_api(base_url: str) -> dict:
    url = base_url.rstrip("/") + "/"
    try:
        with urlopen(url, timeout=3) as response:
            ok = 200 <= response.status < 300
            return {"name": f"API {url}", "ok": ok, "detail": f"HTTP {response.status}"}
    except URLError as exc:
        return {"name": f"API {url}", "ok": False, "detail": str(exc), "optional": True}


if __name__ == "__main__":
    raise SystemExit(main())
