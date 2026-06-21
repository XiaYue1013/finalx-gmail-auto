import ast
from pathlib import Path

from app.analysis.risk_analyzer import RiskAnalyzer
from app.config import settings
from app.gmail.message_parser import _html_to_text
from app.models import GmailMessage


def _load_emails(path: str, variable_name: str):
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    return next(
        ast.literal_eval(node.value)
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == variable_name for target in node.targets)
    )


def _assert_expected_distribution(path: str, variable_name: str, expected_levels: dict[int, str]) -> None:
    settings.enable_external_threat_lookups = False
    settings.enable_llm_intent_classifier = False
    settings.enable_setfit_classifier = False
    analyzer = RiskAnalyzer()

    for mail in _load_emails(path, variable_name):
        message = GmailMessage(
            gmail_id=str(mail["id"]),
            label_ids=["INBOX"],
            subject=mail["subject"],
            sender=mail["sender"],
            sender_email=mail["sender"],
            body_text=_html_to_text(mail["body"]),
            attachment_filenames=[mail["attachment_name"]] if mail.get("attachment_name") else [],
        )

        decision = analyzer.analyze_email(message)

        assert decision.risk_level == expected_levels[mail["id"]], mail["subject"]
        assert decision.high_risk is (expected_levels[mail["id"]] in {"high", "critical"}), mail["subject"]


def test_batch_test_insert_2_expected_risk_distribution():
    expected_levels = {
        1: "high",
        2: "medium",
        3: "low",
        4: "high",
        5: "medium",
        6: "low",
        7: "high",
        8: "low",
        9: "high",
        10: "medium",
    }

    _assert_expected_distribution("batch_test_insert_2.py", "TEST_EMAILS_2", expected_levels)


def test_batch_test_insert_3_expected_risk_distribution():
    expected_levels = {
        1: "high",
        2: "medium",
        3: "low",
        4: "high",
        5: "medium",
        6: "low",
        7: "critical",
        8: "low",
        9: "high",
        10: "medium",
    }

    _assert_expected_distribution("batch_test_insert_3.py", "TEST_EMAILS_3", expected_levels)
