from __future__ import annotations

import argparse
import ast
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.analysis.risk_analyzer import RiskAnalyzer
from app.config import settings
from app.gmail.message_parser import _html_to_text
from app.models import GmailMessage


DATASETS = [
    ("wave1", "第一波：基本風險分布", "batch_test_insert.py", "TEST_EMAILS"),
    ("wave2", "第二波：進階釣魚與垃圾郵件情境", "batch_test_insert_2.py", "TEST_EMAILS_2"),
    ("wave3", "第三波：社交工程與特殊攻擊情境", "batch_test_insert_3.py", "TEST_EMAILS_3"),
]


@dataclass
class EvaluationRow:
    dataset: str
    sample_id: str
    subject: str
    expected_level: str
    predicted_level: str
    expected_threat: bool
    predicted_threat: bool
    risk_score: int
    confidence_score: int
    label_reason: str
    rule_hits: list[str]
    top_evidence: list[str]

    @property
    def outcome(self) -> str:
        if self.expected_threat and self.predicted_threat:
            return "TP"
        if not self.expected_threat and self.predicted_threat:
            return "FP"
        if self.expected_threat and not self.predicted_threat:
            return "FN"
        return "TN"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate FINALX evaluation report from demo email datasets.")
    parser.add_argument("--output", default="EVALUATION_REPORT.md", help="Markdown report path.")
    parser.add_argument("--json-output", default="data/evaluation_report.json", help="Machine-readable JSON report path.")
    parser.add_argument("--enable-external", action="store_true", help="Enable external threat lookups during evaluation.")
    parser.add_argument("--enable-llm", action="store_true", help="Enable Gemini LLM intent classifier during evaluation.")
    parser.add_argument("--disable-setfit", action="store_true", help="Use the rules-only fallback instead of SetFit.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    settings.enable_external_threat_lookups = bool(args.enable_external)
    settings.enable_llm_intent_classifier = bool(args.enable_llm)
    settings.enable_setfit_classifier = not args.disable_setfit
    if settings.enable_setfit_classifier and not (settings.setfit_model_dir / "config.json").exists():
        raise SystemExit("SetFit model is not ready. Run ./run.sh train-setfit or pass --disable-setfit.")

    rows = evaluate_all()
    summary = summarize(rows)
    markdown = render_markdown(
        rows,
        summary,
        external=args.enable_external,
        llm=args.enable_llm,
        setfit=not args.disable_setfit,
    )

    output_path = Path(args.output)
    output_path.write_text(markdown, encoding="utf-8")

    json_path = Path(args.json_output)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(
        json.dumps(
            {
                "created_at": datetime.now(timezone.utc).isoformat(),
                "settings": {
                    "external_threat_lookups": bool(args.enable_external),
                    "llm_intent_classifier": bool(args.enable_llm),
                    "setfit_classifier": not args.disable_setfit,
                    "high_risk_threshold": settings.high_risk_threshold,
                    "medium_risk_threshold": settings.medium_risk_threshold,
                },
                "summary": summary,
                "rows": [row.__dict__ | {"outcome": row.outcome} for row in rows],
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"wrote {output_path}")
    print(f"wrote {json_path}")
    print(json.dumps(summary, ensure_ascii=False))
    return 0


def evaluate_all() -> list[EvaluationRow]:
    analyzer = RiskAnalyzer()
    rows: list[EvaluationRow] = []
    for dataset_id, _name, filename, variable_name in DATASETS:
        for mail in load_emails(filename, variable_name):
            expected_level = expected_level_from_type(str(mail.get("type") or ""))
            message = GmailMessage(
                gmail_id=f"{dataset_id}-{mail.get('id')}",
                label_ids=["INBOX"],
                subject=str(mail.get("subject") or ""),
                sender=str(mail.get("sender") or ""),
                sender_email=str(mail.get("sender") or ""),
                reply_to=str(mail.get("reply_to") or ""),
                body_text=_html_to_text(str(mail.get("body") or "")),
                attachment_filenames=[str(mail["attachment_name"])] if mail.get("attachment_name") else [],
            )
            decision = analyzer.analyze_email(message)
            rows.append(
                EvaluationRow(
                    dataset=dataset_id,
                    sample_id=str(mail.get("id")),
                    subject=message.subject,
                    expected_level=expected_level,
                    predicted_level=decision.risk_level,
                    expected_threat=is_threat_level(expected_level),
                    predicted_threat=is_threat_level(decision.risk_level),
                    risk_score=decision.risk_score,
                    confidence_score=decision.confidence_score,
                    label_reason=decision.label_reason,
                    rule_hits=[hit.rule_id for hit in decision.rule_hits],
                    top_evidence=[
                        f"{item.source}:{item.title}:{item.score_delta}"
                        for item in sorted(decision.evidence, key=lambda entry: abs(entry.score_delta), reverse=True)
                        if item.score_delta != 0
                    ][:5],
                )
            )
    return rows


def load_emails(path: str, variable_name: str) -> list[dict[str, Any]]:
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if any(isinstance(target, ast.Name) and target.id == variable_name for target in node.targets):
            return ast.literal_eval(node.value)
    raise ValueError(f"Cannot find {variable_name} in {path}")


def expected_level_from_type(value: str) -> str:
    stripped = value.strip()
    lowered = value.lower()
    if stripped.startswith("安全") or lowered.startswith("low risk"):
        return "low"
    if stripped.startswith("中風險") or lowered.startswith("medium risk"):
        return "medium"
    if stripped.startswith("高風險") or lowered.startswith("high risk"):
        return "high"
    if "critical" in lowered or "極高" in value:
        return "critical"
    if "high risk" in lowered or "高風險" in value:
        return "high"
    if "medium risk" in lowered or "中風險" in value:
        return "medium"
    return "low"


def is_threat_level(value: str) -> bool:
    return value in {"high", "critical"}


def summarize(rows: list[EvaluationRow]) -> dict[str, Any]:
    tp = sum(1 for row in rows if row.outcome == "TP")
    fp = sum(1 for row in rows if row.outcome == "FP")
    fn = sum(1 for row in rows if row.outcome == "FN")
    tn = sum(1 for row in rows if row.outcome == "TN")
    precision = round(tp / (tp + fp), 4) if tp + fp else 0
    recall = round(tp / (tp + fn), 4) if tp + fn else 0
    f1 = round(2 * precision * recall / (precision + recall), 4) if precision + recall else 0
    exact_level_match = sum(1 for row in rows if row.expected_level == row.predicted_level)
    return {
        "total": len(rows),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "exact_level_accuracy": round(exact_level_match / len(rows), 4) if rows else 0,
        "by_dataset": {
            dataset_id: {
                "total": len(dataset_rows),
                "tp": sum(1 for row in dataset_rows if row.outcome == "TP"),
                "fp": sum(1 for row in dataset_rows if row.outcome == "FP"),
                "fn": sum(1 for row in dataset_rows if row.outcome == "FN"),
                "tn": sum(1 for row in dataset_rows if row.outcome == "TN"),
            }
            for dataset_id in sorted({row.dataset for row in rows})
            for dataset_rows in [[row for row in rows if row.dataset == dataset_id]]
        },
    }


def render_markdown(
    rows: list[EvaluationRow],
    summary: dict[str, Any],
    *,
    external: bool,
    llm: bool,
    setfit: bool,
) -> str:
    created_at = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    mismatches = [row for row in rows if row.outcome in {"FP", "FN"} or row.expected_level != row.predicted_level]
    lines = [
        "# FINALX Gmail Auto Evaluation Report",
        "",
        f"產生時間：{created_at}",
        "",
        "## Evaluation Setup",
        "",
        f"- Dataset：三波 demo 測試信，共 {summary['total']} 封。",
        f"- External threat lookups：{'enabled' if external else 'disabled'}。",
        f"- Gemini LLM intent classifier：{'enabled' if llm else 'disabled'}。",
        f"- SetFit multilingual classifier：{'enabled' if setfit else 'disabled (rules fallback)'}。",
        f"- High risk threshold：{settings.high_risk_threshold}。",
        f"- Medium risk threshold：{settings.medium_risk_threshold}。",
        "- Binary threat target：expected/predicted risk level 為 high 或 critical 即視為威脅。",
        "- 注意：三波 demo 樣本屬回歸測試；獨立泛化能力請以 `./run.sh evaluate-setfit` 的 held-out challenge 為準。",
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
        f"| Total samples | {summary['total']} |",
        f"| True Positive | {summary['tp']} |",
        f"| False Positive | {summary['fp']} |",
        f"| False Negative | {summary['fn']} |",
        f"| True Negative | {summary['tn']} |",
        f"| Precision | {summary['precision']:.4f} |",
        f"| Recall | {summary['recall']:.4f} |",
        f"| F1 | {summary['f1']:.4f} |",
        f"| Exact level accuracy | {summary['exact_level_accuracy']:.4f} |",
        "",
        "## Dataset Breakdown",
        "",
        "| Dataset | Total | TP | FP | FN | TN |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for dataset_id, dataset_summary in summary["by_dataset"].items():
        lines.append(
            f"| {dataset_id} | {dataset_summary['total']} | {dataset_summary['tp']} | {dataset_summary['fp']} | {dataset_summary['fn']} | {dataset_summary['tn']} |"
        )

    lines.extend(
        [
            "",
            "## Per-sample Results",
            "",
            "| Dataset | ID | Expected | Predicted | Score | Confidence | Outcome | Reason | Subject |",
            "| --- | ---: | --- | --- | ---: | ---: | --- | --- | --- |",
        ]
    )
    for row in rows:
        lines.append(
            "| "
            + " | ".join(
                [
                    row.dataset,
                    row.sample_id,
                    row.expected_level,
                    row.predicted_level,
                    str(row.risk_score),
                    str(row.confidence_score),
                    row.outcome,
                    clean_cell(row.label_reason),
                    clean_cell(row.subject),
                ]
            )
            + " |"
        )

    lines.extend(["", "## Review Notes", ""])
    if mismatches:
        lines.extend(
            [
                "以下樣本值得人工複核；不一定代表錯誤，可能是系統把 high 案例升為 critical，或把 medium 案例提高為 high。",
                "",
                "| Dataset | ID | Expected | Predicted | Score | Outcome | Top rules | Top evidence |",
                "| --- | ---: | --- | --- | ---: | --- | --- | --- |",
            ]
        )
        for row in mismatches:
            lines.append(
                "| "
                + " | ".join(
                    [
                        row.dataset,
                        row.sample_id,
                        row.expected_level,
                        row.predicted_level,
                        str(row.risk_score),
                        row.outcome,
                        clean_cell(", ".join(row.rule_hits[:5])),
                        clean_cell("; ".join(row.top_evidence[:3])),
                    ]
                )
                + " |"
            )
    else:
        lines.append("所有樣本的 binary threat 判斷與 expected label 一致，且 risk level 完全相符。")

    lines.extend(
        [
            "",
            "## How To Reproduce",
            "",
            "```bash",
            "./run.sh evaluate",
            "```",
            "",
            "這份報告刻意預設關閉外部 API 與 LLM，讓老師不用 API key 也能重現 baseline 結果。",
        ]
    )
    return "\n".join(lines) + "\n"


def clean_cell(value: str) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")[:180]


if __name__ == "__main__":
    raise SystemExit(main())
