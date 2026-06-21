#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import json
import logging
import sys
from datetime import datetime, timezone
from email.utils import parseaddr
from pathlib import Path
from typing import Any

import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from datasets import Dataset
from setfit import SetFitModel, Trainer, TrainingArguments

from app.analysis.setfit_classifier import (
    DEFAULT_LABELS,
    MODEL_METADATA_FILENAME,
    REFERENCE_EMBEDDINGS_FILENAME,
    build_model_input,
    suppress_false_mistral_regex_warning,
)
from app.config import settings
from app.gmail.message_parser import _html_to_text
from app.models import GmailMessage
from app.store import MongoStateStore


logger = logging.getLogger("finalx_gmail.train_setfit")

LABEL_TO_ID = {label: index for index, label in enumerate(DEFAULT_LABELS)}
BATCH_SOURCES = (
    ("batch_test_insert.py", "TEST_EMAILS"),
    ("batch_test_insert_2.py", "TEST_EMAILS_2"),
    ("batch_test_insert_3.py", "TEST_EMAILS_3"),
)
CURATED_SEED_DATASET = PROJECT_ROOT / "training/setfit_seed_samples.json"

SUPPLEMENTAL_SAMPLES = (
    {
        "label": "legitimate",
        "sender": "webmaster@taishinbank.com.tw",
        "subject": "台新銀行無卡提款設定通知",
        "body": "您的無卡提款設定已完成。若非本人操作，請開啟官方 App 或致電銀行客服確認。請勿回覆本信。",
        "authentication_results": "spf=pass dkim=pass dmarc=pass",
    },
    {
        "label": "legitimate",
        "sender": "webmaster@taishinbank.com.tw",
        "subject": "台新銀行無卡提款設定通知",
        "body": "您的無卡提款設定已完成。若非本人操作，請開啟官方 App 或致電銀行客服確認。請勿回覆本信。",
        "authentication_results": "",
    },
    {
        "label": "legitimate",
        "sender": "alerts@bank.example.com",
        "subject": "提款交易通知",
        "body": "您的帳戶已完成一筆提款交易。本通知不要求點擊連結、提供密碼或回覆驗證碼。如有疑問請自行開啟官方 App。",
        "authentication_results": "",
    },
    {
        "label": "legitimate",
        "sender": "noreply@steampowered.com",
        "subject": "New sign in to Steam",
        "body": "A new sign in was detected. If the details look familiar you can safely ignore this email. Otherwise visit https://help.steampowered.com/en/wizard/HelpWithLogin",
        "authentication_results": "spf=pass dkim=pass dmarc=pass",
    },
    {
        "label": "legitimate",
        "sender": "gaming@nvgaming.nvidia.com",
        "subject": "還在用 GeForce RTX 20 或 30系列? 是時候升級 GeForce RTX 50 系列囉!",
        "body": "NVIDIA GeForce 產品促銷電子報。查看合作通路與顯示卡升級資訊。",
        "authentication_results": "spf=pass dkim=pass dmarc=pass",
    },
    {
        "label": "legitimate",
        "sender": "noreply@nedm.asus.com",
        "subject": "618最後倒數！AI筆電優惠",
        "body": "ASUS 官方電子報，介紹筆電優惠與產品活動。可至官方網站查看。",
        "authentication_results": "spf=pass dkim=pass dmarc=pass",
    },
    {
        "label": "legitimate",
        "sender": "mpost@mail.post.gov.tw",
        "subject": "行動郵局登入通知",
        "body": "行動郵局登入通知。若非本人操作，請自行開啟行動郵局 App 或聯絡官方客服。",
        "authentication_results": "spf=pass dkim=pass dmarc=pass",
    },
    {
        "label": "legitimate",
        "sender": "noreply-accounts@google.com",
        "subject": "You shared some Google Account data with Canva",
        "body": "This is a Google Account privacy notification about an application connection. Review connections from your Google Account settings.",
        "authentication_results": "spf=pass dkim=pass dmarc=pass",
    },
    {
        "label": "legitimate",
        "sender": "no-reply@email.github.com",
        "subject": "GitHub Copilot 線上研討會",
        "body": "GitHub 官方線上活動與產品教育內容。活動報名頁與取消訂閱連結皆屬官方服務。",
        "authentication_results": "spf=pass dkim=pass dmarc=pass",
    },
    {
        "label": "legitimate",
        "sender": "noreply.news@e-mail.hoyoverse.com",
        "subject": "遊戲全新版本今日啟程",
        "body": "遊戲版本更新、角色介紹與官方活動電子報。點擊官方網站查看更新。",
        "authentication_results": "spf=pass dkim=pass dmarc=pass",
    },
    {
        "label": "legitimate",
        "sender": "security@service.example.com",
        "subject": "Your monthly security report is ready",
        "body": "No action is required. Open the official application directly if you want to review account activity.",
        "authentication_results": "spf=pass dkim=pass dmarc=pass",
    },
    {
        "label": "threat",
        "sender": "security@bank-account-check.top",
        "subject": "帳戶即將凍結，請立即驗證",
        "body": "請於一小時內使用下方連結輸入網銀帳號、密碼與簡訊驗證碼，否則帳戶將永久停用。 http://bank-account-check.top/login",
        "authentication_results": "spf=fail dkim=fail dmarc=fail",
    },
    {
        "label": "threat",
        "sender": "support@parcel-redelivery.xyz",
        "subject": "包裹配送失敗，請補繳費用",
        "body": "地址不完整。請立即支付 15 元重新配送費，並輸入信用卡資料。 http://parcel-redelivery.xyz/pay",
        "authentication_results": "spf=fail dmarc=fail",
    },
    {
        "label": "threat",
        "sender": "ceo-office@external-mail.work",
        "subject": "Confidential urgent transfer",
        "body": "I am in a meeting. Wire 25000 USD to this new bank account today and do not call me.",
        "authentication_results": "spf=pass",
    },
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train the FINALX multilingual SetFit email risk classifier.")
    parser.add_argument("--output", type=Path, default=Path(settings.setfit_model_dir))
    parser.add_argument("--base-model", default=settings.setfit_base_model)
    parser.add_argument("--epochs", type=int, default=settings.setfit_training_epochs)
    parser.add_argument("--iterations", type=int, default=settings.setfit_training_iterations)
    parser.add_argument("--feedback-limit", type=int, default=5000)
    parser.add_argument("--skip-feedback", action="store_true")
    parser.add_argument(
        "--head-only",
        action="store_true",
        help="Reuse the existing trained multilingual encoder and refit only the classifier head.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")
    samples = _bootstrap_samples()
    feedback_count = 0
    if not args.skip_feedback:
        feedback_samples = _feedback_samples(args.feedback_limit)
        feedback_count = len(feedback_samples)
        samples.extend(feedback_samples)
    samples = _deduplicate(samples)
    counts = _label_counts(samples)
    missing = [label for label in DEFAULT_LABELS if counts.get(label, 0) < 2]
    if missing:
        raise RuntimeError(f"Not enough training samples for labels: {', '.join(missing)}")

    dataset = Dataset.from_dict(
        {
            "text": [sample["text"] for sample in samples],
            "label": [LABEL_TO_ID[sample["label"]] for sample in samples],
        }
    )
    args.output.mkdir(parents=True, exist_ok=True)
    checkpoints = args.output.parent / f"{args.output.name}-checkpoints"
    logger.info("training SetFit model: samples=%s labels=%s base=%s", len(samples), counts, args.base_model)

    if args.head_only:
        if not (args.output / "config.json").exists():
            raise RuntimeError("--head-only requires an existing trained model in the output directory.")
        with suppress_false_mistral_regex_warning(args.output):
            model = SetFitModel.from_pretrained(
                str(args.output),
                local_files_only=True,
                device=settings.setfit_device,
            )
        embeddings = model.encode(
            [sample["text"] for sample in samples],
            show_progress_bar=False,
        )
        model.model_head.fit(embeddings, [LABEL_TO_ID[sample["label"]] for sample in samples])
    else:
        model = SetFitModel.from_pretrained(
            args.base_model,
            labels=list(DEFAULT_LABELS),
            device=settings.setfit_device,
        )
        training_args = TrainingArguments(
            output_dir=str(checkpoints),
            batch_size=16,
            num_epochs=(args.epochs, 16),
            num_iterations=args.iterations,
            max_length=192,
            show_progress_bar=False,
            report_to="none",
            save_strategy="no",
            logging_strategy="no",
            seed=42,
        )
        trainer = Trainer(model=model, args=training_args, train_dataset=dataset)
        trainer.train()
    model.save_pretrained(str(args.output))
    reference_embeddings = np.asarray(
        model.encode(
            [sample["text"] for sample in samples],
            show_progress_bar=False,
        ),
        dtype=np.float32,
    )
    norms = np.linalg.norm(reference_embeddings, axis=1, keepdims=True)
    normalized_references = reference_embeddings / np.maximum(norms, 1e-12)
    np.savez_compressed(
        args.output / REFERENCE_EMBEDDINGS_FILENAME,
        embeddings=normalized_references,
        labels=np.asarray([sample["label"] for sample in samples]),
    )

    metadata = {
        "labels": list(DEFAULT_LABELS),
        "base_model": args.base_model,
        "sample_count": len(samples),
        "feedback_sample_count": feedback_count,
        "label_counts": counts,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "epochs": args.epochs,
        "iterations": args.iterations,
        "training_mode": "head_only" if args.head_only else "full_setfit",
    }
    (args.output / MODEL_METADATA_FILENAME).write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(json.dumps(metadata, ensure_ascii=False, indent=2))
    return 0


def _bootstrap_samples() -> list[dict[str, str]]:
    samples: list[dict[str, str]] = []
    for path, variable_name in BATCH_SOURCES:
        for item in _load_literal_assignment(Path(path), variable_name):
            label = _label_from_type(str(item.get("type") or ""))
            message = _message_from_mapping(item)
            samples.append({"label": label, "text": build_model_input(message), "source": path})
    for item in SUPPLEMENTAL_SAMPLES:
        message = _message_from_mapping(item)
        samples.append(
            {
                "label": str(item["label"]),
                "text": build_model_input(message),
                "source": "supplemental_regression",
            }
        )
    if CURATED_SEED_DATASET.exists():
        for item in json.loads(CURATED_SEED_DATASET.read_text(encoding="utf-8")):
            message = _message_from_mapping(item)
            samples.append(
                {
                    "label": str(item["label"]),
                    "text": build_model_input(message),
                    "source": "curated_seed_dataset",
                }
            )
    return samples


def _feedback_samples(limit: int) -> list[dict[str, str]]:
    try:
        docs = MongoStateStore().list_labeled_samples(limit=limit)
    except Exception as exc:
        logger.warning("approved feedback unavailable; training bootstrap data only: %s", exc)
        return []
    samples = []
    for doc in docs:
        raw_label = str(doc.get("label") or "")
        label = "legitimate" if raw_label == "safe" else "threat" if raw_label == "threat" else ""
        text = str(doc.get("model_input_text") or "").strip()
        if not text:
            text = "\n".join(
                part
                for part in (
                    f"Sender: {doc.get('sender_email') or doc.get('sender') or ''}",
                    f"Subject: {doc.get('subject') or ''}",
                    f"Reviewer notes: {doc.get('notes') or ''}",
                )
                if part.strip()
            )
        if label and text:
            samples.append({"label": label, "text": text, "source": "approved_feedback"})
    return samples


def _message_from_mapping(item: dict[str, Any]) -> GmailMessage:
    sender = str(item.get("sender") or "")
    _, sender_email = parseaddr(sender)
    body = str(item.get("body") or "")
    return GmailMessage(
        gmail_id=str(item.get("id") or "training"),
        subject=str(item.get("subject") or ""),
        sender=sender,
        sender_email=sender_email or sender,
        body_text=_html_to_text(body) if "<" in body else body,
        authentication_results=str(item.get("authentication_results") or ""),
        received_spf=str(item.get("received_spf") or ""),
        attachment_filenames=[str(item["attachment_name"])] if item.get("attachment_name") else [],
    )


def _load_literal_assignment(path: Path, variable_name: str) -> list[dict[str, Any]]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(target, ast.Name) and target.id == variable_name for target in node.targets):
            continue
        value = ast.literal_eval(node.value)
        if isinstance(value, list):
            return value
    raise RuntimeError(f"{variable_name} not found in {path}")


def _label_from_type(value: str) -> str:
    if value.startswith("安全"):
        return "legitimate"
    if value.startswith("中風險"):
        return "suspicious"
    return "threat"


def _deduplicate(samples: list[dict[str, str]]) -> list[dict[str, str]]:
    output: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for sample in samples:
        key = (sample["label"], sample["text"])
        if key in seen:
            continue
        seen.add(key)
        output.append(sample)
    return output


def _label_counts(samples: list[dict[str, str]]) -> dict[str, int]:
    counts = {label: 0 for label in DEFAULT_LABELS}
    for sample in samples:
        counts[sample["label"]] = counts.get(sample["label"], 0) + 1
    return counts


if __name__ == "__main__":
    raise SystemExit(main())
