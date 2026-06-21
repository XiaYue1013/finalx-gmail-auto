from __future__ import annotations

from typing import Any

from app.config import settings
from app.gmail.auth import build_gmail_service


class GmailClient:
    def __init__(self, service: Any | None = None) -> None:
        self.service = service or build_gmail_service()

    def list_candidates(self, query: str, max_results: int, max_pages: int = 1) -> list[dict[str, str]]:
        messages: list[dict[str, str]] = []
        page_token: str | None = None
        for _ in range(max_pages):
            response = (
                self.service.users()
                .messages()
                .list(
                    userId="me",
                    q=query,
                    maxResults=max_results,
                    includeSpamTrash=False,
                    pageToken=page_token,
                )
                .execute()
            )
            messages.extend(response.get("messages") or [])
            page_token = response.get("nextPageToken")
            if not page_token:
                break
        return messages

    def get_message(self, message_id: str) -> dict:
        return self.service.users().messages().get(userId="me", id=message_id, format="full").execute()

    def ensure_label(self, name: str) -> str:
        labels = self.service.users().labels().list(userId="me").execute().get("labels") or []
        for label in labels:
            if label.get("name") == name:
                return str(label["id"])
        body = {
            "name": name,
            "labelListVisibility": "labelShow",
            "messageListVisibility": "show",
        }
        created = self.service.users().labels().create(userId="me", body=body).execute()
        return str(created["id"])

    def add_labels(self, message_id: str, label_ids: list[str]) -> None:
        if not label_ids:
            return
        body = {"addLabelIds": list(dict.fromkeys(label_ids))}
        self.service.users().messages().modify(userId="me", id=message_id, body=body).execute()

    def watch(self, topic_name: str, label_ids: list[str], label_filter_behavior: str = "INCLUDE") -> dict:
        body: dict[str, Any] = {
            "topicName": topic_name,
            "labelIds": label_ids,
            "labelFilterBehavior": label_filter_behavior,
        }
        return self.service.users().watch(userId="me", body=body).execute()

    def stop_watch(self) -> None:
        self.service.users().stop(userId="me").execute()

    def list_history(
        self,
        *,
        start_history_id: str,
        label_id: str | None = "INBOX",
        history_types: list[str] | None = None,
        max_results: int | None = None,
        max_pages: int | None = None,
    ) -> tuple[list[dict], str | None]:
        history: list[dict] = []
        page_token: str | None = None
        current_history_id: str | None = None
        max_results = max_results or settings.gmail_history_max_results
        max_pages = max_pages or settings.gmail_history_max_pages
        history_types = history_types or ["messageAdded"]

        for _ in range(max_pages):
            request = self.service.users().history().list(
                userId="me",
                startHistoryId=start_history_id,
                labelId=label_id,
                historyTypes=history_types,
                maxResults=max_results,
                pageToken=page_token,
            )
            response = request.execute()
            history.extend(response.get("history") or [])
            current_history_id = response.get("historyId") or current_history_id
            page_token = response.get("nextPageToken")
            if not page_token:
                break
        return history, current_history_id
