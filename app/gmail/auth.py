from __future__ import annotations

from pathlib import Path
from typing import Any

from app.config import settings


SCOPES = [
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.labels",
]


class GmailAuthError(RuntimeError):
    pass


def build_gmail_service(
    credentials_file: Path | None = None,
    token_file: Path | None = None,
    *,
    allow_interactive: bool = False,
) -> Any:
    try:
        from google.auth.exceptions import RefreshError
        from google.auth.transport.requests import Request
        from google.oauth2.credentials import Credentials
        from google_auth_oauthlib.flow import InstalledAppFlow
        from googleapiclient.discovery import build
    except ImportError as exc:
        raise GmailAuthError("缺少 Google API 套件，請先執行 pip install -r requirements.txt。") from exc

    credentials_file = _resolve_credentials_file(credentials_file)
    token_file = token_file or settings.token_file

    if not credentials_file.exists() and not token_file.exists():
        raise GmailAuthError(
            f"找不到 {credentials_file}。請先到 Google Cloud Console 建立 OAuth Desktop Client，"
            "下載 credentials.json 或 client_secret_*.json 後放在專案根目錄。"
        )

    creds = None
    if token_file.exists():
        creds = Credentials.from_authorized_user_file(str(token_file), SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
            except RefreshError:
                if not credentials_file.exists():
                    raise GmailAuthError(f"token 已過期或遭撤銷，且找不到 {credentials_file}，無法重新授權。")
                if not allow_interactive:
                    raise GmailAuthError("Gmail OAuth token 已過期或遭撤銷，請先執行 ./run.sh auth 重新授權。")
                flow = InstalledAppFlow.from_client_secrets_file(str(credentials_file), SCOPES)
                creds = flow.run_local_server(port=0, open_browser=False)
        else:
            if not credentials_file.exists():
                raise GmailAuthError(f"token 已失效且找不到 {credentials_file}，無法重新授權。")
            if not allow_interactive:
                raise GmailAuthError("尚未完成 Gmail OAuth，請先執行 ./run.sh auth。")
            flow = InstalledAppFlow.from_client_secrets_file(str(credentials_file), SCOPES)
            creds = flow.run_local_server(port=0, open_browser=False)
        token_file.write_text(creds.to_json(), encoding="utf-8")

    return build("gmail", "v1", credentials=creds)


def _resolve_credentials_file(explicit_file: Path | None = None) -> Path:
    if explicit_file is not None:
        return explicit_file

    configured = settings.credentials_file
    if configured.exists():
        return configured

    project_root = Path(__file__).resolve().parents[2]
    search_dirs = list(dict.fromkeys([Path.cwd(), project_root]))
    for directory in search_dirs:
        for candidate in sorted(directory.glob("client_secret_*.json")):
            if candidate.is_file():
                return candidate

    return configured
