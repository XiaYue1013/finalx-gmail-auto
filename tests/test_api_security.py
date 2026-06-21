import pytest
from fastapi import HTTPException

from app.config import settings
from app import main as api_main


def test_dashboard_api_requires_token_when_configured(monkeypatch):
    monkeypatch.setattr(settings, "api_token", "secret-token")

    with pytest.raises(HTTPException) as exc_info:
        api_main.require_api_token(token=None, x_finalx_api_token=None)

    assert exc_info.value.status_code == 401
    api_main.require_api_token(token=None, x_finalx_api_token="secret-token")
    api_main.require_api_token(token="secret-token", x_finalx_api_token=None)


def test_dashboard_api_stays_open_when_token_is_not_configured(monkeypatch):
    monkeypatch.setattr(settings, "api_token", None)

    api_main.require_api_token(token=None, x_finalx_api_token=None)
