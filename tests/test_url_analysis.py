from app.analysis.url_analysis_service import UrlAnalysisService
from app.models import ExtractedIndicator


def test_encrypted_tracking_token_is_not_treated_as_redirect_domain():
    url = (
        "https://mhurcv.taishinbank.com.tw/taishin_a/click.aspx?"
        "url=p%2b5Ldcp0o4CB1UXVlTtHKe4bPG%2bcn3RRdog4uLrbEFtsSt8HJLExxjCEH%2bAVE1xw"
        "&link_id=1037755"
    )
    evidence = UrlAnalysisService().analyze(
        [ExtractedIndicator(type="url", value=url, normalized=url, label="網址")]
    )

    assert all(item.title != "網址含外部跳轉目標" for item in evidence)


def test_explicit_redirect_url_is_still_flagged():
    url = "https://tracker.example/click?url=https%3A%2F%2Fphishing.example%2Flogin"
    evidence = UrlAnalysisService().analyze(
        [ExtractedIndicator(type="url", value=url, normalized=url, label="網址")]
    )

    assert any(item.title == "網址含外部跳轉目標" for item in evidence)


def test_same_organization_redirect_is_not_flagged():
    url = "https://accounts.google.com/AccountChooser?continue=https%3A%2F%2Fmyaccount.google.com%2Fconnections%2Foverview"
    evidence = UrlAnalysisService().analyze(
        [ExtractedIndicator(type="url", value=url, normalized=url, label="網址")]
    )

    assert all(item.title != "網址含外部跳轉目標" for item in evidence)
