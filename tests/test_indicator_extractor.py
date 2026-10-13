from app.analysis.indicator_extractor import IndicatorExtractor


def test_extractor_does_not_treat_email_domains_or_filenames_as_urls():
    indicators = IndicatorExtractor().extract(
        "From newsletter@techtrends.xiayue.tw, attachment windows_patch_update.js, "
        "visit https://portal.xiayue.tw/login"
    )

    emails = {item.value for item in indicators if item.type == "email"}
    domains = {item.value for item in indicators if item.type == "domain"}

    assert "newsletter@techtrends.xiayue.tw" in emails
    assert "portal.xiayue.tw" in domains
    assert "techtrends.xiayue.tw" not in domains
    assert "update.js" not in domains


def test_extractor_ignores_css_classes_filenames_and_ips_as_domains():
    indicators = IndicatorExtractor().extract(
        "files package-lock.json credentials.json 013920.png div.preheader a.block "
        "code.inline nte.contactus table.vb div.MsoNormal div.ExternalClass "
        "198.51.100.45 https://real.example.com/login"
    )

    domains = {item.value for item in indicators if item.type == "domain"}

    assert "package-lock.json" not in domains
    assert "credentials.json" not in domains
    assert "013920.png" not in domains
    assert "div.preheader" not in domains
    assert "a.block" not in domains
    assert "code.inline" not in domains
    assert "nte.contactus" not in domains
    assert "table.vb" not in domains
    assert "div.msonormal" not in domains
    assert "div.externalclass" not in domains
    assert "198.51.100.45" not in domains
    assert "real.example.com" in domains
