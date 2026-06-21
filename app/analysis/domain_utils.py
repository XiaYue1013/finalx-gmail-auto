from __future__ import annotations

import re


KNOWN_PUBLIC_SUFFIXES = {
    "com.tw",
    "net.tw",
    "org.tw",
    "gov.tw",
    "edu.tw",
    "co.uk",
    "org.uk",
    "com.au",
    "co.jp",
}

BARE_FILENAME_TLDS = {
    "avi",
    "css",
    "csv",
    "doc",
    "docx",
    "gif",
    "htm",
    "html",
    "ico",
    "jpeg",
    "jpg",
    "json",
    "map",
    "md",
    "pdf",
    "png",
    "ppt",
    "pptx",
    "svg",
    "txt",
    "webp",
    "xls",
    "xlsx",
    "xml",
}
TECHNICAL_SUFFIXES = {"block", "contactus", "externalclass", "imagefix", "inline", "msonormal", "preheader", "vb"}
RESERVED_LOOKUP_TLDS = {"example", "invalid", "localhost", "local", "test"}
DOMAIN_LABEL_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)


def email_domain(email: str) -> str | None:
    if not email or "@" not in email:
        return None
    return email.rsplit("@", 1)[-1].strip().lower().strip(".") or None


def org_domain(domain: str) -> str:
    parts = domain.lower().strip(".").split(".")
    if len(parts) <= 2:
        return domain.lower().strip(".")
    suffix = ".".join(parts[-2:])
    if suffix in KNOWN_PUBLIC_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def same_org_domain(left: str, right: str) -> bool:
    return org_domain(left) == org_domain(right)


def is_probable_domain(domain: str | None) -> bool:
    if not domain:
        return False
    lowered = domain.lower().strip(".")
    parts = lowered.split(".")
    if len(parts) < 2:
        return False
    if all(part.isdigit() for part in parts):
        return False
    if any(not DOMAIN_LABEL_PATTERN.match(part) for part in parts):
        return False
    tld = parts[-1]
    if not tld.isalpha() or not (2 <= len(tld) <= 24):
        return False
    if tld in BARE_FILENAME_TLDS or tld in TECHNICAL_SUFFIXES:
        return False
    return True


def is_external_lookup_domain(domain: str | None) -> bool:
    if not is_probable_domain(domain):
        return False
    tld = domain.lower().strip(".").rsplit(".", 1)[-1]
    return tld not in RESERVED_LOOKUP_TLDS
