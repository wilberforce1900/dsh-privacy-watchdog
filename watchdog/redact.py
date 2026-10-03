"""Sensitive-data redaction for evidence text before it is stored or shared."""
from __future__ import annotations

import os
import re

_SECRET_PATTERNS = [
    (re.compile(r"sk-[A-Za-z0-9_\-]{8,}"), "sk-***REDACTED***"),
    (re.compile(r"ghp_[A-Za-z0-9]{16,}"), "ghp_***REDACTED***"),
    (re.compile(r"gh[roup]_[A-Za-z0-9]{16,}"), "gh-***REDACTED***"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AKIA***REDACTED***"),
    (re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{12,}"), "Bearer ***REDACTED***"),
    (re.compile(r"(?i)api[_-]?key[\"'\s:=]+[A-Za-z0-9._\-]{12,}"), 'api_key="***REDACTED***"'),
    (re.compile(r"(?i)password[\"'\s:=]+[A-Za-z0-9._\-]{4,}"), 'password="***REDACTED***"'),
    (re.compile(r"(?i)\btoken[\"'\s:=]+[A-Za-z0-9._\-]{12,}"), 'token="***REDACTED***"'),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
     "***PRIVATE-KEY-BLOCK***"),
    (re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"), "***EMAIL***"),
]


def redact(text: str) -> str:
    """Mask obvious secrets/PII. Also collapses the real home directory to '~'."""
    if not text:
        return text
    home = os.path.expanduser("~")
    if home and home != "/":
        text = text.replace(home, "~")
    for pattern, replacement in _SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    return text
