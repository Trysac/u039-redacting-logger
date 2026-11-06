"""Default sensitive key names and value patterns.

Sources, last reviewed 2026-11-05:

* bearer: RFC 6750 section 2.1 (``b64token`` syntax of the Bearer scheme).
* aws_key: AWS IAM identifiers (long-term ``AKIA`` and temporary ``ASIA`` key IDs).
* jwt: RFC 7519 and RFC 7515 (base64url segments; ``eyJ`` encodes an opening JSON object).
* private_key: RFC 7468 (PEM textual encoding of private keys).
* github_token: GitHub token formats (``ghp_``, ``gho_``, ``ghu_``, ``ghs_``, ``ghr_``).
* url_credentials: RFC 3986 section 3.2.1 (``user:password@`` userinfo).
* email: RFC 5322 addr-spec, reduced to a bounded practical subset.
* card: ISO/IEC 7812 numbers (13 to 19 digits) validated with the Luhn algorithm.

Every quantifier is bounded and none are nested, so matching time is bounded per
start position; the JWT pattern is guarded so hostile repeated prefixes stay fast.
"""

from __future__ import annotations

import re

_KEY_NAMES = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "set_cookie",
    "private_key",
    "client_secret",
    "access_key",
    "session",
)

DEFAULT_KEYS: frozenset[str] = frozenset(_KEY_NAMES)

_PEM_BEGIN = r"-----BEGIN [A-Z ]{0,40}PRIVATE KEY-----"
_PEM_END = r"-----END [A-Z ]{0,40}PRIVATE KEY-----"
_EMAIL_LOCAL = r"[A-Za-z0-9._%+-]{1,64}"
_EMAIL_LABEL = r"[A-Za-z0-9-]{1,63}"
_EMAIL_DOMAIN = _EMAIL_LABEL + r"(?:\." + _EMAIL_LABEL + r"){0,8}\.[A-Za-z]{2,63}\b"

_BEARER = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9\-._~+/]{8,4096}=*")
_AWS_KEY = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
# The header segment may not contain another "eyJ": a failed start then stops at the next
# candidate start, so inputs like "eyJ-eyJ-..." cost O(n) instead of O(n * 4096).
_JWT = re.compile(
    r"\beyJ(?:(?!eyJ)[A-Za-z0-9_-]){5,4096}\.[A-Za-z0-9_-]{5,8192}\.[A-Za-z0-9_-]{0,4096}"
)
_PRIVATE_KEY = re.compile(_PEM_BEGIN + r"(?s:.*?)(?:" + _PEM_END + r"|\Z)")
_GITHUB_TOKEN = re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b")
_URL_CREDENTIALS = re.compile(r"(?<=://)[^/\s:@]{1,256}:[^/\s@]{1,256}(?=@)")
_EMAIL = re.compile(_EMAIL_LOCAL + "@" + _EMAIL_DOMAIN)

# Candidate spans for card numbers; redact.py validates them with the Luhn check.
CARD_PATTERN = re.compile(r"(?<!\d)[0-9](?:[ -]?[0-9]){12,18}")

DEFAULT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("bearer", _BEARER),
    ("aws_key", _AWS_KEY),
    ("jwt", _JWT),
    ("private_key", _PRIVATE_KEY),
    ("github_token", _GITHUB_TOKEN),
    ("url_credentials", _URL_CREDENTIALS),
    ("email", _EMAIL),
    ("card", CARD_PATTERN),
)
