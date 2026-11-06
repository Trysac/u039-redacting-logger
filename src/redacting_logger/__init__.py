"""JSON log formatter and filter for stdlib logging that redact secrets and personal data."""

from __future__ import annotations

import logging

from .errors import RedactionError
from .logging_ext import JsonFormatter, RedactingFilter, make_handler
from .patterns import DEFAULT_KEYS, DEFAULT_PATTERNS
from .redact import redact
from .rules import RedactionRules

__all__ = [
    "DEFAULT_KEYS",
    "DEFAULT_PATTERNS",
    "JsonFormatter",
    "RedactingFilter",
    "RedactionError",
    "RedactionRules",
    "__version__",
    "make_handler",
    "redact",
]

__version__ = "0.1.0"

logging.getLogger(__name__).addHandler(logging.NullHandler())
