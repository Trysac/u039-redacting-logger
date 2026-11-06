"""Typed errors raised by the library."""

from __future__ import annotations

from typing import Literal

ErrorCode = Literal["invalid_pattern", "invalid_rules"]

_MAX_MESSAGE_CHARS = 200


class RedactionError(ValueError):
    """Raised when the redaction configuration is invalid.

    Attributes:
        code: Stable machine-readable error code, ``invalid_pattern`` or ``invalid_rules``.
    """

    def __init__(self, code: ErrorCode, message: str) -> None:
        super().__init__(message[:_MAX_MESSAGE_CHARS])
        self.code: ErrorCode = code
