"""Redaction rules and their validation."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .errors import RedactionError
from .patterns import DEFAULT_KEYS, DEFAULT_PATTERNS

MAX_PATTERN_CHARS = 500
MAX_PATTERNS = 64

_MAX_PLACEHOLDER_CHARS = 200
_NAME_RE = re.compile(r"[a-z][a-z0-9_]{0,19}")
_NAME_MESSAGE = "pattern name must match ^[a-z][a-z0-9_]{0,19}$"


def _bad_rules(message: str) -> RedactionError:
    return RedactionError("invalid_rules", message)


def _check_int(name: str, value: object, high: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= high:
        raise _bad_rules(f"{name} must be an integer between 1 and {high}")


def _valid_name(name: object) -> bool:
    return isinstance(name, str) and _NAME_RE.fullmatch(name) is not None


def _valid_keys(keys: object) -> bool:
    if not isinstance(keys, set | frozenset):
        return False
    return all(isinstance(key, str) and key != "" for key in keys)


def _valid_entry(entry: object) -> bool:
    if not isinstance(entry, tuple) or len(entry) != 2:
        return False
    return _valid_name(entry[0]) and isinstance(entry[1], re.Pattern)


def _valid_patterns(patterns: object) -> bool:
    if not isinstance(patterns, tuple) or len(patterns) > MAX_PATTERNS:
        return False
    return all(_valid_entry(entry) for entry in patterns)


def _valid_placeholder(value: object) -> bool:
    return isinstance(value, str) and len(value) <= _MAX_PLACEHOLDER_CHARS


def _compile(regex: object) -> re.Pattern[str]:
    if not isinstance(regex, str) or len(regex) > MAX_PATTERN_CHARS:
        raise RedactionError("invalid_pattern", "regex must be a string of at most 500 chars")
    try:
        compiled = re.compile(regex)
    except (re.error, RecursionError, OverflowError):
        raise RedactionError("invalid_pattern", "regex does not compile") from None
    if compiled.search("") is not None:
        raise RedactionError("invalid_pattern", "regex must not match the empty string")
    return compiled


@dataclass
class RedactionRules:
    """Configuration shared by :func:`redact`, the filter and the formatter.

    Attributes:
        sensitive_keys: Key names whose values are replaced by ``placeholder``.
        patterns: ``(name, compiled regex)`` pairs applied to every string, in order.
        placeholder: Replacement for values stored under a sensitive key.
        max_value_chars: Longest string kept; the rest is cut and ``[TRUNCATED]`` appended.
        max_items: Most items kept per list, tuple or mapping.
        max_depth: Deepest container nesting kept; deeper containers become ``[TRUNCATED]``.

    Raises:
        RedactionError: with code ``invalid_rules`` when a field is out of range or malformed.
    """

    sensitive_keys: frozenset[str] = DEFAULT_KEYS
    patterns: tuple[tuple[str, re.Pattern[str]], ...] = DEFAULT_PATTERNS
    placeholder: str = "[REDACTED]"
    max_value_chars: int = 100_000
    max_items: int = 1000
    max_depth: int = 10

    def __post_init__(self) -> None:
        if not _valid_keys(self.sensitive_keys):
            raise _bad_rules("sensitive_keys must be a set of non-empty strings")
        self.sensitive_keys = frozenset(self.sensitive_keys)
        if not _valid_patterns(self.patterns):
            raise _bad_rules("patterns must be a tuple of (name, compiled pattern) pairs")
        if not _valid_placeholder(self.placeholder):
            raise _bad_rules("placeholder must be a string of at most 200 characters")
        _check_int("max_value_chars", self.max_value_chars, 10_000_000)
        _check_int("max_items", self.max_items, 100_000)
        _check_int("max_depth", self.max_depth, 50)

    def add_pattern(self, name: str, regex: str) -> None:
        """Register an extra value pattern replaced by ``[REDACTED:<name>]``.

        Args:
            name: Pattern name matching ``^[a-z][a-z0-9_]{0,19}$``.
            regex: Regular expression of at most 500 characters. It must compile and must
                not match the empty string. Callers are responsible for avoiding
                catastrophic backtracking in their own expressions.

        Raises:
            RedactionError: ``invalid_rules`` for a bad name or too many patterns,
                ``invalid_pattern`` for a bad regex.
        """
        if not _valid_name(name):
            raise _bad_rules(_NAME_MESSAGE)
        if len(self.patterns) >= MAX_PATTERNS:
            raise _bad_rules(f"at most {MAX_PATTERNS} patterns are allowed")
        compiled = _compile(regex)
        self.patterns = (*self.patterns, (name, compiled))


def resolve_rules(rules: RedactionRules | None) -> RedactionRules:
    """Return ``rules``, a fresh default instance for ``None``, or raise on a wrong type."""
    if rules is None:
        return RedactionRules()
    if not isinstance(rules, RedactionRules):
        raise _bad_rules("rules must be a RedactionRules instance")
    return rules
