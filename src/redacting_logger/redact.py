"""Recursive redaction of strings and containers."""

from __future__ import annotations

import math
import re
from collections.abc import Mapping
from typing import Any

from .patterns import CARD_PATTERN
from .rules import RedactionRules, resolve_rules

TRUNCATED = "[TRUNCATED]"
CYCLE = "[CYCLE]"
UNFORMATTABLE = "[UNFORMATTABLE]"

_MAX_INT_BITS = 4096
_MIN_CARD_DIGITS = 13
_MAX_CARD_DIGITS = 19
_WORD = re.compile(r"\w")
_DEFAULT_RULES = RedactionRules()
_Sequence = list[Any] | tuple[Any, ...]


def _normalise_key(key: str) -> str:
    return key.casefold().replace("-", "_").replace(" ", "_")


def _nonfinite_name(value: float) -> str:
    if math.isnan(value):
        return "NaN"
    return "Infinity" if value > 0 else "-Infinity"


def _clean(text: str) -> str:
    """Replace characters that cannot be encoded as UTF-8 (lone surrogates)."""
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return text.encode("utf-8", errors="replace").decode("utf-8")
    return text


def _luhn_valid(digits: str) -> bool:
    total = 0
    for index, char in enumerate(reversed(digits)):
        number = ord(char) - 48
        if index % 2 == 1:
            number *= 2
            if number > 9:
                number -= 9
        total += number
    return total % 10 == 0


def _card_end(text: str, start: int, end: int) -> int | None:
    """Return the end of the longest Luhn-valid card span within ``text[start:end]``.

    The greedy span is tried first, then shorter prefixes that end right before a
    separator, longest first. The span must not be followed by a word character.
    """
    ends: list[int] = []
    digits = 0
    for index in range(start, end):
        if text[index] in " -":
            if _MIN_CARD_DIGITS <= digits <= _MAX_CARD_DIGITS:
                ends.append(index)
        else:
            digits += 1
    if _MIN_CARD_DIGITS <= digits <= _MAX_CARD_DIGITS and _WORD.match(text, end) is None:
        ends.append(end)
    for candidate in reversed(ends):
        compact = text[start:candidate].replace(" ", "").replace("-", "")
        if _luhn_valid(compact):
            return candidate
    return None


def _redact_cards(text: str, replacement: str) -> str:
    pieces: list[str] = []
    last = 0
    position = 0
    while True:
        match = CARD_PATTERN.search(text, position)
        if match is None:
            break
        start = match.start()
        end = _card_end(text, start, match.end())
        if end is None:
            position = start + 1
            continue
        pieces.append(text[last:start])
        pieces.append(replacement)
        last = end
        position = end
    pieces.append(text[last:])
    return "".join(pieces)


def _apply(name: str, pattern: re.Pattern[str], text: str) -> str:
    replacement = f"[REDACTED:{name}]"
    if pattern is CARD_PATTERN:
        return _redact_cards(text, replacement)
    return pattern.sub(lambda _match: replacement, text)


class _Walker:
    """One redaction pass over a value; holds the cycle guard for that pass."""

    def __init__(self, rules: RedactionRules, json_mode: bool) -> None:
        self._rules = rules
        self._json = json_mode
        self._names = frozenset(_normalise_key(name) for name in rules.sensitive_keys)
        self._active: set[int] = set()

    def walk(self, value: Any, depth: int) -> Any:
        try:
            return self._walk(value, depth)
        except Exception:
            return UNFORMATTABLE

    def _walk(self, value: Any, depth: int) -> Any:
        if value is None or isinstance(value, bool):
            return value
        if isinstance(value, str):
            return self._string(value)
        if isinstance(value, bytes | bytearray):
            return self._string(bytes(value).decode("utf-8", errors="replace"))
        if isinstance(value, int):
            if self._json and value.bit_length() > _MAX_INT_BITS:
                return TRUNCATED
            return value
        if isinstance(value, float):
            if self._json and not math.isfinite(value):
                return _nonfinite_name(value)
            return value
        if isinstance(value, Mapping | list | tuple):
            return self._container(value, depth)
        return self._string(repr(value))

    def _container(self, value: Any, depth: int) -> Any:
        if depth > self._rules.max_depth:
            return TRUNCATED
        identity = id(value)
        if identity in self._active:
            return CYCLE
        self._active.add(identity)
        try:
            if isinstance(value, Mapping):
                return self._mapping(value, depth)
            return self._sequence(value, depth)
        finally:
            self._active.discard(identity)

    def _mapping(self, value: Mapping[Any, Any], depth: int) -> dict[Any, Any]:
        limit = self._rules.max_items
        result: dict[Any, Any] = {}
        for count, (key, item) in enumerate(value.items()):
            if count >= limit:
                result[TRUNCATED] = len(value) - count
                break
            new_key = self._key(key)
            sensitive = isinstance(key, str) and self._is_sensitive(key)
            result[new_key] = self._rules.placeholder if sensitive else self.walk(item, depth + 1)
        return result

    def _sequence(self, value: _Sequence, depth: int) -> Any:
        limit = self._rules.max_items
        items: list[Any] = []
        for index, item in enumerate(value):
            if index >= limit:
                items.append(TRUNCATED)
                break
            items.append(self.walk(item, depth + 1))
        return tuple(items) if isinstance(value, tuple) else items

    def _key(self, key: Any) -> Any:
        if isinstance(key, str):
            return self._string(key)
        if not self._json and (key is None or isinstance(key, bool | int | float)):
            return key
        return self._string(repr(key))

    def _is_sensitive(self, key: str) -> bool:
        normal = _normalise_key(key)
        return any(normal == name or normal.endswith("_" + name) for name in self._names)

    def _string(self, text: str) -> str:
        rules = self._rules
        limit = rules.max_value_chars
        cut = len(text) > limit
        if cut:
            text = text[:limit]
        for name, pattern in rules.patterns:
            text = _apply(name, pattern, text)
        if cut:
            text += TRUNCATED
        return _clean(text) if self._json else text


def redact(value: Any, rules: RedactionRules = _DEFAULT_RULES) -> Any:
    """Return a redacted copy of ``value``.

    Strings are cut to ``rules.max_value_chars`` and every pattern is applied. Bytes are
    decoded with ``errors="replace"``. Dicts, lists and tuples are copied recursively
    (keys are pattern-redacted, values under sensitive keys are replaced by the
    placeholder). ``None``, booleans, integers and floats are returned unchanged; any
    other object is replaced by its redacted ``repr``. Cycles become ``[CYCLE]``, excess
    nesting or items become ``[TRUNCATED]`` and a failing ``repr`` becomes
    ``[UNFORMATTABLE]``. The input is never mutated.

    Raises:
        RedactionError: ``invalid_rules`` when ``rules`` is not a ``RedactionRules``.
    """
    return _Walker(resolve_rules(rules), json_mode=False).walk(value, 0)


def redact_for_json(value: Any, rules: RedactionRules) -> Any:
    """Like :func:`redact` but the result only holds JSON-safe values.

    Non-finite floats become ``"NaN"``, ``"Infinity"`` or ``"-Infinity"``, dict keys become
    strings, huge integers are truncated and unencodable characters are replaced.
    """
    return _Walker(rules, json_mode=True).walk(value, 0)
