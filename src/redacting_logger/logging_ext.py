"""Logging integration: a redacting filter, a JSON formatter and a handler factory."""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import IO, Any

from .errors import RedactionError
from .redact import UNFORMATTABLE, redact, redact_for_json
from .rules import RedactionRules, resolve_rules

_PLAIN_FORMATTER = logging.Formatter()
_BLANK_RECORD = logging.LogRecord("x", logging.INFO, "x", 0, "", (), None)
_EXTRA_STANDARD = frozenset({"message", "asctime", "taskName"})
_STANDARD_ATTRS = frozenset(vars(_BLANK_RECORD)) | _EXTRA_STANDARD
_FALLBACK_LINE = '{"message":"[UNFORMATTABLE]"}'


def _exception_text(record: logging.LogRecord, formatter: logging.Formatter) -> str | None:
    """Return the raw (unredacted) exception text of ``record`` if it has one."""
    if record.exc_text:
        return record.exc_text
    info = record.exc_info
    if isinstance(info, tuple) and info[0] is not None:
        try:
            return formatter.formatException(info)
        except Exception:
            return UNFORMATTABLE
    return None


def _copy_static(fields: Mapping[str, Any] | None, limit: int) -> dict[str, Any]:
    if fields is None:
        return {}
    if not isinstance(fields, Mapping) or len(fields) > limit:
        raise RedactionError("invalid_rules", "static_fields must be a small mapping")
    if not all(isinstance(key, str) for key in fields):
        raise RedactionError("invalid_rules", "static_fields keys must be strings")
    return dict(fields)


class RedactingFilter(logging.Filter):
    """Logging filter that redacts a record in place before any handler formats it.

    The message is formatted first (``getMessage``), redacted, stored in ``record.msg``
    and ``record.args`` is set to ``None``. Extra attributes, ``exc_text`` (computed from
    ``exc_info`` when missing) and ``stack_info`` are redacted too.

    Raises:
        RedactionError: ``invalid_rules`` when ``rules`` is not a ``RedactionRules``.
    """

    def __init__(self, rules: RedactionRules | None = None) -> None:
        super().__init__()
        self._rules = resolve_rules(rules)

    def filter(self, record: logging.LogRecord) -> bool:
        """Redact ``record`` in place and always let it through."""
        rules = self._rules
        try:
            message = record.getMessage()
        except Exception:
            message = UNFORMATTABLE
        record.msg = redact(message, rules)
        record.args = None
        extras = {k: v for k, v in vars(record).items() if k not in _STANDARD_ATTRS}
        if extras:
            for name in extras:
                del vars(record)[name]
            vars(record).update(redact(extras, rules))
        exc_text = _exception_text(record, _PLAIN_FORMATTER)
        if exc_text:
            record.exc_text = redact(exc_text, rules)
        if record.stack_info:
            record.stack_info = redact(record.stack_info, rules)
        return True


class JsonFormatter(logging.Formatter):
    """Format records as one redacted, strict JSON object per line.

    Keys: ``ts`` (UTC, millisecond precision), ``level``, ``logger``, ``message``,
    ``exc_info`` and ``stack_info`` (when present), the static fields and the record's
    extras. Extras and static fields never override the core keys. ``format`` never
    raises: on any failure it returns ``{"message":"[UNFORMATTABLE]"}``.

    Raises:
        RedactionError: ``invalid_rules`` for a bad ``rules`` or ``static_fields`` argument.
    """

    def __init__(
        self,
        rules: RedactionRules | None = None,
        static_fields: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__()
        self._rules = resolve_rules(rules)
        self._static = _copy_static(static_fields, self._rules.max_items)

    def format(self, record: logging.LogRecord) -> str:
        """Return the JSON line for ``record`` without a trailing newline."""
        try:
            return self._render(record)
        except Exception:
            return _FALLBACK_LINE

    def _render(self, record: logging.LogRecord) -> str:
        try:
            message = record.getMessage()
        except Exception:
            message = UNFORMATTABLE
        moment = datetime.fromtimestamp(record.created, timezone.utc)
        payload: dict[str, Any] = {
            "ts": moment.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "level": record.levelname,
            "logger": record.name,
            "message": message,
        }
        exc_text = _exception_text(record, self)
        if exc_text:
            payload["exc_info"] = exc_text
        if record.stack_info:
            payload["stack_info"] = record.stack_info
        reserved = frozenset(payload)
        for key, value in self._static.items():
            if key not in reserved:
                payload[key] = value
        for key, value in vars(record).items():
            if key not in _STANDARD_ATTRS and key not in reserved:
                payload[key] = value
        return json.dumps(
            redact_for_json(payload, self._rules),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )


def make_handler(
    stream: IO[str],
    rules: RedactionRules | None = None,
    static_fields: Mapping[str, Any] | None = None,
) -> logging.Handler:
    """Return a ``StreamHandler`` writing redacted JSON lines to ``stream``.

    The handler carries a :class:`RedactingFilter` and a :class:`JsonFormatter` built from
    the same rules. The root logger is never touched; attach the handler yourself.
    """
    resolved = resolve_rules(rules)
    handler = logging.StreamHandler(stream)
    handler.addFilter(RedactingFilter(resolved))
    handler.setFormatter(JsonFormatter(resolved, static_fields))
    return handler
