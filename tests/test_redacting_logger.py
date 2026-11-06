"""Tests for the public API of redacting_logger."""

from __future__ import annotations

import io
import json
import logging
import math
import re
import sys
from typing import Any

import pytest

import redacting_logger
from redacting_logger import (
    DEFAULT_KEYS,
    DEFAULT_PATTERNS,
    JsonFormatter,
    RedactingFilter,
    RedactionError,
    RedactionRules,
    make_handler,
    redact,
)
from redacting_logger.rules import MAX_PATTERNS

GITHUB = "ghp_" + "b" * 36
JWT = "ey" + "JhbGciOiJIUzI1NiJ9." + "ey" + "JzdWIiOiIxMjM0In0." + "c2lnbmF0dXJl"
PEM = "\n".join(
    [
        "-----BEGIN RSA " + "PRIVATE KEY-----",
        "QUJDREVGR0hJSktMTU5PUA==",
        "-----END RSA " + "PRIVATE KEY-----",
    ]
)

SAMPLES = [
    ("bearer", "Bearer abcdef123456", "abcdef123456"),
    ("aws_key", "AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"),
    ("jwt", JWT, "ey" + "JzdWIiOiIxMjM0In0"),
    ("private_key", PEM, "QUJDREVGR0hJSktMTU5PUA=="),
    ("github_token", GITHUB, GITHUB),
    ("url_credentials", "https://u:p@h/x", "u:p@h"),
    ("email", "a@b.co", "a@b.co"),
    ("card", "4111 1111 1111 1111", "4111 1111 1111 1111"),
]


class _BadRepr:
    def __repr__(self) -> str:
        raise RuntimeError("no repr")


class _Thing:
    def __repr__(self) -> str:
        return "Thing " + GITHUB


class _BrokenFormatter(JsonFormatter):
    def formatException(self, ei: Any) -> str:
        raise RuntimeError("broken")


def _reject(constant: str) -> Any:
    raise AssertionError("non-finite constant " + constant)


def _record(
    msg: str = "hi",
    args: Any = (),
    *,
    extra: dict[str, Any] | None = None,
    exc_info: Any = None,
    created: float = 0.0,
) -> logging.LogRecord:
    logger = logging.getLogger("app")
    record = logger.makeRecord("app", logging.INFO, "f.py", 1, msg, args, exc_info, extra=extra)
    record.created = created
    return record


def _emit(record: logging.LogRecord, **kwargs: Any) -> str:
    stream = io.StringIO()
    make_handler(stream, **kwargs).handle(record)
    return stream.getvalue()


def _load(line: str) -> dict[str, Any]:
    assert line.endswith("\n")
    assert line.count("\n") == 1
    loaded = json.loads(line, parse_constant=_reject)
    assert isinstance(loaded, dict)
    return loaded


def _exc_info(text: str) -> Any:
    try:
        raise ValueError(text)
    except ValueError:
        return sys.exc_info()


def test_exact_line_for_epoch_record() -> None:
    line = _emit(_record("hi", extra={"user": "x"}))
    parts = [
        '{"level":"INFO"',
        '"logger":"app"',
        '"message":"hi"',
        '"ts":"1970-01-01T00:00:00.000Z"',
        '"user":"x"}',
    ]
    assert line == ",".join(parts) + "\n"


def test_timestamp_has_millisecond_precision() -> None:
    line = _emit(_record(created=1.001))
    assert _load(line)["ts"] == "1970-01-01T00:00:01.001Z"


def test_sensitive_keys_are_redacted_and_lookalikes_kept() -> None:
    extra = {
        "db": {"Password": "p", "x-api-key": "k", "Set-Cookie": "c"},
        "input_tokens": 10,
        "tokens_used": 3,
    }
    line = _emit(_record(extra=extra))
    inner = ",".join(
        [
            '"Password":"[REDACTED]"',
            '"Set-Cookie":"[REDACTED]"',
            '"x-api-key":"[REDACTED]"',
        ]
    )
    assert '"db":{' + inner + "}" in line
    assert '"input_tokens":10' in line
    assert '"tokens_used":3' in line


def test_message_is_redacted_after_formatting_and_args_stay_none() -> None:
    stream = io.StringIO()
    logger = logging.getLogger("tests.bearer")
    logger.propagate = False
    logger.setLevel(logging.INFO)
    handler = make_handler(stream)
    logger.addHandler(handler)
    try:
        logger.info("auth %s", "Bearer abcdef123456,")
    finally:
        logger.removeHandler(handler)
    assert _load(stream.getvalue())["message"] == "auth [REDACTED:bearer],"
    args = ("Bearer abcdef123456,",)
    record = logging.LogRecord("app", logging.INFO, "f.py", 1, "auth %s", args, None)
    assert RedactingFilter().filter(record) is True
    assert record.args is None
    assert record.msg == "auth [REDACTED:bearer],"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("AKIAIOSFODNN7EXAMPLE", "[REDACTED:aws_key]"),
        ("ghp_" + "a" * 36, "[REDACTED:github_token]"),
        (JWT, "[REDACTED:jwt]"),
        (PEM, "[REDACTED:private_key]"),
        ("a@b.co.", "[REDACTED:email]."),
        ("4111 1111 1111 1111", "[REDACTED:card]"),
        ("https://u:p@h/x", "https://[REDACTED:url_credentials]@h/x"),
    ],
)
def test_default_patterns(raw: str, expected: str) -> None:
    assert redact(raw) == expected


def test_card_adjacency() -> None:
    assert redact("4111 1111 1111 1111 12/27") == "[REDACTED:card] 12/27"
    assert redact("4111 1111 1111 1112") == "4111 1111 1111 1112"
    assert redact("ghp_" + "a" * 37) == "ghp_" + "a" * 37


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("4111-1111-1111-1111", "[REDACTED:card]"),
        ("pay 4111111111111111.", "pay [REDACTED:card]."),
        ("4111111111111111x", "4111111111111111x"),
        ("41111111111111111111", "41111111111111111111"),
        ("ghp_" + "a" * 36 + " AKIAIOSFODNN7EXAMPLE", "[REDACTED:github_token] [REDACTED:aws_key]"),
        ("xghp_" + "a" * 36, "xghp_" + "a" * 36),
        ("AKIAIOSFODNN7EXAMPLEX", "AKIAIOSFODNN7EXAMPLEX"),
        ("<a@b.co>", "<[REDACTED:email]>"),
        ("see a@b.co and c@d.org", "see [REDACTED:email] and [REDACTED:email]"),
        ("Bearer short", "Bearer short"),
        ("bearer abcdefgh12==", "[REDACTED:bearer]"),
        ("user:pw@host", "user:pw@host"),
        ("ftp://u:p@h.co/x", "ftp://[REDACTED:url_credentials]@h.co/x"),
        ("x -----BEGIN PRIVATE KEY-----\nabc", "x [REDACTED:private_key]"),
        ("ey" + "JhbGciOiJIUzI1NiJ9." + "ey" + "JzdWIiOiIxMjM0In0.", "[REDACTED:jwt]"),
        ("12/27 2024-01-01", "12/27 2024-01-01"),
    ],
)
def test_pattern_neighbours(raw: str, expected: str) -> None:
    assert redact(raw) == expected


@pytest.mark.parametrize(("name", "text", "needle"), SAMPLES)
def test_every_pattern_is_redacted_on_every_surface(name: str, text: str, needle: str) -> None:
    tag = "[REDACTED:" + name + "]"
    records = {
        "message": _record(text),
        "args": _record("v=%s", (text,)),
        "extra": _record(extra={"v": text}),
        "key": _record(extra={"d": {text: 1}}),
        "traceback": _record("failed", exc_info=_exc_info(text)),
    }
    for surface, record in records.items():
        line = _emit(record)
        assert needle not in line, surface
        assert tag in line, surface


def test_planted_secret_never_reaches_the_line() -> None:
    extra = {"nested": {"inner": [GITHUB], GITHUB: 1}}
    record = _record("boom", extra=extra, exc_info=_exc_info(GITHUB))
    record.stack_info = "Stack " + GITHUB
    line = _emit(record)
    assert GITHUB not in line
    data = _load(line)
    assert "Traceback" in data["exc_info"]
    assert "[REDACTED:github_token]" in data["exc_info"]
    expected = {"inner": ["[REDACTED:github_token]"], "[REDACTED:github_token]": 1}
    assert data["nested"] == expected
    assert data["stack_info"] == "Stack [REDACTED:github_token]"


def test_formatter_alone_redacts_without_the_filter() -> None:
    record = _record("x", extra={"v": GITHUB}, exc_info=_exc_info(GITHUB))
    line = JsonFormatter().format(record)
    assert GITHUB not in line
    assert json.loads(line, parse_constant=_reject)["v"] == "[REDACTED:github_token]"


def test_formatter_never_raises_and_output_is_strict_json() -> None:
    cycle: dict[str, Any] = {}
    cycle["self"] = cycle
    deep: Any = {}
    for _ in range(11):
        deep = {"k": deep}
    extra = {
        "nan": float("nan"),
        "inf": float("inf"),
        "ninf": float("-inf"),
        "cycle": cycle,
        "deep": deep,
        "bad": _BadRepr(),
    }
    data = _load(_emit(_record(extra=extra)))
    assert data["nan"] == "NaN"
    assert data["inf"] == "Infinity"
    assert data["ninf"] == "-Infinity"
    assert data["cycle"] == {"self": "[CYCLE]"}
    assert data["bad"] == "[UNFORMATTABLE]"
    assert "[TRUNCATED]" in json.dumps(data["deep"])


def test_exotic_values_are_serialisable() -> None:
    extra = {
        "set": {1},
        "bytes": b"ab",
        "keys": {2: "b", 1: "a", None: "n"},
        "lone": "\ud800",
        "big": 10**5000,
        "tuple": (1, 2),
    }
    data = _load(_emit(_record(extra=extra)))
    assert data["set"] == "{1}"
    assert data["bytes"] == "ab"
    assert data["keys"] == {"1": "a", "2": "b", "None": "n"}
    assert data["lone"] == "?"
    assert data["big"] == "[TRUNCATED]"
    assert data["tuple"] == [1, 2]


def test_unformattable_record_uses_fallback_line() -> None:
    record = _record(created=float("inf"))
    assert JsonFormatter().format(record) == '{"message":"[UNFORMATTABLE]"}'


def test_bad_message_arguments_do_not_raise() -> None:
    data = _load(_emit(_record("%s %s", ("a",))))
    assert data["message"] == "[UNFORMATTABLE]"


def test_exception_text_variants() -> None:
    record = _record()
    record.exc_text = "old " + GITHUB
    data = json.loads(JsonFormatter().format(record))
    assert data["exc_info"] == "old [REDACTED:github_token]"
    empty = _record(exc_info=(None, None, None))
    assert "exc_info" not in json.loads(JsonFormatter().format(empty))
    assert "exc_info" not in json.loads(JsonFormatter().format(_record(exc_info=True)))
    broken = _record(exc_info=_exc_info("x"))
    assert json.loads(_BrokenFormatter().format(broken))["exc_info"] == "[UNFORMATTABLE]"


def test_core_keys_cannot_be_overridden_and_static_fields_are_redacted() -> None:
    extra = {"ts": "evil", "level": "evil", "logger": "evil", "other": 1}
    static = {"message": "evil", "svc": "api", "other": 0, "password": "x"}
    data = _load(_emit(_record("m", extra=extra), static_fields=static))
    assert data["ts"] == "1970-01-01T00:00:00.000Z"
    assert data["level"] == "INFO"
    assert data["logger"] == "app"
    assert data["message"] == "m"
    assert data["svc"] == "api"
    assert data["other"] == 1
    assert data["password"] == "[REDACTED]"  # noqa: S105


def test_invalid_formatter_arguments() -> None:
    with pytest.raises(RedactionError) as bad_rules:
        JsonFormatter("rules")  # type: ignore[arg-type]
    assert bad_rules.value.code == "invalid_rules"
    for static in ({1: "a"}, "text"):
        with pytest.raises(RedactionError) as bad_static:
            JsonFormatter(static_fields=static)  # type: ignore[arg-type]
        assert bad_static.value.code == "invalid_rules"
    small = RedactionRules(max_items=1)
    with pytest.raises(RedactionError) as too_many:
        JsonFormatter(small, {"a": 1, "b": 2})
    assert too_many.value.code == "invalid_rules"
    with pytest.raises(RedactionError):
        RedactingFilter("rules")  # type: ignore[arg-type]
    with pytest.raises(RedactionError):
        redact("x", "rules")  # type: ignore[arg-type]


def test_filter_redacts_record_in_place() -> None:
    mapping_args = {"a": "Bearer abcdef123456"}
    record = logging.LogRecord("app", logging.INFO, "f.py", 1, "%(a)s", (mapping_args,), None)
    record.user = "a@b.co"
    record.password = "p"  # noqa: S105
    record.exc_text = "trace " + GITHUB
    record.stack_info = "stack " + GITHUB
    vars(record)["x@y.org"] = 1
    assert RedactingFilter().filter(record) is True
    assert record.msg == "[REDACTED:bearer]"
    assert record.args is None
    assert record.user == "[REDACTED:email]"
    assert record.password == "[REDACTED]"  # noqa: S105
    assert record.exc_text == "trace [REDACTED:github_token]"
    assert record.stack_info == "stack [REDACTED:github_token]"
    assert "x@y.org" not in vars(record)
    assert vars(record)["[REDACTED:email]"] == 1


def test_filter_computes_and_redacts_exception_text() -> None:
    record = logging.LogRecord("app", logging.ERROR, "f.py", 1, "m", (), _exc_info(GITHUB))
    RedactingFilter().filter(record)
    assert record.exc_text is not None
    assert "Traceback" in record.exc_text
    assert GITHUB not in record.exc_text
    assert "[REDACTED:github_token]" in record.exc_text


def test_filter_survives_bad_message_arguments() -> None:
    record = logging.LogRecord("app", logging.INFO, "f.py", 1, "%s %s", ("a",), None)
    assert RedactingFilter().filter(record) is True
    assert record.msg == "[UNFORMATTABLE]"


def test_make_handler_wires_filter_and_formatter_without_touching_root() -> None:
    root = logging.getLogger()
    handlers, level = list(root.handlers), root.level
    handler = make_handler(io.StringIO(), static_fields={"svc": "api"})
    assert isinstance(handler, logging.StreamHandler)
    assert isinstance(handler.formatter, JsonFormatter)
    assert any(isinstance(item, RedactingFilter) for item in handler.filters)
    assert root.handlers == handlers
    assert root.level == level


def test_package_metadata_and_null_handler() -> None:
    assert redacting_logger.__version__ == "0.1.0"
    package_logger = logging.getLogger("redacting_logger")
    assert any(isinstance(item, logging.NullHandler) for item in package_logger.handlers)
    assert set(redacting_logger.__all__) >= {"redact", "make_handler", "RedactionError"}


@pytest.mark.parametrize(
    ("key", "redacted"),
    [
        ("password", True),
        ("PASSWORD", True),
        ("X-Api-Key", True),
        ("Access Key", True),
        ("my_session", True),
        ("csrf-token", True),
        ("Authorization", True),
        ("client_secret", True),
        ("tokenizer", False),
        ("sessions", False),
        ("input_tokens", False),
        ("passwords", False),
    ],
)
def test_key_normalisation(key: str, redacted: bool) -> None:
    assert redact({key: "value"}) == {key: "[REDACTED]" if redacted else "value"}


def test_hostile_jwt_prefixes_are_fast() -> None:
    import time

    start = time.perf_counter()
    redact("ey" + "J-" * 25000)
    redact(("ey" + "J-") * 25000)
    assert time.perf_counter() - start < 2.0


def test_sensitive_value_of_any_type_and_custom_rules() -> None:
    assert redact({"password": None}) == {"password": "[REDACTED]"}
    rules = RedactionRules(sensitive_keys=frozenset({"PIN"}), placeholder="***")
    assert redact({"pin": 1, "password": "x"}, rules) == {"pin": "***", "password": "x"}
    assert isinstance(RedactionRules(sensitive_keys={"pin"}).sensitive_keys, frozenset)
    assert len(DEFAULT_KEYS) == 13


def test_default_pattern_names_and_order() -> None:
    names = [name for name, _ in DEFAULT_PATTERNS]
    assert names == [
        "bearer",
        "aws_key",
        "jwt",
        "private_key",
        "github_token",
        "url_credentials",
        "email",
        "card",
    ]


def test_scalars_and_containers() -> None:
    assert redact(1) == 1
    assert redact(1.5) == 1.5
    assert redact(None) is None
    assert redact(True) is True
    assert math.isnan(redact(float("nan")))
    assert redact(("a@b.co", 1)) == ("[REDACTED:email]", 1)
    assert redact(["a@b.co"]) == ["[REDACTED:email]"]
    assert redact(b"ok " + GITHUB.encode()) == "ok [REDACTED:github_token]"
    assert redact(bytearray(b"\xff")) == "\ufffd"
    assert redact({"a@b.co": 1}) == {"[REDACTED:email]": 1}
    assert redact({1: "a", None: "b", (1, 2): "c"}) == {1: "a", None: "b", "(1, 2)": "c"}
    assert redact(_Thing()) == "Thing [REDACTED:github_token]"
    assert redact(_BadRepr()) == "[UNFORMATTABLE]"


def test_redact_does_not_mutate_its_input() -> None:
    original = {"password": "p", "items": ["a@b.co"]}
    result = redact(original)
    assert original == {"password": "p", "items": ["a@b.co"]}
    assert result == {"password": "[REDACTED]", "items": ["[REDACTED:email]"]}


def test_depth_limit() -> None:
    shallow: Any = []
    for _ in range(10):
        shallow = [shallow]
    assert redact(shallow) == shallow
    deep: Any = []
    for _ in range(11):
        deep = [deep]
    result = redact(deep)
    for _ in range(11):
        result = result[0]
    assert result == "[TRUNCATED]"


def test_cycles_in_lists_and_dicts() -> None:
    looped: list[Any] = []
    looped.append(looped)
    assert redact(looped) == ["[CYCLE]"]
    shared = [1]
    assert redact([shared, shared]) == [[1], [1]]


def test_string_and_item_limits() -> None:
    assert redact("a" * 100_001) == "a" * 100_000 + "[TRUNCATED]"
    assert redact("a" * 100_000) == "a" * 100_000
    assert redact(list(range(1001))) == [*range(1000), "[TRUNCATED]"]
    assert redact(list(range(1000))) == list(range(1000))
    rules = RedactionRules(max_items=2, max_value_chars=5)
    assert redact({"a": 1, "b": 2, "c": 3}, rules) == {"a": 1, "b": 2, "[TRUNCATED]": 1}
    assert redact("abcdefgh", rules) == "abcde[TRUNCATED]"
    assert redact((1, 2, 3), rules) == (1, 2, "[TRUNCATED]")


def test_adversarial_inputs_stay_unchanged() -> None:
    assert redact("1-" * 5000) == "1-" * 5000
    assert redact("4" * 50_000) == "4" * 50_000
    assert redact("eyJ" * 2000) == "eyJ" * 2000
    assert redact("a" * 100_000) == "a" * 100_000
    assert redact("bearer " * 5000) == "bearer " * 5000


def test_add_pattern_success() -> None:
    rules = RedactionRules()
    rules.add_pattern("ssn", r"\b\d{3}-\d{2}-\d{4}\b")
    assert redact("id 123-45-6789 ok", rules) == "id [REDACTED:ssn] ok"
    assert redact("id 123-45-6789 ok") == "id 123-45-6789 ok"
    assert len(rules.patterns) == len(DEFAULT_PATTERNS) + 1
    assert len(DEFAULT_PATTERNS) == 8


def test_add_pattern_rejects_bad_regex_with_invalid_pattern() -> None:
    rules = RedactionRules()
    for regex in ("(", "a" * 501, "a*", "a|", 123):
        with pytest.raises(RedactionError) as info:
            rules.add_pattern("x", regex)  # type: ignore[arg-type]
        assert info.value.code == "invalid_pattern"
        assert isinstance(info.value, ValueError)
        assert len(str(info.value)) <= 200
    assert len(rules.patterns) == len(DEFAULT_PATTERNS)


def test_add_pattern_rejects_bad_names_with_invalid_rules() -> None:
    rules = RedactionRules()
    for name in ("X", "1a", "", "a" * 21, "x\n", "a-b"):
        with pytest.raises(RedactionError) as info:
            rules.add_pattern(name, "a")
        assert info.value.code == "invalid_rules"


def test_add_pattern_caps_the_number_of_patterns() -> None:
    rules = RedactionRules()
    for index in range(MAX_PATTERNS - len(DEFAULT_PATTERNS)):
        rules.add_pattern("p" + str(index), "a")
    with pytest.raises(RedactionError) as info:
        rules.add_pattern("extra", "a")
    assert info.value.code == "invalid_rules"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_items": 0},
        {"max_items": True},
        {"max_items": 100_001},
        {"max_value_chars": 0},
        {"max_depth": 51},
        {"max_depth": "3"},
        {"placeholder": 5},
        {"placeholder": "x" * 201},
        {"sensitive_keys": "abc"},
        {"sensitive_keys": frozenset({""})},
        {"sensitive_keys": frozenset({1})},
        {"patterns": "abc"},
        {"patterns": (("ok",),)},
        {"patterns": (("ok", "a"),)},
        {"patterns": (("Bad", re.compile("a")),)},
        {"patterns": (("ok", re.compile("a")),) * 65},
    ],
)
def test_invalid_rules(kwargs: dict[str, Any]) -> None:
    with pytest.raises(RedactionError) as info:
        RedactionRules(**kwargs)
    assert info.value.code == "invalid_rules"


ACCEPTANCE_FRAGMENTS = [
    "} and created=0 is emitted as exactly ",
    " plus ",
    "; created=1.001 gives ts ",
    ": 10, ",
    " * 36, a three-part ",
    " JWT, a PEM block from ",
    " to its END line, ",
    " become ",
    ") raises RedactionError code ",
    " and add_pattern(",
    ") raises code ",
]


def test_acceptance_fragments_are_distinct() -> None:
    assert len(set(ACCEPTANCE_FRAGMENTS)) == len(ACCEPTANCE_FRAGMENTS)


def test_error_is_value_error_with_bounded_message() -> None:
    error = RedactionError("invalid_rules", "x" * 500)
    assert isinstance(error, ValueError)
    assert error.code == "invalid_rules"
    assert len(str(error)) == 200
