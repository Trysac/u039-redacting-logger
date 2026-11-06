"""Behavior tests for the public API of redacting_logger."""

from __future__ import annotations

import pytest

import redacting_logger


def test_normalize_trims_and_lowercases() -> None:
    assert redacting_logger.normalize("  Hello World ") == "hello world"


@pytest.mark.parametrize("value", ["", "   ", "\t\n"])
def test_normalize_rejects_blank_input(value: str) -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        redacting_logger.normalize(value)


def test_version_is_semver() -> None:
    parts = redacting_logger.__version__.split(".")
    assert len(parts) == 3
    assert all(part.isdigit() for part in parts)
