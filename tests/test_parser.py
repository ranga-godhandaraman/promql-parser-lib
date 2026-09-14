"""Parser-layer tests (Phase 1 foundation used by Phase 2)."""

from __future__ import annotations

import pytest

from promql_analyzer.parser import PromQLSyntaxError, parse_query


def test_parse_valid_query() -> None:
    expr = parse_query("up")
    assert expr is not None


def test_parse_empty_query() -> None:
    with pytest.raises(PromQLSyntaxError):
        parse_query("   ")


def test_parse_rejects_non_string() -> None:
    with pytest.raises(TypeError):
        parse_query(123)  # type: ignore[arg-type]
