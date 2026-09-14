"""Tests for Phase 4 deterministic explanation engine."""

from __future__ import annotations

import pytest

from promql_analyzer import analyze


def test_explain_simple_metric() -> None:
    result = analyze("up")
    text = result.explain()
    assert "up" in text
    assert "metric named" in text
    assert text.startswith("This query")


def test_explain_range_function() -> None:
    result = analyze("rate(http_requests_total[5m])")
    text = result.explain()
    assert "per-second" in text
    assert "rate" in text.lower() or "rate of increase" in text
    assert "5m" in text
    assert "http_requests_total" in text
    # Do not invent HTTP meaning from the metric name.
    assert "HTTP traffic" not in text


def test_explain_label_matcher() -> None:
    result = analyze('http_requests_total{status=~"5.."}')
    text = result.explain(style="detailed")
    assert "status" in text
    assert "5.." in text
    assert "regular expression" in text


def test_explain_aggregation() -> None:
    result = analyze("sum(rate(http_requests_total[5m]))")
    text = result.explain(style="detailed")
    assert "rate" in text.lower() or "per-second" in text
    assert "sums" in text.lower()


def test_explain_grouping() -> None:
    query = """
    sum by(namespace)(
      rate(http_requests_total{status=~"5.."}[5m])
    )
    """
    result = analyze(query)
    text = result.explain(style="detailed")
    assert "namespace" in text
    assert "sums" in text.lower()
    assert "5.." in text or "status" in text
    assert "5m" in text


def test_explain_nested_query_styles() -> None:
    result = analyze("round(sum(rate(metric[5m])))")
    concise = result.explain(style="concise")
    detailed = result.explain(style="detailed")
    assert concise
    assert detailed
    assert len(detailed) >= len(concise)
    assert "metric" in concise
    assert result.explanations.concise == concise
    assert result.explanations.detailed == detailed


def test_explain_rejects_unknown_style() -> None:
    result = analyze("up")
    with pytest.raises(ValueError, match="Unknown explanation style"):
        result.explain(style="poetic")
