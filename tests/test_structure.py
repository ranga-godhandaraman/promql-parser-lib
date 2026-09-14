"""Tests for Phase 2 structural analysis."""

from __future__ import annotations

import pytest

from promql_analyzer import PromQLSyntaxError, analyze


def test_simple_metric() -> None:
    result = analyze("up")
    structure = result.structure

    assert structure.metrics == ("up",)
    assert structure.functions == ()
    assert structure.aggregations == ()
    assert structure.label_matchers == ()
    assert structure.range_vectors == ()
    assert structure.features.contains_aggregation is False
    assert structure.features.contains_binary_operator is False
    assert structure.features.contains_regex_matcher is False
    assert structure.features.contains_nested_function is False


def test_metric_with_labels() -> None:
    result = analyze('http_requests_total{status="500"}')
    structure = result.structure

    assert structure.metrics == ("http_requests_total",)
    assert len(structure.label_matchers) == 1
    matcher = structure.label_matchers[0]
    assert matcher.label == "status"
    assert matcher.operator == "="
    assert matcher.value == "500"
    assert structure.features.contains_regex_matcher is False


def test_regex_matcher() -> None:
    result = analyze('http_requests_total{status=~"5.."}')
    structure = result.structure

    assert structure.metrics == ("http_requests_total",)
    assert len(structure.label_matchers) == 1
    matcher = structure.label_matchers[0]
    assert matcher.label == "status"
    assert matcher.operator == "=~"
    assert matcher.value == "5.."
    assert structure.features.contains_regex_matcher is True


def test_rate_query() -> None:
    result = analyze("rate(http_requests_total[5m])")
    structure = result.structure

    assert structure.metrics == ("http_requests_total",)
    assert structure.functions == ("rate",)
    assert structure.range_vectors == ("5m",)
    assert structure.aggregations == ()
    assert structure.features.contains_nested_function is False


def test_aggregation() -> None:
    result = analyze("sum(rate(http_requests_total[5m]))")
    structure = result.structure

    assert structure.metrics == ("http_requests_total",)
    assert structure.functions == ("sum", "rate")
    assert len(structure.aggregations) == 1
    agg = structure.aggregations[0]
    assert agg.operator == "sum"
    assert agg.grouping == ()
    assert agg.grouping_type is None
    assert structure.range_vectors == ("5m",)
    assert structure.features.contains_aggregation is True
    assert structure.features.contains_nested_function is True


def test_grouping() -> None:
    query = """
    sum by(namespace)(
      rate(http_requests_total[5m])
    )
    """
    result = analyze(query)
    structure = result.structure

    assert structure.metrics == ("http_requests_total",)
    assert structure.functions == ("sum", "rate")
    assert len(structure.aggregations) == 1
    agg = structure.aggregations[0]
    assert agg.operator == "sum"
    assert agg.grouping == ("namespace",)
    assert agg.grouping_type == "by"
    assert structure.range_vectors == ("5m",)


def test_grouping_without() -> None:
    result = analyze("sum without(instance)(rate(http_requests_total[5m]))")
    agg = result.structure.aggregations[0]
    assert agg.operator == "sum"
    assert agg.grouping == ("instance",)
    assert agg.grouping_type == "without"


def test_nested_functions() -> None:
    result = analyze("round(sum(rate(metric[5m])))")
    structure = result.structure

    assert structure.metrics == ("metric",)
    assert structure.functions == ("round", "sum", "rate")
    assert structure.features.contains_nested_function is True
    assert structure.features.contains_aggregation is True
    assert structure.range_vectors == ("5m",)


def test_multiple_metrics_binary_operator() -> None:
    result = analyze("metric_a + metric_b")
    structure = result.structure

    assert structure.metrics == ("metric_a", "metric_b")
    assert structure.features.contains_binary_operator is True
    assert structure.functions == ()
    assert structure.aggregations == ()


def test_label_matcher_operators() -> None:
    result = analyze('m{a="1",b!="2",c=~"x.*",d!~"y.*"}')
    ops = {(m.label, m.operator, m.value) for m in result.structure.label_matchers}
    assert ops == {
        ("a", "=", "1"),
        ("b", "!=", "2"),
        ("c", "=~", "x.*"),
        ("d", "!~", "y.*"),
    }
    assert result.structure.features.contains_regex_matcher is True


def test_offset_and_at_modifier() -> None:
    result = analyze("http_requests_total offset 5m")
    assert result.structure.features.contains_offset is True

    result_at = analyze("http_requests_total @ 1609746000")
    assert result_at.structure.features.contains_at_modifier is True


def test_subquery_feature() -> None:
    result = analyze("rate(http_requests_total[5m])[30m:1m]")
    assert result.structure.features.contains_subquery is True
    assert result.structure.metrics == ("http_requests_total",)


def test_example_query_from_phase_brief() -> None:
    query = """
    sum by(namespace)(
      rate(
        http_requests_total{
          status=~"5.."
        }[5m]
      )
    )
    """
    result = analyze(query)
    structure = result.structure

    assert structure.metrics == ("http_requests_total",)
    assert structure.functions == ("sum", "rate")
    assert structure.aggregations[0].operator == "sum"
    assert structure.aggregations[0].grouping == ("namespace",)
    assert structure.aggregations[0].grouping_type == "by"
    assert structure.label_matchers[0].label == "status"
    assert structure.label_matchers[0].operator == "=~"
    assert structure.label_matchers[0].value == "5.."
    assert structure.range_vectors == ("5m",)
    assert structure.features.contains_regex_matcher is True
    assert structure.features.contains_aggregation is True
    assert structure.features.contains_nested_function is True


def test_invalid_query_raises() -> None:
    with pytest.raises(PromQLSyntaxError):
        analyze("sum(")
