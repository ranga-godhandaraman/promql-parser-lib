"""Tests for Phase 4 structural complexity scoring."""

from __future__ import annotations

from promql_analyzer import ComplexityLevel, analyze


def _factor_names(result) -> set[str]:
    return {f.name for f in result.complexity.factors}


def test_complexity_simple_metric() -> None:
    result = analyze("up")
    assert result.complexity.score == 5
    assert result.complexity.level == ComplexityLevel.SIMPLE
    assert "base" in _factor_names(result)


def test_complexity_single_function() -> None:
    result = analyze("rate(http_requests_total[5m])")
    assert 10 <= result.complexity.score <= 25
    assert result.complexity.level in {
        ComplexityLevel.SIMPLE,
        ComplexityLevel.MODERATE,
    }
    assert "functions" in _factor_names(result)
    assert "range_vectors" in _factor_names(result)


def test_complexity_nested_functions() -> None:
    nested = analyze("sum(rate(http_requests_total[5m]))")
    single = analyze("rate(http_requests_total[5m])")
    assert nested.complexity.score > single.complexity.score
    assert "function_nesting" in _factor_names(nested)
    assert 20 <= nested.complexity.score <= 40
    assert nested.complexity.level == ComplexityLevel.MODERATE


def test_complexity_regex_matcher() -> None:
    plain = analyze('http_requests_total{status="500"}')
    regex = analyze('http_requests_total{status=~"5.."}')
    assert regex.complexity.score > plain.complexity.score
    assert "regex_matchers" in _factor_names(regex)


def test_complexity_aggregation_with_grouping() -> None:
    result = analyze("sum by(namespace)(rate(http_requests_total[5m]))")
    names = _factor_names(result)
    assert "aggregations" in names
    assert "grouping_labels" in names
    assert result.complexity.score >= 25


def test_complexity_complex_query() -> None:
    query = """
    histogram_quantile(
      0.95,
      sum by(le, service)(
        rate(
          http_request_duration_seconds_bucket{
            service=~"api-.*"
          }[5m]
        )
      )
    )
    """
    result = analyze(query)
    assert result.complexity.score >= 60
    assert result.complexity.level in {
        ComplexityLevel.COMPLEX,
        ComplexityLevel.VERY_COMPLEX,
    }
    names = _factor_names(result)
    assert "functions" in names
    assert "function_nesting" in names
    assert "regex_matchers" in names
    assert "grouping_labels" in names
    # Transparent breakdown: contributions sum to score (before cap).
    assert sum(f.contribution for f in result.complexity.factors) == result.complexity.score


def test_complexity_score_capped_and_deterministic() -> None:
    a = analyze("metric_a + metric_b")
    b = analyze("metric_a + metric_b")
    assert a.complexity.score == b.complexity.score
    assert 0 <= a.complexity.score <= 100
    assert "binary_operators" in _factor_names(a)
