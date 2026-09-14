"""Public API and packaging-facing behavior tests."""

from __future__ import annotations

import json

import pytest

import promql_analyzer
from promql_analyzer import (
    AnalysisResult,
    AnalyzerConfig,
    InvalidPromQL,
    PromQLSyntaxError,
    Severity,
    analyze,
    result_to_dict,
)


def test_public_exports() -> None:
    assert callable(promql_analyzer.analyze)
    assert promql_analyzer.InvalidPromQL is PromQLSyntaxError
    assert "analyze" in promql_analyzer.__all__
    assert "AnalyzerConfig" in promql_analyzer.__all__
    assert "result_to_dict" in promql_analyzer.__all__


def test_result_to_dict_stable_keys() -> None:
    result = analyze("sum(rate(http_requests_total[5m]))")
    payload = result_to_dict(result)
    assert set(payload) >= {
        "query",
        "structure",
        "findings",
        "complexity",
        "explanation",
        "explanations",
    }
    assert set(payload["structure"]) >= {
        "metrics",
        "functions",
        "aggregations",
        "label_matchers",
        "range_vectors",
        "features",
    }
    # Must be JSON-serializable.
    encoded = json.dumps(payload, sort_keys=True)
    assert "http_requests_total" in encoded
    assert result.to_dict()["complexity"]["score"] == result.complexity.score


def test_invalid_promql_useful_error() -> None:
    with pytest.raises(InvalidPromQL) as exc_info:
        analyze("sum(")
    err = exc_info.value
    assert err.message
    assert "Invalid PromQL" in str(err)
    assert err.parser_detail is not None
    # Without debug, str(error) should not dump raw parser detail.
    assert "[parser:" not in str(err)


def test_invalid_promql_debug_includes_parser_detail() -> None:
    with pytest.raises(PromQLSyntaxError) as exc_info:
        analyze("sum(", debug=True)
    assert "[parser:" in str(exc_info.value)


def test_analyzer_config_disables_rules() -> None:
    result = analyze(
        "avg(http_requests_total)",
        config=AnalyzerConfig(disabled_rules=("PQL001",)),
    )
    assert all(f.rule_id != "PQL001" for f in result.findings)


def test_analyzer_config_enabled_rules_only() -> None:
    result = analyze(
        'avg(http_requests_total{pod=~".*"})',
        config=AnalyzerConfig(enabled_rules=("PQL002",)),
    )
    assert [f.rule_id for f in result.findings] == ["PQL002"]
    assert result.findings[0].severity == Severity.WARNING


def test_analysis_result_type() -> None:
    result = analyze("up")
    assert isinstance(result, AnalysisResult)
    assert result.structure.metrics == ("up",)
    assert result.complexity.score >= 0
    assert result.explain()
