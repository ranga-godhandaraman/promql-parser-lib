"""Tests for Phase 3 static-analysis rules."""

from __future__ import annotations

from promql_analyzer import AnalyzerConfig, Severity, analyze


def _ids(result) -> list[str]:
    return [f.rule_id for f in result.findings]


def _by_id(result, rule_id: str):
    return [f for f in result.findings if f.rule_id == rule_id]


# ---------------------------------------------------------------------------
# PQL001 — Suspicious counter usage
# ---------------------------------------------------------------------------


def test_pql001_positive_avg_counter() -> None:
    result = analyze("avg(http_requests_total)")
    findings = _by_id(result, "PQL001")
    assert len(findings) == 1
    assert findings[0].severity == Severity.WARNING
    assert "_total" in findings[0].message
    assert findings[0].suggestion is not None
    assert "definitely" not in findings[0].explanation.lower()


def test_pql001_negative_rate_wrapped() -> None:
    result = analyze("sum(rate(http_requests_total[5m]))")
    assert _by_id(result, "PQL001") == []


def test_pql001_edge_bare_counter_and_increase() -> None:
    bare = analyze("http_requests_total")
    assert len(_by_id(bare, "PQL001")) == 1

    with_increase = analyze("increase(http_requests_total[1h])")
    assert _by_id(with_increase, "PQL001") == []

    # Non-_total metric should not trigger the rule.
    other = analyze("avg(http_requests)")
    assert _by_id(other, "PQL001") == []


# ---------------------------------------------------------------------------
# PQL002 — Broad regex matcher
# ---------------------------------------------------------------------------


def test_pql002_positive_star() -> None:
    result = analyze('up{pod=~".*"}')
    findings = _by_id(result, "PQL002")
    assert len(findings) == 1
    assert findings[0].severity == Severity.WARNING
    assert "series" in findings[0].explanation.lower()


def test_pql002_negative_exact_matcher() -> None:
    result = analyze('up{pod="payment-1"}')
    assert _by_id(result, "PQL002") == []


def test_pql002_edge_leading_dot_star_is_info() -> None:
    result = analyze('up{pod=~".*payment.*"}')
    findings = _by_id(result, "PQL002")
    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO

    # Narrow regex without leading .* should not warn.
    narrow = analyze('up{pod=~"payment-.*"}')
    assert _by_id(narrow, "PQL002") == []


# ---------------------------------------------------------------------------
# PQL003 — Suspicious rate window
# ---------------------------------------------------------------------------


def test_pql003_positive_short_window() -> None:
    result = analyze(
        "rate(http_requests_total[10s])",
        config=AnalyzerConfig(scrape_interval_seconds=15, rate_range_min_multiples=4),
    )
    findings = _by_id(result, "PQL003")
    assert len(findings) == 1
    assert findings[0].severity == Severity.WARNING
    assert "heuristic" in findings[0].explanation.lower()


def test_pql003_negative_adequate_window() -> None:
    result = analyze(
        "rate(http_requests_total[5m])",
        config=AnalyzerConfig(scrape_interval_seconds=15, rate_range_min_multiples=4),
    )
    assert _by_id(result, "PQL003") == []


def test_pql003_edge_config_and_irate() -> None:
    # Same 10s window is fine if scrape interval is tiny.
    ok = analyze(
        "rate(metric[10s])",
        config=AnalyzerConfig(scrape_interval_seconds=1, rate_range_min_multiples=4),
    )
    assert _by_id(ok, "PQL003") == []

    irate = analyze(
        "irate(metric[10s])",
        config=AnalyzerConfig(scrape_interval_seconds=15),
    )
    assert len(_by_id(irate, "PQL003")) == 1


# ---------------------------------------------------------------------------
# PQL004 — High-cardinality grouping
# ---------------------------------------------------------------------------


def test_pql004_positive_many_labels() -> None:
    query = """
    sum by(pod, container, instance, request_id)(
      rate(metric[5m])
    )
    """
    result = analyze(query, config=AnalyzerConfig(max_grouping_labels=3))
    warnings = [f for f in _by_id(result, "PQL004") if f.severity == Severity.WARNING]
    assert len(warnings) == 1
    assert "4 labels" in warnings[0].message
    assert "will be slow" not in warnings[0].message.lower()
    assert "may" in warnings[0].explanation.lower() or "depend" in warnings[0].explanation.lower()


def test_pql004_negative_below_threshold() -> None:
    result = analyze(
        "sum by(namespace)(rate(metric[5m]))",
        config=AnalyzerConfig(max_grouping_labels=3),
    )
    assert [f for f in _by_id(result, "PQL004") if f.severity == Severity.WARNING] == []


def test_pql004_edge_threshold_and_optional_info() -> None:
    # Exactly at threshold should not WARNING.
    at_threshold = analyze(
        "sum by(a, b, c)(rate(metric[5m]))",
        config=AnalyzerConfig(max_grouping_labels=3),
    )
    assert [
        f for f in _by_id(at_threshold, "PQL004") if f.severity == Severity.WARNING
    ] == []

    # Two commonly high-cardinality names below threshold -> INFO.
    info_case = analyze(
        "sum by(pod, instance)(rate(metric[5m]))",
        config=AnalyzerConfig(max_grouping_labels=3),
    )
    infos = [f for f in _by_id(info_case, "PQL004") if f.severity == Severity.INFO]
    assert len(infos) == 1


# ---------------------------------------------------------------------------
# PQL005 — Excessive nesting
# ---------------------------------------------------------------------------


def test_pql005_positive_deep_nesting() -> None:
    result = analyze(
        "round(ceil(floor(abs(sgn(up)))))",
        config=AnalyzerConfig(max_nesting_depth=4),
    )
    findings = _by_id(result, "PQL005")
    assert len(findings) == 1
    assert findings[0].severity in {Severity.INFO, Severity.WARNING}
    assert "slow" not in findings[0].message.lower()
    assert "definitely be slow" not in findings[0].explanation.lower()


def test_pql005_negative_shallow() -> None:
    result = analyze(
        "sum(rate(metric[5m]))",
        config=AnalyzerConfig(max_nesting_depth=4),
    )
    assert _by_id(result, "PQL005") == []


def test_pql005_edge_configurable_threshold() -> None:
    query = "sum(rate(metric[5m]))"  # depth 2
    low = analyze(query, config=AnalyzerConfig(max_nesting_depth=1))
    assert len(_by_id(low, "PQL005")) == 1

    high = analyze(query, config=AnalyzerConfig(max_nesting_depth=10))
    assert _by_id(high, "PQL005") == []


# ---------------------------------------------------------------------------
# Engine / configuration
# ---------------------------------------------------------------------------


def test_disabled_rules() -> None:
    result = analyze(
        "avg(http_requests_total)",
        config=AnalyzerConfig(disabled_rules=("PQL001",)),
    )
    assert "PQL001" not in _ids(result)


def test_enabled_rules_only() -> None:
    result = analyze(
        'avg(http_requests_total{pod=~".*"})',
        config=AnalyzerConfig(enabled_rules=("PQL002",)),
    )
    assert _ids(result) == ["PQL002"]


def test_public_api_findings_shape() -> None:
    result = analyze("avg(http_requests_total)", config=AnalyzerConfig())
    assert result.structure.metrics == ("http_requests_total",)
    assert result.findings
    finding = result.findings[0]
    assert finding.rule_id
    assert finding.severity
    assert finding.message
    assert finding.explanation
