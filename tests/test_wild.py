"""Tests for ``dude_rushup.wild()`` noise-risk scoring."""

from __future__ import annotations

from pathlib import Path

import promql_analyzer
from promql_analyzer import NoiseRiskConfig, RuleRecord, dude_rushup
from promql_analyzer.dude_rushup.ast_features import (
    extract_noise_features,
    parse_duration_minutes,
)
from promql_analyzer.dude_rushup.noise import (
    DIM_AGGREGATION,
    DIM_BLAST,
    DIM_EXPRESSION,
    DIM_FOR,
    DIM_SELF,
    DIM_THRESHOLD,
    DIM_VOLATILITY,
    DIM_WINDOW,
    NoiseRiskAnalyzer,
)
from promql_analyzer.parser import parse_query


def _dim(assessment, key: str) -> int:
    for item in assessment.dimensions:
        if item.key == key:
            return item.score
    raise AssertionError(f"missing dimension {key}")


def _alert(
    expr: str,
    *,
    name: str = "Alert",
    for_duration: str | None = "10m",
    file_path: str = "a.yaml",
) -> RuleRecord:
    return RuleRecord(
        file_path=file_path,
        kind="alert",
        name=name,
        expr=expr,
        for_duration=for_duration,
    )


def test_public_wild_export() -> None:
    assert callable(dude_rushup.wild)
    assert "dude_rushup" in promql_analyzer.__all__
    assert callable(promql_analyzer.dude_rushup.wild)


def test_parse_duration_minutes() -> None:
    assert parse_duration_minutes("10m", default_minutes=0) == 10
    assert parse_duration_minutes("1h", default_minutes=0) == 60
    assert parse_duration_minutes("30s", default_minutes=0) == 0.5
    assert parse_duration_minutes(None, default_minutes=0) == 0


def test_ast_features_extract_comparisons_and_ranges() -> None:
    expr = parse_query(
        "avg by (job, instance) (rate(http_requests_total[5m])) > 0.85"
    )
    features = extract_noise_features(expr)
    assert features.has_avg
    assert features.has_rate_or_increase
    assert features.by_label_dims == ("instance", "job")
    assert features.range_minutes == (5.0,)
    assert features.comparisons[0].operator == ">"
    assert features.comparisons[0].value == 0.85
    assert "http_requests_total" in features.metrics


def test_binary_threshold_on_state_metric_is_low() -> None:
    analyzer = NoiseRiskAnalyzer(
        NoiseRiskConfig(state_metrics=("up",), missing_for_minutes=10)
    )
    assessment = analyzer.assess_alert(_alert("up == 0", for_duration="15m"))
    assert assessment is not None
    assert _dim(assessment, DIM_THRESHOLD) == 0
    assert _dim(assessment, DIM_VOLATILITY) == 0
    assert _dim(assessment, DIM_EXPRESSION) == 0
    assert assessment.level == "Low"


def test_binary_threshold_on_non_state_metric_scores_2() -> None:
    analyzer = NoiseRiskAnalyzer(NoiseRiskConfig(state_metrics=(), missing_for_minutes=10))
    assessment = analyzer.assess_alert(
        _alert("custom_errors_total > 0", for_duration="10m")
    )
    assert assessment is not None
    assert _dim(assessment, DIM_THRESHOLD) == 2
    assert any("Binary threshold" in r for r in assessment.risk_reasons)


def test_short_window_and_rate_expression_raise_risk() -> None:
    analyzer = NoiseRiskAnalyzer(
        NoiseRiskConfig(
            volatile_metrics=("nic_rx_total_errors",),
            missing_for_minutes=10,
        )
    )
    assessment = analyzer.assess_alert(
        _alert(
            "rate(nic_rx_total_errors[1m]) > 0",
            for_duration="1m",
        )
    )
    assert assessment is not None
    assert _dim(assessment, DIM_WINDOW) == 3
    assert _dim(assessment, DIM_EXPRESSION) == 2
    assert _dim(assessment, DIM_VOLATILITY) == 2
    assert _dim(assessment, DIM_FOR) == 3
    assert _dim(assessment, DIM_SELF) == 2
    assert assessment.percentage > 55
    assert assessment.level == "High"


def test_long_window_and_for_suppress_noise() -> None:
    analyzer = NoiseRiskAnalyzer(NoiseRiskConfig(missing_for_minutes=10))
    assessment = analyzer.assess_alert(
        _alert(
            "max by (instance) (node_cpu_seconds_total) > 1000",
            for_duration="30m",
        )
    )
    assert assessment is not None
    assert _dim(assessment, DIM_WINDOW) == 0  # no range vector
    assert _dim(assessment, DIM_AGGREGATION) == 0  # max
    assert _dim(assessment, DIM_FOR) == 0
    assert _dim(assessment, DIM_BLAST) == 0
    assert assessment.level in {"Low", "Medium"}


def test_avg_with_few_dims_scores_aggregation() -> None:
    analyzer = NoiseRiskAnalyzer(NoiseRiskConfig(missing_for_minutes=10))
    assessment = analyzer.assess_alert(
        _alert("avg by (job) (request_latency_seconds) > 0.5", for_duration="10m")
    )
    assert assessment is not None
    assert _dim(assessment, DIM_AGGREGATION) == 2


def test_wide_by_clause_blast_radius() -> None:
    analyzer = NoiseRiskAnalyzer(NoiseRiskConfig(missing_for_minutes=10))
    assessment = analyzer.assess_alert(
        _alert(
            "sum by (a, b, c, d) (up) == 0",
            for_duration="10m",
        )
    )
    assert assessment is not None
    assert _dim(assessment, DIM_BLAST) == 2
    assert _dim(assessment, DIM_AGGREGATION) == 1


def test_configurable_tight_threshold() -> None:
    analyzer = NoiseRiskAnalyzer(
        NoiseRiskConfig(
            tight_threshold_values=(85.0, 90.0),
            missing_for_minutes=10,
        )
    )
    assessment = analyzer.assess_alert(
        _alert("cpu_usage_percent > 85", for_duration="10m")
    )
    assert assessment is not None
    assert _dim(assessment, DIM_THRESHOLD) == 1


def test_self_resolving_metric_profile() -> None:
    analyzer = NoiseRiskAnalyzer(
        NoiseRiskConfig(
            self_resolving_metrics=("node_uptime",),
            state_metrics=("node_uptime",),
            missing_for_minutes=10,
        )
    )
    assessment = analyzer.assess_alert(
        _alert("node_uptime < 600", for_duration="5m")
    )
    assert assessment is not None
    assert _dim(assessment, DIM_SELF) == 1
    assert any("self-resolving" in r.lower() for r in assessment.suppression_reasons)


def test_missing_for_treated_as_immediate() -> None:
    analyzer = NoiseRiskAnalyzer(NoiseRiskConfig(missing_for_minutes=0))
    assessment = analyzer.assess_alert(_alert("up == 0", for_duration=None))
    assert assessment is not None
    assert _dim(assessment, DIM_FOR) == 3


def test_to_finding_contains_required_fields() -> None:
    analyzer = NoiseRiskAnalyzer(NoiseRiskConfig(missing_for_minutes=10))
    assessment = analyzer.assess_alert(
        _alert("rate(http_requests_total[5m]) > 100", name="HighQPS", for_duration="2m")
    )
    assert assessment is not None
    finding = analyzer.to_finding(assessment)
    assert finding.rule_id == "NOISE001"
    assert finding.category == "noise_risk"
    assert finding.rule_name == "HighQPS"
    assert finding.file_path == "a.yaml"
    assert finding.score == float(assessment.percentage)
    assert any(e.startswith("score=") for e in finding.evidence)
    assert "static definition risk" in finding.message.lower()
    assert "noisy" not in finding.message.lower() or "risk" in finding.message.lower()


def test_wild_on_directory(tmp_path: Path) -> None:
    rules = tmp_path / "alerts"
    rules.mkdir()
    (rules / "a.yaml").write_text(
        """
groups:
  - name: demo
    rules:
      - alert: StableUp
        expr: up == 0
        for: 15m
      - alert: NoisyRate
        expr: rate(errors_total[1m]) > 0
        for: 1m
      - record: job:up:sum
        expr: sum(up)
""",
        encoding="utf-8",
    )
    (rules / "irrelevant.yaml").write_text("scrape_configs: []\n", encoding="utf-8")

    report = dude_rushup.wild(
        tmp_path,
        config=NoiseRiskConfig(
            state_metrics=("up",),
            volatile_metrics=("errors_total",),
        ),
    )

    assert report.noise_summary is not None
    assert report.noise_summary.alerts_analyzed == 2
    assert len(report.noise_assessments) == 2
    assert len(report.findings) == 2
    assert all(f.category == "noise_risk" for f in report.findings)
    assert report.noise_summary.low + report.noise_summary.medium + report.noise_summary.high == 2
    assert report.noise_summary.highest_risk
    assert report.noise_summary.dimension_averages
    names = {a.alert_name for a in report.noise_assessments}
    assert names == {"StableUp", "NoisyRate"}
    noisy = next(a for a in report.noise_assessments if a.alert_name == "NoisyRate")
    stable = next(a for a in report.noise_assessments if a.alert_name == "StableUp")
    assert noisy.percentage >= stable.percentage


def test_wild_on_single_file(tmp_path: Path) -> None:
    path = tmp_path / "one.yml"
    path.write_text(
        """
groups:
  - name: g
    rules:
      - alert: A
        expr: up == 0
        for: 20m
""",
        encoding="utf-8",
    )
    report = dude_rushup.wild(path, config=NoiseRiskConfig(state_metrics=("up",)))
    assert report.noise_summary is not None
    assert report.noise_summary.alerts_analyzed == 1
    assert report.noise_assessments[0].level == "Low"


def test_level_boundaries() -> None:
    analyzer = NoiseRiskAnalyzer()
    assert analyzer._level_for(25) == "Low"
    assert analyzer._level_for(26) == "Medium"
    assert analyzer._level_for(55) == "Medium"
    assert analyzer._level_for(56) == "High"


def test_recording_rules_are_not_scored() -> None:
    analyzer = NoiseRiskAnalyzer()
    result = analyzer.assess_alert(
        RuleRecord(
            file_path="a.yaml",
            kind="record",
            name="x",
            expr="sum(up)",
        )
    )
    assert result is None
