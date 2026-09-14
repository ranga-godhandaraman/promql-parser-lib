"""Tests for YAML/YML Prometheus rule file analysis."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from promql_analyzer import FileAnalysisReport, analyze_file, analyze_yaml_file
from promql_analyzer.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, main
from promql_analyzer.files import extract_queries_from_yaml_text

SAMPLE_RULES = """
groups:
  - name: example
    rules:
      - alert: HighErrorRate
        expr: sum(rate(http_requests_total{status=~"5.."}[5m])) > 10
        for: 5m
      - record: job:http_requests:rate5m
        expr: sum by (job) (rate(http_requests_total[5m]))
      - alert: BadCounterUsage
        expr: avg(http_requests_total)
"""


def test_extract_queries_from_prometheus_rules() -> None:
    queries = extract_queries_from_yaml_text(SAMPLE_RULES)
    assert len(queries) == 3
    assert queries[0].rule_kind == "alert"
    assert queries[0].rule_name == "HighErrorRate"
    assert "rate(http_requests_total" in queries[0].expr
    assert queries[1].rule_kind == "record"
    assert queries[2].rule_name == "BadCounterUsage"


def test_analyze_yaml_file(tmp_path: Path) -> None:
    path = tmp_path / "alerts.yaml"
    path.write_text(SAMPLE_RULES, encoding="utf-8")
    report = analyze_yaml_file(path)
    assert isinstance(report, FileAnalysisReport)
    assert len(report.queries) == 3
    assert report.queries[0].result is not None
    assert report.queries[0].error is None
    # Third rule should trigger PQL001.
    third = report.queries[2].result
    assert third is not None
    assert any(f.rule_id == "PQL001" for f in third.findings)


def test_analyze_file_dispatches_yaml_and_promql(tmp_path: Path) -> None:
    yaml_path = tmp_path / "rules.yml"
    yaml_path.write_text(SAMPLE_RULES, encoding="utf-8")
    yaml_report = analyze_file(yaml_path)
    assert isinstance(yaml_report, FileAnalysisReport)

    promql_path = tmp_path / "query.promql"
    promql_path.write_text("up\n", encoding="utf-8")
    single = analyze_file(promql_path)
    assert not isinstance(single, FileAnalysisReport)
    assert single.structure.metrics == ("up",)


def test_prometheus_operator_style_yaml() -> None:
    text = """
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: example
spec:
  groups:
    - name: demo
      rules:
        - alert: InstanceDown
          expr: up == 0
"""
    queries = extract_queries_from_yaml_text(text)
    assert len(queries) == 1
    assert queries[0].rule_name == "InstanceDown"
    assert queries[0].expr == "up == 0"


def test_yaml_with_no_expr_raises(tmp_path: Path) -> None:
    path = tmp_path / "empty.yaml"
    path.write_text("groups: []\n", encoding="utf-8")
    with pytest.raises(ValueError, match="no PromQL expr"):
        analyze_yaml_file(path)


def test_cli_analyze_yaml_file(tmp_path: Path, capsys) -> None:
    path = tmp_path / "alerts.yaml"
    path.write_text(SAMPLE_RULES, encoding="utf-8")

    code = main(["analyze-file", str(path)])
    out = capsys.readouterr().out
    assert code == EXIT_OK
    assert "PROMQL FILE ANALYSIS" in out
    assert "HighErrorRate" in out
    assert "Queries: 3" in out


def test_cli_analyze_yaml_json_and_fail_on(tmp_path: Path, capsys) -> None:
    path = tmp_path / "alerts.yaml"
    path.write_text(SAMPLE_RULES, encoding="utf-8")

    code = main(["analyze-file", "--format", "json", str(path)])
    payload = json.loads(capsys.readouterr().out)
    assert code == EXIT_OK
    assert payload["query_count"] == 3
    assert payload["queries"][0]["rule_name"] == "HighErrorRate"

    code_warn = main(["analyze-file", "--fail-on", "warning", str(path)])
    assert code_warn == EXIT_FINDINGS


def test_cli_invalid_yaml(tmp_path: Path, capsys) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("groups: [\n", encoding="utf-8")
    code = main(["analyze-file", str(path)])
    assert code == EXIT_ERROR
    assert "Error:" in capsys.readouterr().err
