"""Tests for typed dude_analyze_* file helpers."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from promql_analyzer import (
    FileAnalysisReport,
    dude_analyze_json,
    dude_analyze_promql,
    dude_analyze_yaml,
    dude_analyze_yml,
)
from promql_analyzer.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, main
from promql_analyzer.files import extract_queries_from_structured_text

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

SAMPLE_RULES_JSON = {
    "groups": [
        {
            "name": "example",
            "rules": [
                {
                    "alert": "HighErrorRate",
                    "expr": 'sum(rate(http_requests_total{status=~"5.."}[5m])) > 10',
                },
                {
                    "record": "job:http_requests:rate5m",
                    "expr": "sum by (job) (rate(http_requests_total[5m]))",
                },
                {
                    "alert": "BadCounterUsage",
                    "expr": "avg(http_requests_total)",
                },
            ],
        }
    ]
}


def test_extract_queries_from_prometheus_rules() -> None:
    queries = extract_queries_from_structured_text(SAMPLE_RULES, suffix=".yaml")
    assert len(queries) == 3
    assert queries[0].rule_kind == "alert"
    assert queries[0].rule_name == "HighErrorRate"
    assert "rate(http_requests_total" in queries[0].expr
    assert queries[1].rule_kind == "record"
    assert queries[2].rule_name == "BadCounterUsage"


def test_dude_analyze_yaml(tmp_path: Path) -> None:
    path = tmp_path / "alerts.yaml"
    path.write_text(SAMPLE_RULES, encoding="utf-8")
    report = dude_analyze_yaml(path)
    assert isinstance(report, FileAnalysisReport)
    assert len(report.queries) == 3
    assert report.queries[0].result is not None
    third = report.queries[2].result
    assert third is not None
    assert any(f.rule_id == "PQL001" for f in third.findings)


def test_dude_analyze_yml(tmp_path: Path) -> None:
    path = tmp_path / "alerts.yml"
    path.write_text(SAMPLE_RULES, encoding="utf-8")
    report = dude_analyze_yml(path)
    assert isinstance(report, FileAnalysisReport)
    assert len(report.queries) == 3


def test_dude_analyze_promql(tmp_path: Path) -> None:
    path = tmp_path / "query.promql"
    path.write_text("up\n", encoding="utf-8")
    result = dude_analyze_promql(path)
    assert result.structure.metrics == ("up",)


def test_dude_analyze_json(tmp_path: Path) -> None:
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(SAMPLE_RULES_JSON), encoding="utf-8")
    report = dude_analyze_json(path)
    assert isinstance(report, FileAnalysisReport)
    assert len(report.queries) == 3
    assert report.queries[0].source.rule_name == "HighErrorRate"


def test_typed_helpers_reject_wrong_suffix(tmp_path: Path) -> None:
    yaml_path = tmp_path / "alerts.yaml"
    yaml_path.write_text(SAMPLE_RULES, encoding="utf-8")
    with pytest.raises(ValueError, match="expected a .yml file"):
        dude_analyze_yml(yaml_path)

    yml_path = tmp_path / "alerts.yml"
    yml_path.write_text(SAMPLE_RULES, encoding="utf-8")
    with pytest.raises(ValueError, match="expected a .yaml file"):
        dude_analyze_yaml(yml_path)

    json_as_yaml = tmp_path / "rules.json"
    json_as_yaml.write_text(json.dumps(SAMPLE_RULES_JSON), encoding="utf-8")
    with pytest.raises(ValueError, match="expected a .promql"):
        dude_analyze_promql(json_as_yaml)


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
    queries = extract_queries_from_structured_text(text, suffix=".yml")
    assert len(queries) == 1
    assert queries[0].rule_name == "InstanceDown"
    assert queries[0].expr == "up == 0"


def test_structured_with_no_promql_raises(tmp_path: Path) -> None:
    path = tmp_path / "empty.yaml"
    path.write_text("groups: []\n", encoding="utf-8")
    with pytest.raises(ValueError, match="no PromQL expressions found"):
        dude_analyze_yaml(path)


OSPREY_CONDITION = """
condition: (time() - kube_job_status_start_time{namespace="genctl",job_name=~"reclaim-.*"} >1200) and on(kube_cluster_name, job_name) (kube_job_status_active{namespace="genctl",job_name=~"reclaim-.*"} > 0) and on(kube_cluster_name) (count by (kube_cluster_name) (kube_node_labels{label_kubernetes_io_arch!="s390x"}) > 0)
context:
  id: ac-0dc590c2-4e1d-434f-91db-b275b1bf554d
  tip_situation: Baremetal reclaim job is long running
  tip_short_description: 'ipops-alerts A baremetal reclaim job has been running for more than 20 min.'
"""


def test_extract_osprey_condition_field() -> None:
    queries = extract_queries_from_structured_text(OSPREY_CONDITION, suffix=".yaml")
    assert len(queries) == 1
    assert queries[0].rule_kind == "condition"
    assert queries[0].rule_name == "Baremetal reclaim job is long running"
    assert "kube_job_status_start_time" in queries[0].expr
    assert queries[0].location == "condition"


def test_dude_analyze_yaml_osprey_condition(tmp_path: Path) -> None:
    path = tmp_path / "metal-osprey-condition.yaml"
    path.write_text(OSPREY_CONDITION, encoding="utf-8")
    report = dude_analyze_yaml(path)
    assert len(report.queries) == 1
    assert report.queries[0].result is not None
    assert report.queries[0].error is None
    assert "kube_job_status_active" in report.queries[0].source.expr


def test_extract_query_and_promql_keys() -> None:
    text = """
items:
  - query: up == 0
    name: InstanceDown
  - promql: sum(rate(http_requests_total[5m]))
"""
    queries = extract_queries_from_structured_text(text, suffix=".yaml")
    assert len(queries) == 2
    assert queries[0].expr == "up == 0"
    assert queries[0].rule_name == "InstanceDown"
    assert "rate(http_requests_total" in queries[1].expr


def test_cli_analyze_yaml_file(tmp_path: Path, capsys) -> None:
    path = tmp_path / "alerts.yaml"
    path.write_text(SAMPLE_RULES, encoding="utf-8")

    code = main(["dude-analyze-yaml", str(path)])
    out = capsys.readouterr().out
    assert code == EXIT_OK
    assert "PROMQL FILE ANALYSIS" in out
    assert "HighErrorRate" in out
    assert "Queries: 3" in out


def test_cli_analyze_json_file(tmp_path: Path, capsys) -> None:
    path = tmp_path / "alerts.json"
    path.write_text(json.dumps(SAMPLE_RULES_JSON), encoding="utf-8")
    code = main(["dude-analyze-json", "--format", "json", str(path)])
    payload = json.loads(capsys.readouterr().out)
    assert code == EXIT_OK
    assert payload["query_count"] == 3
    assert payload["queries"][0]["rule_name"] == "HighErrorRate"


def test_cli_analyze_yaml_json_and_fail_on(tmp_path: Path, capsys) -> None:
    path = tmp_path / "alerts.yaml"
    path.write_text(SAMPLE_RULES, encoding="utf-8")

    code = main(["dude-analyze-yaml", "--format", "json", str(path)])
    payload = json.loads(capsys.readouterr().out)
    assert code == EXIT_OK
    assert payload["query_count"] == 3
    assert payload["queries"][0]["rule_name"] == "HighErrorRate"

    code_warn = main(["dude-analyze-yaml", "--fail-on", "warning", str(path)])
    assert code_warn == EXIT_FINDINGS


def test_cli_invalid_yaml(tmp_path: Path, capsys) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("groups: [\n", encoding="utf-8")
    code = main(["dude-analyze-yaml", str(path)])
    assert code == EXIT_ERROR
    assert "Error:" in capsys.readouterr().err
