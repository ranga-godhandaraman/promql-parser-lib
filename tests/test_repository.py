"""Tests for V2 repository discovery and report foundation."""

from __future__ import annotations

from pathlib import Path

import pytest

from promql_analyzer import (
    AlertRecord,
    AnalysisSummary,
    Finding,
    RepositoryAnalyzer,
    RepositoryReport,
    RepositoryScanConfig,
    RepositoryScanner,
    RuleRecord,
    Severity,
    dude_look,
)
from promql_analyzer.repository.extract import extract_rule_records
from promql_analyzer.repository.models import FailedFile, build_summary


def test_scanner_discovers_yaml_recursively(tmp_path: Path) -> None:
    (tmp_path / "alerts").mkdir()
    (tmp_path / "alerts" / "a.yaml").write_text("x: 1\n", encoding="utf-8")
    (tmp_path / "alerts" / "b.yml").write_text("y: 2\n", encoding="utf-8")
    (tmp_path / "alerts" / "readme.md").write_text("# no\n", encoding="utf-8")
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / "deep").mkdir(parents=True)
    (tmp_path / "nested" / "deep" / "c.yaml").write_text("z: 3\n", encoding="utf-8")

    discovered = RepositoryScanner().discover(tmp_path)
    relatives = {item.relative_path for item in discovered}
    assert relatives == {"alerts/a.yaml", "alerts/b.yml", "nested/deep/c.yaml"}


def test_scanner_single_file(tmp_path: Path) -> None:
    path = tmp_path / "one.yml"
    path.write_text("groups: []\n", encoding="utf-8")
    discovered = RepositoryScanner().discover(path)
    assert len(discovered) == 1
    assert discovered[0].relative_path == "one.yml"


def test_scanner_include_exclude(tmp_path: Path) -> None:
    (tmp_path / "keep").mkdir()
    (tmp_path / "skip").mkdir()
    (tmp_path / "vendor").mkdir()
    (tmp_path / "keep" / "a.yaml").write_text("a: 1\n", encoding="utf-8")
    (tmp_path / "skip" / "b.yaml").write_text("b: 1\n", encoding="utf-8")
    (tmp_path / "vendor" / "c.yaml").write_text("c: 1\n", encoding="utf-8")
    (tmp_path / "root.yaml").write_text("r: 1\n", encoding="utf-8")

    config = RepositoryScanConfig(
        include_globs=("**/*.yaml",),
        exclude_globs=("skip/**", "**/vendor/**"),
    )
    relatives = {item.relative_path for item in RepositoryScanner(config).discover(tmp_path)}
    assert relatives == {"keep/a.yaml", "root.yaml"}


def test_scanner_missing_path_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        RepositoryScanner().discover(tmp_path / "missing")


def test_extract_rule_records_from_prometheus_groups() -> None:
    document = {
        "groups": [
            {
                "name": "example",
                "rules": [
                    {
                        "alert": "InstanceDown",
                        "expr": "up == 0",
                        "for": "5m",
                        "labels": {"severity": "critical"},
                        "annotations": {"summary": "down"},
                    },
                    {
                        "record": "job:up:avg",
                        "expr": "avg(up)",
                    },
                ],
            }
        ]
    }
    records = extract_rule_records(document, file_path="rules/a.yaml")
    assert len(records) == 2
    alert = records[0]
    assert alert.kind == "alert"
    assert alert.name == "InstanceDown"
    assert alert.expr == "up == 0"
    assert alert.group_name == "example"
    assert alert.file_path == "rules/a.yaml"
    assert ("severity", "critical") in alert.labels
    assert records[1].kind == "record"
    assert records[1].name == "job:up:avg"


def test_extract_osprey_condition_document() -> None:
    document = {
        "condition": 'up{job="api"} == 0',
        "context": {
            "id": "ac-123",
            "tip_situation": "API instance down",
        },
    }
    records = extract_rule_records(document, file_path="osprey/a.yaml")
    assert len(records) == 1
    assert records[0].kind == "condition"
    assert records[0].name == "API instance down"
    assert records[0].expr == 'up{job="api"} == 0'
    assert records[0].expr_present is True
    assert records[0].is_alert_like is True


def test_extract_alert_with_condition_instead_of_expr() -> None:
    document = {
        "groups": [
            {
                "name": "example",
                "rules": [
                    {
                        "alert": "InstanceDown",
                        "condition": "up == 0",
                    },
                ],
            }
        ]
    }
    records = extract_rule_records(document, file_path="rules/b.yaml")
    assert len(records) == 1
    assert records[0].kind == "alert"
    assert records[0].name == "InstanceDown"
    assert records[0].expr == "up == 0"
    assert records[0].expr_present is True


def test_repository_analyzer_pipeline(tmp_path: Path) -> None:
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "alerts.yaml").write_text(
        """
groups:
  - name: demo
    rules:
      - alert: HighErrorRate
        expr: avg(http_requests_total)
        labels:
          severity: warning
      - record: job:up:sum
        expr: sum(up)
""",
        encoding="utf-8",
    )
    (rules / "config.yaml").write_text("scrape_configs: []\n", encoding="utf-8")
    (rules / "broken.yaml").write_text("groups: [\n", encoding="utf-8")
    (tmp_path / "notes.md").write_text("ignore\n", encoding="utf-8")

    report = RepositoryAnalyzer().analyze(tmp_path)

    assert isinstance(report, RepositoryReport)
    assert "rules/alerts.yaml" in report.scanned_files
    assert "rules/config.yaml" in report.scanned_files
    assert "rules/broken.yaml" in report.scanned_files
    assert "rules/alerts.yaml" in report.parsed_files
    assert "rules/config.yaml" in report.skipped_files
    assert any(f.path == "rules/broken.yaml" for f in report.failed_files)
    assert len(report.alerts) == 1
    assert report.alerts[0].name == "HighErrorRate"
    assert report.alerts[0].analysis is not None
    assert any(f.rule_id == "PQL001" for f in report.findings)
    assert all(f.file_path == "rules/alerts.yaml" for f in report.findings)
    assert all(f.rule_name == "HighErrorRate" for f in report.findings)
    assert len(report.recording_rules) == 1
    assert report.summary.alerts == 1
    assert report.summary.recording_rules == 1
    assert report.summary.files_failed == 1
    assert report.summary.files_skipped >= 1


def test_repository_analyzer_single_file(tmp_path: Path) -> None:
    path = tmp_path / "one.yml"
    path.write_text(
        """
groups:
  - name: g
    rules:
      - alert: A
        expr: up == 0
""",
        encoding="utf-8",
    )
    report = RepositoryAnalyzer(
        scan_config=RepositoryScanConfig(analyze_promql=False)
    ).analyze(path)
    assert report.summary.alerts == 1
    assert report.alerts[0].analysis is None
    assert report.findings == ()


def test_report_models_and_aliases() -> None:
    finding = Finding(
        rule_id="TEST",
        severity=Severity.WARNING,
        message="msg",
        explanation="why",
        category="lint",
        score=0.5,
        evidence=("e1",),
        file_path="a.yaml",
        rule_name="AlertA",
    )
    alert = RuleRecord(
        file_path="a.yaml",
        kind="alert",
        name="AlertA",
        expr="up == 0",
    )
    assert AlertRecord is RuleRecord
    summary = build_summary(
        scanned_files=("a.yaml",),
        parsed_files=("a.yaml",),
        skipped_files=(),
        failed_files=(FailedFile(path="b.yaml", error="boom"),),
        alerts=(alert,),
        recording_rules=(),
        findings=(finding,),
    )
    assert isinstance(summary, AnalysisSummary)
    assert summary.files_scanned == 1
    assert summary.files_failed == 1
    assert summary.findings == 1
    assert ("WARNING", 1) in summary.findings_by_severity

    report = RepositoryReport(
        root="/tmp/repo",
        scanned_files=("a.yaml",),
        alerts=(alert,),
        findings=(finding,),
        summary=summary,
    )
    assert report.rules == (alert,)


def test_existing_single_query_api_still_works() -> None:
    result = dude_look("sum(rate(http_requests_total[5m]))")
    assert "http_requests_total" in result.structure.metrics
    assert result.complexity.score >= 0
