"""Tests for ``dude_rushup.broken()``, ``vuln()``, and ``secuch()``."""

from __future__ import annotations

from pathlib import Path

from promql_analyzer import (
    BrokenConfig,
    SecuchConfig,
    VulnConfig,
    dude_rushup,
)
from promql_analyzer.dude_rushup.inventory import build_inventory, normalize_expr
from promql_analyzer.repository.extract import extract_rule_records


def _ids(report) -> set[str]:
    return {f.rule_id for f in report.findings}


def _by_id(report, rule_id: str):
    return [f for f in report.findings if f.rule_id == rule_id]


def test_broken_detects_invalid_yaml_without_crashing(tmp_path: Path) -> None:
    (tmp_path / "bad.yaml").write_text("groups: [\n", encoding="utf-8")
    (tmp_path / "good.yaml").write_text(
        """
groups:
  - name: g
    rules:
      - alert: Ok
        expr: up == 0
""",
        encoding="utf-8",
    )
    report = dude_rushup.broken(tmp_path)
    assert any(f.rule_id == "BROKEN001" for f in report.findings)
    assert any(f.file_path == "bad.yaml" for f in report.findings)
    assert report.summary.files_failed == 1
    assert any(a.name == "Ok" for a in report.alerts)


def test_broken_missing_and_empty_expr(tmp_path: Path) -> None:
    (tmp_path / "rules.yaml").write_text(
        """
groups:
  - name: g
    rules:
      - alert: NoExpr
        labels:
          severity: warning
      - alert: EmptyExpr
        expr: "   "
      - alert: BadPromQL
        expr: "sum("
      - alert: BadLabels
        expr: up == 0
        labels: ["x"]
      - alert: BadAnnotations
        expr: up == 0
        annotations: "nope"
      - alert: ""
        expr: up == 0
""",
        encoding="utf-8",
    )
    report = dude_rushup.broken(tmp_path)
    ids = _ids(report)
    assert "BROKEN011" in ids  # missing expr
    assert "BROKEN012" in ids  # empty expr
    assert "BROKEN014" in ids  # invalid promql
    assert "BROKEN015" in ids  # malformed labels
    assert "BROKEN017" in ids  # malformed annotations
    assert "BROKEN010" in ids  # empty alert name
    for finding in report.findings:
        assert finding.category == "broken"
        assert finding.file_path is not None


def test_broken_required_metadata_is_opt_in(tmp_path: Path) -> None:
    (tmp_path / "rules.yaml").write_text(
        """
groups:
  - name: g
    rules:
      - alert: Plain
        expr: up == 0
""",
        encoding="utf-8",
    )
    plain = dude_rushup.broken(tmp_path)
    assert "BROKEN021" not in _ids(plain)

    strict = dude_rushup.broken(
        tmp_path,
        config=BrokenConfig(
            required_alert_labels=("severity",),
            required_alert_annotations=("summary",),
            require_for_on_alerts=True,
        ),
    )
    ids = _ids(strict)
    assert "BROKEN021" in ids
    assert "BROKEN022" in ids
    assert "BROKEN020" in ids


def test_broken_duplicate_alert_names_across_files(tmp_path: Path) -> None:
    (tmp_path / "a.yaml").write_text(
        """
groups:
  - name: g
    rules:
      - alert: Dup
        expr: up == 0
""",
        encoding="utf-8",
    )
    (tmp_path / "b.yaml").write_text(
        """
groups:
  - name: g
    rules:
      - alert: Dup
        expr: up == 1
""",
        encoding="utf-8",
    )
    report = dude_rushup.broken(tmp_path)
    dups = _by_id(report, "BROKENDUP001")
    assert len(dups) == 1
    assert dups[0].rule_name == "Dup"
    assert report.inventory is not None
    assert report.inventory.duplicate_alert_name_count == 1


def test_broken_duplicate_and_near_duplicate_exprs(tmp_path: Path) -> None:
    (tmp_path / "rules.yaml").write_text(
        """
groups:
  - name: g
    rules:
      - alert: One
        expr: "up == 0"
        labels:
          severity: critical
      - alert: Two
        expr: "up   ==    0"
        labels:
          severity: critical
""",
        encoding="utf-8",
    )
    report = dude_rushup.broken(tmp_path)
    assert any(f.rule_id == "BROKENDUP002" for f in report.findings)
    assert any(f.rule_id == "BROKENDUP003" for f in report.findings)
    assert normalize_expr("up   ==    0") == normalize_expr("up == 0")


def test_extract_incomplete_rules() -> None:
    docs = {
        "groups": [
            {
                "name": "g",
                "rules": [
                    {"alert": "X"},
                    {"alert": "", "expr": "up"},
                    {"record": "job:up", "expr": "sum(up)"},
                ],
            }
        ]
    }
    records = extract_rule_records(docs, file_path="r.yaml")
    assert len(records) == 3
    assert records[0].expr_present is False
    assert records[1].name_empty is True
    assert records[2].kind == "record"


def test_vuln_detects_high_confidence_secrets(tmp_path: Path) -> None:
    (tmp_path / "rules.yaml").write_text(
        """
groups:
  - name: g
    rules:
      - alert: Leaky
        expr: up == 0
        labels:
          severity: warning
        annotations:
          summary: normal text
          token: "AKIAIOSFODNN7EXAMPLE"
          runbook: "https://user:s3cr3tpass@example.com/path"
          note: "api_key=abcdEFGHijklMNOP1234"
""",
        encoding="utf-8",
    )
    report = dude_rushup.vuln(tmp_path)
    ids = _ids(report)
    assert "VULN002" in ids
    assert "VULN003" in ids
    assert "VULN006" in ids or "VULN007" in ids
    assert all(f.category == "vuln" for f in report.findings)
    assert all("potential" in f.message.lower() or "possible" in f.message.lower()
               or "potential" in f.explanation.lower() for f in report.findings)
    assert all(f.file_path == "rules.yaml" for f in report.findings)
    assert all(f.rule_name == "Leaky" for f in report.findings)


def test_vuln_ignores_placeholders_and_templates(tmp_path: Path) -> None:
    (tmp_path / "rules.yaml").write_text(
        """
groups:
  - name: g
    rules:
      - alert: Clean
        expr: up == 0
        annotations:
          password: "CHANGEME"
          token: "{{ $labels.instance }}"
          summary: "disk full on {{ $labels.device }}"
""",
        encoding="utf-8",
    )
    report = dude_rushup.vuln(tmp_path)
    assert report.findings == ()


def test_secuch_policy_checks(tmp_path: Path) -> None:
    (tmp_path / "rules.yaml").write_text(
        """
groups:
  - name: g
    rules:
      - alert: PolicyGap
        expr: up == 0
        labels:
          severity: critical
          env: prod
        annotations:
          summary: something
          runbook_url: https://wiki.evil.example/runbook
""",
        encoding="utf-8",
    )
    report = dude_rushup.secuch(
        tmp_path,
        config=SecuchConfig(
            required_labels=("severity", "team"),
            required_annotations=("summary",),
            ownership_labels_any_of=("owner", "team"),
            runbook_annotations_any_of=("runbook_url",),
            forbidden_labels=("env",),
            forbidden_label_values=(("severity", "critical"),),
            allowed_url_domains=("docs.example.com",),
        ),
    )
    ids = _ids(report)
    assert "SECUCH001" in ids  # missing team
    assert "SECUCH003" in ids  # missing ownership
    assert "SECUCH005" in ids  # forbidden env
    assert "SECUCH006" in ids  # forbidden severity=critical
    assert "SECUCH009" in ids  # URL domain
    # runbook annotation present so SECUCH004 should not fire
    assert "SECUCH004" not in ids
    assert all(f.category == "secuch" for f in report.findings)


def test_secuch_defaults_do_not_require_optional_fields(tmp_path: Path) -> None:
    (tmp_path / "rules.yaml").write_text(
        """
groups:
  - name: g
    rules:
      - alert: Minimal
        expr: up == 0
""",
        encoding="utf-8",
    )
    report = dude_rushup.secuch(tmp_path)
    assert report.findings == ()


def test_inventory_stats(tmp_path: Path) -> None:
    (tmp_path / "rules.yaml").write_text(
        """
groups:
  - name: g
    rules:
      - alert: A
        expr: up == 0
        labels:
          severity: warning
      - alert: B
        expr: up == 0
        labels:
          severity: warning
          owner: sre
        annotations:
          runbook_url: https://docs.example.com/a
      - record: job:up:sum
        expr: sum(up)
""",
        encoding="utf-8",
    )
    report = dude_rushup.broken(tmp_path)
    inv = report.inventory
    assert inv is not None
    assert inv.alert_count == 2
    assert inv.recording_rule_count == 1
    assert inv.duplicate_expression_count == 1
    assert ("warning", 2) in inv.severity_distribution
    assert inv.missing_ownership_count == 1
    assert inv.missing_runbook_count == 1

    built = build_inventory(report.alerts, report.recording_rules)
    assert built.alert_count == 2


def test_analyzers_exportable() -> None:
    assert callable(dude_rushup.broken)
    assert callable(dude_rushup.vuln)
    assert callable(dude_rushup.secuch)
    assert BrokenConfig is dude_rushup.BrokenConfig
    assert VulnConfig is dude_rushup.VulnConfig
    assert SecuchConfig is dude_rushup.SecuchConfig
