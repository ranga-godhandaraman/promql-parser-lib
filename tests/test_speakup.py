"""Tests for ``dude_rushup.speakup()``."""

from __future__ import annotations

from pathlib import Path

from promql_analyzer import SpeakupConfig, dude_rushup
from promql_analyzer.dude_rushup.speakup_transforms import (
    safe_drop_broad_regex_on_bare_selector,
    safe_unwrap_outer_parens,
)
from promql_analyzer.parser import parse_query


def test_speakup_marks_recommendations(tmp_path: Path) -> None:
    (tmp_path / "rules.yaml").write_text(
        """
groups:
  - name: g
    rules:
      - alert: Nested
        expr: >
          sum(rate(http_requests_total{job=~".*"}[5m]))
""",
        encoding="utf-8",
    )
    report = dude_rushup.speakup(tmp_path)
    assert report.speakup_suggestions
    assert all(s.finding.category == "speakup" for s in report.speakup_suggestions)
    assert all("[recommendation]" in s.finding.message for s in report.speakup_suggestions)
    assert all(
        any(e.startswith("recommendation=true") for e in s.finding.evidence)
        for s in report.speakup_suggestions
    )


def test_speakup_includes_pql_patterns(tmp_path: Path) -> None:
    (tmp_path / "rules.yaml").write_text(
        """
groups:
  - name: g
    rules:
      - alert: Counter
        expr: http_requests_total
""",
        encoding="utf-8",
    )
    report = dude_rushup.speakup(tmp_path)
    ids = {s.finding.rule_id for s in report.speakup_suggestions}
    assert any(rid.startswith("SPEAKUP-PQL001") for rid in ids)


def test_safe_unwrap_parens_alternative() -> None:
    original = "((up == 0))"
    ast = parse_query(original)
    alt = safe_unwrap_outer_parens(original, ast)
    assert alt is not None
    parse_query(alt)
    assert alt != original


def test_safe_broad_regex_drop() -> None:
    original = 'http_requests_total{job=~".*"}'
    ast = parse_query(original)
    alt = safe_drop_broad_regex_on_bare_selector(original, ast)
    assert alt == "http_requests_total"
    parse_query(alt)


def test_speakup_structural_safe_alternative(tmp_path: Path) -> None:
    (tmp_path / "rules.yaml").write_text(
        """
groups:
  - name: g
    rules:
      - alert: Broad
        expr: 'http_requests_total{job=~".*"}'
""",
        encoding="utf-8",
    )
    report = dude_rushup.speakup(tmp_path)
    safe = [s for s in report.speakup_suggestions if s.equivalence == "structural_safe"]
    assert safe
    assert any(s.alternative_query == "http_requests_total" for s in safe)


def test_speakup_join_and_large_range(tmp_path: Path) -> None:
    (tmp_path / "rules.yaml").write_text(
        """
groups:
  - name: g
    rules:
      - alert: Join
        expr: 'metric_a * on(job) group_left(instance) metric_b'
      - alert: Wide
        expr: 'rate(errors_total[14d]) > 0'
""",
        encoding="utf-8",
    )
    report = dude_rushup.speakup(
        tmp_path,
        config=SpeakupConfig(large_range_minutes=60 * 24 * 7, include_pql_rules=False),
    )
    ids = {s.finding.rule_id for s in report.speakup_suggestions}
    assert "SPEAKUP005" in ids
    assert "SPEAKUP007" in ids


def test_speakup_does_not_claim_equivalence_for_recommendations(tmp_path: Path) -> None:
    (tmp_path / "rules.yaml").write_text(
        """
groups:
  - name: g
    rules:
      - alert: Complex
        expr: >
          sum by (job, instance, pod, container) (
            rate(http_requests_total[5m])
          )
""",
        encoding="utf-8",
    )
    report = dude_rushup.speakup(tmp_path)
    for suggestion in report.speakup_suggestions:
        assert "recommendation=true" in suggestion.finding.evidence
        if suggestion.equivalence == "structural_safe":
            assert suggestion.alternative_query
            # Still a recommendation, never an auto-replace.
            assert "[recommendation]" in suggestion.finding.message
        else:
            assert suggestion.equivalence == "recommendation_only"
