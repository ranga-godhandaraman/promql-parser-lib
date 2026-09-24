"""End-to-end tests for ``comeup_360`` and shared-context rushup pipeline."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from promql_analyzer import RushupConfig, dude_look, dude_rushup
from promql_analyzer.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, main
from promql_analyzer.dude_rushup.context import AnalysisContext


def _write_mixed_repo(tmp_path: Path) -> Path:
    (tmp_path / "good.yaml").write_text(
        """
groups:
  - name: g
    rules:
      - alert: Stable
        expr: up == 0
        for: 15m
        labels:
          severity: warning
        annotations:
          summary: instance down
      - alert: Dup
        expr: up == 0
        for: 5m
      - record: job:up:sum
        expr: sum(up)
""",
        encoding="utf-8",
    )
    (tmp_path / "noisy.yml").write_text(
        """
groups:
  - name: g
    rules:
      - alert: Noisy
        expr: rate(errors_total[1m]) > 0
        for: 1m
      - alert: Dup
        expr: up == 1
      - alert: BrokenExpr
        expr: "sum("
      - alert: MissingExpr
        labels:
          severity: info
""",
        encoding="utf-8",
    )
    (tmp_path / "bad.yaml").write_text("groups: [\n", encoding="utf-8")
    (tmp_path / "skip.yaml").write_text("scrape_configs: []\n", encoding="utf-8")
    # Many nested valid files for "large repo" smoke coverage.
    nested = tmp_path / "team" / "svc"
    nested.mkdir(parents=True)
    for index in range(20):
        (nested / f"alert-{index}.yaml").write_text(
            f"""
groups:
  - name: batch
    rules:
      - alert: Batch{index}
        expr: up == 0
        for: 10m
""",
            encoding="utf-8",
        )
    return tmp_path


def test_comeup_360_single_scan(tmp_path: Path) -> None:
    root = _write_mixed_repo(tmp_path)
    scan_calls = {"n": 0}
    original = AnalysisContext.from_path

    def counting_from_path(path, *, scan_config=None):
        scan_calls["n"] += 1
        return original(path, scan_config=scan_config)

    with patch.object(AnalysisContext, "from_path", side_effect=counting_from_path):
        report = dude_rushup.comeup_360(root)

    assert scan_calls["n"] == 1
    assert report.summary.files_failed >= 1
    assert report.summary.alerts >= 20
    categories = {f.category for f in report.findings}
    assert "broken" in categories
    assert "noise_risk" in categories
    assert "speakup" in categories
    assert report.noise_summary is not None
    assert report.speakup_suggestions is not None
    assert report.inventory is not None


def test_comeup_360_reuses_provided_context(tmp_path: Path) -> None:
    root = _write_mixed_repo(tmp_path)
    ctx = AnalysisContext.from_path(root)
    with patch.object(AnalysisContext, "from_path") as mocked:
        report = dude_rushup.comeup_360(root, context=ctx)
        mocked.assert_not_called()
    assert report.summary.alerts == ctx.report.summary.alerts


def test_individual_analyzers_still_work(tmp_path: Path) -> None:
    root = _write_mixed_repo(tmp_path)
    assert dude_rushup.wild(root).noise_summary is not None
    assert any(f.category == "broken" for f in dude_rushup.broken(root).findings)
    assert isinstance(dude_rushup.vuln(root).findings, tuple)
    assert isinstance(dude_rushup.secuch(root).findings, tuple)
    assert dude_rushup.speakup(root).speakup_suggestions is not None


def test_rushup_config_defaults(tmp_path: Path) -> None:
    root = _write_mixed_repo(tmp_path)
    cfg = RushupConfig(
        enable_vuln=False,
        enable_secuch=False,
        wild=dude_rushup.NoiseRiskConfig(state_metrics=("up",)),
    )
    report = dude_rushup.comeup_360(root, config=cfg)
    assert all(f.category != "vuln" for f in report.findings)
    assert all(f.category != "secuch" for f in report.findings)
    assert report.noise_summary is not None


def test_exports_from_comeup_360(tmp_path: Path) -> None:
    root = _write_mixed_repo(tmp_path)
    report = dude_rushup.comeup_360(root)
    payload = json.loads(report.to_json())
    assert "findings" in payload
    assert report.to_csv().startswith("file_path,")
    assert "\t" in report.to_tsv()
    xlsx = tmp_path / "full.xlsx"
    report.to_excel(str(xlsx))
    assert xlsx.exists()


def test_v1_apis_still_work() -> None:
    result = dude_look("sum(rate(http_requests_total[5m]))")
    assert "http_requests_total" in result.structure.metrics
    assert result.complexity.score >= 0


def test_cli_rushup_360_json(tmp_path: Path, capsys) -> None:
    root = _write_mixed_repo(tmp_path)
    out = tmp_path / "report.json"
    code = main(
        [
            "rushup",
            str(root),
            "--360",
            "--format",
            "json",
            "--output",
            str(out),
            "--fail-on",
            "never",
        ]
    )
    assert code == EXIT_OK
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["summary"]["alerts"] >= 1


def test_cli_rushup_broken_only(tmp_path: Path, capsys) -> None:
    root = _write_mixed_repo(tmp_path)
    code = main(["rushup", str(root), "--broken", "--fail-on", "never"])
    captured = capsys.readouterr()
    assert code == EXIT_OK
    assert "PROMQL RUSHUP REPORT" in captured.out
    assert "BROKEN" in captured.out or "Findings" in captured.out


def test_cli_rushup_missing_path(tmp_path: Path, capsys) -> None:
    code = main(["rushup", str(tmp_path / "missing"), "--360"])
    captured = capsys.readouterr()
    assert code == EXIT_ERROR
    assert "Error:" in captured.err


def test_cli_rushup_fail_on_error(tmp_path: Path) -> None:
    (tmp_path / "rules.yaml").write_text(
        """
groups:
  - name: g
    rules:
      - alert: Bad
        expr: "sum("
""",
        encoding="utf-8",
    )
    code = main(["rushup", str(tmp_path), "--broken", "--fail-on", "error"])
    assert code == EXIT_FINDINGS


def test_cli_xlsx_requires_output(tmp_path: Path, capsys) -> None:
    (tmp_path / "rules.yaml").write_text(
        """
groups:
  - name: g
    rules:
      - alert: A
        expr: up == 0
""",
        encoding="utf-8",
    )
    code = main(["rushup", str(tmp_path), "--360", "--format", "xlsx"])
    assert code == EXIT_ERROR
    assert "xlsx" in capsys.readouterr().err.lower()
