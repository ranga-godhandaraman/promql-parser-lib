"""CLI tests for promql-analyze."""

from __future__ import annotations

import json
from pathlib import Path

from promql_analyzer.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, main


def test_cli_analyze_text(capsys) -> None:
    code = main(["analyze", "sum(rate(http_requests_total[5m]))"])
    captured = capsys.readouterr()
    assert code == EXIT_OK
    assert "PROMQL ANALYSIS" in captured.out
    assert "http_requests_total" in captured.out
    assert "Complexity" in captured.out
    assert "Explanation" in captured.out


def test_cli_analyze_json(capsys) -> None:
    code = main(["analyze", "--format", "json", "sum(rate(http_requests_total[5m]))"])
    captured = capsys.readouterr()
    assert code == EXIT_OK
    payload = json.loads(captured.out)
    assert payload["structure"]["metrics"] == ["http_requests_total"]
    assert "score" in payload["complexity"]
    assert "explanation" in payload
    assert isinstance(payload["findings"], list)


def test_cli_explain(capsys) -> None:
    code = main(["explain", "rate(http_requests_total[5m])"])
    captured = capsys.readouterr()
    assert code == EXIT_OK
    assert "per-second" in captured.out
    assert "http_requests_total" in captured.out


def test_cli_analyze_file(tmp_path: Path, capsys) -> None:
    path = tmp_path / "query.promql"
    path.write_text("up\n", encoding="utf-8")
    code = main(["analyze-file", str(path)])
    captured = capsys.readouterr()
    assert code == EXIT_OK
    assert "up" in captured.out


def test_cli_invalid_query_exit_code(capsys) -> None:
    code = main(["analyze", "sum("])
    captured = capsys.readouterr()
    assert code == EXIT_ERROR
    assert "Invalid PromQL" in captured.err


def test_cli_fail_on_warning(capsys) -> None:
    # avg(_total) triggers PQL001 WARNING
    code_default = main(["analyze", "avg(http_requests_total)"])
    assert code_default == EXIT_OK

    code_warn = main(["analyze", "--fail-on", "warning", "avg(http_requests_total)"])
    assert code_warn == EXIT_FINDINGS

    code_never = main(["analyze", "--fail-on", "never", "avg(http_requests_total)"])
    assert code_never == EXIT_OK


def test_cli_missing_file(capsys) -> None:
    code = main(["analyze-file", "does-not-exist.promql"])
    assert code == EXIT_ERROR
    assert "Error:" in capsys.readouterr().err
