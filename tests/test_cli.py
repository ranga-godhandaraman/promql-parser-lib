"""CLI tests for promql-analyze."""

from __future__ import annotations

import json
from pathlib import Path

from promql_analyzer.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, main


def test_cli_dude_look_text(capsys) -> None:
    code = main(["dude-look", "sum(rate(http_requests_total[5m]))"])
    captured = capsys.readouterr()
    assert code == EXIT_OK
    assert "PROMQL ANALYSIS" in captured.out
    assert "http_requests_total" in captured.out
    assert "Complexity" in captured.out
    assert "Explanation" in captured.out


def test_cli_dude_look_json(capsys) -> None:
    code = main(["dude-look", "--format", "json", "sum(rate(http_requests_total[5m]))"])
    captured = capsys.readouterr()
    assert code == EXIT_OK
    payload = json.loads(captured.out)
    assert payload["structure"]["metrics"] == ["http_requests_total"]
    assert "score" in payload["complexity"]
    assert "explanation" in payload
    assert isinstance(payload["findings"], list)


def test_cli_dude_explain(capsys) -> None:
    code = main(["dude-explain", "rate(http_requests_total[5m])"])
    captured = capsys.readouterr()
    assert code == EXIT_OK
    assert "per-second" in captured.out
    assert "http_requests_total" in captured.out


def test_cli_dude_analyze_promql(tmp_path: Path, capsys) -> None:
    path = tmp_path / "query.promql"
    path.write_text("up\n", encoding="utf-8")
    code = main(["dude-analyze-promql", str(path)])
    captured = capsys.readouterr()
    assert code == EXIT_OK
    assert "up" in captured.out


def test_cli_invalid_query_exit_code(capsys) -> None:
    code = main(["dude-look", "sum("])
    captured = capsys.readouterr()
    assert code == EXIT_ERROR
    assert "Invalid PromQL" in captured.err


def test_cli_fail_on_warning(capsys) -> None:
    code_default = main(["dude-look", "avg(http_requests_total)"])
    assert code_default == EXIT_OK

    code_warn = main(["dude-look", "--fail-on", "warning", "avg(http_requests_total)"])
    assert code_warn == EXIT_FINDINGS

    code_never = main(["dude-look", "--fail-on", "never", "avg(http_requests_total)"])
    assert code_never == EXIT_OK


def test_cli_missing_file(capsys) -> None:
    code = main(["dude-analyze-promql", "does-not-exist.promql"])
    assert code == EXIT_ERROR
    assert "Error:" in capsys.readouterr().err
