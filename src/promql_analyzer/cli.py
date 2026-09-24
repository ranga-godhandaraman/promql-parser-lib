"""Command-line interface for promql-analyzer."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from yaml import YAMLError

from promql_analyzer import __version__
from promql_analyzer.analyze import dude_look
from promql_analyzer.dude_rushup import RushupConfig, comeup_360
from promql_analyzer.dude_rushup.broken import broken
from promql_analyzer.dude_rushup.comeup_360 import run_analyzers
from promql_analyzer.dude_rushup.context import AnalysisContext
from promql_analyzer.dude_rushup.secuch import secuch
from promql_analyzer.dude_rushup.speakup import speakup
from promql_analyzer.dude_rushup.vuln import vuln
from promql_analyzer.dude_rushup.wild import wild
from promql_analyzer.files import (
    FileAnalysisReport,
    dude_analyze_json,
    dude_analyze_promql,
    dude_analyze_yaml,
    dude_analyze_yml,
)
from promql_analyzer.models import AnalysisResult, AnalyzerConfig, Finding, Severity
from promql_analyzer.parser import PromQLSyntaxError
from promql_analyzer.repository.models import RepositoryReport
from promql_analyzer.serialize import file_report_to_dict, result_to_dict

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

_FILE_COMMANDS = {
    "dude-analyze-promql": dude_analyze_promql,
    "dude-analyze-yaml": dude_analyze_yaml,
    "dude-analyze-yml": dude_analyze_yml,
    "dude-analyze-json": dude_analyze_json,
}


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns a process exit code."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "dude-look":
            result = _look_query(args.query, args)
            _emit(result, args)
            return _exit_code_for_findings(result, args.fail_on)

        if args.command == "dude-explain":
            result = _look_query(args.query, args)
            _emit_explanation(result, args)
            return EXIT_OK

        if args.command in _FILE_COMMANDS:
            handler = _FILE_COMMANDS[args.command]
            report_or_result = handler(
                args.path,
                config=_config_from_args(args),
                debug=getattr(args, "debug", False),
            )
            if isinstance(report_or_result, FileAnalysisReport):
                _emit_file_report(report_or_result, args)
                if report_or_result.has_errors:
                    return EXIT_ERROR
                return _exit_code_for_file_report(report_or_result, args.fail_on)

            _emit(report_or_result, args)
            return _exit_code_for_findings(report_or_result, args.fail_on)

        if args.command == "rushup":
            report = _run_rushup(args)
            _emit_rushup_report(report, args)
            return _exit_code_for_repository_report(report, args.fail_on)

        parser.error(f"Unknown command: {args.command}")
        return EXIT_ERROR
    except PromQLSyntaxError as exc:
        _print_invalid_promql(exc, debug=getattr(args, "debug", False))
        return EXIT_ERROR
    except (OSError, ValueError, YAMLError, json.JSONDecodeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_ERROR


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="promql-analyze",
        description=(
            "Static analysis and explanation toolkit for PromQL. "
            "Not a query engine or Prometheus replacement."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    look_parser = subparsers.add_parser(
        "dude-look",
        help="Analyze an inline PromQL query string",
    )
    look_parser.add_argument("query", help="PromQL query string")
    _add_common_options(look_parser)

    explain_parser = subparsers.add_parser(
        "dude-explain",
        help="Explain an inline PromQL query string",
    )
    explain_parser.add_argument("query", help="PromQL query string")
    explain_parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format (default: text)",
    )
    explain_parser.add_argument(
        "--style",
        choices=("concise", "detailed"),
        default="concise",
        help="Explanation style (default: concise)",
    )
    explain_parser.add_argument(
        "--debug",
        action="store_true",
        help="Include raw parser details on syntax errors",
    )

    promql_parser = subparsers.add_parser(
        "dude-analyze-promql",
        help="Analyze a .promql / .txt file",
    )
    promql_parser.add_argument("path", type=Path, help="Path to a .promql or .txt file")
    _add_common_options(promql_parser)

    yaml_parser = subparsers.add_parser(
        "dude-analyze-yaml",
        help="Analyze PromQL found in a .yaml file",
    )
    yaml_parser.add_argument(
        "path",
        type=Path,
        help="Path to a .yaml file containing PromQL (expr, condition, …)",
    )
    _add_common_options(yaml_parser)

    yml_parser = subparsers.add_parser(
        "dude-analyze-yml",
        help="Analyze PromQL found in a .yml file",
    )
    yml_parser.add_argument(
        "path",
        type=Path,
        help="Path to a .yml file containing PromQL (expr, condition, …)",
    )
    _add_common_options(yml_parser)

    json_parser = subparsers.add_parser(
        "dude-analyze-json",
        help="Analyze PromQL found in a .json file",
    )
    json_parser.add_argument(
        "path",
        type=Path,
        help="Path to a .json file containing PromQL (expr, condition, …)",
    )
    _add_common_options(json_parser)

    rushup_parser = subparsers.add_parser(
        "rushup",
        help="V2 repository alert analysis (wild/broken/vuln/secuch/speakup/360)",
    )
    rushup_parser.add_argument(
        "path",
        type=Path,
        help="YAML/YML file, directory, or repository root",
    )
    rushup_parser.add_argument("--wild", action="store_true", help="Noise-risk analysis")
    rushup_parser.add_argument(
        "--broken", action="store_true", help="Broken/incomplete rule analysis"
    )
    rushup_parser.add_argument(
        "--vuln", action="store_true", help="Potential security exposure scanning"
    )
    rushup_parser.add_argument(
        "--secuch", action="store_true", help="Security policy / hygiene checks"
    )
    rushup_parser.add_argument(
        "--speakup", action="store_true", help="PromQL optimization suggestions"
    )
    rushup_parser.add_argument(
        "--360",
        dest="comeup_360",
        action="store_true",
        help="Run all analyzers once on a shared scan",
    )
    rushup_parser.add_argument(
        "--format",
        choices=("text", "json", "csv", "tsv", "xlsx"),
        default="text",
        help="Output format (default: text)",
    )
    rushup_parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=None,
        help="Write report to this path (required for xlsx)",
    )
    rushup_parser.add_argument(
        "--fail-on",
        choices=("never", "error", "warning"),
        default="error",
        help="Exit 1 when findings meet this severity (default: error)",
    )

    return parser


def _add_common_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--style",
        choices=("concise", "detailed"),
        default="concise",
        help="Explanation style (default: concise)",
    )
    parser.add_argument(
        "--fail-on",
        choices=("never", "error", "warning"),
        default="error",
        help=(
            "Exit 1 when findings meet this severity threshold. "
            "Default: error (warnings do not fail). "
            "Use 'warning' to fail on WARNING+, or 'never' to always exit 0 "
            "after a successful parse."
        ),
    )
    parser.add_argument(
        "--scrape-interval",
        type=int,
        default=15,
        metavar="SECONDS",
        help="Assumed scrape interval for PQL003 (default: 15)",
    )
    parser.add_argument(
        "--max-grouping-labels",
        type=int,
        default=3,
        help="Threshold for PQL004 (default: 3)",
    )
    parser.add_argument(
        "--max-nesting-depth",
        type=int,
        default=4,
        help="Threshold for PQL005 (default: 4)",
    )
    parser.add_argument(
        "--disable-rule",
        action="append",
        default=[],
        metavar="RULE_ID",
        help="Disable a rule by ID (repeatable)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Include raw parser details on syntax errors",
    )


def _config_from_args(args: argparse.Namespace) -> AnalyzerConfig:
    return AnalyzerConfig(
        scrape_interval_seconds=getattr(args, "scrape_interval", 15),
        max_grouping_labels=getattr(args, "max_grouping_labels", 3),
        max_nesting_depth=getattr(args, "max_nesting_depth", 4),
        disabled_rules=tuple(getattr(args, "disable_rule", []) or ()),
    )


def _look_query(query: str, args: argparse.Namespace) -> AnalysisResult:
    return dude_look(
        query,
        config=_config_from_args(args),
        debug=getattr(args, "debug", False),
    )


def _run_rushup(args: argparse.Namespace) -> RepositoryReport:
    path = args.path
    if not path.exists():
        raise FileNotFoundError(f"path not found: {path}")

    selected = {
        "wild": bool(args.wild),
        "broken": bool(args.broken),
        "vuln": bool(args.vuln),
        "secuch": bool(args.secuch),
        "speakup": bool(args.speakup),
    }
    run_360 = bool(args.comeup_360) or not any(selected.values())

    if run_360:
        return comeup_360(path)

    if sum(selected.values()) == 1:
        if selected["wild"]:
            return wild(path)
        if selected["broken"]:
            return broken(path)
        if selected["vuln"]:
            return vuln(path)
        if selected["secuch"]:
            return secuch(path)
        return speakup(path)

    cfg = RushupConfig().with_analyzers(
        wild=selected["wild"],
        broken=selected["broken"],
        vuln=selected["vuln"],
        secuch=selected["secuch"],
        speakup=selected["speakup"],
    )
    ctx = AnalysisContext.from_path(path, scan_config=cfg.to_scan_config())
    return run_analyzers(ctx, cfg)


def _emit_rushup_report(report: RepositoryReport, args: argparse.Namespace) -> None:
    fmt = args.format
    output: Path | None = args.output

    if fmt == "xlsx":
        if output is None:
            raise ValueError("--output is required when --format xlsx")
        report.to_excel(str(output))
        print(f"Wrote Excel report → {output}", file=sys.stderr)
        return

    if fmt == "json":
        text = report.to_json()
    elif fmt == "csv":
        text = report.to_csv()
    elif fmt == "tsv":
        text = report.to_tsv()
    else:
        text = format_rushup_report(report)

    if output is not None:
        output.write_text(text if text.endswith("\n") else text + "\n", encoding="utf-8")
        print(f"Wrote report → {output}", file=sys.stderr)
        return
    print(text, end="" if text.endswith("\n") else "\n")


def format_rushup_report(report: RepositoryReport) -> str:
    """Human-readable summary for rushup CLI text mode."""
    lines = [
        "PROMQL RUSHUP REPORT",
        "",
        f"Root: {report.root}",
        f"Files scanned: {report.summary.files_scanned}",
        f"Files parsed: {report.summary.files_parsed}",
        f"Files failed: {report.summary.files_failed}",
        f"Alerts: {report.summary.alerts}",
        f"Recording rules: {report.summary.recording_rules}",
        f"Findings: {report.summary.findings}",
        "",
    ]
    if report.noise_summary is not None:
        ns = report.noise_summary
        lines.extend(
            [
                "Noise risk",
                (
                    f"  analyzed={ns.alerts_analyzed} low={ns.low} "
                    f"medium={ns.medium} high={ns.high} avg={ns.average_percentage}%"
                ),
                "",
            ]
        )
    if report.inventory is not None:
        inv = report.inventory
        lines.extend(
            [
                "Inventory",
                (
                    f"  duplicate_names={inv.duplicate_alert_name_count} "
                    f"duplicate_exprs={inv.duplicate_expression_count} "
                    f"near_duplicates={inv.near_duplicate_count}"
                ),
                "",
            ]
        )

    lines.append("Findings")
    lines.append("")
    if not report.findings:
        lines.append("No findings.")
        lines.append("")
    else:
        for finding in report.findings:
            lines.extend(_format_finding_lines(finding))

    lines.append(
        "Note: Static analysis identifies potential risk and review signals. "
        "It does not guarantee runtime Prometheus/Alertmanager behavior."
    )
    return "\n".join(lines).rstrip() + "\n"


def _format_finding_lines(finding: Finding) -> list[str]:
    severity = (
        finding.severity.value
        if isinstance(finding.severity, Severity)
        else str(finding.severity)
    )
    location = finding.file_path or ""
    if finding.rule_name:
        location = f"{location} :: {finding.rule_name}" if location else finding.rule_name
    lines = [
        f"{finding.rule_id} {severity}"
        + (f" [{finding.category}]" if finding.category else ""),
    ]
    if location:
        lines.append(location)
    lines.append(finding.message)
    if finding.suggestion:
        lines.append(f"Suggestion: {finding.suggestion}")
    lines.append("")
    return lines


def _exit_code_for_repository_report(report: RepositoryReport, fail_on: str) -> int:
    if fail_on == "never":
        return EXIT_OK
    if report.failed_files and fail_on in {"error", "warning"}:
        return EXIT_FINDINGS

    severities = {
        finding.severity if isinstance(finding.severity, Severity) else Severity(finding.severity)
        for finding in report.findings
    }
    if fail_on == "error":
        return EXIT_FINDINGS if Severity.ERROR in severities else EXIT_OK
    if fail_on == "warning":
        if Severity.ERROR in severities or Severity.WARNING in severities:
            return EXIT_FINDINGS
        return EXIT_OK
    return EXIT_OK


def _emit(result: AnalysisResult, args: argparse.Namespace) -> None:
    if args.format == "json":
        payload = result_to_dict(result, explanation_style=args.style)
        print(json.dumps(payload, indent=2, sort_keys=True))
        return
    print(format_text_report(result, explanation_style=args.style))


def _emit_file_report(report: FileAnalysisReport, args: argparse.Namespace) -> None:
    if args.format == "json":
        payload = file_report_to_dict(report, explanation_style=args.style)
        print(json.dumps(payload, indent=2, sort_keys=True))
        return
    print(format_file_report(report, explanation_style=args.style))


def _emit_explanation(result: AnalysisResult, args: argparse.Namespace) -> None:
    if args.format == "json":
        payload = {
            "query": result.query,
            "style": args.style,
            "explanation": result.explain(style=args.style),
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
        return
    print(result.explain(style=args.style))


def format_text_report(result: AnalysisResult, *, explanation_style: str = "concise") -> str:
    """Render a terminal/CI-friendly text report."""
    lines: list[str] = []
    lines.append("PROMQL ANALYSIS")
    lines.append("")
    lines.append("Structure")
    lines.append("")
    lines.append("Metrics:")
    if result.structure.metrics:
        for metric in result.structure.metrics:
            lines.append(f"  - {metric}")
    else:
        lines.append("  (none)")

    lines.append("")
    lines.append("Functions:")
    if result.structure.functions:
        for func in result.structure.functions:
            lines.append(f"  - {func}")
    else:
        lines.append("  (none)")

    lines.append("")
    lines.append("Aggregations:")
    if result.structure.aggregations:
        for agg in result.structure.aggregations:
            grouping = ""
            if agg.grouping:
                labels = ", ".join(agg.grouping)
                grouping = f" {agg.grouping_type or 'by'}({labels})"
            lines.append(f"  - {agg.operator}{grouping}")
    else:
        lines.append("  (none)")

    lines.append("")
    lines.append("Findings")
    lines.append("")
    if not result.findings:
        lines.append("No findings.")
        lines.append("")
    else:
        for finding in result.findings:
            severity = (
                finding.severity.value
                if isinstance(finding.severity, Severity)
                else str(finding.severity)
            )
            lines.append(f"{finding.rule_id} {severity}")
            lines.append(finding.message)
            if finding.suggestion:
                lines.append("")
                lines.append(f"Suggestion: {finding.suggestion}")
            lines.append("")

    lines.append("Complexity")
    lines.append("")
    lines.append(f"{result.complexity.score} / 100")
    lines.append(result.complexity.level.value)
    if result.complexity.factors:
        lines.append("")
        for factor in result.complexity.factors:
            lines.append(f"  +{factor.contribution} {factor.name}: {factor.description}")

    lines.append("")
    lines.append("Explanation")
    lines.append("")
    lines.append(result.explain(style=explanation_style))
    return "\n".join(lines).rstrip() + "\n"


def format_file_report(
    report: FileAnalysisReport,
    *,
    explanation_style: str = "concise",
) -> str:
    """Render a multi-query YAML/file analysis report."""
    lines: list[str] = [
        "PROMQL FILE ANALYSIS",
        "",
        f"File: {report.path}",
        f"Queries: {len(report.queries)}",
        "",
    ]

    for index, item in enumerate(report.queries, start=1):
        title = f"=== Query {index}: {item.source.location} ==="
        lines.append(title)
        if item.source.rule_kind and item.source.rule_name:
            lines.append(f"{item.source.rule_kind}: {item.source.rule_name}")
        lines.append(f"expr: {item.source.expr}")
        lines.append("")

        if item.error is not None:
            lines.append(f"ERROR: {item.error}")
            lines.append("")
            continue

        assert item.result is not None
        nested = format_text_report(item.result, explanation_style=explanation_style)
        lines.append(nested.rstrip())
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _exit_code_for_findings(result: AnalysisResult, fail_on: str) -> int:
    if fail_on == "never":
        return EXIT_OK

    severities = {
        finding.severity if isinstance(finding.severity, Severity) else Severity(finding.severity)
        for finding in result.findings
    }

    if fail_on == "error":
        return EXIT_FINDINGS if Severity.ERROR in severities else EXIT_OK

    if fail_on == "warning":
        if Severity.ERROR in severities or Severity.WARNING in severities:
            return EXIT_FINDINGS
        return EXIT_OK

    return EXIT_OK


def _exit_code_for_file_report(report: FileAnalysisReport, fail_on: str) -> int:
    if fail_on == "never":
        return EXIT_OK

    for item in report.queries:
        if item.result is None:
            continue
        code = _exit_code_for_findings(item.result, fail_on)
        if code != EXIT_OK:
            return code
    return EXIT_OK


def _print_invalid_promql(exc: PromQLSyntaxError, *, debug: bool) -> None:
    parts = [f"Invalid PromQL: {exc.message}"]
    if exc.location:
        parts.append(f"Location: {exc.location}")
    if debug and exc.parser_detail:
        parts.append(f"Parser detail: {exc.parser_detail}")
    print("\n".join(parts), file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
