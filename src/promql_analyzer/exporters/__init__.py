"""Serialize ``RepositoryReport`` to JSON / CSV / TSV / Excel.

Kept separate from analysis logic so the engine does not depend on
rendering or optional Excel libraries.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any, TextIO

from promql_analyzer.models import Finding, Severity
from promql_analyzer.repository.models import RepositoryReport


def report_to_dict(report: RepositoryReport) -> dict[str, Any]:
    """Full structured dictionary for JSON export (deterministic key order)."""
    inventory = report.inventory
    noise_summary = report.noise_summary
    payload: dict[str, Any] = {
        "root": report.root,
        "scanned_files": list(report.scanned_files),
        "parsed_files": list(report.parsed_files),
        "skipped_files": list(report.skipped_files),
        "failed_files": [
            {"path": item.path, "error": item.error} for item in report.failed_files
        ],
        "summary": {
            "files_scanned": report.summary.files_scanned,
            "files_parsed": report.summary.files_parsed,
            "files_failed": report.summary.files_failed,
            "files_skipped": report.summary.files_skipped,
            "alerts": report.summary.alerts,
            "recording_rules": report.summary.recording_rules,
            "findings": report.summary.findings,
            "findings_by_severity": [
                {"severity": sev, "count": count}
                for sev, count in report.summary.findings_by_severity
            ],
        },
        "alerts": [_rule_to_dict(rule) for rule in report.alerts],
        "recording_rules": [_rule_to_dict(rule) for rule in report.recording_rules],
        "findings": [_finding_row(finding) for finding in report.findings],
        "inventory": None,
        "noise_summary": None,
        "noise_assessments": [],
        "speakup_suggestions": [],
    }

    if inventory is not None:
        payload["inventory"] = {
            "alert_count": inventory.alert_count,
            "recording_rule_count": inventory.recording_rule_count,
            "unique_alert_names": inventory.unique_alert_names,
            "duplicate_alert_name_count": inventory.duplicate_alert_name_count,
            "duplicate_expression_count": inventory.duplicate_expression_count,
            "near_duplicate_count": inventory.near_duplicate_count,
            "severity_distribution": [
                {"severity": sev, "count": count}
                for sev, count in inventory.severity_distribution
            ],
            "missing_ownership_count": inventory.missing_ownership_count,
            "missing_runbook_count": inventory.missing_runbook_count,
        }

    if noise_summary is not None:
        payload["noise_summary"] = {
            "alerts_analyzed": noise_summary.alerts_analyzed,
            "low": noise_summary.low,
            "medium": noise_summary.medium,
            "high": noise_summary.high,
            "average_percentage": noise_summary.average_percentage,
            "dimension_averages": [
                {"dimension": name, "average": avg}
                for name, avg in noise_summary.dimension_averages
            ],
            "highest_risk": [
                _noise_assessment_to_dict(item) for item in noise_summary.highest_risk
            ],
        }

    payload["noise_assessments"] = [
        _noise_assessment_to_dict(item) for item in report.noise_assessments
    ]
    payload["speakup_suggestions"] = [
        _speakup_to_dict(item) for item in report.speakup_suggestions
    ]
    return payload


def to_json(
    report: RepositoryReport,
    path: Path | str | None = None,
    *,
    indent: int = 2,
) -> str:
    """Serialize report to JSON text; optionally write to ``path``."""
    text = json.dumps(report_to_dict(report), indent=indent, sort_keys=True)
    if path is not None:
        Path(path).write_text(text + "\n", encoding="utf-8")
    return text


def to_csv(report: RepositoryReport, path: Path | str | None = None) -> str:
    """Flatten findings to CSV rows."""
    return _delimited(report, path=path, delimiter=",")


def to_tsv(report: RepositoryReport, path: Path | str | None = None) -> str:
    """Flatten findings to TSV rows."""
    return _delimited(report, path=path, delimiter="\t")


def to_excel(report: RepositoryReport, path: Path | str) -> None:
    """Write a multi-sheet workbook using a stdlib XLSX writer.

    Analysis code does not import Excel libraries; this exporter is separate.
    """
    from promql_analyzer.exporters.xlsx_writer import write_xlsx

    sheets = {
        "Summary": _summary_rows(report),
        "Alerts": _alerts_rows(report),
        "Findings": _findings_rows(report),
        "Noise Risk": _noise_rows(report),
        "Broken": _category_rows(report, "broken"),
        "Security": _security_rows(report),
        "Suggestions": _suggestions_rows(report),
    }
    write_xlsx(path, sheets)


def _delimited(
    report: RepositoryReport,
    *,
    path: Path | str | None,
    delimiter: str,
) -> str:
    buffer = io.StringIO()
    _write_findings_delimited(buffer, report, delimiter=delimiter)
    text = buffer.getvalue()
    if path is not None:
        Path(path).write_text(text, encoding="utf-8")
    return text


_FINDING_COLUMNS = (
    "file_path",
    "rule_name",
    "rule_id",
    "category",
    "severity",
    "message",
    "explanation",
    "suggestion",
    "score",
    "evidence",
)


def _write_findings_delimited(
    stream: TextIO, report: RepositoryReport, *, delimiter: str
) -> None:
    writer = csv.DictWriter(
        stream,
        fieldnames=_FINDING_COLUMNS,
        delimiter=delimiter,
        lineterminator="\n",
        quoting=csv.QUOTE_MINIMAL,
    )
    writer.writeheader()
    for finding in report.findings:
        writer.writerow(_finding_flat(finding))


def _finding_flat(finding: Finding) -> dict[str, str]:
    severity = (
        finding.severity.value
        if isinstance(finding.severity, Severity)
        else str(finding.severity)
    )
    return {
        "file_path": finding.file_path or "",
        "rule_name": finding.rule_name or "",
        "rule_id": finding.rule_id,
        "category": finding.category or "",
        "severity": severity,
        "message": finding.message,
        "explanation": finding.explanation,
        "suggestion": finding.suggestion or "",
        "score": "" if finding.score is None else str(finding.score),
        "evidence": " | ".join(finding.evidence),
    }


def _finding_row(finding: Finding) -> dict[str, Any]:
    severity = (
        finding.severity.value
        if isinstance(finding.severity, Severity)
        else str(finding.severity)
    )
    return {
        "rule_id": finding.rule_id,
        "severity": severity,
        "message": finding.message,
        "explanation": finding.explanation,
        "suggestion": finding.suggestion,
        "category": finding.category,
        "score": finding.score,
        "evidence": list(finding.evidence),
        "file_path": finding.file_path,
        "rule_name": finding.rule_name,
    }


def _rule_to_dict(rule: Any) -> dict[str, Any]:
    return {
        "file_path": rule.file_path,
        "kind": rule.kind,
        "name": rule.name,
        "expr": rule.expr,
        "group_name": rule.group_name,
        "location": rule.location,
        "labels": dict(rule.labels),
        "annotations": dict(rule.annotations),
        "for_duration": rule.for_duration,
        "parse_error": rule.parse_error,
    }


def _noise_assessment_to_dict(item: Any) -> dict[str, Any]:
    return {
        "alert_name": item.alert_name,
        "file_path": item.file_path,
        "expr": item.expr,
        "for_duration": item.for_duration,
        "total_score": item.total_score,
        "max_score": item.max_score,
        "percentage": item.percentage,
        "level": item.level,
        "risk_reasons": list(item.risk_reasons),
        "suppression_reasons": list(item.suppression_reasons),
        "dimensions": [
            {
                "key": dim.key,
                "name": dim.name,
                "score": dim.score,
                "max_score": dim.max_score,
                "reason": dim.reason,
                "is_risk": dim.is_risk,
            }
            for dim in item.dimensions
        ],
    }


def _speakup_to_dict(item: Any) -> dict[str, Any]:
    return {
        "original_query": item.original_query,
        "reason": item.reason,
        "suggested_approach": item.suggested_approach,
        "alternative_query": item.alternative_query,
        "equivalence": item.equivalence,
        "file_path": item.file_path,
        "rule_name": item.rule_name,
        "complexity_score": item.complexity_score,
        "finding": _finding_row(item.finding),
    }


def _summary_rows(report: RepositoryReport) -> list[list[Any]]:
    rows: list[list[Any]] = [["key", "value"]]
    pairs = [
        ("root", report.root),
        ("files_scanned", report.summary.files_scanned),
        ("files_parsed", report.summary.files_parsed),
        ("files_failed", report.summary.files_failed),
        ("files_skipped", report.summary.files_skipped),
        ("alerts", report.summary.alerts),
        ("recording_rules", report.summary.recording_rules),
        ("findings", report.summary.findings),
    ]
    if report.inventory is not None:
        inv = report.inventory
        pairs.extend(
            [
                ("duplicate_alert_names", inv.duplicate_alert_name_count),
                ("duplicate_expressions", inv.duplicate_expression_count),
                ("missing_ownership", inv.missing_ownership_count),
                ("missing_runbooks", inv.missing_runbook_count),
            ]
        )
    if report.noise_summary is not None:
        ns = report.noise_summary
        pairs.extend(
            [
                ("noise_low", ns.low),
                ("noise_medium", ns.medium),
                ("noise_high", ns.high),
                ("noise_average_pct", ns.average_percentage),
            ]
        )
    rows.extend([list(pair) for pair in pairs])
    return rows


def _alerts_rows(report: RepositoryReport) -> list[list[Any]]:
    rows: list[list[Any]] = [
        [
            "file_path",
            "kind",
            "name",
            "expr",
            "for",
            "group",
            "labels",
            "annotations",
        ]
    ]
    for rule in (*report.alerts, *report.recording_rules):
        rows.append(
            [
                rule.file_path,
                rule.kind,
                rule.name or "",
                rule.expr or "",
                rule.for_duration or "",
                rule.group_name or "",
                json.dumps(dict(rule.labels), sort_keys=True),
                json.dumps(dict(rule.annotations), sort_keys=True),
            ]
        )
    return rows


def _findings_rows(report: RepositoryReport) -> list[list[Any]]:
    rows: list[list[Any]] = [list(_FINDING_COLUMNS)]
    for finding in report.findings:
        flat = _finding_flat(finding)
        rows.append([flat[col] for col in _FINDING_COLUMNS])
    return rows


def _noise_rows(report: RepositoryReport) -> list[list[Any]]:
    rows: list[list[Any]] = [
        [
            "alert_name",
            "file_path",
            "level",
            "percentage",
            "total_score",
            "max_score",
            "expr",
            "risk_reasons",
        ]
    ]
    for item in report.noise_assessments:
        rows.append(
            [
                item.alert_name or "",
                item.file_path,
                item.level,
                item.percentage,
                item.total_score,
                item.max_score,
                item.expr,
                " | ".join(item.risk_reasons),
            ]
        )
    return rows


def _category_rows(report: RepositoryReport, category: str) -> list[list[Any]]:
    rows: list[list[Any]] = [list(_FINDING_COLUMNS)]
    for finding in report.findings:
        if finding.category != category:
            continue
        flat = _finding_flat(finding)
        rows.append([flat[col] for col in _FINDING_COLUMNS])
    return rows


def _security_rows(report: RepositoryReport) -> list[list[Any]]:
    rows: list[list[Any]] = [list(_FINDING_COLUMNS)]
    for finding in report.findings:
        if finding.category not in {"vuln", "secuch"}:
            continue
        flat = _finding_flat(finding)
        rows.append([flat[col] for col in _FINDING_COLUMNS])
    return rows


def _suggestions_rows(report: RepositoryReport) -> list[list[Any]]:
    header = [
        "file_path",
        "rule_name",
        "original_query",
        "reason",
        "suggested_approach",
        "alternative_query",
        "equivalence",
        "complexity_score",
        "finding_rule_id",
        "severity",
    ]
    rows: list[list[Any]] = [header]
    for item in report.speakup_suggestions:
        severity = (
            item.finding.severity.value
            if isinstance(item.finding.severity, Severity)
            else str(item.finding.severity)
        )
        rows.append(
            [
                item.file_path or "",
                item.rule_name or "",
                item.original_query,
                item.reason,
                item.suggested_approach,
                item.alternative_query or "",
                item.equivalence,
                item.complexity_score if item.complexity_score is not None else "",
                item.finding.rule_id,
                severity,
            ]
        )
    if not report.speakup_suggestions:
        for finding in report.findings:
            if finding.category != "speakup":
                continue
            rows.append(
                [
                    finding.file_path or "",
                    finding.rule_name or "",
                    "",
                    finding.explanation,
                    finding.suggestion or "",
                    "",
                    "recommendation_only",
                    finding.score if finding.score is not None else "",
                    finding.rule_id,
                    finding.severity.value
                    if isinstance(finding.severity, Severity)
                    else str(finding.severity),
                ]
            )
    return rows
