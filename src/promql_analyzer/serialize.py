"""Stable JSON-friendly serialization for analysis results."""

from __future__ import annotations

from typing import Any

from promql_analyzer.files import FileAnalysisReport
from promql_analyzer.models import AnalysisResult, Finding, Severity


def _finding_to_dict(finding: Finding) -> dict[str, Any]:
    """Serialize a finding, including optional V2 repository fields when set."""
    payload: dict[str, Any] = {
        "rule_id": finding.rule_id,
        "severity": finding.severity.value
        if isinstance(finding.severity, Severity)
        else str(finding.severity),
        "message": finding.message,
        "explanation": finding.explanation,
        "suggestion": finding.suggestion,
    }
    if finding.category is not None:
        payload["category"] = finding.category
    if finding.score is not None:
        payload["score"] = finding.score
    if finding.evidence:
        payload["evidence"] = list(finding.evidence)
    if finding.file_path is not None:
        payload["file_path"] = finding.file_path
    if finding.rule_name is not None:
        payload["rule_name"] = finding.rule_name
    return payload


def result_to_dict(result: AnalysisResult, *, explanation_style: str = "concise") -> dict[str, Any]:
    """Convert an ``AnalysisResult`` into a JSON-serializable dictionary.

    Key names and nesting are intentionally stable for CI consumers.
    """
    style = explanation_style.strip().lower()
    explanation = result.explain(style=style)

    return {
        "query": result.query,
        "structure": {
            "metrics": list(result.structure.metrics),
            "functions": list(result.structure.functions),
            "aggregations": [
                {
                    "operator": agg.operator,
                    "grouping": list(agg.grouping),
                    "grouping_type": agg.grouping_type,
                }
                for agg in result.structure.aggregations
            ],
            "label_matchers": [
                {
                    "label": matcher.label,
                    "operator": matcher.operator,
                    "value": matcher.value,
                }
                for matcher in result.structure.label_matchers
            ],
            "range_vectors": list(result.structure.range_vectors),
            "features": {
                "contains_regex_matcher": result.structure.features.contains_regex_matcher,
                "contains_binary_operator": result.structure.features.contains_binary_operator,
                "contains_aggregation": result.structure.features.contains_aggregation,
                "contains_nested_function": result.structure.features.contains_nested_function,
                "contains_subquery": result.structure.features.contains_subquery,
                "contains_offset": result.structure.features.contains_offset,
                "contains_at_modifier": result.structure.features.contains_at_modifier,
            },
        },
        "findings": [_finding_to_dict(finding) for finding in result.findings],
        "complexity": {
            "score": result.complexity.score,
            "level": result.complexity.level.value,
            "factors": [
                {
                    "name": factor.name,
                    "contribution": factor.contribution,
                    "description": factor.description,
                }
                for factor in result.complexity.factors
            ],
        },
        "explanation": explanation,
        "explanations": {
            "concise": result.explanations.concise,
            "detailed": result.explanations.detailed,
        },
    }


def file_report_to_dict(
    report: FileAnalysisReport,
    *,
    explanation_style: str = "concise",
) -> dict[str, Any]:
    """Serialize a multi-query file analysis report."""
    queries: list[dict[str, Any]] = []
    for item in report.queries:
        entry: dict[str, Any] = {
            "location": item.source.location,
            "rule_kind": item.source.rule_kind,
            "rule_name": item.source.rule_name,
            "expr": item.source.expr,
            "error": item.error,
            "result": None,
        }
        if item.result is not None:
            entry["result"] = result_to_dict(
                item.result,
                explanation_style=explanation_style,
            )
        queries.append(entry)

    return {
        "path": report.path,
        "query_count": len(report.queries),
        "findings_count": report.findings_count,
        "has_errors": report.has_errors,
        "queries": queries,
    }
