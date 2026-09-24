"""Top-level PromQL string analysis entry point."""

from __future__ import annotations

from promql_analyzer.complexity import score_complexity
from promql_analyzer.explain import explain_query
from promql_analyzer.models import AnalysisResult, AnalyzerConfig
from promql_analyzer.parser import parse_query
from promql_analyzer.rules import RuleContext, run_rules
from promql_analyzer.rules.registry import default_rules
from promql_analyzer.structure import extract_structure


def dude_look(
    query: str,
    config: AnalyzerConfig | None = None,
    *,
    debug: bool = False,
) -> AnalysisResult:
    """Analyze a PromQL query string.

    Returns structural information, lint findings, a structural complexity
    score, and deterministic human-readable explanations.

    Args:
        query: PromQL query text.
        config: Optional analyzer configuration.
        debug: When True, syntax errors include raw parser details.
    """
    cfg = config if config is not None else AnalyzerConfig()
    expr = parse_query(query, debug=debug)
    structure = extract_structure(expr)
    context = RuleContext(query=query, structure=structure, expr=expr, config=cfg)
    findings = run_rules(context, default_rules())
    complexity = score_complexity(structure, expr, cfg)
    explanations = explain_query(expr)
    return AnalysisResult(
        query=query,
        structure=structure,
        findings=tuple(findings),
        complexity=complexity,
        explanations=explanations,
    )
