"""PQL005 — Excessive nesting depth (no complexity scoring yet)."""

from __future__ import annotations

from promql_analyzer.models import Finding, Severity
from promql_analyzer.rules.ast_utils import max_call_nesting_depth
from promql_analyzer.rules.engine import RuleContext


class ExcessiveNestingRule:
    """Flag deeply nested function/aggregation expressions."""

    rule_id = "PQL005"

    def check(self, context: RuleContext) -> list[Finding]:
        threshold = context.config.max_nesting_depth
        if threshold < 1:
            return []

        depth = max_call_nesting_depth(context.expr)
        if depth <= threshold:
            return []

        # WARNING when substantially over the limit; INFO when just over.
        severity = Severity.WARNING if depth >= threshold + 2 else Severity.INFO

        return [
            Finding(
                rule_id=self.rule_id,
                severity=severity,
                message=(
                    f"Query nesting depth is {depth}, which exceeds the "
                    f"configured maximum of {threshold}."
                ),
                explanation=(
                    "Deep nesting of functions and aggregations can make queries "
                    "harder to read and review. This check measures structural "
                    "nesting depth only — it is not a runtime performance score "
                    "and does not mean the query will be slow."
                ),
                suggestion=(
                    "Consider simplifying nested expressions, introducing "
                    "recording rules, or raising `max_nesting_depth` in "
                    "AnalyzerConfig if the nesting is intentional."
                ),
            )
        ]
