"""PQL001 — Suspicious counter usage based on `_total` naming."""

from __future__ import annotations

from promql_parser import VectorSelector

from promql_analyzer.models import Finding, Severity
from promql_analyzer.rules.ast_utils import (
    ancestor_function_names,
    metric_name_from_selector,
    walk_with_ancestors,
)
from promql_analyzer.rules.engine import RuleContext

# Functions commonly used with counters. Presence of any of these as an
# ancestor Call means we treat usage as intentional for this heuristic.
_COUNTER_COMPATIBLE_FUNCTIONS = frozenset(
    {
        "rate",
        "irate",
        "increase",
        "resets",
    }
)


class SuspiciousCounterUsageRule:
    """Warn when `_total` metrics appear without rate-like wrappers."""

    rule_id = "PQL001"

    def check(self, context: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        flagged: set[str] = set()

        def visit(node: object, ancestors: tuple[object, ...]) -> None:
            if not isinstance(node, VectorSelector):
                return
            # Prefer inspecting the vector inside a matrix selector via the
            # matrix path; still valid either way.
            name = metric_name_from_selector(node)
            if name is None or not name.endswith("_total"):
                return
            if name in flagged:
                return

            func_names = ancestor_function_names(ancestors)
            if any(fn in _COUNTER_COMPATIBLE_FUNCTIONS for fn in func_names):
                return

            flagged.add(name)
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    severity=Severity.WARNING,
                    message=(
                        f"Metric `{name}` appears to be a counter based on "
                        "the `_total` suffix and may be used without a "
                        "rate-like function."
                    ),
                    explanation=(
                        "Prometheus counters are typically monotonic and are "
                        "commonly transformed with functions such as rate(), "
                        "irate(), or increase() before aggregation. Direct use "
                        "of a `_total` metric (for example with avg() or sum()) "
                        "can produce misleading results. This is a naming-based "
                        "heuristic — the metric is not known to be a counter "
                        "with certainty."
                    ),
                    suggestion=(
                        f"Consider wrapping `{name}` with rate(), irate(), or "
                        "increase() over an appropriate range window before "
                        "aggregating."
                    ),
                )
            )

        walk_with_ancestors(context.expr, visit)
        return findings
