"""PQL003 — Suspicious rate/irate range windows."""

from __future__ import annotations

import promql_parser
from promql_parser import Call, MatrixSelector

from promql_analyzer.models import Finding, Severity
from promql_analyzer.rules.ast_utils import timedelta_to_seconds, walk_with_ancestors
from promql_analyzer.rules.engine import RuleContext

_RATE_FUNCTIONS = frozenset({"rate", "irate"})


class SuspiciousRateWindowRule:
    """Warn when rate-like windows look short relative to scrape interval."""

    rule_id = "PQL003"

    def check(self, context: RuleContext) -> list[Finding]:
        config = context.config
        if config.scrape_interval_seconds <= 0:
            return []
        if config.rate_range_min_multiples <= 0:
            return []

        min_seconds = config.scrape_interval_seconds * config.rate_range_min_multiples
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()

        def visit(node: object, _ancestors: tuple[object, ...]) -> None:
            if not isinstance(node, Call):
                return
            func_name = node.func.name
            if func_name not in _RATE_FUNCTIONS:
                return
            if not node.args:
                return
            arg0 = node.args[0]
            if not isinstance(arg0, MatrixSelector):
                return

            range_seconds = timedelta_to_seconds(arg0.range)
            if range_seconds >= min_seconds:
                return

            try:
                range_text = promql_parser.display_duration(arg0.range)
            except Exception:  # noqa: BLE001
                range_text = f"{int(range_seconds)}s"

            key = (func_name, range_text)
            if key in seen:
                return
            seen.add(key)

            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    severity=Severity.WARNING,
                    message=(
                        f"`{func_name}()` uses a short range window `[{range_text}]` "
                        f"relative to the configured scrape interval "
                        f"({config.scrape_interval_seconds}s)."
                    ),
                    explanation=(
                        f"This is a heuristic check. With scrape_interval_seconds="
                        f"{config.scrape_interval_seconds} and "
                        f"rate_range_min_multiples={config.rate_range_min_multiples}, "
                        f"ranges shorter than {min_seconds:g}s may not contain enough "
                        f"samples for reliable `{func_name}()` results. Actual scrape "
                        f"intervals and metric freshness vary by environment, so this "
                        f"is not a guarantee of incorrect results."
                    ),
                    suggestion=(
                        f"Consider increasing the range window to at least "
                        f"{min_seconds:g}s (commonly "
                        f"{config.rate_range_min_multiples:g}× scrape interval), "
                        "or adjust AnalyzerConfig if your scrape interval differs."
                    ),
                )
            )

        walk_with_ancestors(context.expr, visit)
        return findings
