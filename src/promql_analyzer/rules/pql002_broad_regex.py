"""PQL002 — Broad regex label matchers."""

from __future__ import annotations

from promql_analyzer.models import Finding, Severity
from promql_analyzer.rules.engine import RuleContext


class BroadRegexMatcherRule:
    """Flag regex matchers that are especially broad."""

    rule_id = "PQL002"

    def check(self, context: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, str, str]] = set()

        for matcher in context.structure.label_matchers:
            if matcher.operator != "=~":
                continue
            key = (matcher.label, matcher.operator, matcher.value)
            if key in seen:
                continue
            seen.add(key)

            severity = _severity_for_pattern(matcher.value)
            if severity is None:
                continue

            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    severity=severity,
                    message=(
                        f"Broad regex matcher detected: "
                        f'`{matcher.label}=~"{matcher.value}"`.'
                    ),
                    explanation=(
                        "Regex label matchers can require evaluating many "
                        "series, especially patterns like '.*' or patterns "
                        "that begin with '.*'. The actual cost depends on "
                        "how many time series exist for the metric and how "
                        "selective other matchers are. This finding is a "
                        "static heuristic and does not mean the query will "
                        "definitely be slow."
                    ),
                    suggestion=(
                        "Prefer exact matchers (`=`) when possible, or narrow "
                        "the regex so it does not start with an unbounded "
                        "`.*` prefix."
                    ),
                )
            )

        return findings


def _severity_for_pattern(pattern: str) -> Severity | None:
    """Return severity for a regex pattern, or None if not notable."""
    if pattern in {".*", "^.*$", "(?s).*"}:
        return Severity.WARNING
    if pattern.startswith(".*"):
        # Leading .* is often expensive; treat as lower-confidence INFO
        # when the pattern has additional content.
        return Severity.INFO
    return None
