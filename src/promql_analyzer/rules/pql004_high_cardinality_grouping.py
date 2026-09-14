"""PQL004 — Potential high-cardinality grouping."""

from __future__ import annotations

from promql_analyzer.models import Finding, Severity
from promql_analyzer.rules.engine import RuleContext


class HighCardinalityGroupingRule:
    """Warn when aggregations group by many labels."""

    rule_id = "PQL004"

    def check(self, context: RuleContext) -> list[Finding]:
        threshold = context.config.max_grouping_labels
        if threshold < 0:
            return []

        findings: list[Finding] = []
        high_card_names = {
            name.lower() for name in context.config.high_cardinality_label_names
        }

        for aggregation in context.structure.aggregations:
            grouping = aggregation.grouping
            if len(grouping) <= threshold:
                # Optional low-confidence info when below threshold but
                # commonly high-cardinality names appear.
                suspicious = [g for g in grouping if g.lower() in high_card_names]
                if suspicious and len(grouping) > 0:
                    # Only emit optional INFO when at least 2 such names to
                    # avoid noisy findings on `sum by(instance)(...)`.
                    if len(suspicious) >= 2:
                        findings.append(
                            Finding(
                                rule_id=self.rule_id,
                                severity=Severity.INFO,
                                message=(
                                    f"`{aggregation.operator}` groups by labels that "
                                    f"are commonly high-cardinality: "
                                    f"{', '.join(suspicious)}."
                                ),
                                explanation=(
                                    "Some label names are frequently high-cardinality "
                                    "in Kubernetes and microservice environments. This "
                                    "is a low-confidence naming heuristic only — these "
                                    "labels are not always expensive, and the rule does "
                                    "not know the real series count."
                                ),
                                suggestion=(
                                    "Review whether all grouping labels are required "
                                    "for the intended result."
                                ),
                            )
                        )
                continue

            grouping_type = aggregation.grouping_type or "by"
            label_list = ", ".join(grouping)
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    severity=Severity.WARNING,
                    message=(
                        f"`{aggregation.operator} {grouping_type}({label_list})` "
                        f"groups by {len(grouping)} labels, which exceeds the "
                        f"configured threshold of {threshold}."
                    ),
                    explanation=(
                        "Grouping by many labels can retain a large number of "
                        "output series. The impact depends on the cardinality of "
                        "those labels in your environment. This finding does not "
                        "mean the query will definitely be slow or return too "
                        "many series."
                    ),
                    suggestion=(
                        "Reduce the number of grouping labels when possible, or "
                        "raise `max_grouping_labels` in AnalyzerConfig if this "
                        "cardinality is intentional."
                    ),
                )
            )

            suspicious = [g for g in grouping if g.lower() in high_card_names]
            if suspicious:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=Severity.INFO,
                        message=(
                            "Among the grouping labels, these names are commonly "
                            f"high-cardinality: {', '.join(suspicious)}."
                        ),
                        explanation=(
                            "This is an optional naming heuristic. Labels such as "
                            "pod, instance, or request_id often have many values, "
                            "but actual cardinality is environment-specific."
                        ),
                        suggestion=None,
                    )
                )

        return findings
