"""``dude_rushup.speakup()`` — PromQL complexity / optimization suggestions."""

from __future__ import annotations

from pathlib import Path

from promql_analyzer.analyze import dude_look
from promql_analyzer.complexity import score_complexity
from promql_analyzer.dude_rushup._base import make_finding, rebuild_report
from promql_analyzer.dude_rushup.context import AnalysisContext
from promql_analyzer.dude_rushup.inventory import build_inventory
from promql_analyzer.dude_rushup.speakup_models import SpeakupConfig, SpeakupSuggestion
from promql_analyzer.dude_rushup.speakup_transforms import (
    binary_join_info,
    find_repeated_subexpressions,
    range_windows_minutes,
    safe_drop_broad_regex_on_bare_selector,
    safe_unwrap_outer_parens,
)
from promql_analyzer.models import AnalyzerConfig, Finding, Severity
from promql_analyzer.parser import PromQLSyntaxError, parse_query
from promql_analyzer.repository.models import (
    RepositoryReport,
    RepositoryScanConfig,
    RuleRecord,
)
from promql_analyzer.structure import extract_structure


def speakup(
    path: Path | str,
    config: SpeakupConfig | None = None,
    *,
    scan_config: RepositoryScanConfig | None = None,
    context: AnalysisContext | None = None,
) -> RepositoryReport:
    """Suggest PromQL optimizations for alerts/rules in a repository.

    Suggestions are recommendations only. Queries are never auto-replaced.
    Concrete alternate PromQL is included only for structurally safe transforms
    that re-parse successfully.
    """
    cfg = config if config is not None else SpeakupConfig()
    effective_scan = scan_config if scan_config is not None else cfg.scan
    ctx = context or AnalysisContext.from_path(path, scan_config=effective_scan)

    analyzer = SpeakupAnalyzer(cfg)
    suggestions = analyzer.analyze_report(ctx.report)
    findings = tuple(item.finding for item in suggestions)
    inventory = build_inventory(ctx.report.alerts, ctx.report.recording_rules)
    return rebuild_report(
        ctx.report,
        findings,
        inventory=inventory,
        speakup_suggestions=tuple(suggestions),
    )


class SpeakupAnalyzer:
    """Produce optimization suggestions from AST + existing PQL rules."""

    def __init__(self, config: SpeakupConfig | None = None) -> None:
        self.config = config if config is not None else SpeakupConfig()
        self.analyzer_config = (
            self.config.analyzer_config
            if self.config.analyzer_config is not None
            else AnalyzerConfig()
        )

    def analyze_report(self, report: RepositoryReport) -> list[SpeakupSuggestion]:
        suggestions: list[SpeakupSuggestion] = []
        rules = list(report.alerts)
        if self.config.include_recording_rules:
            rules.extend(report.recording_rules)
        for rule in rules:
            suggestions.extend(self.analyze_rule(rule))
        return suggestions

    def analyze_rule(self, rule: RuleRecord) -> list[SpeakupSuggestion]:
        if not rule.expr or not rule.expr.strip():
            return []
        try:
            ast = parse_query(rule.expr)
        except PromQLSyntaxError:
            return [
                self._suggestion(
                    original=rule.expr,
                    rule_id="SPEAKUP000",
                    severity=Severity.INFO,
                    message="Query could not be parsed for optimization analysis",
                    reason="Invalid PromQL prevents AST-based optimization suggestions.",
                    approach="Fix syntax first (see dude_rushup.broken()), then re-run speakup.",
                    rule=rule,
                    alternative=None,
                    equivalence="recommendation_only",
                )
            ]

        structure = extract_structure(ast)
        complexity = score_complexity(structure, ast, self.analyzer_config)
        suggestions: list[SpeakupSuggestion] = []

        # Existing PQL001–PQL005 patterns via dude_look (unchanged rule behavior).
        if self.config.include_pql_rules:
            try:
                analysis = dude_look(rule.expr, config=self.analyzer_config)
            except PromQLSyntaxError:
                analysis = None
            if analysis is not None:
                for finding in analysis.findings:
                    suggestions.append(
                        self._from_pql_finding(finding, rule, complexity.score)
                    )

        # Structural complexity band.
        if complexity.level.value in self.config.complexity_levels:
            factor_names = ", ".join(f.name for f in complexity.factors[:6]) or "structure"
            suggestions.append(
                self._suggestion(
                    original=rule.expr,
                    rule_id="SPEAKUP001",
                    severity=Severity.INFO,
                    message=(
                        f"Structurally {complexity.level.value} query "
                        f"(score {complexity.score}/100)"
                    ),
                    reason=(
                        "Structural complexity is elevated based on nesting, matchers, "
                        f"aggregations, and related factors ({factor_names}). "
                        "This is not a runtime cost measurement."
                    ),
                    approach=(
                        "Consider simplifying nesting, reducing grouping labels, or "
                        "moving stable subexpressions into recording rules."
                    ),
                    rule=rule,
                    alternative=None,
                    equivalence="recommendation_only",
                    complexity_score=complexity.score,
                )
            )

        # Excessive nesting — only when PQL rules are not already included.
        if not self.config.include_pql_rules:
            from promql_analyzer.rules.ast_utils import max_call_nesting_depth

            depth = max_call_nesting_depth(ast)
            if depth > self.analyzer_config.max_nesting_depth:
                suggestions.append(
                    self._suggestion(
                        original=rule.expr,
                        rule_id="SPEAKUP002",
                        severity=Severity.WARNING,
                        message=f"Deep nesting (depth {depth})",
                        reason=(
                            "Deep function/aggregation nesting increases review burden and "
                            "can hide expensive subqueries."
                        ),
                        approach=(
                            "Flatten nested calls or extract inner expressions into "
                            "recording rules. Recommendation only — not an auto-rewrite."
                        ),
                        rule=rule,
                        alternative=None,
                        equivalence="recommendation_only",
                        complexity_score=complexity.score,
                    )
                )

            for aggregation in structure.aggregations:
                if len(aggregation.grouping) > self.analyzer_config.max_grouping_labels:
                    grouping = ", ".join(aggregation.grouping)
                    suggestions.append(
                        self._suggestion(
                            original=rule.expr,
                            rule_id="SPEAKUP003",
                            severity=Severity.WARNING,
                            message=(
                                f"Wide grouping in {aggregation.operator} "
                                f"({len(aggregation.grouping)} labels)"
                            ),
                            reason=(
                                f"Grouping by ({grouping}) retains many series dimensions, "
                                "which is often expensive at query time."
                            ),
                            approach=(
                                "Drop labels that are not required for the alert decision, "
                                "or aggregate earlier via a recording rule."
                            ),
                            rule=rule,
                            alternative=None,
                            equivalence="recommendation_only",
                            complexity_score=complexity.score,
                        )
                    )

        # Broad regex.
        for matcher in structure.label_matchers:
            if matcher.operator != "=~":
                continue
            if matcher.value not in {".*", "^.*$", "(?s).*"} and not matcher.value.startswith(
                ".*"
            ):
                continue
            alt = safe_drop_broad_regex_on_bare_selector(rule.expr, ast)
            suggestions.append(
                self._suggestion(
                    original=rule.expr,
                    rule_id="SPEAKUP004",
                    severity=Severity.WARNING
                    if matcher.value in {".*", "^.*$", "(?s).*"}
                    else Severity.INFO,
                    message=f'Broad regex matcher {matcher.label}=~"{matcher.value}"',
                    reason=(
                        "Unbounded or leading-.* regex matchers can force scanning many "
                        "series. Cost depends on metric cardinality."
                    ),
                    approach=(
                        "Prefer exact matchers (`=`) or narrower prefixes. "
                        + (
                            "A structurally safer selector without the redundant "
                            "`=~\".*\"` matcher is provided as an optional alternative."
                            if alt
                            else "No automatic rewrite claimed for this query shape."
                        )
                    ),
                    rule=rule,
                    alternative=alt,
                    equivalence="structural_safe" if alt else "recommendation_only",
                    complexity_score=complexity.score,
                )
            )

        # Joins / vector matching.
        for join in binary_join_info(ast):
            suggestions.append(
                self._suggestion(
                    original=rule.expr,
                    rule_id="SPEAKUP005",
                    severity=Severity.INFO,
                    message=f"Vector-matching join detected ({join})",
                    reason=(
                        "many-to-one / on/ignoring joins can be expensive when label "
                        "sets are large or poorly constrained."
                    ),
                    approach=(
                        "Tighten matchers on both sides, reduce group_left/right label "
                        "payloads, or pre-aggregate with recording rules."
                    ),
                    rule=rule,
                    alternative=None,
                    equivalence="recommendation_only",
                    complexity_score=complexity.score,
                )
            )

        # Repeated subexpressions.
        repeated = find_repeated_subexpressions(ast)
        for text in repeated[:5]:
            suggestions.append(
                self._suggestion(
                    original=rule.expr,
                    rule_id="SPEAKUP006",
                    severity=Severity.INFO,
                    message="Repeated subexpression detected",
                    reason=(
                        f"The subexpression `{text}` appears more than once. "
                        "Prometheus may evaluate overlapping work separately."
                    ),
                    approach=(
                        "Consider extracting the shared subexpression into a recording "
                        "rule. Semantic equivalence of inlining/outlining is not claimed."
                    ),
                    rule=rule,
                    alternative=None,
                    equivalence="recommendation_only",
                    complexity_score=complexity.score,
                    evidence_extra=(f"subexpression={text}",),
                )
            )

        # Large range windows.
        for label, minutes in range_windows_minutes(ast):
            if minutes < self.config.large_range_minutes:
                continue
            suggestions.append(
                self._suggestion(
                    original=rule.expr,
                    rule_id="SPEAKUP007",
                    severity=Severity.INFO,
                    message=f"Large range window [{label}]",
                    reason=(
                        "Very large range selectors increase samples examined per series. "
                        "Whether this is necessary depends on the alert intent."
                    ),
                    approach=(
                        "Use the smallest window that still captures the condition, or "
                        "precompute with a recording rule / subquery carefully."
                    ),
                    rule=rule,
                    alternative=None,
                    equivalence="recommendation_only",
                    complexity_score=complexity.score,
                    evidence_extra=(f"range={label}", f"minutes={minutes:g}"),
                )
            )

        # Redundant outer parentheses — structurally safe rewrite.
        alt_parens = safe_unwrap_outer_parens(rule.expr, ast)
        if alt_parens:
            suggestions.append(
                self._suggestion(
                    original=rule.expr,
                    rule_id="SPEAKUP008",
                    severity=Severity.INFO,
                    message="Redundant outer parentheses",
                    reason=(
                        "The query is wrapped in outer parentheses that do not "
                        "change evaluation."
                    ),
                    approach=(
                        "Optional cleanup: unwrap outer parentheses. Marked "
                        "structural_safe after re-parse; still a recommendation only."
                    ),
                    rule=rule,
                    alternative=alt_parens,
                    equivalence="structural_safe",
                    complexity_score=complexity.score,
                )
            )

        # Nested aggregations — recommendation only.
        if len(structure.aggregations) >= 2:
            suggestions.append(
                self._suggestion(
                    original=rule.expr,
                    rule_id="SPEAKUP009",
                    severity=Severity.INFO,
                    message="Multiple aggregations in one expression",
                    reason=(
                        "Stacked aggregations may be necessary, but often one level "
                        "can be moved to a recording rule for clarity and reuse."
                    ),
                    approach=(
                        "Review whether every aggregation is required; extract stable "
                        "inner aggregates when appropriate. No automatic rewrite."
                    ),
                    rule=rule,
                    alternative=None,
                    equivalence="recommendation_only",
                    complexity_score=complexity.score,
                )
            )

        return suggestions

    def _from_pql_finding(
        self, finding: Finding, rule: RuleRecord, complexity_score: int
    ) -> SpeakupSuggestion:
        return self._suggestion(
            original=rule.expr or "",
            rule_id=f"SPEAKUP-{finding.rule_id}",
            severity=finding.severity,
            message=finding.message,
            reason=finding.explanation,
            approach=(
                finding.suggestion
                or "Review the finding and adjust the query if appropriate. "
                "Recommendation only — queries are not auto-replaced."
            ),
            rule=rule,
            alternative=None,
            equivalence="recommendation_only",
            complexity_score=complexity_score,
            evidence_extra=(f"source_rule={finding.rule_id}",),
        )

    def _suggestion(
        self,
        *,
        original: str,
        rule_id: str,
        severity: Severity,
        message: str,
        reason: str,
        approach: str,
        rule: RuleRecord,
        alternative: str | None,
        equivalence: str,
        complexity_score: int | None = None,
        evidence_extra: tuple[str, ...] = (),
    ) -> SpeakupSuggestion:
        evidence = [
            f"original_query={original}",
            f"equivalence={equivalence}",
            "recommendation=true",
        ]
        if alternative:
            evidence.append(f"alternative_query={alternative}")
        if complexity_score is not None:
            evidence.append(f"complexity_score={complexity_score}")
        evidence.extend(evidence_extra)

        finding = make_finding(
            rule_id=rule_id,
            severity=severity,
            message=f"[recommendation] {message}",
            explanation=reason,
            suggestion=approach,
            category="speakup",
            file_path=rule.file_path,
            rule_name=rule.name,
            score=float(complexity_score) if complexity_score is not None else None,
            evidence=tuple(evidence),
        )
        return SpeakupSuggestion(
            original_query=original,
            reason=reason,
            suggested_approach=approach,
            finding=finding,
            alternative_query=alternative,
            equivalence=equivalence,
            file_path=rule.file_path,
            rule_name=rule.name,
            complexity_score=complexity_score,
        )
