"""8-dimension static noise-risk rubric (``NoiseRiskAnalyzer``)."""

from __future__ import annotations

from promql_analyzer.dude_rushup.ast_features import (
    NoiseAstFeatures,
    extract_noise_features,
    metric_matches,
    parse_duration_minutes,
)
from promql_analyzer.dude_rushup.noise_models import (
    MAX_TOTAL_SCORE,
    DimensionScore,
    NoiseRiskAssessment,
    NoiseRiskConfig,
    NoiseRiskSummary,
)
from promql_analyzer.models import Finding, Severity
from promql_analyzer.parser import PromQLSyntaxError, parse_query
from promql_analyzer.repository.models import RuleRecord

# Stable dimension keys used in evidence / aggregation.
DIM_THRESHOLD = "threshold_tightness"
DIM_WINDOW = "evaluation_window"
DIM_AGGREGATION = "aggregation_breadth"
DIM_VOLATILITY = "metric_volatility"
DIM_EXPRESSION = "expression_type"
DIM_FOR = "for_duration"
DIM_BLAST = "blast_radius"
DIM_SELF = "self_resolving_risk"

_DIM_NAMES = {
    DIM_THRESHOLD: "Threshold tightness",
    DIM_WINDOW: "Evaluation window",
    DIM_AGGREGATION: "Aggregation breadth",
    DIM_VOLATILITY: "Metric volatility",
    DIM_EXPRESSION: "Expression type",
    DIM_FOR: "For duration",
    DIM_BLAST: "Blast radius",
    DIM_SELF: "Self-resolving risk",
}


class NoiseRiskAnalyzer:
    """Score alert noise *risk* using the preserved 8-dimension rubric.

    This is static analysis of alert definitions. It does not observe live
    firing rates and must not be interpreted as proof that an alert is noisy.
    """

    def __init__(self, config: NoiseRiskConfig | None = None) -> None:
        self.config = config if config is not None else NoiseRiskConfig()

    def assess_alert(self, rule: RuleRecord) -> NoiseRiskAssessment | None:
        """Score a single alert/condition rule. Returns None for other kinds."""
        if not rule.is_alert_like:
            return None
        if not rule.expr or not rule.expr.strip():
            return self._unscored(
                rule,
                reason=(
                    "Alert has no PromQL expression; noise-risk scoring requires "
                    "a PromQL condition."
                ),
            )

        try:
            ast = parse_query(rule.expr)
            features = extract_noise_features(ast)
        except PromQLSyntaxError as exc:
            return self._unscored(
                rule,
                reason=f"PromQL could not be parsed for noise-risk scoring: {exc.message}",
            )

        dimensions = self._score_dimensions(features, rule)
        risk_reasons = tuple(d.reason for d in dimensions if d.is_risk and d.reason)
        suppression = tuple(d.reason for d in dimensions if not d.is_risk and d.reason)
        total = sum(d.score for d in dimensions)
        percentage = round(total / MAX_TOTAL_SCORE * 100)
        level = self._level_for(percentage)

        return NoiseRiskAssessment(
            alert_name=rule.name,
            file_path=rule.file_path,
            expr=rule.expr,
            for_duration=rule.for_duration,
            dimensions=dimensions,
            total_score=total,
            max_score=MAX_TOTAL_SCORE,
            percentage=percentage,
            level=level,
            risk_reasons=risk_reasons,
            suppression_reasons=suppression,
            group_name=rule.group_name,
        )

    def assess_many(
        self, rules: tuple[RuleRecord, ...] | list[RuleRecord]
    ) -> list[NoiseRiskAssessment]:
        """Score all alert rules in ``rules``."""
        out: list[NoiseRiskAssessment] = []
        for rule in rules:
            assessment = self.assess_alert(rule)
            if assessment is not None:
                out.append(assessment)
        return out

    def summarize(self, assessments: list[NoiseRiskAssessment]) -> NoiseRiskSummary:
        """Build repository-level noise-risk aggregation."""
        if not assessments:
            return NoiseRiskSummary()

        low = sum(1 for a in assessments if a.level == "Low")
        medium = sum(1 for a in assessments if a.level == "Medium")
        high = sum(1 for a in assessments if a.level == "High")
        avg = sum(a.percentage for a in assessments) / len(assessments)

        ranked = sorted(
            assessments,
            key=lambda a: (a.percentage, a.total_score, a.alert_name or ""),
            reverse=True,
        )
        top = tuple(ranked[: max(0, self.config.top_risk_limit)])

        dim_totals: dict[str, list[int]] = {key: [] for key in _DIM_NAMES}
        for assessment in assessments:
            for dim in assessment.dimensions:
                if dim.key in dim_totals:
                    dim_totals[dim.key].append(dim.score)

        averages: list[tuple[str, float]] = []
        for key, name in _DIM_NAMES.items():
            values = dim_totals[key]
            avg_score = sum(values) / len(values) if values else 0.0
            averages.append((name, round(avg_score, 3)))

        return NoiseRiskSummary(
            alerts_analyzed=len(assessments),
            low=low,
            medium=medium,
            high=high,
            average_percentage=round(avg, 2),
            highest_risk=top,
            dimension_averages=tuple(averages),
        )

    def to_finding(self, assessment: NoiseRiskAssessment) -> Finding:
        """Convert an assessment into a shared ``Finding``."""
        severity = {
            "High": Severity.WARNING,
            "Medium": Severity.INFO,
            "Low": Severity.INFO,
        }.get(assessment.level, Severity.INFO)

        name = assessment.alert_name or "(unnamed alert)"
        message = (
            f"Noise risk {assessment.level} ({assessment.percentage}%) "
            f"for alert {name} — static definition risk, not observed firing"
        )
        explanation_parts = [
            f"Total score {assessment.total_score}/{assessment.max_score} "
            f"({assessment.percentage}%).",
        ]
        if assessment.risk_reasons:
            explanation_parts.append(
                "Risk factors: " + " ".join(assessment.risk_reasons)
            )
        if assessment.suppression_reasons:
            explanation_parts.append(
                "Suppression factors: " + " ".join(assessment.suppression_reasons)
            )

        evidence = [
            f"level={assessment.level}",
            f"score={assessment.total_score}/{assessment.max_score}",
            f"percentage={assessment.percentage}",
            f"for={assessment.for_duration or ''}",
        ]
        for dim in assessment.dimensions:
            evidence.append(f"{dim.key}={dim.score}/{dim.max_score}")
        evidence.extend(f"risk:{reason}" for reason in assessment.risk_reasons)
        evidence.extend(f"ok:{reason}" for reason in assessment.suppression_reasons)

        return Finding(
            rule_id="NOISE001",
            severity=severity,
            message=message,
            explanation=" ".join(explanation_parts),
            suggestion=(
                "Review the highlighted rubric dimensions and consider longer "
                "`for` windows, less volatile metrics, or tighter aggregations "
                "if false-positive risk is a concern."
                if assessment.level != "Low"
                else None
            ),
            category="noise_risk",
            score=float(assessment.percentage),
            evidence=tuple(evidence),
            file_path=assessment.file_path,
            rule_name=assessment.alert_name,
        )

    def _level_for(self, percentage: int) -> str:
        if percentage <= self.config.low_max_percent:
            return "Low"
        if percentage <= self.config.medium_max_percent:
            return "Medium"
        return "High"

    def _unscored(self, rule: RuleRecord, *, reason: str) -> NoiseRiskAssessment:
        """Return a High-risk placeholder when scoring cannot run."""
        dimensions = tuple(
            DimensionScore(
                key=key,
                name=name,
                score=0,
                reason=reason if key == DIM_THRESHOLD else "",
                is_risk=bool(reason) if key == DIM_THRESHOLD else False,
            )
            for key, name in _DIM_NAMES.items()
        )
        # Unparseable / missing expr is itself a reliability risk signal;
        # surface as Medium so it is visible without claiming live noise.
        percentage = 50
        return NoiseRiskAssessment(
            alert_name=rule.name,
            file_path=rule.file_path,
            expr=rule.expr or "",
            for_duration=rule.for_duration,
            dimensions=dimensions,
            total_score=0,
            max_score=MAX_TOTAL_SCORE,
            percentage=percentage,
            level="Medium",
            risk_reasons=(reason,),
            suppression_reasons=(),
            group_name=rule.group_name,
        )

    def _score_dimensions(
        self, features: NoiseAstFeatures, rule: RuleRecord
    ) -> tuple[DimensionScore, ...]:
        return (
            self._score_threshold(features),
            self._score_window(features),
            self._score_aggregation(features),
            self._score_volatility(features),
            self._score_expression(features),
            self._score_for_duration(rule),
            self._score_blast_radius(features),
            self._score_self_resolving(features),
        )

    def _score_threshold(self, features: NoiseAstFeatures) -> DimensionScore:
        name = _DIM_NAMES[DIM_THRESHOLD]
        if not features.comparisons:
            return DimensionScore(
                key=DIM_THRESHOLD,
                name=name,
                score=0,
                reason=(
                    "No numeric comparison threshold found — "
                    "threshold tightness could not be scored from the AST."
                ),
                is_risk=False,
            )

        # Use the primary (first) comparison, matching the original script's
        # single-threshold extraction style.
        comparison = features.comparisons[0]
        value = comparison.value
        is_state = metric_matches(features.metrics, self.config.state_metrics) or metric_matches(
            features.metrics, self.config.stable_metrics
        )

        if _is_binary_threshold(comparison.operator, value):
            if is_state:
                return DimensionScore(
                    key=DIM_THRESHOLD,
                    name=name,
                    score=0,
                    reason=(
                        "Binary threshold on a state/health metric — fires only when "
                        "the status flag changes; little floating-point fluctuation risk."
                    ),
                    is_risk=False,
                )
            return DimensionScore(
                key=DIM_THRESHOLD,
                name=name,
                score=2,
                reason=(
                    f"Binary threshold ({comparison.operator} {value:g}) on a non-state "
                    "metric — any matching sample can trigger, including transients."
                ),
                is_risk=True,
            )

        if value in self.config.tight_threshold_values or any(
            abs(value - t) < 1e-9 for t in self.config.tight_threshold_values
        ):
            return DimensionScore(
                key=DIM_THRESHOLD,
                name=name,
                score=1,
                reason=(
                    f"Configured tight threshold {comparison.operator} {value:g} — "
                    "sustained values near this level can cause fire/resolve cycles."
                ),
                is_risk=True,
            )

        loose = self.config.loose_threshold_magnitude
        if loose is not None and abs(value) >= loose:
            return DimensionScore(
                key=DIM_THRESHOLD,
                name=name,
                score=0,
                reason=(
                    f"Threshold {comparison.operator} {value:g} is at/above the configured "
                    "loose magnitude, providing noise headroom above typical baselines."
                ),
                is_risk=False,
            )

        return DimensionScore(
            key=DIM_THRESHOLD,
            name=name,
            score=0,
            reason=(
                f"Threshold {comparison.operator} {value:g} is not classified as tight "
                "by the current profile; no extra threshold noise risk applied."
            ),
            is_risk=False,
        )

    def _score_window(self, features: NoiseAstFeatures) -> DimensionScore:
        name = _DIM_NAMES[DIM_WINDOW]
        if not features.range_minutes:
            return DimensionScore(
                key=DIM_WINDOW,
                name=name,
                score=0,
                reason=(
                    "No range vector window — metric is an instant selector; "
                    "no burst-window sensitivity."
                ),
                is_risk=False,
            )

        # Score using the shortest window (most sensitive), preserving the
        # original rubric's conservative stance toward short ranges.
        minutes = min(features.range_minutes)
        label = features.range_labels[features.range_minutes.index(minutes)]
        if minutes <= 1:
            return DimensionScore(
                key=DIM_WINDOW,
                name=name,
                score=3,
                reason=(
                    f"Very short evaluation window [{label}] — "
                    "captures single-scrape spikes."
                ),
                is_risk=True,
            )
        if minutes <= 5:
            return DimensionScore(
                key=DIM_WINDOW,
                name=name,
                score=2,
                reason=(
                    f"Short evaluation window [{label}] — "
                    "brief bursts can satisfy the condition."
                ),
                is_risk=True,
            )
        if minutes <= 10:
            return DimensionScore(
                key=DIM_WINDOW,
                name=name,
                score=1,
                reason=(
                    f"Moderate evaluation window [{label}] — "
                    "balances sensitivity and noise."
                ),
                is_risk=True,
            )
        return DimensionScore(
            key=DIM_WINDOW,
            name=name,
            score=0,
            reason=(
                f"Long evaluation window [{label}] — "
                "smooths transient spikes before firing."
            ),
            is_risk=False,
        )

    def _score_aggregation(self, features: NoiseAstFeatures) -> DimensionScore:
        name = _DIM_NAMES[DIM_AGGREGATION]
        dims = len(features.by_label_dims)

        if features.has_avg and dims <= 2:
            return DimensionScore(
                key=DIM_AGGREGATION,
                name=name,
                score=2,
                reason=(
                    f"avg across {dims} label dimension(s) — healthy series may mask "
                    "degraded ones, while near-threshold averages can fluctuate."
                ),
                is_risk=True,
            )
        if features.has_min_or_max:
            return DimensionScore(
                key=DIM_AGGREGATION,
                name=name,
                score=0,
                reason=(
                    "max/min aggregation is worst-case aware — fires when the extreme "
                    "value crosses the threshold, not the average."
                ),
                is_risk=False,
            )
        if dims >= 4:
            return DimensionScore(
                key=DIM_AGGREGATION,
                name=name,
                score=1,
                reason=(
                    f"Wide by-clause with {dims} label dimensions — many independent "
                    "alert series increase total firing volume."
                ),
                is_risk=True,
            )
        return DimensionScore(
            key=DIM_AGGREGATION,
            name=name,
            score=0,
            reason=(
                f"Tight by-clause with {dims} label dimension(s) — scoped grouping "
                "reduces cross-object noise."
            ),
            is_risk=False,
        )

    def _score_volatility(self, features: NoiseAstFeatures) -> DimensionScore:
        name = _DIM_NAMES[DIM_VOLATILITY]
        if metric_matches(features.metrics, self.config.volatile_metrics):
            return DimensionScore(
                key=DIM_VOLATILITY,
                name=name,
                score=2,
                reason=(
                    "Uses a configured high-churn/volatile metric — rate/increase on "
                    "such counters can spike during internal operations or resets."
                ),
                is_risk=True,
            )
        if metric_matches(features.metrics, self.config.stable_metrics) or metric_matches(
            features.metrics, self.config.state_metrics
        ):
            return DimensionScore(
                key=DIM_VOLATILITY,
                name=name,
                score=0,
                reason=(
                    "Uses a configured state/stable metric — values change on genuine "
                    "status transitions rather than continuous churn."
                ),
                is_risk=False,
            )
        return DimensionScore(
            key=DIM_VOLATILITY,
            name=name,
            score=1,
            reason=(
                "Uses a general gauge/counter metric without a stable/volatile "
                "profile match — values may drift near thresholds under normal load."
            ),
            is_risk=True,
        )

    def _score_expression(self, features: NoiseAstFeatures) -> DimensionScore:
        name = _DIM_NAMES[DIM_EXPRESSION]
        if features.has_rate_or_increase:
            return DimensionScore(
                key=DIM_EXPRESSION,
                name=name,
                score=2,
                reason=(
                    "rate()/increase()/irate()/delta() recompute each scrape — "
                    "counter resets or scrape gaps can produce artificial spikes."
                ),
                is_risk=True,
            )
        if metric_matches(features.metrics, self.config.state_metrics) or metric_matches(
            features.metrics, self.config.stable_metrics
        ):
            return DimensionScore(
                key=DIM_EXPRESSION,
                name=name,
                score=0,
                reason=(
                    "Pure gauge/state expression — no derivative calculation; "
                    "result does not amplify counter noise."
                ),
                is_risk=False,
            )
        return DimensionScore(
            key=DIM_EXPRESSION,
            name=name,
            score=1,
            reason=(
                "Simple threshold comparison on a gauge — stable between scrapes, "
                "but workload-driven fluctuations are still possible."
            ),
            is_risk=False,
        )

    def _score_for_duration(self, rule: RuleRecord) -> DimensionScore:
        name = _DIM_NAMES[DIM_FOR]
        raw = rule.for_duration
        for_min = parse_duration_minutes(
            raw, default_minutes=self.config.missing_for_minutes
        )
        display = raw if raw else f"(missing; treated as {for_min:g}m)"

        if for_min <= 1:
            return DimensionScore(
                key=DIM_FOR,
                name=name,
                score=3,
                reason=(
                    f"Very short for: {display} — almost no debounce; "
                    "a single bad scrape can fire the alert."
                ),
                is_risk=True,
            )
        if for_min <= 5:
            return DimensionScore(
                key=DIM_FOR,
                name=name,
                score=2,
                reason=(
                    f"Short for: {display} — only a few consecutive bad scrapes "
                    "are needed to fire."
                ),
                is_risk=True,
            )
        if for_min <= 10:
            return DimensionScore(
                key=DIM_FOR,
                name=name,
                score=1,
                reason=(
                    f"Moderate for: {display} — condition must persist through "
                    "several scrape cycles before firing."
                ),
                is_risk=False,
            )
        return DimensionScore(
            key=DIM_FOR,
            name=name,
            score=0,
            reason=(
                f"Long for: {display} — strong debounce; transient spikes resolve "
                "before the alert fires."
            ),
            is_risk=False,
        )

    def _score_blast_radius(self, features: NoiseAstFeatures) -> DimensionScore:
        name = _DIM_NAMES[DIM_BLAST]
        dims = len(features.by_label_dims)
        if dims >= 4:
            return DimensionScore(
                key=DIM_BLAST,
                name=name,
                score=2,
                reason=(
                    f"High-cardinality by-clause ({dims} dims) — many independent "
                    "alert instances can fire simultaneously."
                ),
                is_risk=True,
            )
        if dims >= 3:
            return DimensionScore(
                key=DIM_BLAST,
                name=name,
                score=1,
                reason=(
                    f"Medium cardinality ({dims} dims) — moderate concurrent "
                    "instances in multi-entity environments."
                ),
                is_risk=True,
            )
        return DimensionScore(
            key=DIM_BLAST,
            name=name,
            score=0,
            reason=(
                f"Low cardinality ({dims} dims) — limited concurrent instances "
                "even in large environments."
            ),
            is_risk=False,
        )

    def _score_self_resolving(self, features: NoiseAstFeatures) -> DimensionScore:
        name = _DIM_NAMES[DIM_SELF]
        if metric_matches(features.metrics, self.config.self_resolving_metrics):
            return DimensionScore(
                key=DIM_SELF,
                name=name,
                score=1,
                reason=(
                    "Uses a configured self-resolving metric — the condition may "
                    "clear without human action once the transient window passes."
                ),
                is_risk=False,
            )
        if features.has_rate_or_increase:
            return DimensionScore(
                key=DIM_SELF,
                name=name,
                score=2,
                reason=(
                    "Self-resolving risk — rate/increase windows slide forward; "
                    "the alert can auto-resolve once a burst exits the window."
                ),
                is_risk=True,
            )
        return DimensionScore(
            key=DIM_SELF,
            name=name,
            score=0,
            reason=(
                "Alert only resolves when the root condition genuinely clears — "
                "lower risk of premature auto-resolution."
            ),
            is_risk=False,
        )


def _is_binary_threshold(operator: str, value: float) -> bool:
    if abs(value) > 1e-12 and abs(value - 1.0) > 1e-12:
        return False
    # 0 and 1 comparisons commonly encode boolean/state flips.
    return operator in {"==", "!=", ">", ">=", "<", "<="}
