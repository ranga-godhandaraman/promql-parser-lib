"""Noise-risk scoring models for ``dude_rushup.wild()``."""

from __future__ import annotations

from dataclasses import dataclass, field

from promql_analyzer.repository.models import RepositoryScanConfig

MAX_DIMENSION_SCORE = 3
MAX_TOTAL_SCORE = 24  # 8 dimensions × 3


@dataclass(frozen=True)
class NoiseRiskConfig:
    """Configuration for static noise-risk scoring.

    Metric knowledge is intentionally configurable so domain-specific volatility
    profiles are not hardcoded into the generic library.
    """

    # Substring matches against metric names discovered via the PromQL AST.
    volatile_metrics: tuple[str, ...] = ()
    stable_metrics: tuple[str, ...] = ()
    # Metrics whose binary thresholds are expected (status flags, health gauges).
    state_metrics: tuple[str, ...] = ("up",)
    # Metrics that naturally clear without intervention (e.g. uptime windows).
    self_resolving_metrics: tuple[str, ...] = ()

    # Optional absolute threshold values treated as "tight" (score 1) when
    # compared with ``>``, ``>=``, ``<``, or ``<=``. Empty = no extra hints.
    tight_threshold_values: tuple[float, ...] = ()
    # Values at/above this magnitude are treated as having noise headroom (score 0).
    loose_threshold_magnitude: float | None = None

    # Level cutoffs on percentage (inclusive upper bounds for Low / Medium).
    low_max_percent: int = 25
    medium_max_percent: int = 55

    # When a rule has no ``for:`` clause, treat as this many minutes.
    # Prometheus fires immediately when ``for`` is absent → default 0.
    missing_for_minutes: float = 0.0

    # How many highest-risk alerts to surface in the repository summary.
    top_risk_limit: int = 10

    # Optional repository scan settings for discovery.
    scan: RepositoryScanConfig = field(
        default_factory=lambda: RepositoryScanConfig(
            analyze_promql=False,
            enrich_findings=False,
        )
    )


@dataclass(frozen=True)
class DimensionScore:
    """One rubric dimension score (0–3) with explanation."""

    key: str
    name: str
    score: int
    max_score: int = MAX_DIMENSION_SCORE
    reason: str = ""
    is_risk: bool = False


@dataclass(frozen=True)
class NoiseRiskAssessment:
    """Noise-risk assessment for a single alert rule."""

    alert_name: str | None
    file_path: str
    expr: str
    for_duration: str | None
    dimensions: tuple[DimensionScore, ...]
    total_score: int
    max_score: int = MAX_TOTAL_SCORE
    percentage: int = 0
    level: str = "Low"  # Low | Medium | High
    risk_reasons: tuple[str, ...] = ()
    suppression_reasons: tuple[str, ...] = ()
    group_name: str | None = None


@dataclass(frozen=True)
class NoiseRiskSummary:
    """Repository-level aggregation of noise-risk assessments."""

    alerts_analyzed: int = 0
    low: int = 0
    medium: int = 0
    high: int = 0
    average_percentage: float = 0.0
    highest_risk: tuple[NoiseRiskAssessment, ...] = ()
    dimension_averages: tuple[tuple[str, float], ...] = ()
