"""Optimization suggestion models for ``dude_rushup.speakup()``."""

from __future__ import annotations

from dataclasses import dataclass, field

from promql_analyzer.models import AnalyzerConfig, Finding
from promql_analyzer.repository.models import RepositoryScanConfig


@dataclass(frozen=True)
class SpeakupConfig:
    """Configuration for speakup optimization analysis."""

    analyzer_config: AnalyzerConfig | None = None
    include_pql_rules: bool = True
    # Emit suggestions when structural complexity reaches this level.
    complexity_levels: tuple[str, ...] = ("complex", "very_complex")
    # Flag range windows at/above this many minutes.
    large_range_minutes: float = 60 * 24 * 7  # 7d
    # Analyze recording rules as well as alerts.
    include_recording_rules: bool = True
    scan: RepositoryScanConfig = field(
        default_factory=lambda: RepositoryScanConfig(
            analyze_promql=False,
            enrich_findings=False,
        )
    )


@dataclass(frozen=True)
class SpeakupSuggestion:
    """A single optimization recommendation for a PromQL expression.

    ``equivalence`` values:
    - ``structural_safe`` — alternative was AST-derived and re-parsed; still a
      recommendation, not an automatic replacement.
    - ``recommendation_only`` — guidance without a concrete rewrite, or a
      rewrite whose semantic equivalence is not claimed.
    """

    original_query: str
    reason: str
    suggested_approach: str
    finding: Finding
    alternative_query: str | None = None
    equivalence: str = "recommendation_only"
    file_path: str | None = None
    rule_name: str | None = None
    complexity_score: int | None = None
