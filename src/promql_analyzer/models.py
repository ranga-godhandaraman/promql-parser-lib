"""Public data models for PromQL analysis results."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    """Finding severity levels."""

    ERROR = "ERROR"
    WARNING = "WARNING"
    INFO = "INFO"


class ComplexityLevel(str, Enum):
    """Human-readable structural complexity band."""

    SIMPLE = "simple"
    MODERATE = "moderate"
    COMPLEX = "complex"
    VERY_COMPLEX = "very_complex"


@dataclass(frozen=True)
class LabelMatcher:
    """A single label matcher from a vector selector."""

    label: str
    operator: str
    value: str


@dataclass(frozen=True)
class Aggregation:
    """An aggregation operation and optional grouping clause."""

    operator: str
    grouping: tuple[str, ...] = ()
    grouping_type: str | None = None  # "by", "without", or None


@dataclass(frozen=True)
class QueryFeatures:
    """Boolean structural features derived from the AST."""

    contains_regex_matcher: bool = False
    contains_binary_operator: bool = False
    contains_aggregation: bool = False
    contains_nested_function: bool = False
    contains_subquery: bool = False
    contains_offset: bool = False
    contains_at_modifier: bool = False


@dataclass(frozen=True)
class QueryStructure:
    """Structural facts extracted from a PromQL query."""

    metrics: tuple[str, ...] = ()
    functions: tuple[str, ...] = ()
    aggregations: tuple[Aggregation, ...] = ()
    label_matchers: tuple[LabelMatcher, ...] = ()
    range_vectors: tuple[str, ...] = ()
    features: QueryFeatures = field(default_factory=QueryFeatures)


@dataclass(frozen=True)
class Finding:
    """A single static-analysis finding produced by a rule."""

    rule_id: str
    severity: Severity
    message: str
    explanation: str
    suggestion: str | None = None


@dataclass(frozen=True)
class ComplexityFactor:
    """One contributor to the structural complexity score."""

    name: str
    contribution: int
    description: str


@dataclass(frozen=True)
class ComplexityResult:
    """Transparent structural complexity score (not runtime cost)."""

    score: int
    level: ComplexityLevel
    factors: tuple[ComplexityFactor, ...] = ()


@dataclass(frozen=True)
class Explanation:
    """Deterministic human-readable explanations of a query."""

    concise: str
    detailed: str


@dataclass(frozen=True)
class ComplexityWeights:
    """Point contributions used by the complexity scorer."""

    base: int = 5
    per_function: int = 4
    per_nesting_level_above_1: int = 8
    per_label_matcher: int = 2
    per_regex_matcher: int = 8
    per_aggregation: int = 6
    per_grouping_label: int = 5
    per_range_vector: int = 3
    per_binary_operator: int = 5
    subquery: int = 12
    offset: int = 4
    at_modifier: int = 4


@dataclass(frozen=True)
class ComplexityThresholds:
    """Score upper bounds for complexity levels (inclusive)."""

    simple_max: int = 20
    moderate_max: int = 45
    complex_max: int = 70


@dataclass(frozen=True)
class AnalyzerConfig:
    """Configuration for analysis and rule behavior.

    Rule selection:
      - If ``enabled_rules`` is set, only those rule IDs run.
      - ``disabled_rules`` always takes precedence and suppresses matches.
    """

    enabled_rules: tuple[str, ...] | None = None
    disabled_rules: tuple[str, ...] = ()
    scrape_interval_seconds: int = 15
    # Warn when rate()/irate() range < scrape_interval * this multiple.
    rate_range_min_multiples: float = 4.0
    max_grouping_labels: int = 3
    max_nesting_depth: int = 4
    # Optional low-confidence hints for PQL004 (never treated as hard errors).
    high_cardinality_label_names: tuple[str, ...] = (
        "pod",
        "pod_name",
        "instance",
        "container",
        "container_id",
        "uuid",
        "request_id",
        "trace_id",
        "id",
    )
    complexity_weights: ComplexityWeights = field(default_factory=ComplexityWeights)
    complexity_thresholds: ComplexityThresholds = field(
        default_factory=ComplexityThresholds
    )


@dataclass(frozen=True)
class AnalysisResult:
    """Result of analyzing a PromQL query."""

    query: str
    structure: QueryStructure
    findings: tuple[Finding, ...] = ()
    complexity: ComplexityResult = field(
        default_factory=lambda: ComplexityResult(score=0, level=ComplexityLevel.SIMPLE)
    )
    explanations: Explanation = field(
        default_factory=lambda: Explanation(concise="", detailed="")
    )

    def explain(self, style: str = "concise") -> str:
        """Return a deterministic explanation of the query.

        Args:
            style: ``"concise"`` (default) or ``"detailed"``.
        """
        normalized = style.strip().lower()
        if normalized == "concise":
            return self.explanations.concise
        if normalized == "detailed":
            return self.explanations.detailed
        raise ValueError(
            f"Unknown explanation style {style!r}; use 'concise' or 'detailed'"
        )

    def to_dict(self, *, explanation_style: str = "concise") -> dict:
        """Return a JSON-serializable dictionary representation."""
        from promql_analyzer.serialize import result_to_dict

        return result_to_dict(self, explanation_style=explanation_style)
