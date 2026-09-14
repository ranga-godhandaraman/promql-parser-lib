"""Built-in rule registry."""

from __future__ import annotations

from promql_analyzer.rules.engine import Rule
from promql_analyzer.rules.pql001_suspicious_counter import SuspiciousCounterUsageRule
from promql_analyzer.rules.pql002_broad_regex import BroadRegexMatcherRule
from promql_analyzer.rules.pql003_rate_window import SuspiciousRateWindowRule
from promql_analyzer.rules.pql004_high_cardinality_grouping import (
    HighCardinalityGroupingRule,
)
from promql_analyzer.rules.pql005_excessive_nesting import ExcessiveNestingRule


def default_rules() -> list[Rule]:
    """Return the built-in rule set in stable ID order."""
    return [
        SuspiciousCounterUsageRule(),
        BroadRegexMatcherRule(),
        SuspiciousRateWindowRule(),
        HighCardinalityGroupingRule(),
        ExcessiveNestingRule(),
    ]
