"""Simple static-analysis rule engine."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from promql_analyzer.models import AnalyzerConfig, Finding, QueryStructure

if TYPE_CHECKING:
    from promql_parser import Expr


@dataclass(frozen=True)
class RuleContext:
    """Inputs available to every rule."""

    query: str
    structure: QueryStructure
    expr: Expr
    config: AnalyzerConfig


class Rule(Protocol):
    """A rule that returns zero or more findings for a query."""

    rule_id: str

    def check(self, context: RuleContext) -> list[Finding]:
        """Analyze ``context`` and return findings."""


def is_rule_enabled(rule_id: str, config: AnalyzerConfig) -> bool:
    """Return whether ``rule_id`` should run under ``config``."""
    if rule_id in config.disabled_rules:
        return False
    if config.enabled_rules is not None:
        return rule_id in config.enabled_rules
    return True


def run_rules(context: RuleContext, rules: list[Rule]) -> list[Finding]:
    """Run enabled rules in order and collect findings."""
    findings: list[Finding] = []
    for rule in rules:
        if not is_rule_enabled(rule.rule_id, context.config):
            continue
        findings.extend(rule.check(context))
    return findings
