"""Shared analysis context for ``dude_rushup`` analyzers.

All analyzers reuse one discovery → parse → extract pass via ``AnalysisContext``.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from promql_analyzer.dude_rushup._base import scan_rules
from promql_analyzer.repository.models import RepositoryReport, RepositoryScanConfig


@dataclass(frozen=True)
class AnalysisContext:
    """Immutable shared repository analysis context.

    Built once per invocation and passed to every analyzer so YAML/PromQL are
    not re-scanned independently.
    """

    root: Path
    report: RepositoryReport

    @classmethod
    def from_path(
        cls,
        path: Path | str,
        *,
        scan_config: RepositoryScanConfig | None = None,
    ) -> AnalysisContext:
        """Discover files, parse YAML, and extract rules once."""
        report = scan_rules(path, scan_config=scan_config)
        return cls(root=Path(path).resolve(), report=report)
