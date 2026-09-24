"""Load and analyze PromQL from typed file helpers.

Public helpers:

* ``dude_analyze_promql`` — single PromQL text file
* ``dude_analyze_yaml`` — PromQL discovered inside a ``.yaml`` document
* ``dude_analyze_yml`` — PromQL discovered inside a ``.yml`` document
* ``dude_analyze_json`` — PromQL discovered inside a ``.json`` document

Structured helpers discover PromQL from common fields such as ``expr``,
``condition``, ``query``, and ``promql``, plus conservative heuristics for
other PromQL-looking string values.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from promql_analyzer.analyze import dude_look
from promql_analyzer.discovery import ExtractedQuery, discover_promql_queries
from promql_analyzer.models import AnalysisResult, AnalyzerConfig
from promql_analyzer.parser import PromQLSyntaxError

YAML_SUFFIXES = {".yml", ".yaml"}
JSON_SUFFIXES = {".json"}
PROMQL_SUFFIXES = {".promql", ".txt"}

# Re-export for public/package compatibility.
__all__ = [
    "ExtractedQuery",
    "FileAnalysisReport",
    "FileQueryResult",
    "dude_analyze_json",
    "dude_analyze_promql",
    "dude_analyze_yaml",
    "dude_analyze_yml",
    "extract_queries_from_structured_text",
]


@dataclass(frozen=True)
class FileQueryResult:
    """Analysis outcome for one extracted expression."""

    source: ExtractedQuery
    result: AnalysisResult | None = None
    error: str | None = None


@dataclass(frozen=True)
class FileAnalysisReport:
    """Analysis report for a file that may contain multiple queries."""

    path: str
    queries: tuple[FileQueryResult, ...]

    @property
    def findings_count(self) -> int:
        total = 0
        for item in self.queries:
            if item.result is not None:
                total += len(item.result.findings)
        return total

    @property
    def has_errors(self) -> bool:
        return any(item.error is not None for item in self.queries)


def dude_analyze_promql(
    path: Path | str,
    config: AnalyzerConfig | None = None,
    *,
    debug: bool = False,
) -> AnalysisResult:
    """Analyze a single PromQL text file (``.promql`` / ``.txt``)."""
    file_path = _require_existing(path)
    _require_suffix(file_path, PROMQL_SUFFIXES, expected="a .promql or .txt file")
    text = _read_nonempty(file_path)
    return dude_look(text, config=config, debug=debug)


def dude_analyze_yaml(
    path: Path | str,
    config: AnalyzerConfig | None = None,
    *,
    debug: bool = False,
) -> FileAnalysisReport:
    """Discover and analyze PromQL expressions inside a ``.yaml`` file."""
    file_path = _require_existing(path)
    _require_suffix(file_path, {".yaml"}, expected="a .yaml file")
    return _analyze_structured_file(file_path, suffix=".yaml", config=config, debug=debug)


def dude_analyze_yml(
    path: Path | str,
    config: AnalyzerConfig | None = None,
    *,
    debug: bool = False,
) -> FileAnalysisReport:
    """Discover and analyze PromQL expressions inside a ``.yml`` file."""
    file_path = _require_existing(path)
    _require_suffix(file_path, {".yml"}, expected="a .yml file")
    return _analyze_structured_file(file_path, suffix=".yml", config=config, debug=debug)


def dude_analyze_json(
    path: Path | str,
    config: AnalyzerConfig | None = None,
    *,
    debug: bool = False,
) -> FileAnalysisReport:
    """Discover and analyze PromQL expressions inside a ``.json`` file."""
    file_path = _require_existing(path)
    _require_suffix(file_path, {".json"}, expected="a .json file")
    return _analyze_structured_file(file_path, suffix=".json", config=config, debug=debug)


def extract_queries_from_structured_text(
    text: str,
    *,
    suffix: str,
) -> list[ExtractedQuery]:
    """Parse YAML or JSON text and return discovered PromQL strings."""
    normalized = suffix.lower()
    if normalized in YAML_SUFFIXES:
        documents = list(yaml.safe_load_all(text))
    elif normalized in JSON_SUFFIXES:
        documents = [json.loads(text)]
    else:
        raise ValueError(f"unsupported structured format: {suffix}")

    extracted: list[ExtractedQuery] = []
    for doc_index, document in enumerate(documents):
        if document is None:
            continue
        prefix = f"doc[{doc_index}]" if len(documents) > 1 else ""
        extracted.extend(discover_promql_queries(document, path=prefix))
    return extracted


def _analyze_structured_file(
    file_path: Path,
    *,
    suffix: str,
    config: AnalyzerConfig | None,
    debug: bool,
) -> FileAnalysisReport:
    text = _read_nonempty(file_path)
    queries = extract_queries_from_structured_text(text, suffix=suffix)
    if not queries:
        raise ValueError(
            f"no PromQL expressions found in {suffix} file: {file_path}. "
            "Looked for common fields (expr, condition, query, promql, …) "
            "and other PromQL-looking string values."
        )
    return _analyze_extracted(str(file_path), queries, config=config, debug=debug)


def _analyze_extracted(
    path: str,
    queries: list[ExtractedQuery],
    config: AnalyzerConfig | None,
    *,
    debug: bool,
) -> FileAnalysisReport:
    results: list[FileQueryResult] = []
    for source in queries:
        try:
            analysis = dude_look(source.expr, config=config, debug=debug)
            results.append(FileQueryResult(source=source, result=analysis))
        except PromQLSyntaxError as exc:
            results.append(FileQueryResult(source=source, error=str(exc)))
    return FileAnalysisReport(path=path, queries=tuple(results))


def _require_existing(path: Path | str) -> Path:
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"file not found: {file_path}")
    return file_path


def _require_suffix(file_path: Path, allowed: set[str], *, expected: str) -> None:
    suffix = file_path.suffix.lower()
    if suffix not in allowed:
        allowed_list = ", ".join(sorted(allowed))
        raise ValueError(
            f"expected {expected} (allowed suffixes: {allowed_list}), got: {file_path}"
        )


def _read_nonempty(file_path: Path) -> str:
    text = file_path.read_text(encoding="utf-8")
    if not text.strip():
        raise ValueError(f"file is empty: {file_path}")
    return text
