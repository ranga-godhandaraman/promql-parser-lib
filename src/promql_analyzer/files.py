"""Extract and analyze PromQL expressions embedded in YAML files.

Supports common Prometheus rule layouts, including:

* Prometheus rule files (``groups[].rules[].expr``)
* Prometheus Operator ``PrometheusRule`` resources (``spec.groups...``)

Any mapping entry whose key is ``expr`` and whose value is a string is treated
as a PromQL expression. This is intentionally conservative.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from promql_analyzer.analyze import analyze
from promql_analyzer.models import AnalysisResult, AnalyzerConfig
from promql_analyzer.parser import PromQLSyntaxError

YAML_SUFFIXES = {".yml", ".yaml"}


@dataclass(frozen=True)
class ExtractedQuery:
    """A PromQL expression discovered inside a YAML document."""

    expr: str
    location: str
    rule_kind: str | None = None  # "alert", "record", or None
    rule_name: str | None = None


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


def is_yaml_path(path: Path | str) -> bool:
    """Return True when ``path`` looks like a YAML file."""
    return Path(path).suffix.lower() in YAML_SUFFIXES


def extract_queries_from_yaml_text(text: str) -> list[ExtractedQuery]:
    """Parse YAML text and return all discovered ``expr`` PromQL strings."""
    documents = list(yaml.safe_load_all(text))
    extracted: list[ExtractedQuery] = []
    for doc_index, document in enumerate(documents):
        prefix = f"doc[{doc_index}]" if len(documents) > 1 else ""
        extracted.extend(_walk(document, path=prefix))
    return extracted


def extract_queries_from_yaml_file(path: Path | str) -> list[ExtractedQuery]:
    """Read a YAML file and return discovered PromQL expressions."""
    file_path = Path(path)
    text = file_path.read_text(encoding="utf-8")
    if not text.strip():
        raise ValueError(f"file is empty: {file_path}")
    return extract_queries_from_yaml_text(text)


def analyze_yaml_file(
    path: Path | str,
    config: AnalyzerConfig | None = None,
    *,
    debug: bool = False,
) -> FileAnalysisReport:
    """Analyze every PromQL ``expr`` found in a YAML/YML file."""
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"file not found: {file_path}")

    queries = extract_queries_from_yaml_file(file_path)
    if not queries:
        raise ValueError(
            f"no PromQL expr fields found in YAML file: {file_path}. "
            "Expected Prometheus-style rules with an 'expr' key."
        )

    results: list[FileQueryResult] = []
    for source in queries:
        try:
            analysis = analyze(source.expr, config=config, debug=debug)
            results.append(FileQueryResult(source=source, result=analysis))
        except PromQLSyntaxError as exc:
            results.append(FileQueryResult(source=source, error=str(exc)))
    return FileAnalysisReport(path=str(file_path), queries=tuple(results))


def analyze_file(
    path: Path | str,
    config: AnalyzerConfig | None = None,
    *,
    debug: bool = False,
) -> AnalysisResult | FileAnalysisReport:
    """Analyze a PromQL text file or a YAML rule file.

    * ``.yml`` / ``.yaml`` → extract and analyze all ``expr`` fields
    * other extensions → treat the whole file as one PromQL query
    """
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"file not found: {file_path}")

    if is_yaml_path(file_path):
        return analyze_yaml_file(file_path, config=config, debug=debug)

    text = file_path.read_text(encoding="utf-8")
    if not text.strip():
        raise ValueError(f"file is empty: {file_path}")
    return analyze(text, config=config, debug=debug)


def _walk(node: Any, path: str) -> list[ExtractedQuery]:
    found: list[ExtractedQuery] = []

    if isinstance(node, dict):
        # Prometheus rule object: may contain expr plus alert/record name.
        if "expr" in node and isinstance(node["expr"], str) and node["expr"].strip():
            rule_kind, rule_name = _rule_identity(node)
            location = path or "expr"
            if rule_kind and rule_name:
                if path:
                    location = f"{location}.{rule_kind}={rule_name}"
                else:
                    location = f"{rule_kind}={rule_name}"
            elif path:
                location = f"{path}.expr"
            else:
                location = "expr"
            found.append(
                ExtractedQuery(
                    expr=node["expr"].strip(),
                    location=location,
                    rule_kind=rule_kind,
                    rule_name=rule_name,
                )
            )

        for key, value in node.items():
            child_path = f"{path}.{key}" if path else str(key)
            # Avoid double-counting the expr string itself as a nested walk target
            # while still walking nested structures under other keys.
            if key == "expr" and isinstance(value, str):
                continue
            found.extend(_walk(value, child_path))
        return found

    if isinstance(node, list):
        for index, item in enumerate(node):
            child_path = f"{path}[{index}]" if path else f"[{index}]"
            found.extend(_walk(item, child_path))
    return found


def _rule_identity(rule: dict[str, Any]) -> tuple[str | None, str | None]:
    if isinstance(rule.get("alert"), str) and rule["alert"].strip():
        return "alert", rule["alert"].strip()
    if isinstance(rule.get("record"), str) and rule["record"].strip():
        return "record", rule["record"].strip()
    return None, None
