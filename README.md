# PromQL Analyzer

**PromQL Analyzer** is a static analysis and explanation toolkit for PromQL.

It helps developers understand, review, and lint existing PromQL queries — without
executing them against Prometheus.

Think of it as:

> Ruff/Pylint-style analysis for PromQL, with deterministic explanations.

## What it is

- A Python library (`analyze(...)`) for structural analysis
- A CLI (`promql-analyze`) for terminals and CI logs
- Analysis of Prometheus rule YAML/YML files (`expr` fields)
- A small set of heuristic lint rules (`PQL001`–`PQL005`)
- A transparent structural complexity score (0–100)
- Deterministic human-readable query explanations

## What it is NOT

- Not a PromQL query engine
- Not a Prometheus replacement
- Not a runtime performance profiler
- Not an AI/LLM service

Static findings are heuristics. They never claim a query will definitely be slow.

## Installation

```bash
pip install promql-analyzer
```

For local development:

```bash
pip install -e ".[dev]"
```

## Python usage

```python
from promql_analyzer import analyze, AnalyzerConfig

result = analyze(
    'sum by(namespace)(rate(http_requests_total{status=~"5.."}[5m]))'
)

print(result.structure.metrics)
print(result.structure.functions)
print(result.findings)
print(result.complexity.score, result.complexity.level)
print(result.explain())            # concise
print(result.explain("detailed"))  # detailed
print(result.to_dict())            # JSON-serializable dict
```

### Analyze Prometheus rule YAML

```python
from promql_analyzer import analyze_file

report = analyze_file("alerts.yaml")  # or alerts.yml
for item in report.queries:
    print(item.source.rule_kind, item.source.rule_name, item.source.expr)
    if item.error:
        print("parse error:", item.error)
    else:
        print(item.result.findings)
```

`analyze_file()` also accepts plain `.promql` text files (single query).

YAML support looks for string values under `expr` keys, covering:

- Prometheus rule files (`groups[].rules[].expr`)
- Prometheus Operator `PrometheusRule` resources (`spec.groups...`)

### Configuration

```python
config = AnalyzerConfig(
    scrape_interval_seconds=15,
    max_grouping_labels=3,
    max_nesting_depth=4,
    disabled_rules=("PQL002",),
)

result = analyze(query, config=config)
```

### Invalid PromQL

```python
from promql_analyzer import analyze, InvalidPromQL

try:
    analyze("sum(")
except InvalidPromQL as exc:
    print(exc.message)
    print(exc.location)        # may be None
    print(exc.parser_detail)   # raw detail available; shown in str(exc) only with debug=True
```

`InvalidPromQL` is an alias of `PromQLSyntaxError`.

## CLI usage

### Analyze an inline query

```bash
promql-analyze analyze 'sum(rate(http_requests_total[5m]))'
```

### Explain a query

```bash
promql-analyze explain 'sum(rate(http_requests_total[5m]))'
promql-analyze explain --style detailed 'sum(rate(http_requests_total[5m]))'
```

### Analyze a file

```bash
# Single PromQL query file
promql-analyze analyze-file query.promql

# Prometheus rules YAML / YML (all expr fields)
promql-analyze analyze-file alerts.yaml
promql-analyze analyze-file alerts.yml --format json
promql-analyze analyze-file alerts.yaml --fail-on warning
```

### JSON output

```bash
promql-analyze analyze --format json 'sum(rate(http_requests_total[5m]))'
```

JSON keys are stable and suitable for CI tooling.

### Exit codes

| Code | Meaning |
|-----:|---------|
| 0 | Success (and findings below the fail threshold) |
| 1 | Findings met the `--fail-on` threshold |
| 2 | Invalid PromQL, missing file, or other CLI error |

Defaults:

- `--fail-on error` — warnings do **not** fail the process
- `--fail-on warning` — WARNING and ERROR fail
- `--fail-on never` — always exit 0 after a successful parse/analysis

Examples:

```bash
promql-analyze analyze --fail-on warning 'avg(http_requests_total)'
promql-analyze analyze --fail-on never 'avg(http_requests_total)'
promql-analyze analyze --debug 'sum('
```

### Useful flags

```bash
promql-analyze analyze \
  --scrape-interval 15 \
  --max-grouping-labels 3 \
  --max-nesting-depth 4 \
  --disable-rule PQL001 \
  --style detailed \
  --format text \
  'sum(rate(http_requests_total[5m]))'
```

## Rules

### PQL001 — Suspicious counter usage

**Detects:** metrics ending in `_total` used without `rate()`, `irate()`, `increase()`, or `resets()`.

**Why it matters:** counters are commonly rate-transformed before aggregation; direct use (for example `avg(http_requests_total)`) can be misleading.

**False positives:** naming is only a heuristic. A gauge can end in `_total`.

### PQL002 — Broad regex matcher

**Detects:** `label=~".*"` (WARNING) and patterns beginning with `.*` (INFO).

**Why it matters:** broad regex matching may evaluate many series. Cost depends on cardinality.

**False positives:** some broad patterns are intentional and cheap on low-cardinality metrics.

### PQL003 — Suspicious rate window

**Detects:** short `rate()` / `irate()` ranges relative to `scrape_interval_seconds * rate_range_min_multiples`.

**Why it matters:** short windows may not contain enough samples for reliable rates.

**False positives:** scrape intervals vary by environment; configure `AnalyzerConfig` / `--scrape-interval`.

### PQL004 — Potential high-cardinality grouping

**Detects:** aggregations grouping by more than `max_grouping_labels` labels. Optionally emits INFO for commonly high-cardinality label names.

**Why it matters:** many grouping labels can retain many output series.

**False positives:** required high-dimension groupings are valid; raise the threshold when intentional.

### PQL005 — Excessive nesting

**Detects:** function/aggregation nesting deeper than `max_nesting_depth`.

**Why it matters:** deep nesting hurts readability/reviewability. This is not a runtime cost score.

**False positives:** some nested forms are idiomatic (for example histogram quantiles).

## Complexity

`result.complexity.score` is a **structural** score from 0–100 with a transparent factor breakdown.

Levels:

| Score | Level |
|------:|-------|
| 0–20 | simple |
| 21–45 | moderate |
| 46–70 | complex |
| 71–100 | very_complex |

This is **not** Prometheus execution cost. Runtime cost depends on series cardinality, Prometheus configuration, storage backend, recording rules, and actual metric data.

## Limitations

- Analysis is static and offline
- Lint rules are heuristic and suppressible
- YAML support extracts `expr` fields only (not Grafana dashboard panels / arbitrary YAML)
- Parser compatibility follows `promql-parser` (Prometheus ~v2.45-oriented upstream)
- Explanations never invent metric business meaning from names alone
- No Grafana/Prometheus server integration in V1

## Development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
ruff check src tests
```

## Release / publishing (manual)

Do **not** publish automatically from CI without review.

1. **Local install**

   ```bash
   pip install -e ".[dev]"
   promql-analyze --version
   ```

2. **Build**

   ```bash
   python -m build
   ```

3. **Test the distribution**

   ```bash
   python -m twine check dist/*
   python -m venv /tmp/promql-analyzer-dist-test
   /tmp/promql-analyzer-dist-test/bin/pip install dist/*.whl
   /tmp/promql-analyzer-dist-test/bin/promql-analyze analyze 'up'
   ```

4. **Publish to TestPyPI**

   ```bash
   python -m twine upload --repository testpypi dist/*
   pip install -i https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple promql-analyzer
   ```

5. **Publish to PyPI**

   ```bash
   python -m twine upload dist/*
   ```

## License

MIT
