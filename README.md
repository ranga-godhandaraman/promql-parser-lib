# PromQL Analyzer

**PromQL Analyzer** is a static analysis and explanation toolkit for PromQL.

It helps you review PromQL queries and Prometheus alert/rule repositories **without
executing queries** against Prometheus.

> Ruff/Pylint-style analysis for PromQL — plus V2 repository-level alert risk review.

---

## Table of contents

1. [What it is / is not](#what-it-is)
2. [Installation](#installation)
3. [Quick start](#quick-start)
4. [V1 — single-query & file analysis](#v1--single-query--file-analysis)
5. [V2 — repository analysis (`dude_rushup`)](#v2--repository-analysis-dude_rushup)
6. [CLI reference](#cli-reference)
7. [Exports](#exports)
8. [Lint rules (PQL001–PQL005)](#lint-rules-pql001pql005)
9. [Complexity score](#complexity-score)
10. [Limitations](#limitations)
11. [Development](#development)
12. [Publishing](#publishing)

---

## What it is

- **V1 library**: `dude_look(...)` for structural analysis of one PromQL string
- **V1 file helpers**: `dude_analyze_promql` / `dude_analyze_yaml` / `dude_analyze_yml` / `dude_analyze_json`
- **Lint rules**: `PQL001`–`PQL005` plus a transparent structural complexity score (0–100)
- **V2 `dude_rushup`**: repository/folder scanners:
  - `wild()` — noise-**risk** scoring
  - `broken()` — broken / incomplete rules
  - `vuln()` — potential secret / credential exposure
  - `secuch()` — configurable security policy / hygiene
  - `speakup()` — optimization **recommendations**
  - `comeup_360()` — all of the above on **one shared scan**
- **CLI**: `promql-analyze` (V1 commands + `rushup`)

## What it is NOT

- Not a PromQL query engine
- Not a Prometheus / Alertmanager replacement
- Not a runtime performance profiler or live noise detector
- Not an AI / LLM service

**Important:** Static analysis identifies *potential risk* and review signals. It does
**not** guarantee runtime Prometheus/Alertmanager behavior, confirm vulnerabilities, or
prove that an alert is actually noisy in production.

---

## Installation

Requires **Python 3.10+**.

```bash
pip install promql-analyzer
```

Verify:

```bash
promql-analyze --version
```

### Local / editable install

```bash
git clone https://github.com/ranga-godhandaraman/promql-parser-lib.git
cd promql-parser-lib   # or your local promql-analyzer checkout
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
promql-analyze --version
pytest
```

Runtime dependencies (installed automatically):

- `promql-parser`
- `PyYAML`

No optional Excel package is required — `.xlsx` export uses the standard library.

---

## Quick start

### Analyze one query

```bash
promql-analyze dude-look 'sum(rate(http_requests_total[5m]))'
```

```python
from promql_analyzer import dude_look

result = dude_look("sum(rate(http_requests_total[5m]))")
print(result.findings)
print(result.complexity.score)
print(result.explain())
```

### Analyze a whole alert repo (V2)

```bash
promql-analyze rushup ./alerts --360 --format json --output report.json
```

```python
from promql_analyzer import dude_rushup

report = dude_rushup.comeup_360("./alerts")
print(report.summary)
report.to_json("report.json")
```

---

## V1 — single-query & file analysis

### Python: `dude_look`

```python
from promql_analyzer import dude_look, AnalyzerConfig, InvalidPromQL

result = dude_look(
    'sum by(namespace)(rate(http_requests_total{status=~"5.."}[5m]))',
    config=AnalyzerConfig(
        scrape_interval_seconds=15,
        max_grouping_labels=3,
        max_nesting_depth=4,
        disabled_rules=("PQL002",),  # optional
    ),
)

print(result.structure.metrics)
print(result.structure.functions)
print(result.structure.aggregations)
print(result.findings)
print(result.complexity.score, result.complexity.level)
print(result.explain())                 # concise
print(result.explain("detailed"))
print(result.to_dict())                 # JSON-serializable
```

### Invalid PromQL

```python
from promql_analyzer import dude_look, InvalidPromQL

try:
    dude_look("sum(")
except InvalidPromQL as exc:
    print(exc.message)
    print(exc.location)         # may be None
    print(exc.parser_detail)    # raw detail; included in str(exc) only with debug=True
```

`InvalidPromQL` is an alias of `PromQLSyntaxError`.

### Python: file helpers

```python
from promql_analyzer import (
    dude_analyze_promql,
    dude_analyze_yaml,
    dude_analyze_yml,
    dude_analyze_json,
)

dude_analyze_promql("query.promql")   # .promql / .txt
dude_analyze_yaml("alerts.yaml")      # .yaml only
dude_analyze_yml("alerts.yml")        # .yml only
dude_analyze_json("alerts.json")      # .json only
```

Each helper validates the file extension. Structured formats discover PromQL from
common fields (`expr`, `condition`, `query`, `promql`, …) and, when needed,
other PromQL-looking string values (Prometheus rules, Prometheus Operator
`PrometheusRule`, Osprey-style `condition` documents, etc.).

```python
report = dude_analyze_yaml("alerts.yaml")
print(report.path, report.findings_count, report.has_errors)
for item in report.queries:
    print(item.source.rule_name, item.source.expr)
    if item.error:
        print("ERROR:", item.error)
    else:
        print(item.result.findings)
```

### V1 CLI commands

```bash
# Inline query analysis
promql-analyze dude-look 'sum(rate(http_requests_total[5m]))'
promql-analyze dude-look --format json 'sum(rate(http_requests_total[5m]))'
promql-analyze dude-look --style detailed --fail-on warning 'avg(http_requests_total)'
promql-analyze dude-look --debug 'sum('

# Explanation only
promql-analyze dude-explain 'sum(rate(http_requests_total[5m]))'
promql-analyze dude-explain --style detailed 'sum(rate(http_requests_total[5m]))'
promql-analyze dude-explain --format json 'up'

# Files
promql-analyze dude-analyze-promql query.promql
promql-analyze dude-analyze-yaml alerts.yaml
promql-analyze dude-analyze-yml alerts.yml --format json
promql-analyze dude-analyze-json alerts.json --fail-on warning

# Common V1 flags
promql-analyze dude-look \
  --scrape-interval 15 \
  --max-grouping-labels 3 \
  --max-nesting-depth 4 \
  --disable-rule PQL001 \
  --style detailed \
  --format text \
  --fail-on error \
  'sum(rate(http_requests_total[5m]))'
```

---

## V2 — repository analysis (`dude_rushup`)

V2 accepts a **single YAML/YML file**, a **directory**, or a **repository root**.

`comeup_360()` (and multi-flag CLI runs) use one shared pipeline:

```text
discover files
    → parse YAML
    → extract rules
    → shared AnalysisContext
    → run analyzers
    → aggregate findings
    → RepositoryReport
```

Analyzers are **not** re-scanned five independent times inside `comeup_360()`.

### Analyzer APIs

| Function | Category | Purpose |
|----------|----------|---------|
| `dude_rushup.wild(path, config=None)` | `noise_risk` | 8-dimension noise-**risk** score |
| `dude_rushup.broken(path, config=None)` | `broken` | Invalid YAML/PromQL, missing fields, duplicates |
| `dude_rushup.vuln(path, config=None)` | `vuln` | Potential secrets / credentials in metadata |
| `dude_rushup.secuch(path, config=None)` | `secuch` | Org policy: required labels, runbooks, URL allowlists |
| `dude_rushup.speakup(path, config=None)` | `speakup` | Complexity / optimization **recommendations** |
| `dude_rushup.comeup_360(path, config=None)` | *(all)* | Run enabled analyzers on one shared scan |

### Python examples

```python
from promql_analyzer import (
    dude_rushup,
    RushupConfig,
    NoiseRiskConfig,
    BrokenConfig,
    VulnConfig,
    SecuchConfig,
    SpeakupConfig,
)

# --- Full pass ---
report = dude_rushup.comeup_360("alerts/")

print(report.root)
print(report.summary)                 # files / alerts / findings counts
print(report.noise_summary)           # low / medium / high noise-risk
print(report.inventory)               # duplicates, ownership/runbook stats
print(len(report.speakup_suggestions))

for f in report.findings:
    print(f.category, f.rule_id, f.severity, f.file_path, f.rule_name)
    print(" ", f.message)

# --- Individual analyzers ---
dude_rushup.wild("alerts/file.yaml")
dude_rushup.broken("alerts/")
dude_rushup.vuln("alerts/")
dude_rushup.secuch(
    "alerts/",
    config=SecuchConfig(
        required_labels=("severity", "team"),
        required_annotations=("summary",),
        ownership_labels_any_of=("owner", "team"),
        runbook_annotations_any_of=("runbook_url", "runbook"),
        forbidden_labels=("password",),
        allowed_url_domains=("docs.example.com", "wiki.example.com"),
    ),
)
dude_rushup.speakup("alerts/")
```

### Unified configuration (`RushupConfig`)

```python
from promql_analyzer import RushupConfig, NoiseRiskConfig, BrokenConfig, SecuchConfig

config = RushupConfig(
    # Discovery
    include_globs=("**/*.yaml", "**/*.yml"),
    exclude_globs=("**/vendor/**", "**/.git/**", "**/.venv/**"),
    follow_symlinks=False,

    # Which analyzers run under comeup_360
    enable_wild=True,
    enable_broken=True,
    enable_vuln=True,
    enable_secuch=True,
    enable_speakup=True,

    # Analyzer-specific knobs
    wild=NoiseRiskConfig(
        volatile_metrics=("errors_total", "ems_events"),
        stable_metrics=("node_new_status",),
        state_metrics=("up",),
        self_resolving_metrics=("node_uptime",),
        tight_threshold_values=(85.0, 90.0),
        low_max_percent=25,
        medium_max_percent=55,
    ),
    broken=BrokenConfig(
        required_alert_labels=("severity",),
        required_alert_annotations=(),
        require_for_on_alerts=False,
        validate_promql=True,
    ),
    secuch=SecuchConfig(
        required_labels=("severity",),
        ownership_labels_any_of=("owner", "team"),
        runbook_annotations_any_of=("runbook_url",),
        allowed_url_domains=("docs.example.com",),
    ),
)

report = dude_rushup.comeup_360(".", config=config)
# Comeup360Config is an alias of RushupConfig
```

Defaults are safe: you can call `comeup_360(path)` with no config.

### Sample repository summary

```text
PROMQL RUSHUP REPORT

Root: /path/to/alerts
Files scanned: 12
Files parsed: 10
Files failed: 1
Alerts: 42
Recording rules: 8
Findings: 27

Noise risk
  analyzed=42 low=20 medium=15 high=7 avg=31.2%

Inventory
  duplicate_names=2 duplicate_exprs=1 near_duplicates=1
```

### Sample noise-risk finding

```text
NOISE001 WARNING [noise_risk]
alerts/netapp.yaml :: NoisyRate
Noise risk High (67%) for alert NoisyRate — static definition risk, not observed firing
Suggestion: Review the highlighted rubric dimensions and consider longer `for` windows...
```

Per-alert detail is also on `report.noise_assessments` (dimension scores, reasons, %).

### Sample broken / security / speakup findings

```text
BROKEN001 ERROR [broken]
bad.yaml
Invalid YAML / unreadable rules file

BROKEN014 ERROR [broken]
rules.yaml :: BrokenExpr
Invalid PromQL expression

BROKENDUP001 WARNING [broken]
a.yaml :: Dup
Duplicate alert name 'Dup' across 2 rules

VULN002 ERROR [vuln]
secrets.yaml :: Leaky
Possible AWS access key id in rule metadata [HIGH potential risk]

SECUCH003 WARNING [secuch]
policy.yaml :: PolicyGap
Missing ownership metadata

SPEAKUP004 WARNING [speakup]
opt.yaml :: Broad
[recommendation] Broad regex matcher job=~".*"
```

---

## CLI reference

Entry point:

```bash
promql-analyze --version
promql-analyze --help
promql-analyze <command> --help
```

### Commands overview

| Command | Description |
|---------|-------------|
| `dude-look` | Analyze an inline PromQL string |
| `dude-explain` | Print a deterministic explanation |
| `dude-analyze-promql` | Analyze a `.promql` / `.txt` file |
| `dude-analyze-yaml` | Analyze a `.yaml` rules file |
| `dude-analyze-yml` | Analyze a `.yml` rules file |
| `dude-analyze-json` | Analyze a `.json` rules file |
| `rushup` | V2 repository analysis |

### `rushup` (V2)

```bash
promql-analyze rushup <path> [analyzer flags...] [output flags...]
```

`<path>` may be:

- a single `.yaml` / `.yml` file
- a directory
- a repository root (recursive discovery)

#### Analyzer flags

| Flag | Behavior |
|------|----------|
| *(none)* | Same as `--360` (all analyzers) |
| `--360` | Run wild + broken + vuln + secuch + speakup (one shared scan) |
| `--wild` | Noise-risk only |
| `--broken` | Broken/incomplete rules only |
| `--vuln` | Potential security exposure only |
| `--secuch` | Security policy / hygiene only |
| `--speakup` | Optimization suggestions only |

You can combine flags (`--broken --speakup`); the CLI still uses **one shared scan**.

#### Output flags

| Flag | Values | Notes |
|------|--------|-------|
| `--format` | `text` (default), `json`, `csv`, `tsv`, `xlsx` | |
| `--output` / `-o` | file path | Write report to disk; **required** for `xlsx` |
| `--fail-on` | `never`, `error` (default), `warning` | CI exit behavior |

#### Full `rushup` examples

```bash
# All analyzers (text to stdout)
promql-analyze rushup ./alerts
promql-analyze rushup ./alerts --360

# Single file
promql-analyze rushup ./alerts/team-a.yaml --broken

# Individual analyzers
promql-analyze rushup ./alerts --wild
promql-analyze rushup ./alerts --broken
promql-analyze rushup ./alerts --vuln
promql-analyze rushup ./alerts --secuch
promql-analyze rushup ./alerts --speakup

# Combined (still one scan)
promql-analyze rushup ./alerts --broken --wild --speakup

# JSON / CSV / TSV / Excel
promql-analyze rushup ./alerts --360 --format json --output report.json
promql-analyze rushup ./alerts --360 --format csv  --output findings.csv
promql-analyze rushup ./alerts --360 --format tsv  --output findings.tsv
promql-analyze rushup ./alerts --360 --format xlsx --output report.xlsx

# CI: fail on ERROR findings (default)
promql-analyze rushup ./alerts --360 --fail-on error

# CI: also fail on WARNING
promql-analyze rushup ./alerts --360 --fail-on warning

# Always exit 0 after a successful run
promql-analyze rushup ./alerts --360 --fail-on never
```

### Exit codes (all commands)

| Code | Meaning |
|-----:|---------|
| `0` | Success (findings below `--fail-on` threshold) |
| `1` | Findings met the `--fail-on` threshold (or failed YAML files under rushup) |
| `2` | Invalid PromQL, missing path, bad flags, or other CLI error |

---

## Exports

Works on any `RepositoryReport` from V2 analyzers / `comeup_360`:

```python
report = dude_rushup.comeup_360("alerts/")

report.to_json("report.json")   # full structured JSON (sorted keys)
report.to_csv("findings.csv")   # flattened findings rows
report.to_tsv("findings.tsv")
report.to_excel("report.xlsx")  # multi-sheet workbook
```

Or without writing a file:

```python
json_text = report.to_json()
csv_text = report.to_csv()
```

### Excel sheets

| Sheet | Contents |
|-------|----------|
| Summary | Scan counts, inventory, noise aggregates |
| Alerts | Alert + recording rule inventory |
| Findings | All findings |
| Noise Risk | Per-alert noise assessments |
| Broken | `category=broken` findings |
| Security | `vuln` + `secuch` findings |
| Suggestions | `speakup` recommendations / alternatives |

---

## Lint rules (PQL001–PQL005)

Used by V1 `dude_look` / file helpers, and reused inside `speakup` / `comeup_360`.

| ID | Detects |
|----|---------|
| **PQL001** | `_total` metrics used without `rate` / `irate` / `increase` / `resets` |
| **PQL002** | Broad regex matchers (`=~".*"` or leading `.*`) |
| **PQL003** | Short `rate`/`irate` windows vs scrape-interval multiples |
| **PQL004** | Aggregations grouping by many labels |
| **PQL005** | Deep function/aggregation nesting |

Disable via config or CLI:

```bash
promql-analyze dude-look --disable-rule PQL001 --disable-rule PQL002 '...'
```

```python
AnalyzerConfig(disabled_rules=("PQL001", "PQL002"))
```

---

## Complexity score

`result.complexity.score` is **structural only** (0–100), not Prometheus runtime cost.

| Score | Level |
|------:|-------|
| 0–20 | `simple` |
| 21–45 | `moderate` |
| 46–70 | `complex` |
| 71–100 | `very_complex` |

Runtime cost depends on series cardinality, scrape config, storage, recording rules, and live data.

---

## Limitations

- Offline / static only — no Prometheus or Alertmanager API calls
- Findings are heuristics; tune thresholds and disable noisy rules
- YAML discovery looks for PromQL in common fields (`expr`, `condition`, `query`, …), not only Prometheus `alert`/`record` + `expr`; Grafana dashboards are still out of scope
- `wild` = definition noise-**risk**, not observed firing rates
- `vuln` = *potential* exposure, not confirmed vulnerabilities
- `speakup` recommendations are not applied automatically; only a few alternatives are `structural_safe`
- Near-duplicate detection is intentionally conservative
- Parser behavior follows `promql-parser` (Prometheus ~v2.45-oriented)

---

## Development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Tests
pytest
pytest tests/test_comeup_360.py -q

# Lint
ruff check src tests

# Manual CLI smoke
promql-analyze dude-look 'up'
promql-analyze rushup tests --360 --fail-on never
```

---

## Publishing

Do **not** publish automatically from CI without review.

```bash
pip install -e ".[dev]"
promql-analyze --version

python -m build
python -m twine check dist/*

# Smoke-test the wheel
python -m venv /tmp/promql-analyzer-dist-test
/tmp/promql-analyzer-dist-test/bin/pip install dist/*.whl
/tmp/promql-analyzer-dist-test/bin/promql-analyze dude-look 'up'
/tmp/promql-analyzer-dist-test/bin/promql-analyze rushup --help

# TestPyPI then PyPI
python -m twine upload --repository testpypi dist/*
python -m twine upload dist/*
```

---

## License

MIT
