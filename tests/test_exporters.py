"""Tests for RepositoryReport exporters."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET

from promql_analyzer import dude_rushup
from promql_analyzer.exporters import report_to_dict, to_csv, to_json, to_tsv


def _sample_repo(tmp_path: Path) -> Path:
    (tmp_path / "rules.yaml").write_text(
        """
groups:
  - name: g
    rules:
      - alert: A
        expr: up == 0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: down
      - alert: B
        expr: 'http_requests_total{job=~".*"}'
        labels:
          severity: critical
""",
        encoding="utf-8",
    )
    return tmp_path


def test_to_json_deterministic_and_complete(tmp_path: Path) -> None:
    report = dude_rushup.broken(_sample_repo(tmp_path))
    text1 = report.to_json()
    text2 = to_json(report)
    assert text1 == text2
    payload = json.loads(text1)
    assert set(payload) >= {
        "root",
        "summary",
        "alerts",
        "recording_rules",
        "findings",
        "inventory",
        "speakup_suggestions",
        "noise_assessments",
    }
    assert payload == report_to_dict(report)
    assert to_json(report) == to_json(report)

    out = tmp_path / "out.json"
    report.to_json(str(out))
    assert json.loads(out.read_text(encoding="utf-8")) == payload


def test_to_csv_and_tsv_flatten_findings(tmp_path: Path) -> None:
    report = dude_rushup.speakup(_sample_repo(tmp_path))
    csv_text = report.to_csv()
    tsv_text = report.to_tsv()
    assert csv_text.startswith(
        "file_path,rule_name,rule_id,category,severity,message,"
    )
    assert tsv_text.startswith(
        "file_path\trule_name\trule_id\tcategory\tseverity\tmessage\t"
    )
    assert to_csv(report) == csv_text
    assert to_tsv(report) == tsv_text
    assert csv_text.count("\n") >= 1 + len(report.findings)

    csv_path = tmp_path / "findings.csv"
    tsv_path = tmp_path / "findings.tsv"
    report.to_csv(str(csv_path))
    report.to_tsv(str(tsv_path))
    assert csv_path.read_text(encoding="utf-8") == csv_text
    assert tsv_path.read_text(encoding="utf-8") == tsv_text


def test_to_excel_creates_expected_sheets(tmp_path: Path) -> None:
    report = dude_rushup.speakup(_sample_repo(tmp_path))
    broken = dude_rushup.broken(tmp_path)
    from dataclasses import replace

    merged = replace(
        report,
        findings=tuple(list(report.findings) + list(broken.findings)),
        inventory=broken.inventory,
    )
    path = tmp_path / "report.xlsx"
    merged.to_excel(str(path))
    assert path.exists()

    with zipfile.ZipFile(path) as zf:
        names = set(zf.namelist())
        assert "xl/workbook.xml" in names
        workbook = ET.fromstring(zf.read("xl/workbook.xml"))
        ns = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
        sheet_names = [node.attrib["name"] for node in workbook.findall("m:sheets/m:sheet", ns)]
        assert set(sheet_names) >= {
            "Summary",
            "Alerts",
            "Findings",
            "Noise Risk",
            "Broken",
            "Security",
            "Suggestions",
        }
        summary = zf.read("xl/worksheets/sheet1.xml").decode("utf-8")
        assert "files_scanned" in summary or "key" in summary


def test_excel_does_not_require_openpyxl(tmp_path: Path) -> None:
    report = dude_rushup.broken(_sample_repo(tmp_path))
    path = tmp_path / "no-deps.xlsx"
    report.to_excel(str(path))
    assert path.stat().st_size > 0
