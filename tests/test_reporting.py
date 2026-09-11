"""Unit tests for JSON and HTML reporting."""

import json
from pathlib import Path
from webvuln.models.finding import ConfidenceLevel, Finding, FindingCategory, SeverityLevel
from webvuln.models.scan import ScanResult, ScanTarget
from webvuln.reporting.html_report import HTMLReporter
from webvuln.reporting.json_report import JSONReporter


def test_json_and_html_report_generation(tmp_path):
    target = ScanTarget(
        raw_url="http://target.local",
        normalized_url="http://target.local/",
        scheme="http",
        host="target.local",
        port=80,
        allowed_scope=["target.local"],
    )
    result = ScanResult(target=target)
    f = Finding(
        id="WV-HDR-001",
        title="Missing CSP",
        category=FindingCategory.SECURITY_HEADERS,
        severity=SeverityLevel.MEDIUM,
        confidence=ConfidenceLevel.HIGH,
        url="http://target.local/",
        description="CSP header is missing.",
        evidence="Header not present",
        remediation="Configure Content-Security-Policy.",
        scanner="HeaderScanner",
    )
    result.findings.append(f)
    result.calculate_summary(duration=1.2)

    # 1. Test JSON report
    json_path = tmp_path / "scan.json"
    JSONReporter.generate(result, json_path)
    assert json_path.exists()

    with open(json_path, "r", encoding="utf-8") as jf:
        data = json.load(jf)
        assert data["target"]["host"] == "target.local"
        assert len(data["findings"]) == 1
        assert data["findings"][0]["title"] == "Missing CSP"

    # 2. Test HTML report
    html_path = tmp_path / "scan.html"
    HTMLReporter.generate(result, html_path)
    assert html_path.exists()

    with open(html_path, "r", encoding="utf-8") as hf:
        content = hf.read()
        assert "WebVuln Security Assessment Report" in content
        assert "target.local" in content
        assert "Missing CSP" in content
