"""Unit tests for finding and scan summary models."""

from webvuln.models.finding import Finding, SeverityLevel, ConfidenceLevel, FindingCategory
from webvuln.models.scan import ScanResult, ScanTarget


def test_finding_creation_and_serialization():
    finding = Finding(
        id="WV-XSS-001",
        title="Reflected Cross-Site Scripting",
        category=FindingCategory.XSS,
        severity=SeverityLevel.HIGH,
        confidence=ConfidenceLevel.CONFIRMED,
        url="http://target.local/search?q=test",
        parameter="q",
        description="Unsanitized user input reflected in DOM context.",
        evidence="Observed <script>alert(1)</script> in response body",
        remediation="Apply contextual HTML entity encoding on all user output.",
        references=["https://owasp.org/www-community/attacks/xss/"],
        scanner="XSSScanner",
    )
    assert finding.severity == SeverityLevel.HIGH
    data = finding.to_dict()
    assert data["id"] == "WV-XSS-001"
    assert data["severity"] == "HIGH"
    assert "timestamp" in data


def test_scan_result_summary_calculation():
    target = ScanTarget(
        raw_url="http://localhost:8000",
        normalized_url="http://localhost:8000/",
        scheme="http",
        host="localhost",
        port=8000,
        base_path="/",
        allowed_scope=["localhost"],
    )
    result = ScanResult(target=target)
    f1 = Finding(
        id="WV-HDR-001",
        title="Missing CSP",
        category=FindingCategory.SECURITY_HEADERS,
        severity=SeverityLevel.MEDIUM,
        confidence=ConfidenceLevel.HIGH,
        url="http://localhost:8000/",
        description="CSP header is missing.",
        evidence="Header not present",
        remediation="Configure Content-Security-Policy.",
        scanner="HeaderScanner",
    )
    result.findings.append(f1)
    result.calculate_summary(duration=1.5)

    assert result.summary.total_findings == 1
    assert result.summary.medium_count == 1
    assert result.summary.critical_count == 0
    assert result.summary.duration_seconds == 1.5
