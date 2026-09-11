"""Unit tests for RiskEngine and finding correlation."""

from webvuln.core.risk import RiskEngine
from webvuln.models.finding import ConfidenceLevel, Finding, FindingCategory, SeverityLevel


def test_risk_score_calculation():
    f1 = Finding(
        id="F1",
        title="SQL Injection",
        category=FindingCategory.INJECTION,
        severity=SeverityLevel.HIGH,
        confidence=ConfidenceLevel.CONFIRMED,
        url="http://target.local/item",
        description="SQLi detected",
        evidence="Error signature",
        remediation="Use prepared statements",
        scanner="SQLiScanner",
    )
    f2 = Finding(
        id="F2",
        title="Missing CSP",
        category=FindingCategory.SECURITY_HEADERS,
        severity=SeverityLevel.MEDIUM,
        confidence=ConfidenceLevel.HIGH,
        url="http://target.local/",
        description="CSP missing",
        evidence="Header absent",
        remediation="Add CSP",
        scanner="HeaderScanner",
    )

    risk_score = RiskEngine.calculate_overall_risk([f1, f2])
    assert 7.5 <= risk_score <= 10.0


def test_correlate_and_deduplicate():
    f1 = Finding(
        id="F1",
        title="Missing CSP",
        category=FindingCategory.SECURITY_HEADERS,
        severity=SeverityLevel.MEDIUM,
        confidence=ConfidenceLevel.HIGH,
        url="http://target.local/",
        description="CSP missing",
        evidence="Header absent",
        remediation="Add CSP",
        scanner="HeaderScanner",
    )
    f2 = Finding(
        id="F2",
        title="Missing CSP",
        category=FindingCategory.SECURITY_HEADERS,
        severity=SeverityLevel.MEDIUM,
        confidence=ConfidenceLevel.HIGH,
        url="http://target.local/",
        description="CSP missing duplicate",
        evidence="Header absent",
        remediation="Add CSP",
        scanner="HeaderScanner",
    )

    deduped = RiskEngine.correlate_and_deduplicate([f1, f2])
    assert len(deduped) == 1
