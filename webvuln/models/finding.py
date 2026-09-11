"""Vulnerability finding model and severity definitions."""

from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class SeverityLevel(str, Enum):
    """Vulnerability severity rating following industry standard triage."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ConfidenceLevel(str, Enum):
    """Confidence rating to distinguish tentative observations from high-certainty findings."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CONFIRMED = "CONFIRMED"


class FindingCategory(str, Enum):
    """Vulnerability category grouping."""
    INJECTION = "Injection (SQLi, Command)"
    XSS = "Cross-Site Scripting (XSS)"
    TRAVERSAL = "Path Traversal & LFI"
    REDIRECT = "Open Redirect"
    SECURITY_HEADERS = "Security Headers Misconfiguration"
    COOKIE_SECURITY = "Cookie & Session Security"
    CORS = "Cross-Origin Resource Sharing (CORS)"
    TLS_SSL = "TLS/SSL Configuration"
    API_SECURITY = "API Security & Info Disclosure"
    AUTH_IDOR = "Authentication & Authorization (IDOR/BOLA)"
    FINGERPRINT = "Technology Fingerprint"


class Finding(BaseModel):
    """Detailed security finding produced by a scanner module."""

    id: str = Field(..., description="Unique deterministic identifier for the finding")
    title: str = Field(..., description="Short, descriptive finding title")
    category: FindingCategory = Field(..., description="Vulnerability category")
    severity: SeverityLevel = Field(..., description="Assessed vulnerability severity")
    confidence: ConfidenceLevel = Field(default=ConfidenceLevel.MEDIUM, description="Confidence in the detection")
    url: str = Field(..., description="Affected URL")
    parameter: Optional[str] = Field(default=None, description="Affected parameter name or header")
    description: str = Field(..., description="Technical explanation of the vulnerability")
    evidence: str = Field(..., description="Non-sensitive proof or observed behavior (e.g. reflection snippet)")
    remediation: str = Field(..., description="Clear, actionable remediation guidance")
    references: List[str] = Field(default_factory=list, description="Authoritative reference links (OWASP, CWE, RFC)")
    scanner: str = Field(..., description="Name of the scanner module that generated this finding")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Timestamp when finding was created")
    cvss_estimate: Optional[float] = Field(default=None, description="Estimated CVSS v3.1 score for risk weighting")

    def to_dict(self) -> dict:
        """Serialize finding to dictionary."""
        data = self.model_dump()
        data["timestamp"] = self.timestamp.isoformat()
        return data
