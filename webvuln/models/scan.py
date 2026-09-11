"""Overall scan execution context and report summary models."""

from datetime import datetime, timezone
from typing import Dict, List, Optional
from pydantic import BaseModel, Field
from webvuln.models.finding import Finding, SeverityLevel
from webvuln.models.request import DiscoveredRequest


class ScanTarget(BaseModel):
    """Validated target metadata."""

    raw_url: str = Field(..., description="Raw user-supplied URL")
    normalized_url: str = Field(..., description="Normalized root URL")
    scheme: str = Field(..., description="http or https")
    host: str = Field(..., description="Target hostname or IP")
    port: int = Field(..., description="Target port number")
    base_path: str = Field(default="/", description="Base path component")
    allowed_scope: List[str] = Field(default_factory=list, description="Allowed in-scope hosts/domains")


class ScanSummary(BaseModel):
    """Statistical summary of scan results."""

    total_requests: int = 0
    discovered_urls: int = 0
    scanned_endpoints: int = 0
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    duration_seconds: float = 0.0
    overall_risk_score: float = 0.0


class ScanResult(BaseModel):
    """Complete aggregated results from a scanner run."""

    target: ScanTarget
    start_time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    end_time: Optional[datetime] = None
    technologies: Dict[str, float] = Field(default_factory=dict, description="Detected tech and confidence (0-100%)")
    endpoints: List[DiscoveredRequest] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    summary: ScanSummary = Field(default_factory=ScanSummary)

    def calculate_summary(self, duration: float = 0.0) -> None:
        """Compute severity statistics and duration."""
        self.summary.discovered_urls = len(self.endpoints)
        self.summary.scanned_endpoints = len({e.url for e in self.endpoints})
        self.summary.total_findings = len(self.findings)
        self.summary.duration_seconds = duration

        counts = {s: 0 for s in SeverityLevel}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        self.summary.critical_count = counts[SeverityLevel.CRITICAL]
        self.summary.high_count = counts[SeverityLevel.HIGH]
        self.summary.medium_count = counts[SeverityLevel.MEDIUM]
        self.summary.low_count = counts[SeverityLevel.LOW]
        self.summary.info_count = counts[SeverityLevel.INFO]
