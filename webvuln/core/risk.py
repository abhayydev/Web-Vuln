"""Comprehensive risk evaluation, CVSS-style weighting, finding correlation, and deduplication."""

from typing import Dict, List, Set
from webvuln.models.finding import ConfidenceLevel, Finding, SeverityLevel


class RiskEngine:
    """Computes aggregated risk scores, weights severity/confidence, and deduplicates findings."""

    SEVERITY_WEIGHTS: Dict[SeverityLevel, float] = {
        SeverityLevel.CRITICAL: 10.0,
        SeverityLevel.HIGH: 7.5,
        SeverityLevel.MEDIUM: 4.5,
        SeverityLevel.LOW: 2.0,
        SeverityLevel.INFO: 0.0,
    }

    CONFIDENCE_MULTIPLIERS: Dict[ConfidenceLevel, float] = {
        ConfidenceLevel.CONFIRMED: 1.0,
        ConfidenceLevel.HIGH: 0.9,
        ConfidenceLevel.MEDIUM: 0.7,
        ConfidenceLevel.LOW: 0.4,
    }

    @classmethod
    def calculate_overall_risk(cls, findings: List[Finding]) -> float:
        """Calculates an overall scan risk score (0.0 to 10.0) based on finding severity and confidence."""
        if not findings:
            return 0.0

        scores: List[float] = []
        for f in findings:
            base_weight = cls.SEVERITY_WEIGHTS.get(f.severity, 0.0)
            conf_mult = cls.CONFIDENCE_MULTIPLIERS.get(f.confidence, 0.7)
            item_score = base_weight * conf_mult
            scores.append(item_score)

        if not scores:
            return 0.0

        # Weighted aggregate: highest individual score + logarithmic contribution of remaining findings
        max_score = max(scores)
        sum_remaining = sum(s for s in scores if s < max_score)
        dampened = min(10.0, max_score + (sum_remaining / 20.0))
        return round(dampened, 1)

    @classmethod
    def correlate_and_deduplicate(cls, findings: List[Finding]) -> List[Finding]:
        """Removes duplicate findings matching identical vulnerability classes and parameters."""
        unique_findings: List[Finding] = []
        seen_keys: Set[str] = set()

        for f in findings:
            key = f"{f.category.value}:{f.title}:{f.url}:{f.parameter or ''}"
            if key not in seen_keys:
                seen_keys.add(key)
                unique_findings.append(f)

        # Sort findings by severity order (CRITICAL -> INFO)
        severity_order = {
            SeverityLevel.CRITICAL: 0,
            SeverityLevel.HIGH: 1,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.LOW: 3,
            SeverityLevel.INFO: 4,
        }
        return sorted(unique_findings, key=lambda x: (severity_order.get(x.severity, 5), -(x.cvss_estimate or 0)))
