"""Security Headers scanner detecting missing, weak, or misconfigured response headers."""

from typing import List, Optional
from webvuln.core.context import ScanContext
from webvuln.core.scanner import BaseScanner
from webvuln.models.finding import ConfidenceLevel, Finding, FindingCategory, SeverityLevel
from webvuln.models.request import DiscoveredRequest
from webvuln.models.response import HTTPResponse
from webvuln.models.scan import ScanTarget


class HeaderScanner(BaseScanner):
    """Audits HTTP security headers against OWASP and industry best practices."""

    @property
    def name(self) -> str:
        return "HeaderScanner"

    @property
    def description(self) -> str:
        return "Inspects HTTP response headers for missing security controls (CSP, HSTS, X-Frame-Options, etc.)."

    async def scan(
        self,
        target: ScanTarget,
        context: ScanContext,
        endpoint: DiscoveredRequest,
        response: Optional[HTTPResponse] = None,
    ) -> List[Finding]:
        findings: List[Finding] = []

        # Fetch baseline response if not pre-provided
        if response is None:
            response = await context.get(endpoint.url)
        if not response:
            return findings

        # 1. Content-Security-Policy (CSP)
        csp = response.get_header("Content-Security-Policy")
        if not csp:
            findings.append(
                Finding(
                    id=f"WV-HDR-CSP-{hash(endpoint.url) & 0xFFFFFFFF:08x}",
                    title="Missing Content-Security-Policy Header",
                    category=FindingCategory.SECURITY_HEADERS,
                    severity=SeverityLevel.MEDIUM,
                    confidence=ConfidenceLevel.HIGH,
                    url=endpoint.url,
                    description="The server does not specify a Content-Security-Policy (CSP) header, increasing susceptibility to Cross-Site Scripting (XSS) and data injection attacks.",
                    evidence="Header 'Content-Security-Policy' is absent from HTTP response.",
                    remediation="Configure a restrictive Content-Security-Policy header (e.g., default-src 'self').",
                    references=["https://owasp.org/www-project-secure-headers/#content-security-policy"],
                    scanner=self.name,
                    cvss_estimate=5.3,
                )
            )
        elif "unsafe-inline" in csp or "unsafe-eval" in csp:
            findings.append(
                Finding(
                    id=f"WV-HDR-CSP-WEAK-{hash(endpoint.url) & 0xFFFFFFFF:08x}",
                    title="Weak Content-Security-Policy Configuration",
                    category=FindingCategory.SECURITY_HEADERS,
                    severity=SeverityLevel.LOW,
                    confidence=ConfidenceLevel.HIGH,
                    url=endpoint.url,
                    description="The Content-Security-Policy header includes 'unsafe-inline' or 'unsafe-eval', diminishing protection against script injection.",
                    evidence=f"Observed CSP directive: {csp[:120]}...",
                    remediation="Replace 'unsafe-inline' with nonce-based or hash-based CSP directives.",
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy"],
                    scanner=self.name,
                    cvss_estimate=3.7,
                )
            )

        # 2. Strict-Transport-Security (HSTS)
        if target.scheme == "https":
            hsts = response.get_header("Strict-Transport-Security")
            if not hsts:
                findings.append(
                    Finding(
                        id=f"WV-HDR-HSTS-{hash(endpoint.url) & 0xFFFFFFFF:08x}",
                        title="Missing Strict-Transport-Security Header",
                        category=FindingCategory.SECURITY_HEADERS,
                        severity=SeverityLevel.MEDIUM,
                        confidence=ConfidenceLevel.CONFIRMED,
                        url=endpoint.url,
                        description="HTTPS is used but the Strict-Transport-Security header is absent, making users vulnerable to SSL stripping and downgrade attacks.",
                        evidence="Header 'Strict-Transport-Security' is absent from HTTPS response.",
                        remediation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'.",
                        references=["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"],
                        scanner=self.name,
                        cvss_estimate=4.8,
                    )
                )

        # 3. X-Content-Type-Options
        xcto = response.get_header("X-Content-Type-Options")
        if not xcto or xcto.lower() != "nosniff":
            findings.append(
                Finding(
                    id=f"WV-HDR-XCTO-{hash(endpoint.url) & 0xFFFFFFFF:08x}",
                    title="Missing or Invalid X-Content-Type-Options Header",
                    category=FindingCategory.SECURITY_HEADERS,
                    severity=SeverityLevel.LOW,
                    confidence=ConfidenceLevel.CONFIRMED,
                    url=endpoint.url,
                    description="X-Content-Type-Options is not set to 'nosniff', allowing browsers to MIME-sniff responses away from the declared Content-Type.",
                    evidence=f"Header 'X-Content-Type-Options' is '{xcto or 'absent'}'.",
                    remediation="Set 'X-Content-Type-Options: nosniff'.",
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"],
                    scanner=self.name,
                    cvss_estimate=3.1,
                )
            )

        # 4. X-Frame-Options / Clickjacking Protection
        xfo = response.get_header("X-Frame-Options")
        if not xfo and (not csp or "frame-ancestors" not in csp):
            findings.append(
                Finding(
                    id=f"WV-HDR-XFO-{hash(endpoint.url) & 0xFFFFFFFF:08x}",
                    title="Missing Clickjacking Defense (X-Frame-Options / frame-ancestors)",
                    category=FindingCategory.SECURITY_HEADERS,
                    severity=SeverityLevel.MEDIUM,
                    confidence=ConfidenceLevel.HIGH,
                    url=endpoint.url,
                    description="Neither X-Frame-Options nor CSP 'frame-ancestors' are present, leaving the application vulnerable to Clickjacking attacks.",
                    evidence="Headers 'X-Frame-Options' and CSP 'frame-ancestors' are absent.",
                    remediation="Set 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN', or use CSP 'frame-ancestors'.",
                    references=["https://owasp.org/www-community/attacks/Clickjacking"],
                    scanner=self.name,
                    cvss_estimate=4.3,
                )
            )

        # 5. Referrer-Policy
        ref_pol = response.get_header("Referrer-Policy")
        if not ref_pol:
            findings.append(
                Finding(
                    id=f"WV-HDR-REF-{hash(endpoint.url) & 0xFFFFFFFF:08x}",
                    title="Missing Referrer-Policy Header",
                    category=FindingCategory.SECURITY_HEADERS,
                    severity=SeverityLevel.INFO,
                    confidence=ConfidenceLevel.HIGH,
                    url=endpoint.url,
                    description="Referrer-Policy is not explicitly set, which may leak URL query parameters in the Referer header to external domains.",
                    evidence="Header 'Referrer-Policy' is absent.",
                    remediation="Set 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'.",
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"],
                    scanner=self.name,
                    cvss_estimate=2.0,
                )
            )

        # 6. Permissions-Policy
        perm_pol = response.get_header("Permissions-Policy")
        if not perm_pol:
            findings.append(
                Finding(
                    id=f"WV-HDR-PERM-{hash(endpoint.url) & 0xFFFFFFFF:08x}",
                    title="Missing Permissions-Policy Header",
                    category=FindingCategory.SECURITY_HEADERS,
                    severity=SeverityLevel.INFO,
                    confidence=ConfidenceLevel.HIGH,
                    url=endpoint.url,
                    description="Permissions-Policy is not configured to restrict access to sensitive browser features (camera, microphone, geolocation).",
                    evidence="Header 'Permissions-Policy' is absent.",
                    remediation="Define a Permissions-Policy restricting unused device APIs.",
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"],
                    scanner=self.name,
                    cvss_estimate=1.5,
                )
            )

        return findings
