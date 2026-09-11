"""CORS Misconfiguration Scanner testing origin reflection, wildcards, and credentials."""

from typing import List, Optional
from webvuln.core.context import ScanContext
from webvuln.core.scanner import BaseScanner
from webvuln.models.finding import ConfidenceLevel, Finding, FindingCategory, SeverityLevel
from webvuln.models.request import DiscoveredRequest
from webvuln.models.response import HTTPResponse
from webvuln.models.scan import ScanTarget


class CORSScanner(BaseScanner):
    """Safely audits Cross-Origin Resource Sharing (CORS) configurations."""

    @property
    def name(self) -> str:
        return "CORSScanner"

    @property
    def description(self) -> str:
        return "Checks for arbitrary origin reflection, wildcards with credentials, and insecure CORS headers."

    async def scan(
        self,
        target: ScanTarget,
        context: ScanContext,
        endpoint: DiscoveredRequest,
        response: Optional[HTTPResponse] = None,
    ) -> List[Finding]:
        findings: List[Finding] = []

        test_origins = [
            "https://evil-attacker.invalid",
            "https://null",
            f"https://{target.host}.attacker.invalid",
        ]

        for test_origin in test_origins:
            headers = {"Origin": test_origin}
            res = await context.get(endpoint.url, headers=headers)
            if not res:
                continue

            acao = res.get_header("Access-Control-Allow-Origin")
            acac = res.get_header("Access-Control-Allow-Credentials", "").lower() == "true"

            if not acao:
                continue

            # 1. Arbitrary Origin Reflection with Credentials (CRITICAL/HIGH)
            if (acao == test_origin or acao == "null") and acac:
                findings.append(
                    Finding(
                        id=f"WV-CORS-CRED-{hash(endpoint.url) & 0xFFFFFFFF:08x}",
                        title="Insecure CORS Policy: Arbitrary Origin Reflection with Credentials",
                        category=FindingCategory.CORS,
                        severity=SeverityLevel.HIGH,
                        confidence=ConfidenceLevel.CONFIRMED,
                        url=endpoint.url,
                        description="The server reflects arbitrary requested origins in Access-Control-Allow-Origin while also setting Access-Control-Allow-Credentials: true. An attacker can execute authenticated cross-origin data theft.",
                        evidence=f"Request Origin: '{test_origin}' -> Response ACAO: '{acao}', ACAC: 'true'",
                        remediation="Implement a strict whitelist of authorized origins and never reflect arbitrary origins when credentials are enabled.",
                        references=["https://portswigger.net/web-security/cors", "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"],
                        scanner=self.name,
                        cvss_estimate=8.2,
                    )
                )
                break  # Stop further origin checks once highest severity found

            # 2. Wildcard origin (*)
            elif acao == "*" and not acac:
                findings.append(
                    Finding(
                        id=f"WV-CORS-WILD-{hash(endpoint.url) & 0xFFFFFFFF:08x}",
                        title="Permissive CORS Policy (Wildcard Access-Control-Allow-Origin)",
                        category=FindingCategory.CORS,
                        severity=SeverityLevel.INFO if "/api/" in endpoint.url else SeverityLevel.LOW,
                        confidence=ConfidenceLevel.HIGH,
                        url=endpoint.url,
                        description="The endpoint allows all external domains via 'Access-Control-Allow-Origin: *'. Ensure this endpoint does not expose sensitive user data.",
                        evidence="Response Header: 'Access-Control-Allow-Origin: *'",
                        remediation="If private/sensitive data is returned, restrict ACAO to specific trusted origins.",
                        references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"],
                        scanner=self.name,
                        cvss_estimate=2.5,
                    )
                )
                break

        return findings
