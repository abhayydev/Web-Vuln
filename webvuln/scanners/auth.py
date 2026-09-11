"""Authentication posture and transport security analysis scanner."""

from typing import List, Optional
from bs4 import BeautifulSoup
from webvuln.core.context import ScanContext
from webvuln.core.scanner import BaseScanner
from webvuln.models.finding import ConfidenceLevel, Finding, FindingCategory, SeverityLevel
from webvuln.models.request import DiscoveredRequest
from webvuln.models.response import HTTPResponse
from webvuln.models.scan import ScanTarget


class AuthScanner(BaseScanner):
    """Audits authentication forms for transport security and form hardening."""

    @property
    def name(self) -> str:
        return "AuthScanner"

    @property
    def description(self) -> str:
        return "Checks for password fields submitted over unencrypted HTTP and missing form defenses."

    async def scan(
        self,
        target: ScanTarget,
        context: ScanContext,
        endpoint: DiscoveredRequest,
        response: Optional[HTTPResponse] = None,
    ) -> List[Finding]:
        findings: List[Finding] = []

        if response is None:
            response = await context.get(endpoint.url)
        if not response or not response.body:
            return findings

        # Parse HTML for authentication forms and password fields
        if "html" in response.content_type or "<html" in response.body.lower():
            soup = BeautifulSoup(response.body, "html.parser")
            password_inputs = soup.find_all("input", attrs={"type": "password"})

            if password_inputs:
                # 1. Password field over plaintext HTTP
                if target.scheme == "http":
                    findings.append(
                        Finding(
                            id=f"WV-AUTH-HTTP-{hash(endpoint.url) & 0xFFFFFFFF:08x}",
                            title="Authentication Form Transmitted Over Plaintext HTTP",
                            category=FindingCategory.AUTH_IDOR,
                            severity=SeverityLevel.HIGH,
                            confidence=ConfidenceLevel.CONFIRMED,
                            url=endpoint.url,
                            description="A password input field was detected on an unencrypted HTTP connection, allowing intermediate network observers to intercept credentials in plaintext.",
                            evidence="HTML form containing <input type='password'> served over HTTP scheme.",
                            remediation="Enforce HTTPS across all authentication pages and configure automatic HTTP-to-HTTPS redirects.",
                            references=[
                                "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
                                "https://cwe.mitre.org/data/definitions/319.html",
                            ],
                            scanner=self.name,
                            cvss_estimate=7.5,
                        )
                    )

                # 2. Check for anti-CSRF tokens in authentication forms
                for form in soup.find_all("form"):
                    if form.find("input", attrs={"type": "password"}):
                        inputs = [inp.get("name", "").lower() for inp in form.find_all("input") if inp.get("name")]
                        has_csrf = any(k in inputs for k in ["csrf", "token", "_token", "csrf_token", "authenticity_token"])
                        if not has_csrf and form.get("method", "GET").upper() == "POST":
                            findings.append(
                                Finding(
                                    id=f"WV-AUTH-CSRF-{hash(endpoint.url) & 0xFFFFFFFF:08x}",
                                    title="Missing Anti-CSRF Token in Authentication Form",
                                    category=FindingCategory.AUTH_IDOR,
                                    severity=SeverityLevel.LOW,
                                    confidence=ConfidenceLevel.MEDIUM,
                                    url=endpoint.url,
                                    description="The login form does not include an explicit synchronizer anti-CSRF token, which may allow login CSRF attacks.",
                                    evidence="POST form containing password input lacks standard CSRF token field.",
                                    remediation="Implement synchronizer CSRF tokens or SameSite cookie restrictions for login requests.",
                                    references=["https://owasp.org/www-community/attacks/csrf"],
                                    scanner=self.name,
                                    cvss_estimate=3.5,
                                )
                            )

        return findings
