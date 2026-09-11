"""Open Redirect vulnerability scanner testing controlled external redirection."""

from urllib.parse import urlparse
from typing import List, Optional
from webvuln.core.context import ScanContext
from webvuln.core.scanner import BaseScanner
from webvuln.models.finding import ConfidenceLevel, Finding, FindingCategory, SeverityLevel
from webvuln.models.request import DiscoveredRequest, HTTPMethod
from webvuln.models.response import HTTPResponse
from webvuln.models.scan import ScanTarget


class OpenRedirectScanner(BaseScanner):
    """Audits redirection parameters for unvalidated external domain navigation."""

    @property
    def name(self) -> str:
        return "OpenRedirectScanner"

    @property
    def description(self) -> str:
        return "Identifies parameters that redirect users to arbitrary external web destinations."

    REDIRECT_PARAMS = {"url", "redirect", "next", "return", "continue", "destination", "goto", "target", "r", "u"}
    SAFE_TEST_DESTINATION = "https://scanner.invalid/"

    async def scan(
        self,
        target: ScanTarget,
        context: ScanContext,
        endpoint: DiscoveredRequest,
        response: Optional[HTTPResponse] = None,
    ) -> List[Finding]:
        findings: List[Finding] = []

        params_to_test = dict(endpoint.params)
        for param_name, orig_val in params_to_test.items():
            if param_name.lower() in self.REDIRECT_PARAMS or "http" in str(orig_val) or "/" in str(orig_val):
                test_params = dict(params_to_test)
                test_params[param_name] = self.SAFE_TEST_DESTINATION

                # Perform request without automatically following redirects
                test_res = await context.request(
                    method=endpoint.method.value,
                    url=endpoint.url,
                    params=test_params,
                    follow_redirects=False,
                )

                if not test_res:
                    continue

                # Inspect HTTP 30x Location header
                location = test_res.get_header("Location", "")
                if test_res.status_code in (301, 302, 303, 307, 308) and (
                    location.startswith("https://scanner.invalid") or "scanner.invalid" in location
                ):
                    findings.append(
                        Finding(
                            id=f"WV-REDIR-OPEN-{hash(endpoint.url + param_name) & 0xFFFFFFFF:08x}",
                            title=f"Open Redirect in Parameter '{param_name}'",
                            category=FindingCategory.REDIRECT,
                            severity=SeverityLevel.MEDIUM,
                            confidence=ConfidenceLevel.CONFIRMED,
                            url=endpoint.url,
                            parameter=param_name,
                            description=f"The application accepted an arbitrary external URL in parameter '{param_name}' and returned an HTTP {test_res.status_code} redirect to that destination.",
                            evidence=f"Location header observed: '{location}'",
                            remediation="Avoid user-controlled redirect targets or validate destinations against a strict whitelist of relative/authorized URLs.",
                            references=[
                                "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
                                "https://cwe.mitre.org/data/definitions/601.html",
                            ],
                            scanner=self.name,
                            cvss_estimate=5.4,
                        )
                    )

        return findings
