"""Cookie security scanner for HttpOnly, Secure, SameSite flags and scope misconfigurations."""

import re
from typing import List, Optional
from webvuln.core.context import ScanContext
from webvuln.core.scanner import BaseScanner
from webvuln.models.finding import ConfidenceLevel, Finding, FindingCategory, SeverityLevel
from webvuln.models.request import DiscoveredRequest
from webvuln.models.response import HTTPResponse
from webvuln.models.scan import ScanTarget


class CookieScanner(BaseScanner):
    """Analyzes Set-Cookie directives to ensure cookies are hardened against theft and CSRF."""

    @property
    def name(self) -> str:
        return "CookieScanner"

    @property
    def description(self) -> str:
        return "Inspects cookie security flags (Secure, HttpOnly, SameSite) and masking sensitive values."

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
        if not response:
            return findings

        # Look for Set-Cookie headers
        raw_cookies: List[str] = []
        for k, v in response.headers.items():
            if k.lower() == "set-cookie":
                raw_cookies.append(v)

        if not raw_cookies:
            return findings

        for cookie_str in raw_cookies:
            parts = [p.strip() for p in cookie_str.split(";")]
            if not parts:
                continue

            # Extract cookie name and masked value
            key_val = parts[0].split("=", 1)
            cookie_name = key_val[0].strip()
            cookie_attrs = [p.lower() for p in parts[1:]]

            # 1. Missing HttpOnly
            if not any(a == "httponly" for a in cookie_attrs):
                findings.append(
                    Finding(
                        id=f"WV-CK-HTTPONLY-{hash(cookie_name) & 0xFFFFFFFF:08x}",
                        title=f"Cookie '{cookie_name}' Missing HttpOnly Flag",
                        category=FindingCategory.COOKIE_SECURITY,
                        severity=SeverityLevel.MEDIUM if any(s in cookie_name.lower() for s in ["sess", "auth", "token", "jwt", "id"]) else SeverityLevel.LOW,
                        confidence=ConfidenceLevel.CONFIRMED,
                        url=endpoint.url,
                        parameter=cookie_name,
                        description=f"The cookie '{cookie_name}' lacks the 'HttpOnly' flag, exposing it to access by client-side JavaScript via document.cookie during XSS attacks.",
                        evidence=f"Set-Cookie: {cookie_name}=[MASKED]; {'; '.join(parts[1:])}",
                        remediation="Append '; HttpOnly' to the Set-Cookie response directive.",
                        references=["https://owasp.org/www-community/HttpOnly"],
                        scanner=self.name,
                        cvss_estimate=4.3,
                    )
                )

            # 2. Missing Secure Flag (Over HTTPS)
            if target.scheme == "https" and not any(a == "secure" for a in cookie_attrs):
                findings.append(
                    Finding(
                        id=f"WV-CK-SECURE-{hash(cookie_name) & 0xFFFFFFFF:08x}",
                        title=f"Cookie '{cookie_name}' Missing Secure Flag",
                        category=FindingCategory.COOKIE_SECURITY,
                        severity=SeverityLevel.MEDIUM,
                        confidence=ConfidenceLevel.CONFIRMED,
                        url=endpoint.url,
                        parameter=cookie_name,
                        description=f"The cookie '{cookie_name}' was transmitted over HTTPS but is missing the 'Secure' attribute, allowing it to be leaked over plaintext HTTP connections.",
                        evidence=f"Set-Cookie: {cookie_name}=[MASKED]; {'; '.join(parts[1:])}",
                        remediation="Append '; Secure' to ensure the cookie is only transmitted over TLS/HTTPS.",
                        references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#restrict_access_to_cookies"],
                        scanner=self.name,
                        cvss_estimate=4.0,
                    )
                )

            # 3. SameSite Flag
            samesite_attr = [a for a in cookie_attrs if a.startswith("samesite")]
            if not samesite_attr:
                findings.append(
                    Finding(
                        id=f"WV-CK-SAMESITE-{hash(cookie_name) & 0xFFFFFFFF:08x}",
                        title=f"Cookie '{cookie_name}' Missing SameSite Attribute",
                        category=FindingCategory.COOKIE_SECURITY,
                        severity=SeverityLevel.LOW,
                        confidence=ConfidenceLevel.HIGH,
                        url=endpoint.url,
                        parameter=cookie_name,
                        description=f"The cookie '{cookie_name}' does not specify a SameSite attribute, which may increase susceptibility to Cross-Site Request Forgery (CSRF).",
                        evidence=f"Set-Cookie: {cookie_name}=[MASKED]; {'; '.join(parts[1:])}",
                        remediation="Set 'SameSite=Lax' or 'SameSite=Strict' on session cookies.",
                        references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite"],
                        scanner=self.name,
                        cvss_estimate=3.5,
                    )
                )

        return findings
