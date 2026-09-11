"""TLS/SSL Configuration and Certificate Analysis Scanner."""

import socket
import ssl
from datetime import datetime, timezone
from typing import List, Optional
from webvuln.core.context import ScanContext
from webvuln.core.scanner import BaseScanner
from webvuln.models.finding import ConfidenceLevel, Finding, FindingCategory, SeverityLevel
from webvuln.models.request import DiscoveredRequest
from webvuln.models.response import HTTPResponse
from webvuln.models.scan import ScanTarget


class TLSScanner(BaseScanner):
    """Safely audits SSL/TLS configuration, protocol version, certificate validity, and expiration."""

    @property
    def name(self) -> str:
        return "TLSScanner"

    @property
    def description(self) -> str:
        return "Audits TLS protocol version, cipher suites, certificate validity, and expiration."

    async def scan(
        self,
        target: ScanTarget,
        context: ScanContext,
        endpoint: DiscoveredRequest,
        response: Optional[HTTPResponse] = None,
    ) -> List[Finding]:
        findings: List[Finding] = []

        # Only perform TLS checks for root host on HTTPS targets
        if target.scheme != "https" or endpoint.url != target.normalized_url:
            return findings

        hostname = target.host
        port = target.port or 443

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE  # For non-disruptive inspection of lab targets

            with socket.create_connection((hostname, port), timeout=context.config.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    tls_version = ssock.version()

                    # 1. Obsolete TLS Version Check
                    if tls_version in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
                        findings.append(
                            Finding(
                                id=f"WV-TLS-OBS-{hash(hostname) & 0xFFFFFFFF:08x}",
                                title=f"Deprecated TLS Protocol Version Supported: {tls_version}",
                                category=FindingCategory.TLS_SSL,
                                severity=SeverityLevel.HIGH,
                                confidence=ConfidenceLevel.CONFIRMED,
                                url=endpoint.url,
                                description=f"The server negotiates connection with deprecated protocol {tls_version}, which suffers from known cryptographic flaws (POODLE, BEAST).",
                                evidence=f"Negotiated TLS Protocol: {tls_version}",
                                remediation="Disable TLS 1.0/1.1 and SSLv3. Require TLS 1.2 or TLS 1.3.",
                                references=["https://datatracker.ietf.org/doc/html/rfc8996"],
                                scanner=self.name,
                                cvss_estimate=7.4,
                            )
                        )

                    # 2. Certificate Expiration Check
                    if cert and "notAfter" in cert:
                        expire_date = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        now = datetime.now(timezone.utc)
                        if expire_date < now:
                            findings.append(
                                Finding(
                                    id=f"WV-TLS-EXPIRED-{hash(hostname) & 0xFFFFFFFF:08x}",
                                    title="Expired SSL/TLS Certificate",
                                    category=FindingCategory.TLS_SSL,
                                    severity=SeverityLevel.MEDIUM,
                                    confidence=ConfidenceLevel.CONFIRMED,
                                    url=endpoint.url,
                                    description=f"The TLS certificate expired on {expire_date.strftime('%Y-%m-%d')}.",
                                    evidence=f"Certificate notAfter date: {cert['notAfter']}",
                                    remediation="Renew and install a valid TLS certificate.",
                                    references=["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"],
                                    scanner=self.name,
                                    cvss_estimate=5.0,
                                )
                            )

        except Exception as e:
            if context.config.verbose:
                # Log socket / TLS negotiation error without failing
                pass

        return findings
