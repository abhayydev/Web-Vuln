"""Object reference and parameter structure scanner identifying direct identifier patterns."""

import re
from typing import List, Optional
from webvuln.core.context import ScanContext
from webvuln.core.scanner import BaseScanner
from webvuln.models.finding import ConfidenceLevel, Finding, FindingCategory, SeverityLevel
from webvuln.models.request import DiscoveredRequest
from webvuln.models.response import HTTPResponse
from webvuln.models.scan import ScanTarget


class IDORScanner(BaseScanner):
    """Analyzes endpoints for predictable direct object identifiers in URLs and parameters."""

    @property
    def name(self) -> str:
        return "IDORScanner"

    @property
    def description(self) -> str:
        return "Identifies predictable object references and numeric IDs in endpoint parameters."

    ID_PARAM_PATTERNS = {"id", "user_id", "userid", "account_id", "account", "order_id", "order", "doc_id", "invoice_id", "item_id"}
    UUID_REGEX = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)

    async def scan(
        self,
        target: ScanTarget,
        context: ScanContext,
        endpoint: DiscoveredRequest,
        response: Optional[HTTPResponse] = None,
    ) -> List[Finding]:
        findings: List[Finding] = []

        params = dict(endpoint.params)
        for param_name, val in params.items():
            str_val = str(val).strip()
            is_numeric = str_val.isdigit()
            is_uuid = bool(self.UUID_REGEX.match(str_val))

            if param_name.lower() in self.ID_PARAM_PATTERNS or (is_numeric and len(str_val) <= 8):
                findings.append(
                    Finding(
                        id=f"WV-IDOR-PARAM-{hash(endpoint.url + param_name) & 0xFFFFFFFF:08x}",
                        title=f"Direct Object Identifier Pattern Detected in Parameter '{param_name}'",
                        category=FindingCategory.AUTH_IDOR,
                        severity=SeverityLevel.INFO,
                        confidence=ConfidenceLevel.HIGH,
                        url=endpoint.url,
                        parameter=param_name,
                        description=f"Parameter '{param_name}' uses sequential or direct identifier formatting ('{str_val}'). If access controls are not verified server-side on every request, this endpoint may be susceptible to Insecure Direct Object References (IDOR / BOLA).",
                        evidence=f"Observed object reference parameter: '{param_name}={str_val}'",
                        remediation="Enforce strict server-side authorization checks verifying user ownership before returning or modifying requested records.",
                        references=[
                            "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html",
                            "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
                        ],
                        scanner=self.name,
                        cvss_estimate=2.0,
                    )
                )

        return findings
