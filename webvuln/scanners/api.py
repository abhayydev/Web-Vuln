"""API security scanner testing OpenAPI/Swagger documentation, unsafe HTTP methods, and JSON data exposure."""

import json
from typing import Any, Dict, List, Optional, Set
from webvuln.core.context import ScanContext
from webvuln.core.scanner import BaseScanner
from webvuln.models.finding import ConfidenceLevel, Finding, FindingCategory, SeverityLevel
from webvuln.models.request import DiscoveredRequest, HTTPMethod
from webvuln.models.response import HTTPResponse
from webvuln.models.scan import ScanTarget
from webvuln.utils.url import normalize_url


class APIScanner(BaseScanner):
    """Audits REST API endpoints, OpenAPI specs, information disclosure, and unauthenticated routes."""

    @property
    def name(self) -> str:
        return "APIScanner"

    @property
    def description(self) -> str:
        return "Discovers Swagger/OpenAPI documentation, audits unsafe HTTP methods, and identifies unauthenticated JSON exposure."

    OPENAPI_PATHS = [
        "/openapi.json",
        "/swagger.json",
        "/api/swagger.json",
        "/v2/swagger.json",
        "/v3/api-docs",
        "/api-docs",
        "/docs",
        "/swagger-ui.html",
        "/swagger-ui/",
        "/api/docs",
    ]

    UNSAFE_METHODS = ["PUT", "DELETE", "PATCH"]

    async def scan(
        self,
        target: ScanTarget,
        context: ScanContext,
        endpoint: DiscoveredRequest,
        response: Optional[HTTPResponse] = None,
    ) -> List[Finding]:
        findings: List[Finding] = []

        # 1. Target-level OpenAPI/Swagger Specification Discovery
        if endpoint.url == target.normalized_url:
            for api_path in self.OPENAPI_PATHS:
                doc_url = normalize_url(api_path, base_url=target.normalized_url)
                doc_res = await context.get(doc_url)
                if doc_res and doc_res.status_code == 200:
                    if doc_res.is_json or "swagger" in doc_res.body.lower() or "openapi" in doc_res.body.lower():
                        findings.append(
                            Finding(
                                id=f"WV-API-DOCS-{hash(doc_url) & 0xFFFFFFFF:08x}",
                                title="Publicly Accessible OpenAPI / Swagger API Documentation",
                                category=FindingCategory.API_SECURITY,
                                severity=SeverityLevel.INFO,
                                confidence=ConfidenceLevel.CONFIRMED,
                                url=doc_url,
                                description="Interactive API schema documentation (OpenAPI/Swagger) was found exposed without authentication, providing structural details of backend endpoints.",
                                evidence=f"Exposed documentation endpoint returned HTTP 200 at: '{doc_url}'",
                                remediation="Restrict public access to interactive API docs in production environments using authentication or internal network controls.",
                                references=["https://owasp.org/www-project-api-security/"],
                                scanner=self.name,
                                cvss_estimate=2.0,
                            )
                        )
                        break

        # 2. Endpoint-level HTTP Methods & Information Disclosure Analysis
        if response is None:
            response = await context.get(endpoint.url)

        if response and response.status_code == 200:
            # Check for sensitive stack/debug keys in JSON responses
            if response.is_json:
                try:
                    data = json.loads(response.body)
                    sensitive_keys = {"traceback", "stacktrace", "debug_info", "internal_id", "sql", "exception"}
                    found_keys = []
                    if isinstance(data, dict):
                        found_keys = [k for k in data.keys() if k.lower() in sensitive_keys]

                    if found_keys:
                        findings.append(
                            Finding(
                                id=f"WV-API-DISCLOSE-{hash(endpoint.url) & 0xFFFFFFFF:08x}",
                                title=f"Excessive API Information Disclosure in JSON Response",
                                category=FindingCategory.API_SECURITY,
                                severity=SeverityLevel.LOW,
                                confidence=ConfidenceLevel.HIGH,
                                url=endpoint.url,
                                description=f"The API response discloses internal debugging keys: {', '.join(found_keys)}.",
                                evidence=f"Sensitive keys identified in response payload: {', '.join(found_keys)}",
                                remediation="Ensure backend debug modes are disabled and suppress internal exception objects from API responses.",
                                references=["https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/"],
                                scanner=self.name,
                                cvss_estimate=3.8,
                            )
                        )
                except Exception:
                    pass

            # 3. OPTIONS Method / Allowed Unsafe Methods Check
            options_res = await context.request("OPTIONS", endpoint.url)
            if options_res and options_res.status_code in (200, 204):
                allow_header = options_res.get_header("Allow", "")
                enabled_unsafe = [m for m in self.UNSAFE_METHODS if m in allow_header.upper()]
                if enabled_unsafe:
                    findings.append(
                        Finding(
                            id=f"WV-API-METHODS-{hash(endpoint.url) & 0xFFFFFFFF:08x}",
                            title=f"Potentially Unsafe HTTP Methods Enabled: {', '.join(enabled_unsafe)}",
                            category=FindingCategory.API_SECURITY,
                            severity=SeverityLevel.LOW,
                            confidence=ConfidenceLevel.HIGH,
                            url=endpoint.url,
                            description=f"The endpoint advertises support for modifying HTTP methods ({', '.join(enabled_unsafe)}) via the Allow header.",
                            evidence=f"Allow header returned: '{allow_header}'",
                            remediation="Verify that write/delete methods require strict authentication and authorization checks.",
                            references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Allow"],
                            scanner=self.name,
                            cvss_estimate=3.0,
                        )
                    )

        return findings
