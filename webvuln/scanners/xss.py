"""Reflected input and context-encoding analysis scanner using benign markers."""

import html
import re
from typing import List, Optional
from webvuln.core.context import ScanContext
from webvuln.core.scanner import BaseScanner
from webvuln.models.finding import ConfidenceLevel, Finding, FindingCategory, SeverityLevel
from webvuln.models.request import DiscoveredRequest, HTTPMethod
from webvuln.models.response import HTTPResponse
from webvuln.models.scan import ScanTarget
from webvuln.utils.payloads import generate_marker


class XSSScanner(BaseScanner):
    """Audits parameters for unencoded reflection in HTML responses using benign markers."""

    @property
    def name(self) -> str:
        return "XSSScanner"

    @property
    def description(self) -> str:
        return "Detects unescaped user reflection in HTML contexts using non-destructive audit markers."

    async def scan(
        self,
        target: ScanTarget,
        context: ScanContext,
        endpoint: DiscoveredRequest,
        response: Optional[HTTPResponse] = None,
    ) -> List[Finding]:
        findings: List[Finding] = []

        # Audit both GET query parameters and POST form fields
        params_to_test = dict(endpoint.params)
        form_data_to_test = dict(endpoint.form_data)

        if not params_to_test and not form_data_to_test:
            return findings

        # Test query parameters
        for param_name, orig_val in params_to_test.items():
            marker = generate_marker(prefix="WV_REFLECT")
            # Safe probe containing delimiter characters to test context escaping
            test_probe = f"{marker}\"'<>"
            test_params = dict(params_to_test)
            test_params[param_name] = test_probe

            test_res = await context.request(
                method=endpoint.method.value,
                url=endpoint.url,
                params=test_params if endpoint.method == HTTPMethod.GET else None,
                data=test_params if endpoint.method == HTTPMethod.POST else None,
            )

            if not test_res or not test_res.body or test_probe not in test_res.body:
                continue

            # Analyze reflection context
            encoded_probe = html.escape(test_probe)
            if test_probe in test_res.body:
                # Raw unencoded special characters reflected
                findings.append(
                    Finding(
                        id=f"WV-XSS-REFLECT-{hash(endpoint.url + param_name) & 0xFFFFFFFF:08x}",
                        title=f"Unencoded Parameter Reflection in Parameter '{param_name}'",
                        category=FindingCategory.XSS,
                        severity=SeverityLevel.HIGH,
                        confidence=ConfidenceLevel.HIGH,
                        url=endpoint.url,
                        parameter=param_name,
                        description=f"User-controlled parameter '{param_name}' was reflected in the HTML response without contextual entity escaping (quotes/brackets intact), indicating potential Cross-Site Scripting (XSS).",
                        evidence=f"Injected benign marker '{test_probe}' observed unescaped in response body.",
                        remediation="Apply contextual HTML encoding (e.g. htmlspecialchars / OWASP Java Encoder) before rendering user input in HTML markup.",
                        references=[
                            "https://owasp.org/www-community/attacks/xss/",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                        ],
                        scanner=self.name,
                        cvss_estimate=7.2,
                    )
                )

        # Test POST form fields
        for field_name, orig_val in form_data_to_test.items():
            marker = generate_marker(prefix="WV_FORM_REFLECT")
            test_probe = f"{marker}\"'<>"
            test_data = dict(form_data_to_test)
            test_data[field_name] = test_probe

            test_res = await context.request(
                method="POST",
                url=endpoint.url,
                data=test_data,
            )

            if test_res and test_res.body and test_probe in test_res.body:
                findings.append(
                    Finding(
                        id=f"WV-XSS-FORM-{hash(endpoint.url + field_name) & 0xFFFFFFFF:08x}",
                        title=f"Unencoded Form Field Reflection in '{field_name}'",
                        category=FindingCategory.XSS,
                        severity=SeverityLevel.HIGH,
                        confidence=ConfidenceLevel.HIGH,
                        url=endpoint.url,
                        parameter=field_name,
                        description=f"Form input '{field_name}' was submitted via POST and reflected without contextual encoding.",
                        evidence=f"Injected probe '{test_probe}' found unescaped in response.",
                        remediation="Ensure server-side output encoding is applied across all reflected form parameters.",
                        references=["https://owasp.org/www-community/attacks/xss/"],
                        scanner=self.name,
                        cvss_estimate=6.8,
                    )
                )

        return findings
