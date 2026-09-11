"""Path Traversal and Local File Inclusion (LFI) parameter detection scanner."""

import re
from typing import List, Optional
from webvuln.core.context import ScanContext
from webvuln.core.scanner import BaseScanner
from webvuln.models.finding import ConfidenceLevel, Finding, FindingCategory, SeverityLevel
from webvuln.models.request import DiscoveredRequest, HTTPMethod
from webvuln.models.response import HTTPResponse
from webvuln.models.scan import ScanTarget


class TraversalScanner(BaseScanner):
    """Safely audits file/path parameters for non-destructive traversal anomalies."""

    @property
    def name(self) -> str:
        return "TraversalScanner"

    @property
    def description(self) -> str:
        return "Detects path traversal parameters and file handling misconfigurations using harmless probes."

    SUSPICIOUS_PARAM_NAMES = {"file", "path", "page", "include", "template", "doc", "view", "folder", "item"}

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
            if param_name.lower() in self.SUSPICIOUS_PARAM_NAMES or "/" in str(orig_val) or "\\" in str(orig_val):
                # Harmless non-destructive relative navigation probe
                test_params = dict(params_to_test)
                test_params[param_name] = "../"

                test_res = await context.request(
                    method=endpoint.method.value,
                    url=endpoint.url,
                    params=test_params,
                )

                if test_res and test_res.status_code in (200, 500) and test_res.body:
                    # Check for path disclosure or file operation errors
                    if any(p in test_res.body.lower() for p in ["failed to open stream", "no such file or directory", "path not found", "illegal path"]):
                        findings.append(
                            Finding(
                                id=f"WV-TRAV-PARAM-{hash(endpoint.url + param_name) & 0xFFFFFFFF:08x}",
                                title=f"Path Traversal Parameter Observed: '{param_name}'",
                                category=FindingCategory.TRAVERSAL,
                                severity=SeverityLevel.MEDIUM,
                                confidence=ConfidenceLevel.MEDIUM,
                                url=endpoint.url,
                                parameter=param_name,
                                description=f"Parameter '{param_name}' appears to manipulate server filesystem paths and triggered file system error messages when probed with relative directory sequences.",
                                evidence="Response contained file system error indicators upon path manipulation.",
                                remediation="Validate user input against a strict whitelist of allowed filenames and resolve absolute canonical paths safely using Path.resolve() / realpath.",
                                references=[
                                    "https://owasp.org/www-community/attacks/Path_Traversal",
                                    "https://cwe.mitre.org/data/definitions/22.html",
                                ],
                                scanner=self.name,
                                cvss_estimate=6.5,
                            )
                        )

        return findings
