"""SQL Injection scanner utilizing conservative error-signature analysis and safe syntax checks."""

import re
from typing import Dict, List, Optional, Tuple
from webvuln.core.context import ScanContext
from webvuln.core.scanner import BaseScanner
from webvuln.models.finding import ConfidenceLevel, Finding, FindingCategory, SeverityLevel
from webvuln.models.request import DiscoveredRequest, HTTPMethod
from webvuln.models.response import HTTPResponse
from webvuln.models.scan import ScanTarget


class SQLiScanner(BaseScanner):
    """Detects SQL Injection vulnerabilities safely via database error signatures."""

    @property
    def name(self) -> str:
        return "SQLiScanner"

    @property
    def description(self) -> str:
        return "Analyzes server responses for database error patterns and unhandled SQL syntax anomalies."

    # Comprehensive database error signatures across major engines
    DB_ERROR_PATTERNS: List[Tuple[str, re.Pattern]] = [
        ("MySQL", re.compile(r"you have an error in your sql syntax|warning: mysql_|check the manual that corresponds to your mysql server version", re.IGNORECASE)),
        ("PostgreSQL", re.compile(r"postgresql.*error|pg_query\(\)|syntax error at or near|unterminated quoted string at or near", re.IGNORECASE)),
        ("Microsoft SQL Server", re.compile(r"driver.*sql[\-\_\ ]*server|ole db.*sql server|unclosed quotation mark after the character string|microsoft ole db provider for sql server", re.IGNORECASE)),
        ("SQLite", re.compile(r"sqlite3::sqlexception|sqlite error|unrecognized token:|near \".*\": syntax error", re.IGNORECASE)),
        ("Oracle", re.compile(r"ora-[0-9]{4,5}|oracle error|quoted string not properly terminated", re.IGNORECASE)),
    ]

    def _check_sql_errors(self, body: str) -> Optional[str]:
        """Scans response body for known RDBMS syntax error signatures."""
        if not body:
            return None
        for db_name, pattern in self.DB_ERROR_PATTERNS:
            match = pattern.search(body)
            if match:
                return f"{db_name} error message matched: '{match.group(0)}'"
        return None

    async def scan(
        self,
        target: ScanTarget,
        context: ScanContext,
        endpoint: DiscoveredRequest,
        response: Optional[HTTPResponse] = None,
    ) -> List[Finding]:
        findings: List[Finding] = []

        params_to_test = dict(endpoint.params)
        if not params_to_test and endpoint.form_data:
            params_to_test = dict(endpoint.form_data)

        if not params_to_test:
            return findings

        # Safe diagnostic probe: single quote to trigger syntax diagnostic check
        for param_name, orig_val in params_to_test.items():
            test_params = dict(params_to_test)
            test_params[param_name] = f"{orig_val}'"

            test_res = await context.request(
                method=endpoint.method.value,
                url=endpoint.url,
                params=test_params if endpoint.method == HTTPMethod.GET else None,
                data=test_params if endpoint.method == HTTPMethod.POST else None,
            )

            if not test_res or not test_res.body:
                continue

            error_evidence = self._check_sql_errors(test_res.body)
            if error_evidence:
                findings.append(
                    Finding(
                        id=f"WV-SQLI-ERR-{hash(endpoint.url + param_name) & 0xFFFFFFFF:08x}",
                        title=f"Potential SQL Injection in Parameter '{param_name}'",
                        category=FindingCategory.INJECTION,
                        severity=SeverityLevel.HIGH,
                        confidence=ConfidenceLevel.CONFIRMED,
                        url=endpoint.url,
                        parameter=param_name,
                        description=f"Appending a single quote to parameter '{param_name}' triggered a database syntax error in the server response, indicating unparameterized SQL query concatenation.",
                        evidence=error_evidence,
                        remediation="Utilize parameterized queries / prepared statements (e.g. PDO, SQLAlchemy, parameterized cursor) with bind variables for all user-supplied inputs.",
                        references=[
                            "https://owasp.org/www-community/attacks/SQL_Injection",
                            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                        ],
                        scanner=self.name,
                        cvss_estimate=8.8,
                    )
                )

        return findings
