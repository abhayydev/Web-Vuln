"""Unit tests for SQLiScanner."""

import pytest
from webvuln.config import ScanConfig
from webvuln.core.context import ScanContext
from webvuln.core.target import TargetValidator
from webvuln.models.request import DiscoveredRequest, HTTPMethod
from webvuln.models.response import HTTPResponse
from webvuln.scanners.sqli import SQLiScanner


@pytest.mark.asyncio
async def test_sqli_scanner_mysql_error_detection(monkeypatch):
    target = TargetValidator.validate_and_parse("http://target.local")
    config = ScanConfig(target_url=target.normalized_url)
    endpoint = DiscoveredRequest(url="http://target.local/products", method=HTTPMethod.GET, params={"id": "10"})

    async def mock_request(self, method, url, params=None, **kwargs):
        val = (params or {}).get("id", "")
        if "'" in val:
            return HTTPResponse(
                url=url,
                status_code=500,
                headers={"Content-Type": "text/html"},
                body="Database Error: You have an error in your SQL syntax near '' at line 1",
            )
        return HTTPResponse(url=url, status_code=200, body="Product 10")

    monkeypatch.setattr(ScanContext, "request", mock_request)

    scanner = SQLiScanner()
    async with ScanContext(config) as ctx:
        findings = await scanner.scan(target, ctx, endpoint)

    assert len(findings) == 1
    assert "Potential SQL Injection" in findings[0].title
    assert "MySQL error message" in findings[0].evidence
