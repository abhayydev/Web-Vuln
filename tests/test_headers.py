"""Unit tests for HeaderScanner."""

import pytest
from webvuln.config import ScanConfig
from webvuln.core.context import ScanContext
from webvuln.core.target import TargetValidator
from webvuln.models.request import DiscoveredRequest
from webvuln.models.response import HTTPResponse
from webvuln.scanners.headers import HeaderScanner


@pytest.mark.asyncio
async def test_header_scanner_detects_missing_csp_and_hsts():
    target = TargetValidator.validate_and_parse("https://target.local")
    config = ScanConfig(target_url=target.normalized_url)
    endpoint = DiscoveredRequest(url=target.normalized_url)

    res = HTTPResponse(
        url=target.normalized_url,
        status_code=200,
        headers={"Content-Type": "text/html"},
        body="<html><body>App</body></html>",
    )

    scanner = HeaderScanner()
    async with ScanContext(config) as ctx:
        findings = await scanner.scan(target, ctx, endpoint, response=res)

    titles = [f.title for f in findings]
    assert "Missing Content-Security-Policy Header" in titles
    assert "Missing Strict-Transport-Security Header" in titles
    assert "Missing or Invalid X-Content-Type-Options Header" in titles
