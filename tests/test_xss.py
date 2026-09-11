"""Unit tests for XSSScanner."""

import pytest
from webvuln.config import ScanConfig
from webvuln.core.context import ScanContext
from webvuln.core.target import TargetValidator
from webvuln.models.request import DiscoveredRequest, HTTPMethod
from webvuln.models.response import HTTPResponse
from webvuln.scanners.xss import XSSScanner


@pytest.mark.asyncio
async def test_xss_scanner_unencoded_reflection(monkeypatch):
    target = TargetValidator.validate_and_parse("http://target.local")
    config = ScanConfig(target_url=target.normalized_url)
    endpoint = DiscoveredRequest(url="http://target.local/search", method=HTTPMethod.GET, params={"q": "apple"})

    async def mock_request(self, method, url, params=None, **kwargs):
        reflected_val = (params or {}).get("q", "")
        return HTTPResponse(
            url=url,
            status_code=200,
            headers={"Content-Type": "text/html"},
            body=f"<div>Results for: {reflected_val}</div>",
        )

    monkeypatch.setattr(ScanContext, "request", mock_request)

    scanner = XSSScanner()
    async with ScanContext(config) as ctx:
        findings = await scanner.scan(target, ctx, endpoint)

    assert len(findings) == 1
    assert "Unencoded Parameter Reflection" in findings[0].title
    assert findings[0].parameter == "q"
