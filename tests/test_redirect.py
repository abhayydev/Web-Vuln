"""Unit tests for OpenRedirectScanner."""

import pytest
from webvuln.config import ScanConfig
from webvuln.core.context import ScanContext
from webvuln.core.target import TargetValidator
from webvuln.models.request import DiscoveredRequest, HTTPMethod
from webvuln.models.response import HTTPResponse
from webvuln.scanners.redirect import OpenRedirectScanner


@pytest.mark.asyncio
async def test_open_redirect_detection(monkeypatch):
    target = TargetValidator.validate_and_parse("http://target.local")
    config = ScanConfig(target_url=target.normalized_url)
    endpoint = DiscoveredRequest(url="http://target.local/redirect", method=HTTPMethod.GET, params={"next": "/dashboard"})

    async def mock_request(self, method, url, params=None, **kwargs):
        dest = (params or {}).get("next", "")
        return HTTPResponse(
            url=url,
            status_code=302,
            headers={"Location": dest},
            body="",
        )

    monkeypatch.setattr(ScanContext, "request", mock_request)

    scanner = OpenRedirectScanner()
    async with ScanContext(config) as ctx:
        findings = await scanner.scan(target, ctx, endpoint)

    assert len(findings) == 1
    assert "Open Redirect" in findings[0].title
    assert findings[0].parameter == "next"
