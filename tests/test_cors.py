"""Unit tests for CORSScanner."""

import pytest
from webvuln.config import ScanConfig
from webvuln.core.context import ScanContext
from webvuln.core.target import TargetValidator
from webvuln.models.finding import SeverityLevel
from webvuln.models.request import DiscoveredRequest
from webvuln.models.response import HTTPResponse
from webvuln.scanners.cors import CORSScanner


@pytest.mark.asyncio
async def test_cors_scanner_origin_reflection(monkeypatch):
    target = TargetValidator.validate_and_parse("https://target.local")
    config = ScanConfig(target_url=target.normalized_url)
    endpoint = DiscoveredRequest(url=target.normalized_url)

    async def mock_get(self, url, headers=None, **kwargs):
        req_origin = (headers or {}).get("Origin", "")
        return HTTPResponse(
            url=url,
            status_code=200,
            headers={
                "Access-Control-Allow-Origin": req_origin,
                "Access-Control-Allow-Credentials": "true",
            },
            body="{}",
        )

    monkeypatch.setattr(ScanContext, "get", mock_get)

    scanner = CORSScanner()
    async with ScanContext(config) as ctx:
        findings = await scanner.scan(target, ctx, endpoint)

    assert len(findings) == 1
    assert findings[0].severity == SeverityLevel.HIGH
    assert "Arbitrary Origin Reflection with Credentials" in findings[0].title
