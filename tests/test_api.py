"""Unit tests for APIScanner."""

import pytest
from webvuln.config import ScanConfig
from webvuln.core.context import ScanContext
from webvuln.core.target import TargetValidator
from webvuln.models.request import DiscoveredRequest
from webvuln.models.response import HTTPResponse
from webvuln.scanners.api import APIScanner


@pytest.mark.asyncio
async def test_api_scanner_openapi_discovery(monkeypatch):
    target = TargetValidator.validate_and_parse("http://target.local")
    config = ScanConfig(target_url=target.normalized_url)
    endpoint = DiscoveredRequest(url=target.normalized_url)

    async def mock_get(self, url, **kwargs):
        if "/openapi.json" in url:
            return HTTPResponse(
                url=url,
                status_code=200,
                headers={"Content-Type": "application/json"},
                body='{"openapi": "3.0.0", "info": {"title": "Lab API"}}',
                is_json=True,
            )
        return HTTPResponse(url=url, status_code=404, body="Not found")

    async def mock_request(self, method, url, **kwargs):
        return HTTPResponse(url=url, status_code=200, headers={"Allow": "GET, POST"}, body="")

    monkeypatch.setattr(ScanContext, "get", mock_get)
    monkeypatch.setattr(ScanContext, "request", mock_request)

    scanner = APIScanner()
    async with ScanContext(config) as ctx:
        findings = await scanner.scan(target, ctx, endpoint)

    titles = [f.title for f in findings]
    assert any("OpenAPI / Swagger API Documentation" in t for t in titles)


@pytest.mark.asyncio
async def test_api_scanner_debug_keys_disclosure(monkeypatch):
    target = TargetValidator.validate_and_parse("http://target.local")
    config = ScanConfig(target_url=target.normalized_url)
    endpoint = DiscoveredRequest(url="http://target.local/api/users")

    api_response = HTTPResponse(
        url=endpoint.url,
        status_code=200,
        headers={"Content-Type": "application/json"},
        body='{"users": [], "traceback": "Exception at line 42", "debug_info": "env=dev"}',
        is_json=True,
    )

    async def mock_get(self, url, **kwargs):
        return api_response

    async def mock_request(self, method, url, **kwargs):
        if method == "OPTIONS":
            return HTTPResponse(url=url, status_code=200, headers={"Allow": "GET, POST, DELETE"}, body="")
        return api_response

    monkeypatch.setattr(ScanContext, "get", mock_get)
    monkeypatch.setattr(ScanContext, "request", mock_request)

    scanner = APIScanner()
    async with ScanContext(config) as ctx:
        findings = await scanner.scan(target, ctx, endpoint, response=api_response)

    titles = [f.title for f in findings]
    assert any("Excessive API Information Disclosure" in t for t in titles)
    assert any("Unsafe HTTP Methods Enabled" in t for t in titles)
