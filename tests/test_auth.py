"""Unit tests for AuthScanner and IDORScanner."""

import pytest
from webvuln.config import ScanConfig
from webvuln.core.context import ScanContext
from webvuln.core.target import TargetValidator
from webvuln.models.request import DiscoveredRequest
from webvuln.models.response import HTTPResponse
from webvuln.scanners.auth import AuthScanner
from webvuln.scanners.idor import IDORScanner


@pytest.mark.asyncio
async def test_auth_scanner_password_over_http():
    target = TargetValidator.validate_and_parse("http://target.local")
    config = ScanConfig(target_url=target.normalized_url)
    endpoint = DiscoveredRequest(url="http://target.local/login")

    res = HTTPResponse(
        url=endpoint.url,
        status_code=200,
        headers={"Content-Type": "text/html"},
        body="""
        <form action="/login" method="POST">
            <input type="text" name="user" />
            <input type="password" name="pass" />
        </form>
        """,
    )

    scanner = AuthScanner()
    async with ScanContext(config) as ctx:
        findings = await scanner.scan(target, ctx, endpoint, response=res)

    titles = [f.title for f in findings]
    assert any("Authentication Form Transmitted Over Plaintext HTTP" in t for t in titles)
    assert any("Missing Anti-CSRF Token" in t for t in titles)


@pytest.mark.asyncio
async def test_idor_scanner_numeric_id_detection():
    target = TargetValidator.validate_and_parse("http://target.local")
    config = ScanConfig(target_url=target.normalized_url)
    endpoint = DiscoveredRequest(url="http://target.local/invoices", params={"invoice_id": "1045"})

    scanner = IDORScanner()
    async with ScanContext(config) as ctx:
        findings = await scanner.scan(target, ctx, endpoint)

    assert len(findings) == 1
    assert "Direct Object Identifier Pattern Detected" in findings[0].title
    assert findings[0].parameter == "invoice_id"
