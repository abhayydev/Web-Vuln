"""Unit tests for CookieScanner."""

import pytest
from webvuln.config import ScanConfig
from webvuln.core.context import ScanContext
from webvuln.core.target import TargetValidator
from webvuln.models.request import DiscoveredRequest
from webvuln.models.response import HTTPResponse
from webvuln.scanners.cookies import CookieScanner


@pytest.mark.asyncio
async def test_cookie_scanner_flags_missing_httponly_and_secure():
    target = TargetValidator.validate_and_parse("https://target.local")
    config = ScanConfig(target_url=target.normalized_url)
    endpoint = DiscoveredRequest(url=target.normalized_url)

    res = HTTPResponse(
        url=target.normalized_url,
        status_code=200,
        headers={"Set-Cookie": "sessionid=secret_val_123; Path=/"},
        body="OK",
    )

    scanner = CookieScanner()
    async with ScanContext(config) as ctx:
        findings = await scanner.scan(target, ctx, endpoint, response=res)

    titles = [f.title for f in findings]
    assert "Cookie 'sessionid' Missing HttpOnly Flag" in titles
    assert "Cookie 'sessionid' Missing Secure Flag" in titles
    assert "Cookie 'sessionid' Missing SameSite Attribute" in titles

    # Ensure secret value is masked in evidence
    for f in findings:
        assert "secret_val_123" not in f.evidence
        assert "[MASKED]" in f.evidence
