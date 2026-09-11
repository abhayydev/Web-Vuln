"""Unit tests for asynchronous crawler and deduplication."""

import pytest
from webvuln.config import ScanConfig
from webvuln.core.context import ScanContext
from webvuln.core.target import TargetValidator
from webvuln.discovery.crawler import Crawler
from webvuln.models.response import HTTPResponse


@pytest.mark.asyncio
async def test_crawler_respects_scope_and_depth(monkeypatch):
    target = TargetValidator.validate_and_parse("http://target.local")
    config = ScanConfig(target_url=target.normalized_url, max_depth=2, max_urls=10)

    # Mock context get responses
    async def mock_get(self, url, **kwargs):
        if url == "http://target.local/":
            return HTTPResponse(
                url=url,
                status_code=200,
                body='<a href="/page1">Page 1</a><a href="http://external.com/page">External</a>',
                content_type="text/html",
            )
        elif url == "http://target.local/page1":
            return HTTPResponse(
                url=url,
                status_code=200,
                body='<a href="/page2">Page 2</a>',
                content_type="text/html",
            )
        elif url == "http://target.local/page2":
            return HTTPResponse(
                url=url,
                status_code=200,
                body='<b>End page</b>',
                content_type="text/html",
            )
        return None

    monkeypatch.setattr(ScanContext, "get", mock_get)

    async with ScanContext(config) as ctx:
        crawler = Crawler(target, config, ctx)
        endpoints = await crawler.crawl()

        discovered_urls = {e.url for e in endpoints}
        assert "http://target.local/" in discovered_urls
        assert "http://target.local/page1" in discovered_urls
        assert "http://external.com/page" not in discovered_urls
