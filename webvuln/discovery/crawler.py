"""Asynchronous BFS Web Crawler with strict scope restriction, form parsing, and deduplication."""

import asyncio
from typing import Dict, List, Set
from webvuln.config import ScanConfig
from webvuln.core.context import ScanContext
from webvuln.core.target import TargetValidator
from webvuln.discovery.links import LinkExtractor
from webvuln.discovery.parameters import ParameterExtractor
from webvuln.discovery.robots import RobotsParser
from webvuln.discovery.sitemap import SitemapParser
from webvuln.logger import logger
from webvuln.models.request import DiscoveredRequest, HTTPMethod
from webvuln.models.response import HTTPResponse
from webvuln.models.scan import ScanTarget
from webvuln.utils.url import normalize_url


class Crawler:
    """Asynchronous BFS Web Crawler navigating target endpoints."""

    def __init__(self, target: ScanTarget, config: ScanConfig, context: ScanContext):
        self.target = target
        self.config = config
        self.context = context
        self.visited_urls: Set[str] = set()
        self.discovered_endpoints: List[DiscoveredRequest] = []
        self._queue: asyncio.Queue[tuple[str, int]] = asyncio.Queue()

    async def crawl(self) -> List[DiscoveredRequest]:
        """Executes the asynchronous BFS crawl workflow."""
        logger.info(f"Starting discovery crawl on {self.target.normalized_url} (Max Depth: {self.config.max_depth}, Max URLs: {self.config.max_urls})")

        # 1. Passive discovery via robots.txt and sitemap.xml
        try:
            robots_urls, sitemaps = await RobotsParser.discover(self.target.normalized_url, self.context)
            for r_url in robots_urls:
                if TargetValidator.is_in_scope(r_url, self.target):
                    await self._queue.put((r_url, 1))

            for s_url in sitemaps:
                s_urls = await SitemapParser.discover(self.target.normalized_url, self.context, explicit_sitemap_url=s_url)
                for u in s_urls:
                    if TargetValidator.is_in_scope(u, self.target):
                        await self._queue.put((u, 1))

            # Standard sitemap.xml lookup
            direct_sitemap = await SitemapParser.discover(self.target.normalized_url, self.context)
            for u in direct_sitemap:
                if TargetValidator.is_in_scope(u, self.target):
                    await self._queue.put((u, 1))
        except Exception as e:
            logger.debug(f"Error during passive robots/sitemap discovery: {e}")

        # 2. Add root target URL to queue
        await self._queue.put((self.target.normalized_url, 0))

        # 3. BFS worker loop
        while not self._queue.empty() and len(self.visited_urls) < self.config.max_urls:
            url, depth = await self._queue.get()
            normalized = normalize_url(url)

            if normalized in self.visited_urls:
                continue

            if not TargetValidator.is_in_scope(normalized, self.target):
                continue

            self.visited_urls.add(normalized)

            # Query params discovery
            query_params = ParameterExtractor.extract_query_parameters(normalized)
            self.discovered_endpoints.append(
                DiscoveredRequest(
                    url=normalized,
                    method=HTTPMethod.GET,
                    params=query_params,
                    source="crawler",
                    depth=depth,
                )
            )

            # Fetch page content
            response = await self.context.get(normalized)
            if not response or response.status_code >= 400 or not response.body:
                continue

            # Process forms if HTML
            if "html" in response.content_type:
                forms = ParameterExtractor.extract_forms(response.body, base_url=normalized)
                for form in forms:
                    if TargetValidator.is_in_scope(form.url, self.target):
                        self.discovered_endpoints.append(form)

                # Extract links if depth limit not reached
                if depth < self.config.max_depth:
                    links = LinkExtractor.extract_links(response.body, base_url=normalized)
                    for link in links:
                        if link not in self.visited_urls and TargetValidator.is_in_scope(link, self.target):
                            await self._queue.put((link, depth + 1))

            # Process JS files for endpoints
            elif "javascript" in response.content_type or normalized.endswith(".js"):
                js_links = LinkExtractor.extract_from_javascript(response.body, base_url=normalized)
                for j_link in js_links:
                    if j_link not in self.visited_urls and TargetValidator.is_in_scope(j_link, self.target):
                        await self._queue.put((j_link, depth + 1))

        logger.info(f"Crawl completed. Discovered {len(self.discovered_endpoints)} endpoints across {len(self.visited_urls)} URLs.")
        return self.discovered_endpoints
