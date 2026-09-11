"""Sitemap.xml parser for automated endpoint discovery."""

import re
from typing import Set
from bs4 import BeautifulSoup
from webvuln.core.context import ScanContext
from webvuln.utils.url import normalize_url


class SitemapParser:
    """Discovers endpoints published in XML sitemaps."""

    @classmethod
    async def discover(cls, base_url: str, context: ScanContext, explicit_sitemap_url: str = None) -> Set[str]:
        """Fetches and parses sitemap.xml endpoints."""
        discovered_urls: Set[str] = set()
        target_sitemap = explicit_sitemap_url or normalize_url("/sitemap.xml", base_url=base_url)

        response = await context.get(target_sitemap)
        if not response or response.status_code != 200 or not response.body:
            return discovered_urls

        try:
            soup = BeautifulSoup(response.body, "html.parser")
            # Parse <loc> tags inside <url> or <sitemap>
            for loc in soup.find_all("loc"):
                if loc.string:
                    discovered_urls.add(normalize_url(loc.string.strip(), base_url=base_url))
        except Exception:
            # Fallback regex parsing if XML parsing fails
            for match in re.finditer(r"<loc>(https?://[^<]+)</loc>", response.body, re.IGNORECASE):
                discovered_urls.add(normalize_url(match.group(1).strip(), base_url=base_url))

        return discovered_urls
