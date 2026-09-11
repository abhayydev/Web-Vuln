"""Robots.txt parser for endpoint and disallowed directory discovery."""

import re
from typing import List, Set
from webvuln.core.context import ScanContext
from webvuln.utils.url import normalize_url


class RobotsParser:
    """Discovers paths, hidden administrative routes, and sitemaps from robots.txt."""

    @classmethod
    async def discover(cls, base_url: str, context: ScanContext) -> tuple[Set[str], List[str]]:
        """Fetches and parses /robots.txt from the target host.

        Returns:
            A tuple of (discovered_paths_set, sitemaps_list).
        """
        discovered_urls: Set[str] = set()
        sitemaps: List[str] = []

        robots_url = normalize_url("/robots.txt", base_url=base_url)
        response = await context.get(robots_url)

        if not response or response.status_code != 200 or not response.body:
            return discovered_urls, sitemaps

        for line in response.body.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Check Disallow and Allow directives
            match_path = re.match(r"^(?:Disallow|Allow):\s*(.+)$", line, re.IGNORECASE)
            if match_path:
                path_val = match_path.group(1).strip()
                if path_val and not path_val.startswith("*"):
                    full_url = normalize_url(path_val, base_url=base_url)
                    if full_url:
                        discovered_urls.add(full_url)

            # Check Sitemap directive
            match_sitemap = re.match(r"^Sitemap:\s*(.+)$", line, re.IGNORECASE)
            if match_sitemap:
                sitemap_val = match_sitemap.group(1).strip()
                if sitemap_val:
                    sitemaps.append(normalize_url(sitemap_val, base_url=base_url))

        return discovered_urls, sitemaps
