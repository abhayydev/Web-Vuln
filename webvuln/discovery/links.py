"""Link and endpoint extractor parsing HTML and JavaScript files."""

import re
from typing import Set
from bs4 import BeautifulSoup
from webvuln.utils.url import normalize_url, is_static_asset

# Regex patterns to detect API endpoints and paths inside JavaScript code or inline scripts
JS_ENDPOINT_REGEX = re.compile(
    r"""(?:"|')((?:/api/|/v[1-9]/|/[a-zA-Z0-9_\-]+/)[a-zA-Z0-9_\-/]+(?:\?[a-zA-Z0-9_=&]*)?)(?:"|')""",
    re.IGNORECASE,
)


class LinkExtractor:
    """Extracts hyperlinked URLs, script references, and API endpoints from HTML and JS sources."""

    @classmethod
    def extract_links(cls, html_content: str, base_url: str) -> Set[str]:
        """Extracts candidate URLs from <a>, <link>, <script>, <iframe>, and <form> tags."""
        discovered: Set[str] = set()
        if not html_content:
            return discovered

        soup = BeautifulSoup(html_content, "html.parser")

        # Extract href attributes
        for tag in soup.find_all(["a", "link", "area"], href=True):
            href = tag["href"].strip()
            if href and not href.startswith(("javascript:", "mailto:", "tel:", "#")):
                full_url = normalize_url(href, base_url=base_url)
                if full_url and not is_static_asset(full_url):
                    discovered.add(full_url)

        # Extract src attributes (scripts, iframes)
        for tag in soup.find_all(["script", "iframe", "embed"], src=True):
            src = tag["src"].strip()
            if src and not src.startswith("data:"):
                full_url = normalize_url(src, base_url=base_url)
                if full_url:
                    discovered.add(full_url)

        # Extract form actions
        for form in soup.find_all("form", action=True):
            action = form["action"].strip()
            if action and not action.startswith(("javascript:", "#")):
                full_url = normalize_url(action, base_url=base_url)
                if full_url and not is_static_asset(full_url):
                    discovered.add(full_url)

        # Extract embedded API routes from inline scripts
        for script in soup.find_all("script"):
            if script.string:
                for match in JS_ENDPOINT_REGEX.finditer(script.string):
                    rel_path = match.group(1)
                    full_url = normalize_url(rel_path, base_url=base_url)
                    if full_url and not is_static_asset(full_url):
                        discovered.add(full_url)

        return discovered

    @classmethod
    def extract_from_javascript(cls, js_content: str, base_url: str) -> Set[str]:
        """Scans raw JavaScript file text for API and route definitions."""
        discovered: Set[str] = set()
        if not js_content:
            return discovered

        for match in JS_ENDPOINT_REGEX.finditer(js_content):
            rel_path = match.group(1)
            full_url = normalize_url(rel_path, base_url=base_url)
            if full_url and not is_static_asset(full_url):
                discovered.add(full_url)

        return discovered
