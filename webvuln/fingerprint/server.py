"""Web server software and reverse proxy fingerprinting engine."""

import re
from typing import Dict, List, Tuple
from webvuln.models.response import HTTPResponse


class ServerDetector:
    """Detects web servers, reverse proxies, and operating platforms with confidence scoring."""

    SERVER_PATTERNS: List[Tuple[str, re.Pattern, float]] = [
        ("Nginx", re.compile(r"nginx(?:/([0-9.]+))?", re.IGNORECASE), 0.95),
        ("Apache HTTP Server", re.compile(r"apache(?:/([0-9.]+))?", re.IGNORECASE), 0.95),
        ("Microsoft-IIS", re.compile(r"microsoft-iis(?:/([0-9.]+))?", re.IGNORECASE), 0.95),
        ("Cloudflare", re.compile(r"cloudflare", re.IGNORECASE), 0.95),
        ("Caddy", re.compile(r"caddy", re.IGNORECASE), 0.95),
        ("LiteSpeed", re.compile(r"litespeed", re.IGNORECASE), 0.90),
        ("Gunicorn", re.compile(r"gunicorn(?:/([0-9.]+))?", re.IGNORECASE), 0.90),
        ("Werkzeug", re.compile(r"werkzeug(?:/([0-9.]+))?", re.IGNORECASE), 0.90),
        ("Kestrel", re.compile(r"kestrel", re.IGNORECASE), 0.90),
        ("Node.js / Express", re.compile(r"express", re.IGNORECASE), 0.85),
    ]

    @classmethod
    def analyze(cls, response: HTTPResponse) -> Dict[str, float]:
        """Analyzes HTTP headers and response characteristics to identify server technologies."""
        results: Dict[str, float] = {}

        server_hdr = response.get_header("Server", "")
        if server_hdr:
            for name, pattern, conf in cls.SERVER_PATTERNS:
                match = pattern.search(server_hdr)
                if match:
                    version = match.group(1) if match.groups() and match.group(1) else ""
                    tech_label = f"{name} {version}".strip()
                    results[tech_label] = max(results.get(tech_label, 0.0), conf)

        # Via / X-Served-By inspection
        via_hdr = response.get_header("Via", "")
        if "cloudflare" in via_hdr.lower() or "cf-ray" in [h.lower() for h in response.headers.keys()]:
            results["Cloudflare Proxy"] = 0.95

        if "varnish" in via_hdr.lower() or "x-varnish" in [h.lower() for h in response.headers.keys()]:
            results["Varnish Cache"] = 0.90

        return results
