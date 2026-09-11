"""Web application framework and backend technology detection."""

import re
from typing import Dict, List, Tuple
from webvuln.models.response import HTTPResponse


class FrameworkDetector:
    """Detects backend languages, web frameworks, and CMS engines."""

    # Explicit headers mapping
    POWERED_BY_PATTERNS: List[Tuple[str, re.Pattern, float]] = [
        ("PHP", re.compile(r"php(?:/([0-9.]+))?", re.IGNORECASE), 0.95),
        ("Express / Node.js", re.compile(r"express", re.IGNORECASE), 0.90),
        ("ASP.NET", re.compile(r"asp\.net", re.IGNORECASE), 0.95),
        ("Next.js", re.compile(r"next\.js", re.IGNORECASE), 0.95),
    ]

    # Cookie name signatures
    COOKIE_PATTERNS: List[Tuple[str, re.Pattern, float]] = [
        ("Django", re.compile(r"csrftoken|sessionid", re.IGNORECASE), 0.80),
        ("Laravel", re.compile(r"laravel_session|XSRF-TOKEN", re.IGNORECASE), 0.85),
        ("Flask / Werkzeug", re.compile(r"^session$", re.IGNORECASE), 0.70),
        ("Spring / Java", re.compile(r"JSESSIONID", re.IGNORECASE), 0.85),
        ("ASP.NET", re.compile(r"ASP\.NET_SessionId|\.AspNetCore\.", re.IGNORECASE), 0.90),
        ("PHP", re.compile(r"PHPSESSID", re.IGNORECASE), 0.90),
        ("WordPress", re.compile(r"wordpress_|wp-settings-", re.IGNORECASE), 0.95),
        ("Ruby on Rails", re.compile(r"_session_id|remember_token", re.IGNORECASE), 0.70),
    ]

    @classmethod
    def analyze(cls, response: HTTPResponse) -> Dict[str, float]:
        """Identifies backend frameworks based on headers, cookies, and error artifacts."""
        results: Dict[str, float] = {}

        # 1. X-Powered-By header
        powered_by = response.get_header("X-Powered-By", "")
        if powered_by:
            for name, pattern, conf in cls.POWERED_BY_PATTERNS:
                match = pattern.search(powered_by)
                if match:
                    version = match.group(1) if match.groups() and match.group(1) else ""
                    label = f"{name} {version}".strip()
                    results[label] = max(results.get(label, 0.0), conf)

        # 2. X-AspNet-Version / X-Generator
        asp_ver = response.get_header("X-AspNet-Version", "")
        if asp_ver:
            results[f"ASP.NET {asp_ver}"] = 0.98

        # 3. Cookie signature inspection
        set_cookie = response.get_header("Set-Cookie", "")
        if set_cookie:
            for name, pattern, conf in cls.COOKIE_PATTERNS:
                if pattern.search(set_cookie):
                    results[name] = max(results.get(name, 0.0), conf)

        return results
