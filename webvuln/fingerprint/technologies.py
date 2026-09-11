"""Comprehensive technology fingerprinting aggregating headers, DOM patterns, and scripts."""

import re
from typing import Dict, List, Tuple
from bs4 import BeautifulSoup
from webvuln.core.context import ScanContext
from webvuln.fingerprint.framework import FrameworkDetector
from webvuln.fingerprint.server import ServerDetector
from webvuln.models.response import HTTPResponse


class TechnologyFingerprinter:
    """Orchestrates passive fingerprinting of servers, frameworks, CMS, and frontend libraries."""

    # HTML / DOM / Script pattern markers
    HTML_PATTERNS: List[Tuple[str, re.Pattern, float]] = [
        ("WordPress", re.compile(r"/wp-content/|/wp-includes/|name=\"generator\" content=\"WordPress", re.IGNORECASE), 0.95),
        ("Drupal", re.compile(r"Drupal\.settings|name=\"generator\" content=\"Drupal", re.IGNORECASE), 0.95),
        ("Joomla", re.compile(r"/media/system/js/|name=\"generator\" content=\"Joomla", re.IGNORECASE), 0.95),
        ("React", re.compile(r"data-reactroot|__NEXT_DATA__|react-dom", re.IGNORECASE), 0.85),
        ("Vue.js", re.compile(r"data-v-[a-f0-9]+|__NUXT__|vue\.js|vue\.min\.js", re.IGNORECASE), 0.85),
        ("Angular", re.compile(r"ng-version|ng-app|_ngcontent|angular\.js", re.IGNORECASE), 0.85),
        ("Bootstrap", re.compile(r"bootstrap(?:\.min)?\.css|bootstrap(?:\.min)?\.js", re.IGNORECASE), 0.80),
        ("jQuery", re.compile(r"jquery(?:\.min)?\.js|jquery-[0-9.]+", re.IGNORECASE), 0.85),
        ("Tailwind CSS", re.compile(r"tailwindcss|tw-[a-z0-9]", re.IGNORECASE), 0.70),
        ("Django", re.compile(r"csrfmiddlewaretoken", re.IGNORECASE), 0.90),
        ("Laravel", re.compile(r"_token.*value=.*|laravel", re.IGNORECASE), 0.75),
    ]

    @classmethod
    def analyze_response(cls, response: HTTPResponse) -> Dict[str, float]:
        """Runs full passive detection on a single HTTP response."""
        results: Dict[str, float] = {}

        # 1. Server detections
        for tech, conf in ServerDetector.analyze(response).items():
            results[tech] = max(results.get(tech, 0.0), conf)

        # 2. Framework detections
        for tech, conf in FrameworkDetector.analyze(response).items():
            results[tech] = max(results.get(tech, 0.0), conf)

        # 3. HTML / DOM signatures
        if response.body and ("html" in response.content_type or "<html" in response.body.lower()):
            for tech, pattern, conf in cls.HTML_PATTERNS:
                if pattern.search(response.body):
                    results[tech] = max(results.get(tech, 0.0), conf)

            # Meta generator tag inspection
            try:
                soup = BeautifulSoup(response.body, "html.parser")
                meta_gen = soup.find("meta", attrs={"name": re.compile(r"generator", re.I)})
                if meta_gen and meta_gen.get("content"):
                    gen_val = meta_gen["content"].strip()
                    results[gen_val] = 0.98
            except Exception:
                pass

        return results

    @classmethod
    async def fingerprint_target(cls, target_url: str, context: ScanContext) -> Dict[str, float]:
        """Fetches target root and performs consolidated fingerprinting."""
        response = await context.get(target_url)
        if not response:
            return {}
        return cls.analyze_response(response)
