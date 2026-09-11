"""Parameter and HTML Form extractor."""

from urllib.parse import parse_qsl, urlparse
from typing import Any, Dict, List
from bs4 import BeautifulSoup
from webvuln.models.request import DiscoveredRequest, HTTPMethod
from webvuln.utils.url import normalize_url


class ParameterExtractor:
    """Extracts query parameters and structured HTML forms for fuzzing and testing."""

    @classmethod
    def extract_query_parameters(cls, url: str) -> Dict[str, str]:
        """Extracts key-value query parameters from a URL."""
        parsed = urlparse(url)
        return dict(parse_qsl(parsed.query, keep_blank_values=True))

    @classmethod
    def extract_forms(cls, html_content: str, base_url: str) -> List[DiscoveredRequest]:
        """Parses HTML document to extract all interactive web forms."""
        discovered_forms: List[DiscoveredRequest] = []
        if not html_content:
            return discovered_forms

        soup = BeautifulSoup(html_content, "html.parser")
        forms = soup.find_all("form")

        for form in forms:
            action = form.get("action", "").strip() or base_url
            target_url = normalize_url(action, base_url=base_url)
            raw_method = form.get("method", "GET").strip().upper()
            method = HTTPMethod.POST if raw_method == "POST" else HTTPMethod.GET

            form_data: Dict[str, Any] = {}

            # Input fields
            for inp in form.find_all("input"):
                name = inp.get("name")
                if not name:
                    continue
                inp_type = inp.get("type", "text").lower()
                val = inp.get("value", "")
                if inp_type in ("checkbox", "radio"):
                    val = val or "on"
                form_data[name] = val

            # Textarea fields
            for textarea in form.find_all("textarea"):
                name = textarea.get("name")
                if name:
                    form_data[name] = textarea.text or "test"

            # Select dropdowns
            for select in form.find_all("select"):
                name = select.get("name")
                if name:
                    first_opt = select.find("option")
                    form_data[name] = first_opt.get("value", "1") if first_opt else "1"

            discovered_forms.append(
                DiscoveredRequest(
                    url=target_url,
                    method=method,
                    params=form_data if method == HTTPMethod.GET else {},
                    form_data=form_data if method == HTTPMethod.POST else {},
                    source="form_extractor",
                )
            )

        return discovered_forms
