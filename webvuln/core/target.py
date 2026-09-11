"""Target validation, normalization, and strict scope boundary enforcement."""

import re
from urllib.parse import urlparse, urlunparse
from typing import Optional, Set
from webvuln.models.scan import ScanTarget


class TargetValidationError(ValueError):
    """Raised when a supplied target is invalid, malformed, or out of scope."""
    pass


class TargetValidator:
    """Validates, normalizes, and verifies security scope for scanning targets."""

    SUPPORTED_SCHEMES = {"http", "https"}

    @classmethod
    def validate_and_parse(cls, raw_url: str, custom_scope: Optional[Set[str]] = None) -> ScanTarget:
        """Parses, normalizes, and validates the target URL."""
        if not raw_url or not isinstance(raw_url, str):
            raise TargetValidationError("Target URL cannot be empty.")

        raw_url = raw_url.strip()

        # Add http scheme if user forgot scheme for quick lab targets
        if not re.match(r"^[a-zA-Z]+://", raw_url):
            raw_url = f"http://{raw_url}"

        parsed = urlparse(raw_url)

        if parsed.scheme.lower() not in cls.SUPPORTED_SCHEMES:
            raise TargetValidationError(f"Unsupported scheme '{parsed.scheme}'. Only HTTP and HTTPS are supported.")

        if not parsed.hostname:
            raise TargetValidationError(f"Invalid target URL '{raw_url}': Hostname is missing.")

        hostname = parsed.hostname.lower()
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        base_path = parsed.path if parsed.path and parsed.path != "" else "/"

        # Normalize URL: clean default ports, trailing slashes on base
        netloc = hostname if (port in (80, 443)) else f"{hostname}:{port}"
        normalized = urlunparse((parsed.scheme.lower(), netloc, base_path, "", "", ""))

        allowed_scope = {hostname}
        if custom_scope:
            allowed_scope.update(s.lower().strip() for s in custom_scope if s.strip())

        return ScanTarget(
            raw_url=raw_url,
            normalized_url=normalized,
            scheme=parsed.scheme.lower(),
            host=hostname,
            port=port,
            base_path=base_path,
            allowed_scope=list(allowed_scope),
        )

    @classmethod
    def is_in_scope(cls, url: str, target: ScanTarget) -> bool:
        """Determines whether a given candidate URL is within the authorized scan scope."""
        try:
            parsed = urlparse(url)
            if not parsed.hostname:
                return False

            host = parsed.hostname.lower()

            for allowed in target.allowed_scope:
                if host == allowed or host.endswith(f".{allowed}"):
                    return True
            return False
        except Exception:
            return False
