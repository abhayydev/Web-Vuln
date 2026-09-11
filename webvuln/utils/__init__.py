"""Utility helpers for WebVuln Scanner."""

from webvuln.utils.url import normalize_url, extract_domain, is_static_asset, STATIC_EXTENSIONS
from webvuln.utils.hashing import compute_sha256, compute_endpoint_hash
from webvuln.utils.payloads import generate_marker

__all__ = [
    "normalize_url",
    "extract_domain",
    "is_static_asset",
    "STATIC_EXTENSIONS",
    "compute_sha256",
    "compute_endpoint_hash",
    "generate_marker",
]
