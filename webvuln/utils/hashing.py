"""Hashing and cryptographic utilities for fingerprinting requests and findings."""

import hashlib
from typing import Any, Dict


def compute_sha256(content: str) -> str:
    """Computes SHA-256 hash string of text content."""
    return hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()


def compute_endpoint_hash(method: str, url_without_query: str, params: Dict[str, Any]) -> str:
    """Generates a unique deterministic fingerprint for an endpoint to prevent duplicate scanning."""
    param_keys = sorted(params.keys())
    sig = f"{method.upper()}:{url_without_query}:{'&'.join(param_keys)}"
    return hashlib.md5(sig.encode("utf-8")).hexdigest()
