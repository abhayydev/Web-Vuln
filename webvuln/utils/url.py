"""URL utility functions for cleaning, resolving, and canonicalizing endpoints."""

import re
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse
from typing import Optional, Set


def normalize_url(url: str, base_url: Optional[str] = None) -> str:
    """Canonicalizes a URL by stripping fragments, standardizing ports, and sorting parameters."""
    if not url:
        return ""

    url = url.strip()

    # Resolve relative URL if base_url is supplied
    if base_url:
        url = urljoin(base_url, url)

    parsed = urlparse(url)
    if not parsed.scheme or not parsed.hostname:
        return url

    scheme = parsed.scheme.lower()
    hostname = parsed.hostname.lower()
    port = parsed.port

    # Strip default ports
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        netloc = hostname
    elif port:
        netloc = f"{hostname}:{port}"
    else:
        netloc = hostname

    # Clean path (ensure single slashes, maintain trailing slash if present)
    path = parsed.path or "/"
    path = re.sub(r"/+", "/", path)

    # Sort query parameters for deduplication
    query_params = parse_qsl(parsed.query, keep_blank_values=True)
    sorted_query = urlencode(sorted(query_params))

    # Reassemble without fragments (anchors)
    return urlunparse((scheme, netloc, path, parsed.params, sorted_query, ""))


def extract_domain(url: str) -> str:
    """Extracts hostname from a given URL."""
    try:
        return urlparse(url).hostname.lower() or ""
    except Exception:
        return ""


def get_path_extension(url: str) -> str:
    """Returns the lowercase file extension from the URL path, e.g., '.js', '.png'."""
    parsed = urlparse(url)
    path = parsed.path
    if "." in path:
        return path.rsplit(".", 1)[-1].lower()
    return ""


STATIC_EXTENSIONS: Set[str] = {
    "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "bmp", "tiff",
    "css", "woff", "woff2", "ttf", "eot", "otf",
    "mp4", "webm", "ogg", "mp3", "wav", "avi", "mov",
    "pdf", "zip", "tar", "gz", "rar", "7z", "exe", "dmg",
}


def is_static_asset(url: str) -> bool:
    """Checks if the URL points to a static media or font asset that does not need vulnerability scanning."""
    ext = get_path_extension(url)
    return ext in STATIC_EXTENSIONS
