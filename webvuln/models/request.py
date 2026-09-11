"""HTTP Request model for crawled and tested endpoints."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class HTTPMethod(str, Enum):
    """Standard HTTP request methods."""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    OPTIONS = "OPTIONS"
    HEAD = "HEAD"


class DiscoveredRequest(BaseModel):
    """Represents a discovered endpoint or attack surface entry point."""

    url: str = Field(..., description="Target endpoint URL")
    method: HTTPMethod = Field(default=HTTPMethod.GET, description="HTTP method")
    headers: Dict[str, str] = Field(default_factory=dict, description="Request headers")
    params: Dict[str, str] = Field(default_factory=dict, description="URL query parameters")
    form_data: Dict[str, Any] = Field(default_factory=dict, description="Form input fields")
    json_data: Optional[Dict[str, Any]] = Field(default=None, description="JSON body payload")
    source: str = Field(default="crawler", description="Source of discovery (crawler, sitemap, robots, api)")
    depth: int = Field(default=0, description="Crawl depth at which endpoint was discovered")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Discovery timestamp")
