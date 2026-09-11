"""HTTP Response representation for analysis by scanners."""

from typing import Dict, Optional
from pydantic import BaseModel, Field


class HTTPResponse(BaseModel):
    """Encapsulates an HTTP response for scanner consumption."""

    url: str = Field(..., description="Requested URL (after redirects)")
    status_code: int = Field(..., description="HTTP status code")
    headers: Dict[str, str] = Field(default_factory=dict, description="Response headers")
    body: str = Field(default="", description="Response body text content")
    response_time: float = Field(default=0.0, description="Round-trip response latency in seconds")
    content_type: str = Field(default="text/html", description="MIME content type")
    is_json: bool = Field(default=False, description="Whether response is valid JSON")

    def get_header(self, name: str, default: Optional[str] = None) -> Optional[str]:
        """Case-insensitive header lookup."""
        name_lower = name.lower()
        for k, v in self.headers.items():
            if k.lower() == name_lower:
                return v
        return default
