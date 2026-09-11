"""Global configuration settings and execution options for WebVuln Scanner."""

from pathlib import Path
from typing import List, Optional, Set, Dict
from pydantic import BaseModel, Field


class ScanConfig(BaseModel):
    """Immutable scan configuration options parsed from CLI or config file."""

    target_url: str = Field(..., description="Target base URL to scan")
    scope_domains: Set[str] = Field(default_factory=set, description="Allowed domains for scanning and crawling")
    max_depth: int = Field(default=3, ge=1, le=10, description="Maximum crawling depth")
    max_urls: int = Field(default=50, ge=1, le=1000, description="Maximum URLs to discover and analyze")
    concurrency: int = Field(default=5, ge=1, le=50, description="Maximum concurrent HTTP requests")
    timeout: float = Field(default=10.0, ge=1.0, le=60.0, description="HTTP request timeout in seconds")
    rate_limit: float = Field(default=0.0, ge=0.0, le=5.0, description="Delay between requests in seconds")
    user_agent: str = Field(
        default="WebVuln-Scanner/0.1.0 (Security-Audit-Educational; +https://github.com/example/webvuln)",
        description="HTTP User-Agent header value",
    )
    headers: Dict[str, str] = Field(default_factory=dict, description="Custom HTTP headers to attach to requests")
    proxy: Optional[str] = Field(default=None, description="Optional HTTP/HTTPS proxy URL")
    follow_redirects: bool = Field(default=True, description="Whether to follow HTTP redirects automatically")
    verify_ssl: bool = Field(default=False, description="Verify SSL/TLS certificates (set False for lab self-signed certs)")
    checks: List[str] = Field(
        default_factory=lambda: [
            "headers",
            "cookies",
            "cors",
            "tls",
            "xss",
            "sqli",
            "traversal",
            "redirect",
            "api",
            "auth",
            "idor",
        ],
        description="Active and passive check modules to run",
    )
    exclude_checks: List[str] = Field(default_factory=list, description="Checks to explicitly exclude")
    output_dir: Path = Field(default=Path("reports"), description="Output directory for JSON/HTML reports")
    verbose: bool = Field(default=False, description="Enable verbose logging output")
