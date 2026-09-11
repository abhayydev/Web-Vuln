"""Asynchronous HTTP Client with connection pooling, rate limiting, and safe error handling."""

import asyncio
import time
from typing import Any, Dict, Optional
import httpx
from webvuln.config import ScanConfig
from webvuln.logger import logger
from webvuln.models.response import HTTPResponse


class ScanContext:
    """Manages the async HTTP session, connection pooling, rate limiting, and request lifecycle."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self._semaphore = asyncio.Semaphore(config.concurrency)
        self._client: Optional[httpx.AsyncClient] = None
        self._total_requests = 0
        self._last_request_time = 0.0

    async def __aenter__(self) -> "ScanContext":
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()

    async def start(self) -> None:
        """Initializes the httpx AsyncClient."""
        headers = {
            "User-Agent": self.config.user_agent,
            "Accept": "*/*",
            **self.config.headers,
        }
        limits = httpx.Limits(
            max_connections=self.config.concurrency * 2,
            max_keepalive_connections=self.config.concurrency,
        )
        self._client = httpx.AsyncClient(
            headers=headers,
            limits=limits,
            timeout=httpx.Timeout(self.config.timeout, connect=5.0),
            verify=self.config.verify_ssl,
            follow_redirects=self.config.follow_redirects,
            proxy=self.config.proxy,
        )

    async def close(self) -> None:
        """Closes the underlying HTTP client cleanly."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    @property
    def total_requests(self) -> int:
        return self._total_requests

    async def request(
        self,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        follow_redirects: Optional[bool] = None,
    ) -> Optional[HTTPResponse]:
        """Executes a safe async HTTP request governed by concurrency semaphores and rate limits."""
        if not self._client:
            raise RuntimeError("ScanContext HTTP client is not initialized. Use 'async with' or call start().")

        async with self._semaphore:
            # Respect configured rate limits
            if self.config.rate_limit > 0:
                elapsed = time.monotonic() - self._last_request_time
                if elapsed < self.config.rate_limit:
                    await asyncio.sleep(self.config.rate_limit - elapsed)

            start_t = time.monotonic()
            self._last_request_time = start_t
            self._total_requests += 1

            try:
                kwargs = {
                    "params": params,
                    "data": data,
                    "json": json_data,
                    "headers": headers,
                }
                if follow_redirects is not None:
                    kwargs["follow_redirects"] = follow_redirects

                res = await self._client.request(method, url, **kwargs)
                response_time = time.monotonic() - start_t

                # Limit response body reading to 2MB to prevent memory exhaustion
                raw_bytes = res.content[: 2 * 1024 * 1024]
                body_text = raw_bytes.decode("utf-8", errors="replace")

                content_type = res.headers.get("content-type", "").lower()
                is_json = "application/json" in content_type

                return HTTPResponse(
                    url=str(res.url),
                    status_code=res.status_code,
                    headers=dict(res.headers),
                    body=body_text,
                    response_time=response_time,
                    content_type=content_type,
                    is_json=is_json,
                )

            except httpx.TimeoutException:
                if self.config.verbose:
                    logger.debug(f"Request timeout for {method} {url}")
                return None
            except httpx.ConnectError as e:
                if self.config.verbose:
                    logger.debug(f"Connection failed for {url}: {e}")
                return None
            except Exception as e:
                if self.config.verbose:
                    logger.debug(f"HTTP request error ({method} {url}): {e}")
                return None

    async def get(self, url: str, **kwargs) -> Optional[HTTPResponse]:
        """Convenience helper for GET requests."""
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> Optional[HTTPResponse]:
        """Convenience helper for POST requests."""
        return await self.request("POST", url, **kwargs)
