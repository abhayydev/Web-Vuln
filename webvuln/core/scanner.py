"""Abstract BaseScanner interface defining the contract for all modular vulnerability checks."""

from abc import ABC, abstractmethod
from typing import List, Optional
from webvuln.core.context import ScanContext
from webvuln.models.finding import Finding
from webvuln.models.request import DiscoveredRequest
from webvuln.models.response import HTTPResponse
from webvuln.models.scan import ScanTarget


class BaseScanner(ABC):
    """Base class for all active and passive security assessment modules."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique human-readable identifier for the scanner module."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Brief summary of the security tests performed by this module."""
        pass

    @abstractmethod
    async def scan(
        self,
        target: ScanTarget,
        context: ScanContext,
        endpoint: DiscoveredRequest,
        response: Optional[HTTPResponse] = None,
    ) -> List[Finding]:
        """Executes vulnerability checks against a specific endpoint."""
        pass
