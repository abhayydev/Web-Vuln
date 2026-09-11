"""Structured, sanitized logging with Rich console styling."""

import logging
import re
from rich.console import Console
from rich.logging import RichHandler

console = Console()

# Regular expressions for masking sensitive data in logs
SENSITIVE_PATTERNS = [
    (re.compile(r"(Bearer\s+)[A-Za-z0-9\-\._~\+\/]+=*", re.IGNORECASE), r"\1[MASKED_TOKEN]"),
    (re.compile(r"(password|passwd|secret|api_key|token|access_token|sessionid|jwt)=([^\s&;]+)", re.IGNORECASE), r"\1=[MASKED]"),
    (re.compile(r"(Set-Cookie:\s*[^=]+)=([^;]+)", re.IGNORECASE), r"\1=[MASKED_COOKIE]"),
]


class SanitizingFormatter(logging.Formatter):
    """Custom formatter that automatically strips sensitive credentials from log output."""

    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)
        for pattern, replacement in SENSITIVE_PATTERNS:
            msg = pattern.sub(replacement, msg)
        return msg


def setup_logger(verbose: bool = False) -> logging.Logger:
    """Configures the root WebVuln application logger."""
    level = logging.DEBUG if verbose else logging.INFO

    handler = RichHandler(
        console=console,
        show_time=True,
        show_path=False,
        rich_tracebacks=True,
        tracebacks_show_locals=False,
    )
    handler.setFormatter(SanitizingFormatter("%(message)s"))

    logger = logging.getLogger("webvuln")
    logger.setLevel(level)
    logger.handlers.clear()
    logger.addHandler(handler)
    logger.propagate = False

    # Suppress verbose logs from third-party libraries
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    return logger


logger = setup_logger()
