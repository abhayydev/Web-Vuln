"""Payload and string generation utilities."""

import random
import string


def generate_marker(prefix: str = "WVSCAN", length: int = 6) -> str:
    """Generates a harmless alphanumeric probe marker for reflection and context tracking."""
    rand_chars = "".join(random.choices(string.ascii_uppercase + string.digits, k=length))
    return f"{prefix}_{rand_chars}"
