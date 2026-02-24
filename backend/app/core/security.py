"""
Security utilities: domain validation, input sanitization, and rate limiting.

Provides:
- ``validate_domain`` -- validates and normalises a domain name.
- ``sanitize_input``  -- strips dangerous characters from user-supplied text.
- ``RateLimiter``     -- in-memory token-bucket rate limiter.
"""

from __future__ import annotations

import html
import re
import time
from typing import Optional

# ── Constants ────────────────────────────────────────────────────────────────

# RFC 1035 compliant domain pattern: labels separated by dots, each label
# starts with a letter, may contain letters/digits/hyphens, and ends with a
# letter or digit.  Total length must not exceed 253 characters.
_DOMAIN_LABEL_PATTERN: str = r"[a-zA-Z](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
_DOMAIN_REGEX: re.Pattern[str] = re.compile(
    rf"^(?:{_DOMAIN_LABEL_PATTERN}\.)+{_DOMAIN_LABEL_PATTERN}$"
)
_MAX_DOMAIN_LENGTH: int = 253

# Characters explicitly forbidden in general text input.
_DANGEROUS_PATTERN: re.Pattern[str] = re.compile(r"[<>&\"'`\\;|$(){}\[\]]")


# ── Domain Validation ────────────────────────────────────────────────────────

def validate_domain(domain: str) -> str:
    """Validate and normalise a domain name.

    The domain is stripped of whitespace, lowered, and trailing dots are
    removed.  It is then checked against RFC 1035 constraints.

    Args:
        domain: The raw domain string supplied by the user.

    Returns:
        The cleaned, normalised domain string.

    Raises:
        ValueError: If the domain is empty, too long, or does not match the
            allowed pattern.
    """
    if not domain or not domain.strip():
        raise ValueError("Domain must not be empty.")

    cleaned: str = domain.strip().lower().rstrip(".")

    if len(cleaned) > _MAX_DOMAIN_LENGTH:
        raise ValueError(
            f"Domain exceeds maximum length of {_MAX_DOMAIN_LENGTH} characters."
        )

    if not _DOMAIN_REGEX.match(cleaned):
        raise ValueError(
            f"Invalid domain format: '{cleaned}'. "
            "A valid domain consists of labels separated by dots "
            "(e.g. 'example.com')."
        )

    return cleaned


# ── Input Sanitization ───────────────────────────────────────────────────────

def sanitize_input(text: str, max_length: int = 1000) -> str:
    """Sanitize arbitrary user-supplied text.

    Processing steps:
    1. Strip leading/trailing whitespace.
    2. Truncate to *max_length* characters.
    3. Remove dangerous shell / HTML metacharacters.
    4. HTML-escape any remaining special characters.

    Args:
        text: The raw input string.
        max_length: Maximum allowed length after truncation.  Defaults to 1000.

    Returns:
        The sanitized string safe for storage and display.
    """
    if not text:
        return ""

    cleaned: str = text.strip()[:max_length]
    cleaned = _DANGEROUS_PATTERN.sub("", cleaned)
    cleaned = html.escape(cleaned, quote=True)
    return cleaned


# ── Rate Limiter ─────────────────────────────────────────────────────────────

class RateLimiter:
    """In-memory token-bucket rate limiter.

    Each *key* (e.g. an IP address or API-key identifier) receives a separate
    bucket.  Tokens refill at a constant rate up to a configured capacity.

    Example::

        limiter = RateLimiter(capacity=10, refill_rate=2.0)
        if limiter.allow("192.168.1.1"):
            ...  # process request
        else:
            ...  # reject / return 429

    Attributes:
        capacity: Maximum number of tokens a bucket can hold.
        refill_rate: Tokens added per second.
    """

    def __init__(self, capacity: int = 10, refill_rate: float = 1.0) -> None:
        """Initialise the rate limiter.

        Args:
            capacity: Maximum burst size (tokens per bucket).
            refill_rate: Tokens restored per second.
        """
        if capacity <= 0:
            raise ValueError("Capacity must be a positive integer.")
        if refill_rate <= 0:
            raise ValueError("Refill rate must be a positive number.")

        self.capacity: int = capacity
        self.refill_rate: float = refill_rate
        self._buckets: dict[str, _Bucket] = {}

    def allow(self, key: str) -> bool:
        """Check whether a request identified by *key* is allowed.

        Consumes one token if available.

        Args:
            key: An identifier for the requester (IP, user id, etc.).

        Returns:
            ``True`` if the request is permitted, ``False`` if the rate limit
            has been exceeded.
        """
        now: float = time.monotonic()
        bucket: _Bucket = self._get_or_create_bucket(key, now)
        bucket.refill(now, self.refill_rate, self.capacity)

        if bucket.tokens >= 1.0:
            bucket.tokens -= 1.0
            return True
        return False

    def remaining(self, key: str) -> int:
        """Return the number of tokens currently available for *key*.

        Args:
            key: The requester identifier.

        Returns:
            The integer number of tokens remaining (floored).
        """
        now: float = time.monotonic()
        bucket: _Bucket = self._get_or_create_bucket(key, now)
        bucket.refill(now, self.refill_rate, self.capacity)
        return int(bucket.tokens)

    def reset(self, key: Optional[str] = None) -> None:
        """Reset one or all buckets.

        Args:
            key: If provided, only the bucket for this key is removed.
                 If ``None``, all buckets are cleared.
        """
        if key is not None:
            self._buckets.pop(key, None)
        else:
            self._buckets.clear()

    # ── Private Helpers ──────────────────────────────────────────────────

    def _get_or_create_bucket(self, key: str, now: float) -> "_Bucket":
        """Retrieve an existing bucket or initialise a new one at full capacity."""
        if key not in self._buckets:
            self._buckets[key] = _Bucket(
                tokens=float(self.capacity),
                last_refill=now,
            )
        return self._buckets[key]


class _Bucket:
    """Internal state for a single token bucket."""

    __slots__ = ("tokens", "last_refill")

    def __init__(self, tokens: float, last_refill: float) -> None:
        self.tokens: float = tokens
        self.last_refill: float = last_refill

    def refill(self, now: float, rate: float, capacity: int) -> None:
        """Add tokens based on elapsed time since last refill."""
        elapsed: float = now - self.last_refill
        self.tokens = min(float(capacity), self.tokens + elapsed * rate)
        self.last_refill = now
