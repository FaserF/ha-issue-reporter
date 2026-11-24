"""Typed exceptions and ETag cache entries for GitHubClient."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

CORE_MIN_RESERVE = 20
SEARCH_MIN_RESERVE = 2
CIRCUIT_THRESHOLD = 3
CIRCUIT_COOLDOWN = timedelta(minutes=5)


class GitHubAPIError(Exception):
    """Raised when a GitHub API request fails."""


class GitHubNetworkError(GitHubAPIError):
    """Raised on transient transport / timeout / 5xx GitHub errors."""


class GitHubRateLimitError(GitHubAPIError):
    """Raised when GitHub primary or secondary rate limit is reached."""

    def __init__(
        self,
        message: str,
        *,
        reset_at: datetime | None = None,
        retry_after: int | None = None,
        resource: str = "core",
        is_secondary: bool = False,
    ) -> None:
        """Initialize rate-limit error with reset metadata."""
        super().__init__(message)
        self.reset_at = reset_at
        self.retry_after = retry_after
        self.resource = resource
        self.is_secondary = is_secondary


@dataclass
class ETagEntry:
    """Cached response payload with ETag and timestamp."""

    fetched_at: datetime
    data: Any
    etag: str | None = None


NOT_MODIFIED = object()


class RateLimitTracker:
    """Tracks per-resource GitHub rate limits and transient failure circuit breaker."""

    def __init__(self) -> None:
        """Initialize counters."""
        self.core_remaining: int | None = None
        self.core_reset: int | None = None
        self.search_remaining: int | None = None
        self.search_reset: int | None = None
        self.consecutive_failures = 0
        self.circuit_open_until: datetime | None = None

    @property
    def is_circuit_open(self) -> bool:
        """Return True when transient failure circuit breaker is active."""
        if self.circuit_open_until is None:
            return False
        if datetime.now(UTC) >= self.circuit_open_until:
            self.circuit_open_until = None
            self.consecutive_failures = 0
            return False
        return True

    def record_success(self) -> None:
        """Reset failure counter and close circuit breaker."""
        self.consecutive_failures = 0
        self.circuit_open_until = None

    def record_failure(self) -> None:
        """Increment failure counter and open circuit breaker on threshold."""
        self.consecutive_failures += 1
        if self.consecutive_failures >= CIRCUIT_THRESHOLD:
            self.circuit_open_until = datetime.now(UTC) + CIRCUIT_COOLDOWN

    def check_proactive_limits(self, resource: str) -> None:
        """Abort before making a network call if circuit or quota is exhausted."""
        if self.is_circuit_open:
            raise GitHubNetworkError(
                "GitHub API circuit breaker open after repeated failures"
            )
        now = datetime.now(UTC)
        if (
            resource == "search"
            and self.search_remaining is not None
            and self.search_remaining < SEARCH_MIN_RESERVE
            and self.search_reset is not None
        ):
            rst = datetime.fromtimestamp(self.search_reset, tz=UTC)
            if now < rst:
                raise GitHubRateLimitError(
                    "GitHub Search API quota reserve reached",
                    reset_at=rst,
                    resource="search",
                )
        elif (
            resource != "search"
            and self.core_remaining is not None
            and self.core_remaining < CORE_MIN_RESERVE
            and self.core_reset is not None
        ):
            rst = datetime.fromtimestamp(self.core_reset, tz=UTC)
            if now < rst:
                raise GitHubRateLimitError(
                    "GitHub Core API quota reserve reached",
                    reset_at=rst,
                    resource="core",
                )

    def update_from_headers(self, headers: Mapping[Any, str]) -> None:
        """Track X-RateLimit headers per resource without failing on missing headers."""
        resource = str(headers.get("X-RateLimit-Resource") or "core").lower()
        rem = headers.get("X-RateLimit-Remaining")
        rst = headers.get("X-RateLimit-Reset")
        if resource == "search":
            if rem is not None and str(rem).isdigit():
                self.search_remaining = int(rem)
            if rst is not None and str(rst).isdigit():
                self.search_reset = int(rst)
        else:
            if rem is not None and str(rem).isdigit():
                self.core_remaining = int(rem)
            if rst is not None and str(rst).isdigit():
                self.core_reset = int(rst)
