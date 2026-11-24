"""Configurable local, transient, and custom error filtering."""

from __future__ import annotations

import re
from typing import Any

from .const import (
    CONF_CUSTOM_IGNORE_PATTERNS,
    CONF_IGNORE_AUTH_ERRORS,
    CONF_IGNORE_LIFECYCLE_ERRORS,
    CONF_IGNORE_NETWORK_ERRORS,
    CONF_IGNORE_RATE_LIMIT_ERRORS,
    CONF_TARGET_OVERRIDES,
    DEFAULT_IGNORE_AUTH_ERRORS,
    DEFAULT_IGNORE_LIFECYCLE_ERRORS,
    DEFAULT_IGNORE_NETWORK_ERRORS,
    DEFAULT_IGNORE_RATE_LIMIT_ERRORS,
    LOGGER,
)
from .models import LogEvent, TargetOverride

NETWORK_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bClientConnector(?:Error|DNSError)\b", re.IGNORECASE),
    re.compile(
        r"\b(?:ClientOSError|ServerDisconnectedError|ClientTimeout)\b", re.IGNORECASE
    ),
    re.compile(
        r"\b(?:ConnectionRefusedError|ConnectionResetError|BrokenPipeError)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:socket\.gaierror|TimeoutError|asyncio\.TimeoutError)\b", re.IGNORECASE
    ),
    re.compile(
        r"Name or service not known|Temporary failure in name resolution", re.IGNORECASE
    ),
    re.compile(
        r"Cannot connect to host|Host is unreachable|Network is unreachable|No route to host",
        re.IGNORECASE,
    ),
    re.compile(r"context deadline exceeded|Client\.Timeout exceeded", re.IGNORECASE),
    re.compile(
        r"(?:status(?:\s+code)?|HTTP(?:\s+Error)?|error)\s*['\":\s]*(?:502|503|504)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:Bad Gateway|Service Unavailable|Gateway Timeout)\b", re.IGNORECASE
    ),
    re.compile(
        r"Unable to discover the device|is not reachable|Connection error (?:updating|fetching)",
        re.IGNORECASE,
    ),
    re.compile(
        r"Timeout connecting to\b|timed out while\b|\[Errno (?:101|104|110|111|113)\]",
        re.IGNORECASE,
    ),
)

AUTH_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"\b(?:ConfigEntryAuthFailed|InvalidAuth|AuthenticationError)\b", re.IGNORECASE
    ),
    re.compile(
        r"(?:HTTP(?:\s+Error)?|status(?:\s+code)?)\s*['\":\s]*(?:401|403)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"INVALID USERNAME/PASSWORD|Invalid credentials|Authentication failed",
        re.IGNORECASE,
    ),
    re.compile(
        r"session expired|token expired|invalid_grant|unauthorized", re.IGNORECASE
    ),
    re.compile(r"Please re-authenticate", re.IGNORECASE),
)

RATE_LIMIT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"(?:HTTP(?:\s+Error)?|status(?:\s+code)?)\s*['\":\s]*429\b", re.IGNORECASE
    ),
    re.compile(r"\bToo Many Requests\b|rate limit exceeded", re.IGNORECASE),
)

LIFECYCLE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"\bCancelledError\b|Task was destroyed|Event loop is closed", re.IGNORECASE
    ),
    re.compile(r"Home Assistant is shutting down", re.IGNORECASE),
)


def _compile_custom_patterns(raw: Any) -> list[re.Pattern[str]]:
    """Compile user-defined regex list safely."""
    patterns: list[str] = []
    if isinstance(raw, list):
        patterns = [str(p).strip() for p in raw if str(p).strip()]
    elif isinstance(raw, str):
        patterns = [line.strip() for line in raw.splitlines() if line.strip()]

    compiled: list[re.Pattern[str]] = []
    for pat in patterns:
        try:
            compiled.append(re.compile(pat, re.IGNORECASE))
        except re.error as err:
            LOGGER.warning("Ignoring invalid custom filter regex %r: %s", pat, err)
    return compiled


class ErrorFilter:
    """Filters out local connectivity, auth, rate-limit, and user-ignored errors."""

    def __init__(self, config: dict[str, Any]) -> None:
        """Initialize filter flags and custom regex patterns."""
        self.update_config(config)

    def update_config(self, config: dict[str, Any]) -> None:
        """Reload filter toggles and compiled custom patterns."""
        self._ignore_network = bool(
            config.get(CONF_IGNORE_NETWORK_ERRORS, DEFAULT_IGNORE_NETWORK_ERRORS)
        )
        self._ignore_auth = bool(
            config.get(CONF_IGNORE_AUTH_ERRORS, DEFAULT_IGNORE_AUTH_ERRORS)
        )
        self._ignore_rate_limit = bool(
            config.get(CONF_IGNORE_RATE_LIMIT_ERRORS, DEFAULT_IGNORE_RATE_LIMIT_ERRORS)
        )
        self._ignore_lifecycle = bool(
            config.get(CONF_IGNORE_LIFECYCLE_ERRORS, DEFAULT_IGNORE_LIFECYCLE_ERRORS)
        )
        self._custom_patterns = _compile_custom_patterns(
            config.get(CONF_CUSTOM_IGNORE_PATTERNS)
        )
        raw_overrides = config.get(CONF_TARGET_OVERRIDES) or {}
        self._per_target_patterns: dict[str, list[re.Pattern[str]]] = {}
        for tkey, ov_raw in raw_overrides.items():
            ov = TargetOverride.from_dict(ov_raw)
            if ov.ignore_patterns:
                self._per_target_patterns[tkey] = _compile_custom_patterns(
                    ov.ignore_patterns
                )

    def should_ignore(self, event: LogEvent) -> tuple[bool, str | None]:
        """Return (True, reason) if event matches an ignored local/transient category."""
        haystack = f"{event.exception_type}\n{event.message}\n{event.traceback}"

        if self._ignore_network and any(p.search(haystack) for p in NETWORK_PATTERNS):
            return True, "local_network_error"
        if self._ignore_auth and any(p.search(haystack) for p in AUTH_PATTERNS):
            return True, "local_auth_error"
        if self._ignore_rate_limit and any(
            p.search(haystack) for p in RATE_LIMIT_PATTERNS
        ):
            return True, "rate_limit_error"
        if self._ignore_lifecycle and any(
            p.search(haystack) for p in LIFECYCLE_PATTERNS
        ):
            return True, "lifecycle_error"

        for pat in self._custom_patterns:
            if pat.search(haystack):
                return True, "custom_ignore_pattern"

        for pat in self._per_target_patterns.get(event.target_key, ()):
            if pat.search(haystack):
                return True, "target_ignore_pattern"

        return False, None
