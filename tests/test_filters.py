"""Tests for local, transient, and custom error filters."""

from __future__ import annotations

import logging

from custom_components.issue_reporter.const import (
    CONF_CUSTOM_IGNORE_PATTERNS,
    CONF_IGNORE_AUTH_ERRORS,
    CONF_IGNORE_NETWORK_ERRORS,
    CONF_TARGET_OVERRIDES,
)
from custom_components.issue_reporter.filters import ErrorFilter
from custom_components.issue_reporter.models import LogEvent


def _event(target_key: str, msg: str, exc: str = "") -> LogEvent:
    return LogEvent(
        target_key=target_key,
        kind="integration",
        logger_name="test.logger",
        severity="ERROR",
        levelno=logging.ERROR,
        message=msg,
        exception_type=exc,
    )


def test_network_auth_ratelimit_filters() -> None:
    """Test ignoring local network, auth, rate-limit, and lifecycle errors."""
    flt = ErrorFilter({})

    # Network & timeout samples (including 502 and context deadline exceeded)
    assert flt.should_ignore(
        _event(
            "integration:jellyha", "Jellyfin API error 502 for GET https://host/Info"
        )
    )[0]
    assert flt.should_ignore(
        _event(
            "addon:edfe50eb_shielddns",
            "Cluster periodic sync failed: context deadline exceeded (Client.Timeout exceeded while awaiting headers)",
        )
    )[0]
    assert flt.should_ignore(
        _event(
            "integration:localtuya",
            "Connection failed: [Errno 113] Host is unreachable ('192.168.1.10', '6668')",
        )
    )[0]

    # Auth / 401 / 403 samples
    assert flt.should_ignore(
        _event(
            "addon:edfe50eb_traderepublic",
            "WS Keeper: connection error: server rejected WebSocket connection: HTTP 401",
        )
    )[0]
    assert flt.should_ignore(
        _event(
            "integration:traderepublic",
            "Authentication failed: Trade Republic session expired",
            exc="ConfigEntryAuthFailed",
        )
    )[0]

    # Rate limit & lifecycle
    assert flt.should_ignore(
        _event("integration:demo", "HTTP Error 429: Too Many Requests")
    )[0]
    assert flt.should_ignore(
        _event("integration:demo", "CancelledError while shutting down")
    )[0]

    # Genuine code bug must NOT be ignored!
    ignored, reason = flt.should_ignore(
        _event(
            "integration:aegisbot",
            "Detected that custom integration 'aegisbot' calls async_get_or_create with deprecated via_device",
        )
    )
    assert ignored is False
    assert reason is None

    ignored2, _ = flt.should_ignore(
        _event(
            "integration:sonarr",
            "Unexpected error: 'RootFolder' object has no attribute 'freeSpace'",
            exc="AttributeError",
        )
    )
    assert ignored2 is False


def test_filter_toggles_and_custom_patterns() -> None:
    """Test disabling built-in filters and applying custom/per-target regexes."""
    flt = ErrorFilter(
        {
            CONF_IGNORE_NETWORK_ERRORS: False,
            CONF_IGNORE_AUTH_ERRORS: False,
            CONF_CUSTOM_IGNORE_PATTERNS: [r"Baskets API failed with status 404"],
            CONF_TARGET_OVERRIDES: {
                "integration:demo": {"ignore_patterns": [r"expected noisy warning"]}
            },
        }
    )

    assert not flt.should_ignore(
        _event("integration:x", "ConnectionRefusedError: [Errno 111]")
    )[0]
    assert not flt.should_ignore(
        _event("integration:x", "HTTP Error 401 Unauthorized")
    )[0]
    assert flt.should_ignore(
        _event(
            "integration:foodsharing",
            'Baskets API failed with status 404: {"message":"Invalid query parameter"}',
        )
    )[0]
    assert flt.should_ignore(
        _event("integration:demo", "An expected noisy warning happened")
    )[0]
    assert not flt.should_ignore(
        _event("integration:other", "An expected noisy warning happened")
    )[0]
