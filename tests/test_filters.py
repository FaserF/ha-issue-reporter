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


def test_real_ha_draft_false_positives_ignored() -> None:
    """Verify transient nginx, integration timeout, and Baileys drop samples are filtered."""
    flt = ErrorFilter({})

    false_positives = [
        (
            "addon:edfe50eb_nginx",
            "2026/11/24 16:47:42 [info] 572#572: *142 SSL_write() failed (SSL: error:80000068:system library::Connection reset by peer) (104: Connection reset by peer)",
        ),
        (
            "addon:edfe50eb_nginx",
            "2026/11/24 17:50:11 [error] 573#573: *195 upstream prematurely closed connection while sending to client",
        ),
        (
            "addon:edfe50eb_nginx",
            '2026/11/25 16:31:02 [error] 567#567: *1410 open() "/var/lib/nginx/html/tv/file.mkv" failed (2: No such file or directory)',
        ),
        (
            "addon:edfe50eb_paseo",
            "2026/11/25 12:13:11 [error] 386#386: *1 connect() failed (111: Connection refused) while connecting to upstream",
        ),
        (
            "integration:shielddns",
            "Error fetching shielddns ([REDACTED_SECRET]:443) data: Error communicating with API ([REDACTED_SECRET])",
        ),
        (
            "addon:edfe50eb_shielddns",
            'Network error contacting primary: Get "http://[REDACTED_HOST]:9443/api/cluster/replicas": dial tcp 10.0.0.1:9443: i/o timeout',
        ),
        (
            "integration:aegisbot",
            "Error fetching aegisbot data: Error communicating with API: Timeout error fetching information",
        ),
        (
            "integration:headscale",
            "Error fetching headscale data: Error communicating with Headscale: [Errno 1] [SSL: RECORD_LAYER_FAILURE]",
        ),
        (
            "integration:headscale",
            "Timeout fetching headscale data",
        ),
        (
            "integration:phoenix_bad",
            "Failed to fetch Sauna data: Request timeout",
        ),
        (
            "addon:edfe50eb_whatsapp",
            "stream errored out",
        ),
        (
            "addon:edfe50eb_whatsapp",
            "error in sending keep alive",
        ),
        (
            "addon:edfe50eb_whatsapp",
            "timed out waiting for message",
        ),
        (
            "addon:edfe50eb_whatsapp",
            "❌ WhatsApp server rejected message with error: 479",
        ),
    ]
    for target_key, msg in false_positives:
        ignored, _reason = flt.should_ignore(_event(target_key, msg))
        assert ignored is True, f"Expected false positive to be filtered: {msg}"
