"""Tests for fingerprinting, version intelligence, and GitHub deduplication."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

from custom_components.issue_reporter.const import (
    CONF_COMMENT_ON_NEWER_VERSION,
    CONF_OWNER_FILTER_MODE,
    FINGERPRINT_PREFIX,
    OWNER_FILTER_SELF,
)
from custom_components.issue_reporter.dedup import (
    async_check_github_duplicate,
    compute_fingerprint,
    is_target_outdated,
)
from custom_components.issue_reporter.models import LogEvent, TargetInfo


def _target(version: str = "1.2.0", channel: str = "stable", **kwargs) -> TargetInfo:
    return TargetInfo(
        target_key="integration:openwrt",
        kind="integration",
        identifier="openwrt",
        short_name="openwrt",
        name="OpenWrt",
        version=version,
        repo_owner="FaserF",
        repo_name="ha-openwrt",
        repo_url="https://github.com/FaserF/ha-openwrt",
        channel=channel,
        owner_matched=True,
        enabled=True,
        **kwargs,
    )


def _event(msg: str, exc: str = "KeyError") -> LogEvent:
    return LogEvent(
        target_key="integration:openwrt",
        kind="integration",
        logger_name="custom_components.openwrt.coordinator",
        severity="ERROR",
        levelno=logging.ERROR,
        message=msg,
        exception_type=exc,
    )


def test_fingerprint_stability() -> None:
    """Fingerprints must ignore volatile IPs, timestamps, and IDs."""
    t = _target()
    fp1 = compute_fingerprint(
        t, _event("2026-11-24 10:00:00 Failed reading 192.168.1.1:443 id 999888")
    )
    fp2 = compute_fingerprint(
        t, _event("2026-11-25 12:34:56 Failed reading 10.0.0.5:8080 id 123456")
    )
    assert fp1 == fp2
    assert len(fp1) == 16


def test_outdated_version_and_dev_edge_exemption() -> None:
    """Outdated releases are skipped, while dev/edge builds remain eligible."""
    assert is_target_outdated(_target(version="2.5.0"), "v2.5.7", allow_dev_edge=True)
    assert not is_target_outdated(
        _target(version="2.5.7"), "v2.5.7", allow_dev_edge=True
    )
    assert not is_target_outdated(
        _target(version="2.5.0-dev0", channel="dev"), "v2.5.7", allow_dev_edge=True
    )
    assert is_target_outdated(
        _target(version="2.5.0-dev0", channel="dev"), "v2.5.7", allow_dev_edge=False
    )

    addon_upd = TargetInfo(
        target_key="addon:edfe50eb_aegisbot",
        kind="addon",
        identifier="edfe50eb_aegisbot",
        short_name="aegisbot",
        name="AegisBot",
        version="0.6.2",
        repo_owner="FaserF",
        repo_name="hassio-addons",
        repo_url="https://github.com/FaserF/hassio-addons",
        channel="stable",
        update_available=True,
    )
    assert is_target_outdated(addon_upd, None, allow_dev_edge=True)


async def test_duplicate_detection_exact_fuzzy_comment_and_regression() -> None:
    """Test exact, cross-user fuzzy, newer-version comment, and closed regression."""
    t = _target(version="2.5.8")
    ev = _event("KeyError 'lan_rx_bytes' while parsing ubus response", exc="KeyError")
    fp = compute_fingerprint(t, ev)

    github = MagicMock()
    # 1. Exact fingerprint open match -> comment_open since 2.5.8 > 2.5.6
    github.async_search_issues = AsyncMock(
        return_value=[
            {
                "number": 42,
                "html_url": "https://github.com/FaserF/ha-openwrt/issues/42",
                "state": "open",
                "title": "[Bug]: KeyError lan_rx_bytes",
                "body": f"Version v2.5.6 <!-- {FINGERPRINT_PREFIX}{fp} -->",
            }
        ]
    )
    github.async_get_issue_comments = AsyncMock(return_value=[])
    res1 = await async_check_github_duplicate(
        github,
        t,
        ev,
        fp,
        {
            CONF_OWNER_FILTER_MODE: OWNER_FILTER_SELF,
            CONF_COMMENT_ON_NEWER_VERSION: True,
        },
    )
    assert res1.action == "comment_open"
    assert res1.issue_number == 42
    assert "2.5.8" in res1.comment_body

    # Already commented for 2.5.8 -> skip_open
    github.async_get_issue_comments = AsyncMock(
        return_value=[{"body": "Reproduction note: still observed on `2.5.8`"}]
    )
    res_dup_comment = await async_check_github_duplicate(
        github, t, ev, fp, {CONF_COMMENT_ON_NEWER_VERSION: True}
    )
    assert res_dup_comment.action == "skip_open"

    # 2. Cross-user fuzzy match on human-filed open issue -> skip_open when comment disabled
    github.async_search_issues = AsyncMock(
        side_effect=[
            [],  # exact search empty
            [
                {
                    "number": 77,
                    "html_url": "https://github.com/FaserF/ha-openwrt/issues/77",
                    "state": "open",
                    "title": "KeyError 'lan_rx_bytes' while parsing ubus response",
                    "body": "Happens on OpenWrt 24.10 using version 2.5.8",
                }
            ],
        ]
    )
    res2 = await async_check_github_duplicate(
        github, t, ev, fp, {CONF_COMMENT_ON_NEWER_VERSION: False}
    )
    assert res2.action == "skip_open"
    assert res2.issue_number == 77

    # 3. Closed match within 90 days on same version -> skip_closed
    recent = datetime.now(UTC).isoformat()
    github.async_search_issues = AsyncMock(
        return_value=[
            {
                "number": 19,
                "html_url": "https://github.com/FaserF/ha-openwrt/issues/19",
                "state": "closed",
                "closed_at": recent,
                "title": "KeyError lan_rx_bytes",
                "body": "Fixed in 2.5.8",
            }
        ]
    )
    github.async_get_latest_release = AsyncMock(return_value="v2.5.8")
    res3 = await async_check_github_duplicate(github, t, ev, fp, {})
    assert res3.action == "skip_closed"

    # 4. Closed match on older version while installed is newer -> regression_new
    old_close = (datetime.now(UTC) - timedelta(days=5)).isoformat()
    t_newer = _target(version="2.6.0")
    github.async_search_issues = AsyncMock(
        return_value=[
            {
                "number": 19,
                "html_url": "https://github.com/FaserF/ha-openwrt/issues/19",
                "state": "closed",
                "closed_at": old_close,
                "title": "KeyError lan_rx_bytes",
                "body": "Version 2.5.6",
            }
        ]
    )
    res4 = await async_check_github_duplicate(github, t_newer, ev, fp, {})
    assert res4.action == "regression_new"
    assert res4.issue_number == 19
