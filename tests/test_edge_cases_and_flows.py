"""Additional edge-case tests to ensure >85% coverage across coordinator, flows, and repairs."""

from __future__ import annotations

import logging
from collections import deque
from unittest.mock import AsyncMock, patch

from homeassistant import config_entries
from homeassistant.data_entry_flow import FlowResultType
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.issue_reporter.const import (
    AUTH_DEVICE_FLOW,
    AUTH_PAT,
    CONF_AUTH_METHOD,
    CONF_DRY_RUN,
    CONF_GITHUB_TOKEN,
    CONF_GITHUB_USER,
    CONF_MAX_ISSUES_PER_HOUR,
    CONF_OAUTH_CLIENT_ID,
    CONF_OWNER_FILTER_MODE,
    DOMAIN,
    OWNER_FILTER_SELF,
)
from custom_components.issue_reporter.dedup import DuplicateMatch
from custom_components.issue_reporter.log_monitor import async_poll_addon_logs
from custom_components.issue_reporter.models import LogEvent, TargetInfo
from custom_components.issue_reporter.repairs import PendingDraftRepairFlow

from .test_coordinator_and_entities import _setup_integration


async def test_coordinator_edge_outcomes_and_state_persistence(
    hass,
    mock_custom_components,
    mock_supervisor_client,
) -> None:
    """Cover filtered, outdated, duplicate skip/comment, leak guard abort, rate limit, and reload."""
    entry = await _setup_integration(
        hass, mock_custom_components, mock_supervisor_client, dry_run=True
    )
    coord = entry.runtime_data

    # 1. Filtered network event
    net_ev = LogEvent(
        target_key="integration:openwrt",
        kind="integration",
        logger_name="custom_components.openwrt",
        severity="ERROR",
        levelno=logging.ERROR,
        message="ClientConnectorError: Cannot connect to host",
    )
    assert await coord._async_process_event(net_ev) == "filtered"

    # 2. Outdated target skipped
    coord.targets["integration:openwrt"].latest_version = "9.9.9"
    ev_outdated = LogEvent(
        target_key="integration:openwrt",
        kind="integration",
        logger_name="custom_components.openwrt",
        severity="ERROR",
        levelno=logging.ERROR,
        message="Unique runtime failure on outdated build",
    )
    assert await coord._async_process_event(ev_outdated) == "outdated"
    coord.targets["integration:openwrt"].latest_version = "2.5.7"

    # 3. Duplicate skip & comment paths
    ev_dup = LogEvent(
        target_key="integration:openwrt",
        kind="integration",
        logger_name="custom_components.openwrt",
        severity="ERROR",
        levelno=logging.ERROR,
        message="Duplicate bug report payload",
    )
    with patch(
        "custom_components.issue_reporter.coordinator.async_check_github_duplicate",
        return_value=DuplicateMatch(action="skip_open", issue_number=10),
    ):
        assert await coord._async_process_event(ev_dup) == "skip_open"

    await coord.async_clear_cooldowns()
    with patch(
        "custom_components.issue_reporter.coordinator.async_check_github_duplicate",
        return_value=DuplicateMatch(
            action="comment_open", issue_number=10, comment_body="Still occurs"
        ),
    ):
        assert await coord._async_process_event(ev_dup) == "comment_skipped_dry_run"

    # 4. Dry-run draft stored + Leak Guard abort path
    await coord.async_clear_cooldowns()
    coord.github.async_fetch_bug_templates = AsyncMock(return_value=[])
    with patch(
        "custom_components.issue_reporter.coordinator.async_check_github_duplicate",
        return_value=DuplicateMatch(action="none"),
    ):
        assert await coord._async_process_event(ev_dup) == "dry_run_draft"
        assert len(coord.pending_drafts) == 1

    # Force leak guard abort via mocked verify_no_leaks
    await coord.async_clear_cooldowns()
    with (
        patch(
            "custom_components.issue_reporter.coordinator.async_check_github_duplicate",
            return_value=DuplicateMatch(action="none"),
        ),
        patch.object(
            coord.redactor,
            "verify_no_leaks",
            return_value=(False, ["pattern_survived:github_token"]),
        ),
    ):
        assert await coord._async_process_event(ev_dup) == "leak_guard_blocked"
        assert coord.stats.leak_guard_blocks == 1

    # 5. Rate limit enforcement
    coord.config[CONF_MAX_ISSUES_PER_HOUR] = 1
    coord.store.record_post_rate("FaserF/ha-openwrt")
    ev_rate = LogEvent(
        target_key="integration:openwrt",
        kind="integration",
        logger_name="custom_components.openwrt",
        severity="ERROR",
        levelno=logging.ERROR,
        message="Brand new failure hitting hourly cap",
    )
    assert await coord._async_process_event(ev_rate) == "rate_limited"

    # 6. PendingDraftRepairFlow interactive approval & dismissal
    draft_id = next(iter(coord.pending_drafts))
    flow = PendingDraftRepairFlow(
        f"draft_{draft_id}",
        {
            "kind": "draft",
            "draft_id": draft_id,
            "repo": "FaserF/ha-openwrt",
            "title": "T",
            "excerpt": "E",
        },
    )
    flow.hass = hass
    form = await flow.async_step_init()
    assert form["type"] == "form"
    done = await flow.async_step_init({"action": "dismiss"})
    assert done["type"] == "create_entry"

    # Persist and verify reload restores stats
    await coord.store.async_save()
    await coord.store.async_load()
    assert coord.stats.leak_guard_blocks == 1


async def test_addon_poller_error_state_fallback(hass) -> None:
    """Test async_poll_addon_logs synthesizes AddonStateError when container is in error state."""
    target = TargetInfo(
        target_key="addon:edfe50eb_entramirror",
        kind="addon",
        identifier="edfe50eb_entramirror",
        short_name="entramirror",
        name="EntraMirror",
        version="0.1.2-dev0",
        repo_owner="FaserF",
        repo_name="hassio-addons",
        repo_url="https://github.com/FaserF/hassio-addons",
        enabled=True,
    )
    seen: dict[str, deque[str]] = {}

    class _DummyHassio:
        async def send_command(self, endpoint: str, **kwargs):
            return ""

    hass.data["hassio"] = _DummyHassio()
    with patch(
        "custom_components.issue_reporter.log_monitor.is_hassio", return_value=True
    ):
        events = await async_poll_addon_logs(
            hass,
            {target.target_key: target},
            seen,
            lambda _: logging.ERROR,
            addon_states={"edfe50eb_entramirror": "error"},
        )
    assert len(events) == 1
    assert events[0].exception_type == "AddonStateError"


async def test_device_flow_and_remaining_options_steps(hass) -> None:
    """Test OAuth Device Flow config step and remaining OptionsFlow steps."""
    res = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )
    res_df = await hass.config_entries.flow.async_configure(
        res["flow_id"], {CONF_AUTH_METHOD: AUTH_DEVICE_FLOW}
    )
    assert res_df["step_id"] == "auth_device_flow"

    with (
        patch(
            "custom_components.issue_reporter.config_flow.async_request_device_code",
            return_value={
                "device_code": "dc1",
                "user_code": "ABCD-EFGH",
                "verification_uri": "https://github.com/login/device",
                "interval": 1,
            },
        ),
        patch(
            "custom_components.issue_reporter.config_flow.async_poll_device_token",
            return_value="gho_oauth_tok",
        ),
        patch(
            "custom_components.issue_reporter.config_flow.async_validate_pat",
            return_value={"login": "FaserF", "scopes": ["public_repo"]},
        ),
    ):
        res_wait = await hass.config_entries.flow.async_configure(
            res_df["flow_id"], {CONF_OAUTH_CLIENT_ID: "client_123"}
        )
        await hass.async_block_till_done()
        if res_wait["type"] is FlowResultType.SHOW_PROGRESS:
            res_wait = await hass.config_entries.flow.async_configure(
                res_wait["flow_id"]
            )
    assert res_wait["step_id"] == "scope"

    entry = MockConfigEntry(
        domain=DOMAIN,
        unique_id=DOMAIN,
        data={
            CONF_AUTH_METHOD: AUTH_PAT,
            CONF_GITHUB_TOKEN: "ghp_x",
            CONF_GITHUB_USER: "FaserF",
        },
        options={CONF_OWNER_FILTER_MODE: OWNER_FILTER_SELF, CONF_DRY_RUN: True},
    )
    entry.add_to_hass(hass)
    entry.runtime_data = type(
        "Dummy",
        (),
        {
            "targets": {
                "addon:edfe50eb_dbf": TargetInfo(
                    target_key="addon:edfe50eb_dbf",
                    kind="addon",
                    identifier="edfe50eb_dbf",
                    short_name="dbf",
                    name="DBF",
                    version="1.1.12",
                    repo_owner="FaserF",
                    repo_name="hassio-addons",
                    repo_url="https://github.com/FaserF/hassio-addons",
                    enabled=True,
                )
            }
        },
    )()

    # General step
    o1 = await hass.config_entries.options.async_init(entry.entry_id)
    g1 = await hass.config_entries.options.async_configure(
        o1["flow_id"], {"next_step_id": "general"}
    )
    g_done = await hass.config_entries.options.async_configure(
        g1["flow_id"],
        {
            CONF_OWNER_FILTER_MODE: OWNER_FILTER_SELF,
            "owner_allowlist": "FaserF",
            CONF_DRY_RUN: False,
            "min_severity": "ERROR",
            "min_occurrences_error": 1,
            "min_occurrences_warning": 3,
            "occurrence_window_minutes": 15,
            "cooldown_hours": 24,
            "max_issues_per_hour": 5,
            "max_issues_per_repo_day": 2,
            "skip_outdated": True,
            "allow_dev_edge": True,
            "comment_on_newer_version": True,
            "addon_poll_minutes": 10,
            "include_core_addons": False,
        },
    )
    assert g_done["type"] is FlowResultType.CREATE_ENTRY

    # Redaction step
    o2 = await hass.config_entries.options.async_init(entry.entry_id)
    r1 = await hass.config_entries.options.async_configure(
        o2["flow_id"], {"next_step_id": "redaction"}
    )
    r_done = await hass.config_entries.options.async_configure(
        r1["flow_id"],
        {
            "custom_redactions": "myhome.example",
            "custom_redaction_regexes": r"ID-\d+",
            "strict_entropy_guard": True,
        },
    )
    assert r_done["type"] is FlowResultType.CREATE_ENTRY

    # Auth rotation step
    o3 = await hass.config_entries.options.async_init(entry.entry_id)
    a1 = await hass.config_entries.options.async_configure(
        o3["flow_id"], {"next_step_id": "auth"}
    )
    with patch(
        "custom_components.issue_reporter.options_flow.async_validate_pat",
        return_value={"login": "FaserF", "scopes": ["public_repo"]},
    ):
        a_done = await hass.config_entries.options.async_configure(
            a1["flow_id"], {CONF_GITHUB_TOKEN: "ghp_rotated", "fallback_token": ""}
        )
    assert a_done["type"] is FlowResultType.CREATE_ENTRY
