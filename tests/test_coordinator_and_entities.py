"""End-to-end tests for coordinator pipeline, sensors, services, repairs, diagnostics, and system health."""

from __future__ import annotations

import logging
from unittest.mock import AsyncMock, patch

from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.issue_reporter.const import (
    AUTH_PAT,
    CONF_AUTH_METHOD,
    CONF_CUSTOM_REDACTIONS,
    CONF_DRY_RUN,
    CONF_GITHUB_TOKEN,
    CONF_GITHUB_USER,
    CONF_OWNER_FILTER_MODE,
    DOMAIN,
    MODE_APPROVAL,
    OWNER_FILTER_SELF,
    SERVICE_APPROVE_DRAFT,
    SERVICE_CLEAR_COOLDOWNS,
    SERVICE_DISMISS_DRAFT,
    SERVICE_PREVIEW_DRAFT,
    SERVICE_SCAN_NOW,
    SERVICE_TEST_REDACTION,
)
from custom_components.issue_reporter.diagnostics import (
    async_get_config_entry_diagnostics,
)
from custom_components.issue_reporter.models import LogEvent
from custom_components.issue_reporter.repairs import async_create_fix_flow
from custom_components.issue_reporter.system_health import async_system_health_info

from .conftest import REPO_TEMPLATE_BUG_YML


async def _setup_integration(
    hass,
    mock_custom_components,
    mock_supervisor_client,
    *,
    dry_run: bool = False,
) -> MockConfigEntry:
    entry = MockConfigEntry(
        domain=DOMAIN,
        unique_id=DOMAIN,
        title="Issue Reporter (FaserF)",
        data={
            CONF_AUTH_METHOD: AUTH_PAT,
            CONF_GITHUB_TOKEN: "ghp_super_secret_token_value",
            CONF_GITHUB_USER: "FaserF",
        },
        options={
            CONF_OWNER_FILTER_MODE: OWNER_FILTER_SELF,
            CONF_DRY_RUN: dry_run,
            CONF_CUSTOM_REDACTIONS: ["private.example"],
        },
    )
    entry.add_to_hass(hass)

    with (
        patch(
            "custom_components.issue_reporter.auth.async_validate_pat",
            return_value={"login": "FaserF", "scopes": ["public_repo"]},
        ),
        patch(
            "custom_components.issue_reporter.discovery.async_get_custom_components",
            return_value=mock_custom_components,
        ),
        patch(
            "custom_components.issue_reporter.discovery.is_hassio", return_value=True
        ),
        patch(
            "custom_components.issue_reporter.discovery.get_supervisor_client",
            return_value=mock_supervisor_client,
        ),
        patch("custom_components.issue_reporter.redactor.is_hassio", return_value=True),
        patch(
            "custom_components.issue_reporter.redactor.get_supervisor_client",
            return_value=mock_supervisor_client,
        ),
        patch(
            "custom_components.issue_reporter.coordinator.is_hassio", return_value=True
        ),
        patch(
            "custom_components.issue_reporter.coordinator.get_supervisor_client",
            return_value=mock_supervisor_client,
        ),
        patch(
            "custom_components.issue_reporter.log_monitor.async_fetch_core_logs",
            return_value=[],
        ),
        patch(
            "custom_components.issue_reporter.log_monitor.async_poll_addon_logs",
            return_value=[],
        ),
        patch(
            "custom_components.issue_reporter.github_client.GitHubClient.async_get_repo_info",
            return_value={"has_issues": True, "archived": False},
        ),
    ):
        assert await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()

    return entry


async def test_full_pipeline_sensors_services_diagnostics_and_health(
    hass,
    mock_custom_components,
    mock_supervisor_client,
) -> None:
    """Verify full coordinator lifecycle, sensors, services, diagnostics, and repairs."""
    entry = await _setup_integration(
        hass, mock_custom_components, mock_supervisor_client, dry_run=False
    )
    coord = entry.runtime_data

    # Check minimal 6 sensors (no per-target clutter!)
    sensor_states = [
        s.entity_id
        for s in hass.states.async_all("sensor")
        if "issue_reporter" in s.entity_id
    ]
    assert len(sensor_states) == 5  # 6th (github_api_remaining) is disabled_by_default!
    monitored = hass.states.get("sensor.issue_reporter_monitored_targets")
    assert monitored is not None
    # FaserF integrations (openwrt, aegisbot) + FaserF add-ons (entramirror, dbf) = 4
    assert int(monitored.state) == 4

    # 1. Test redaction service
    red_resp = await hass.services.async_call(
        DOMAIN,
        SERVICE_TEST_REDACTION,
        {"text": "Call private.example failed with SuperSecretClient123!"},
        blocking=True,
        return_response=True,
    )
    assert "private.example" not in red_resp["redacted_text"]
    assert "SuperSecretClient123!" not in red_resp["redacted_text"]
    assert red_resp["leak_guard_passed"] is True

    # 2. Mock GitHub client for preview & auto-create pipeline
    coord.github.async_get_latest_release = AsyncMock(return_value="v2.5.7")
    coord.github.async_search_issues = AsyncMock(return_value=[])
    coord.github.async_fetch_bug_templates = AsyncMock(
        return_value=[
            {
                "name": "bug_report.yml",
                "path": ".github/ISSUE_TEMPLATE/bug_report.yml",
                "content": REPO_TEMPLATE_BUG_YML,
            }
        ]
    )
    coord.github.async_create_issue = AsyncMock(
        return_value={
            "number": 101,
            "html_url": "https://github.com/FaserF/ha-openwrt/issues/101",
        }
    )

    prev = await hass.services.async_call(
        DOMAIN,
        SERVICE_PREVIEW_DRAFT,
        {
            "target_key": "integration:openwrt",
            "sample_message": "Crash on node1.tailnet.example.invalid",
            "severity": "ERROR",
        },
        blocking=True,
        return_response=True,
    )
    assert prev["repo"] == "FaserF/ha-openwrt"
    assert prev["leak_guard_passed"] is True
    assert "node1.tailnet.example.invalid" not in prev["body"]

    # 3. Process an auto-create event directly
    ev = LogEvent(
        target_key="integration:openwrt",
        kind="integration",
        logger_name="custom_components.openwrt.sensor",
        severity="ERROR",
        levelno=logging.ERROR,
        message="Unhandled KeyError on node1.tailnet.example.invalid",
        exception_type="KeyError",
    )
    outcome = await coord._async_process_event(ev)
    assert outcome == "created"
    assert coord.stats.issues_created == 1

    # Re-processing same error immediately hits cooldown
    assert await coord._async_process_event(ev) == "cooldown"

    # 4. Approval Queue + Repair flow + approve_draft / dismiss_draft
    coord.targets["integration:aegisbot"].mode = MODE_APPROVAL
    coord.github.async_get_latest_release = AsyncMock(return_value="v1.0.3")
    ev2 = LogEvent(
        target_key="integration:aegisbot",
        kind="integration",
        logger_name="custom_components.aegisbot",
        severity="ERROR",
        levelno=logging.ERROR,
        message="Unique bug in aegisbot",
        exception_type="RuntimeError",
    )
    assert await coord._async_process_event(ev2) == "approval_queued"
    assert len(coord.pending_drafts) == 1
    draft_id = next(iter(coord.pending_drafts))

    # Repair fix flow works cleanly
    fix_flow = await async_create_fix_flow(
        hass, f"draft_{draft_id}", {"kind": "draft", "draft_id": draft_id}
    )
    assert fix_flow is not None

    await hass.services.async_call(
        DOMAIN, SERVICE_APPROVE_DRAFT, {"draft_id": draft_id}, blocking=True
    )
    assert len(coord.pending_drafts) == 0
    assert coord.stats.issues_created == 2

    # 5. Dismiss draft and clear cooldowns services
    ev3 = LogEvent(
        target_key="integration:aegisbot",
        kind="integration",
        logger_name="custom_components.aegisbot",
        severity="ERROR",
        levelno=logging.ERROR,
        message="Second unique bug",
        exception_type="TypeError",
    )
    assert await coord._async_process_event(ev3) == "approval_queued"
    d2_id = next(iter(coord.pending_drafts))
    await hass.services.async_call(
        DOMAIN, SERVICE_DISMISS_DRAFT, {"draft_id": d2_id}, blocking=True
    )
    assert len(coord.pending_drafts) == 0
    await hass.services.async_call(DOMAIN, SERVICE_CLEAR_COOLDOWNS, {}, blocking=True)

    # 6. Diagnostics MUST redact stored token, System Health returns operational info
    diag = await async_get_config_entry_diagnostics(hass, entry)
    assert "ghp_super_secret_token_value" not in str(diag)
    health = await async_system_health_info(hass)
    assert health["monitored_integrations"] == 2
    assert health["monitored_addons"] == 2
    assert health["issues_created"] == 2

    # 7. Clean unload detaches log handler
    with patch(
        "custom_components.issue_reporter.discovery.is_hassio", return_value=False
    ):
        await hass.services.async_call(DOMAIN, SERVICE_SCAN_NOW, {}, blocking=True)
    assert await hass.config_entries.async_unload(entry.entry_id)
