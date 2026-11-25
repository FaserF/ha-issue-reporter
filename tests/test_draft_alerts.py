"""Tests for configurable repair and interactive notification draft alerts."""

from __future__ import annotations

import logging
from unittest.mock import AsyncMock, patch

from aiohttp.test_utils import make_mocked_request
from homeassistant.components import persistent_notification
from homeassistant.helpers import issue_registry as ir
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.issue_reporter.const import (
    AUTH_PAT,
    CONF_AUTH_METHOD,
    CONF_DRAFT_NOTIFICATION_MODE,
    CONF_DRAFT_NOTIFY_SERVICE,
    CONF_DRY_RUN,
    CONF_GITHUB_TOKEN,
    CONF_GITHUB_USER,
    CONF_MIN_SEVERITY,
    CONF_OWNER_FILTER_MODE,
    CONF_REQUIRE_APPROVAL,
    DOMAIN,
    DRAFT_ACTION_URL_PATH,
    DRAFT_ALERT_NOTIFICATION,
    DRAFT_ALERT_REPAIR,
    MOBILE_ACTION_APPROVE_PREFIX,
    MOBILE_ACTION_DISMISS_PREFIX,
    OWNER_FILTER_SELF,
)
from custom_components.issue_reporter.models import LogEvent
from custom_components.issue_reporter.notifications import (
    DraftActionView,
    draft_notification_id,
)


async def _setup_entry(
    hass,
    mock_custom_components,
    mock_supervisor_client,
    *,
    alert_mode: str | None = None,
    notify_service: str = "",
) -> MockConfigEntry:
    options: dict[str, object] = {
        CONF_OWNER_FILTER_MODE: OWNER_FILTER_SELF,
        CONF_DRY_RUN: False,
        CONF_REQUIRE_APPROVAL: True,
        CONF_MIN_SEVERITY: "ERROR",
    }
    if alert_mode is not None:
        options[CONF_DRAFT_NOTIFICATION_MODE] = alert_mode
    if notify_service:
        options[CONF_DRAFT_NOTIFY_SERVICE] = notify_service

    entry = MockConfigEntry(
        domain=DOMAIN,
        unique_id=DOMAIN,
        data={
            CONF_AUTH_METHOD: AUTH_PAT,
            CONF_GITHUB_TOKEN: "ghp_test_token",
            CONF_GITHUB_USER: "FaserF",
        },
        options=options,
    )
    entry.add_to_hass(hass)
    with (
        patch(
            "custom_components.issue_reporter.discovery.async_get_custom_components",
            return_value=mock_custom_components,
        ),
        patch(
            "custom_components.issue_reporter.discovery.is_hassio",
            return_value=False,
        ),
        patch(
            "custom_components.issue_reporter.redactor.is_hassio",
            return_value=False,
        ),
        patch(
            "custom_components.issue_reporter.coordinator.is_hassio",
            return_value=False,
        ),
        patch(
            "custom_components.issue_reporter.log_monitor.async_fetch_core_logs",
            return_value=[],
        ),
        patch(
            "custom_components.issue_reporter.auth.async_validate_pat",
            return_value={"login": "FaserF", "scopes": ["public_repo"]},
        ),
    ):
        assert await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()

    coord = entry.runtime_data
    coord.github.async_get_latest_release = AsyncMock(return_value="v2.5.7")
    coord.github.async_get_repo_issues = AsyncMock(return_value=([], False))
    coord.github.async_search_issues = AsyncMock(return_value=[])
    coord.github.async_fetch_bug_templates = AsyncMock(return_value=[])
    coord.github.async_create_issue = AsyncMock(
        return_value={
            "number": 99,
            "html_url": "https://github.com/FaserF/ha-openwrt/issues/99",
        }
    )
    return entry


def _make_event(msg: str) -> LogEvent:
    return LogEvent(
        target_key="integration:openwrt",
        kind="integration",
        logger_name="custom_components.openwrt",
        severity="ERROR",
        levelno=logging.ERROR,
        message=msg,
        exception_type="RuntimeError",
    )


async def test_default_alert_mode_raises_repair_and_clears_on_approve(
    hass, mock_custom_components, mock_supervisor_client
) -> None:
    """Default mode raises one HA Repair per draft and removes it on approval."""
    entry = await _setup_entry(hass, mock_custom_components, mock_supervisor_client)
    coord = entry.runtime_data
    assert (
        coord.config.get(CONF_DRAFT_NOTIFICATION_MODE, DRAFT_ALERT_REPAIR)
        == DRAFT_ALERT_REPAIR
    )

    assert (
        await coord._async_process_event(_make_event("Failure one"))
        == "approval_queued"
    )
    assert (
        await coord._async_process_event(_make_event("Failure two"))
        == "approval_queued"
    )
    assert len(coord.pending_drafts) == 2

    reg = ir.async_get(hass)
    draft_ids = list(coord.pending_drafts.keys())
    for did in draft_ids:
        assert reg.async_get_issue(DOMAIN, f"draft_{did}") is not None
        assert draft_notification_id(did) not in hass.data.get(
            persistent_notification.DOMAIN, {}
        )

    await coord.async_approve_draft(draft_ids[0])
    assert reg.async_get_issue(DOMAIN, f"draft_{draft_ids[0]}") is None
    assert reg.async_get_issue(DOMAIN, f"draft_{draft_ids[1]}") is not None

    await coord.async_dismiss_draft(draft_ids[1])
    assert reg.async_get_issue(DOMAIN, f"draft_{draft_ids[1]}") is None


async def test_notification_mode_per_draft_interactive_approve_and_dismiss(
    hass, mock_custom_components, mock_supervisor_client
) -> None:
    """Notification mode creates per-draft notifications and deletes them on approve/dismiss."""
    entry = await _setup_entry(
        hass,
        mock_custom_components,
        mock_supervisor_client,
        alert_mode=DRAFT_ALERT_NOTIFICATION,
    )
    coord = entry.runtime_data
    reg = ir.async_get(hass)

    with (
        patch(
            "custom_components.issue_reporter.notifications.persistent_notification.async_create"
        ) as create_mock,
        patch(
            "custom_components.issue_reporter.notifications.persistent_notification.async_dismiss"
        ) as dismiss_mock,
    ):
        assert (
            await coord._async_process_event(_make_event("First notification bug"))
            == "approval_queued"
        )
        assert (
            await coord._async_process_event(_make_event("Second notification bug"))
            == "approval_queued"
        )
        draft_ids = list(coord.pending_drafts.keys())
        assert len(draft_ids) == 2
        assert create_mock.call_count == 2
        created_ids = [
            call.kwargs["notification_id"] for call in create_mock.call_args_list
        ]
        assert created_ids == [draft_notification_id(d) for d in draft_ids]

        # No repairs created when configured for notifications
        for did in draft_ids:
            assert reg.async_get_issue(DOMAIN, f"draft_{did}") is None

        # Interactive DraftActionView validation & POST approve/dismiss
        view = DraftActionView()
        d1 = coord.pending_drafts[draft_ids[0]]
        bad_req = make_mocked_request(
            "GET",
            f"{DRAFT_ACTION_URL_PATH}?draft_id={d1.draft_id}&token=wrong",
        )
        bad_req.app["hass"] = hass  # type: ignore[index]
        bad_resp = await view.get(bad_req)
        assert bad_resp.status == 403

        get_req = make_mocked_request(
            "GET",
            f"{DRAFT_ACTION_URL_PATH}?draft_id={d1.draft_id}&token={d1.action_token}&decision=approve",
        )
        get_req.app["hass"] = hass  # type: ignore[index]
        get_resp = await view.get(get_req)
        assert get_resp.status == 200
        assert d1.title in get_resp.text

        post_approve = make_mocked_request(
            "POST",
            f"{DRAFT_ACTION_URL_PATH}?draft_id={d1.draft_id}&token={d1.action_token}&decision=approve",
        )
        post_approve.app["hass"] = hass  # type: ignore[index]
        post_approve.post = AsyncMock(  # type: ignore[method-assign]
            return_value={
                "draft_id": d1.draft_id,
                "token": d1.action_token,
                "decision": "approve",
            }
        )
        resp_approve = await view.post(post_approve)
        assert resp_approve.status == 200
        assert d1.draft_id not in coord.pending_drafts
        assert coord.stats.issues_created == 1
        dismiss_mock.assert_any_call(hass, draft_notification_id(d1.draft_id))

        # Dismiss second draft interactively
        d2 = coord.pending_drafts[draft_ids[1]]
        post_dismiss = make_mocked_request("POST", DRAFT_ACTION_URL_PATH)
        post_dismiss.app["hass"] = hass  # type: ignore[index]
        post_dismiss.post = AsyncMock(  # type: ignore[method-assign]
            return_value={
                "draft_id": d2.draft_id,
                "token": d2.action_token,
                "decision": "dismiss",
            }
        )
        resp_dismiss = await view.post(post_dismiss)
        assert resp_dismiss.status == 200
        assert len(coord.pending_drafts) == 0
        dismiss_mock.assert_any_call(hass, draft_notification_id(d2.draft_id))


async def test_mobile_push_actions_and_auto_clear(
    hass, mock_custom_components, mock_supervisor_client
) -> None:
    """Optional notify service sends actionable push buttons and clears tag on action."""
    notify_calls: list[dict[str, object]] = []

    async def _fake_notify(call) -> None:
        notify_calls.append(dict(call.data))

    hass.services.async_register("notify", "mobile_app_phone", _fake_notify)
    entry = await _setup_entry(
        hass,
        mock_custom_components,
        mock_supervisor_client,
        alert_mode=DRAFT_ALERT_NOTIFICATION,
        notify_service="notify.mobile_app_phone",
    )
    coord = entry.runtime_data

    assert (
        await coord._async_process_event(_make_event("Mobile action bug 1"))
        == "approval_queued"
    )
    assert (
        await coord._async_process_event(_make_event("Mobile action bug 2"))
        == "approval_queued"
    )
    await hass.async_block_till_done()
    assert len(notify_calls) == 2

    d1_id, d2_id = list(coord.pending_drafts.keys())
    hass.bus.async_fire(
        "mobile_app_notification_action",
        {"action": f"{MOBILE_ACTION_APPROVE_PREFIX}{d1_id}"},
    )
    await hass.async_block_till_done()
    assert d1_id not in coord.pending_drafts
    assert coord.stats.issues_created == 1
    assert any(
        c.get("message") == "clear_notification"
        and (c.get("data") or {}).get("tag") == draft_notification_id(d1_id)
        for c in notify_calls
    )

    hass.bus.async_fire(
        "mobile_app_notification_action",
        {"action": f"{MOBILE_ACTION_DISMISS_PREFIX}{d2_id}"},
    )
    await hass.async_block_till_done()
    assert d2_id not in coord.pending_drafts
    assert any(
        c.get("message") == "clear_notification"
        and (c.get("data") or {}).get("tag") == draft_notification_id(d2_id)
        for c in notify_calls
    )


async def test_sync_draft_alerts_switches_between_repair_and_notification(
    hass, mock_custom_components, mock_supervisor_client
) -> None:
    """Switching alert mode reconciles alerts for existing approval drafts cleanly."""
    entry = await _setup_entry(
        hass,
        mock_custom_components,
        mock_supervisor_client,
        alert_mode=DRAFT_ALERT_REPAIR,
    )
    coord = entry.runtime_data
    reg = ir.async_get(hass)

    assert (
        await coord._async_process_event(_make_event("Switch mode error"))
        == "approval_queued"
    )
    did = next(iter(coord.pending_drafts))
    assert reg.async_get_issue(DOMAIN, f"draft_{did}") is not None

    with patch(
        "custom_components.issue_reporter.notifications.persistent_notification.async_create"
    ) as create_mock:
        coord.config[CONF_DRAFT_NOTIFICATION_MODE] = DRAFT_ALERT_NOTIFICATION
        await coord._async_sync_draft_alerts()
        assert reg.async_get_issue(DOMAIN, f"draft_{did}") is None
        create_mock.assert_called_once()
        assert create_mock.call_args.kwargs["notification_id"] == draft_notification_id(
            did
        )

    with patch(
        "custom_components.issue_reporter.notifications.persistent_notification.async_dismiss"
    ) as dismiss_mock:
        coord.config[CONF_DRAFT_NOTIFICATION_MODE] = DRAFT_ALERT_REPAIR
        await coord._async_sync_draft_alerts()
        assert reg.async_get_issue(DOMAIN, f"draft_{did}") is not None
        dismiss_mock.assert_called_once_with(hass, draft_notification_id(did))
