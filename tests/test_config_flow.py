"""Tests for ConfigFlow, ReauthFlow, and OptionsFlow."""

from __future__ import annotations

from unittest.mock import patch

from homeassistant import config_entries
from homeassistant.data_entry_flow import FlowResultType
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.issue_reporter.const import (
    AUTH_GITHUB_APP,
    AUTH_NONE,
    AUTH_PAT,
    CONF_APP_ID,
    CONF_AUTH_METHOD,
    CONF_CUSTOM_IGNORE_PATTERNS,
    CONF_CUSTOM_REDACTIONS,
    CONF_DRY_RUN,
    CONF_FALLBACK_AUTH_METHOD,
    CONF_GITHUB_TOKEN,
    CONF_GITHUB_USER,
    CONF_MIN_SEVERITY,
    CONF_OWNER_ALLOWLIST,
    CONF_OWNER_FILTER_MODE,
    CONF_PRIVATE_KEY,
    DOMAIN,
    MODE_APPROVAL,
    OWNER_FILTER_CUSTOM,
    OWNER_FILTER_SELF,
)
from custom_components.issue_reporter.models import TargetInfo


async def test_config_flow_pat_happy_path(hass) -> None:
    """Test PAT setup flow from user step through scope step."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "user"

    result2 = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_AUTH_METHOD: AUTH_PAT}
    )
    assert result2["step_id"] == "auth_pat"

    with patch(
        "custom_components.issue_reporter.config_flow.async_validate_pat",
        return_value={"login": "FaserF", "scopes": ["public_repo"]},
    ):
        result3 = await hass.config_entries.flow.async_configure(
            result2["flow_id"], {CONF_GITHUB_TOKEN: "ghp_test"}
        )
    assert result3["step_id"] == "scope"

    with patch("custom_components.issue_reporter.async_setup_entry", return_value=True):
        result4 = await hass.config_entries.flow.async_configure(
            result3["flow_id"],
            {
                CONF_OWNER_FILTER_MODE: OWNER_FILTER_SELF,
                CONF_OWNER_ALLOWLIST: "",
                CONF_MIN_SEVERITY: "ERROR",
                CONF_DRY_RUN: True,
                CONF_CUSTOM_REDACTIONS: "private.example",
            },
        )
    assert result4["type"] is FlowResultType.CREATE_ENTRY
    assert result4["title"] == "Issue Reporter (FaserF)"
    assert result4["options"][CONF_CUSTOM_REDACTIONS] == ["private.example"]


async def test_config_flow_github_app_and_reauth(hass) -> None:
    """Test GitHub App setup flow with fallback skip and reauth."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )
    res_app = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_AUTH_METHOD: AUTH_GITHUB_APP}
    )
    assert res_app["step_id"] == "auth_github_app"

    with patch(
        "custom_components.issue_reporter.config_flow.async_validate_github_app",
        return_value={
            "installation_id": "171483846",
            "account_login": "FaserF",
            "repository_selection": "all",
        },
    ):
        res_fb = await hass.config_entries.flow.async_configure(
            res_app["flow_id"],
            {
                CONF_APP_ID: "5320646",
                CONF_PRIVATE_KEY: "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----",
            },
        )
    assert res_fb["step_id"] == "fallback_auth"

    res_scope = await hass.config_entries.flow.async_configure(
        res_fb["flow_id"], {CONF_FALLBACK_AUTH_METHOD: AUTH_NONE}
    )
    assert res_scope["step_id"] == "scope"

    with patch("custom_components.issue_reporter.async_setup_entry", return_value=True):
        created = await hass.config_entries.flow.async_configure(
            res_scope["flow_id"],
            {
                CONF_OWNER_FILTER_MODE: OWNER_FILTER_CUSTOM,
                CONF_OWNER_ALLOWLIST: "FaserF",
                CONF_MIN_SEVERITY: "ERROR",
                CONF_DRY_RUN: False,
            },
        )
    assert created["type"] is FlowResultType.CREATE_ENTRY

    # Test reauth on PAT entry
    entry = MockConfigEntry(
        domain=DOMAIN,
        unique_id=DOMAIN,
        data={
            CONF_AUTH_METHOD: AUTH_PAT,
            CONF_GITHUB_TOKEN: "old",
            CONF_GITHUB_USER: "FaserF",
        },
    )
    entry.add_to_hass(hass)
    reauth = await entry.start_reauth_flow(hass)
    assert reauth["step_id"] == "reauth_confirm"
    with (
        patch(
            "custom_components.issue_reporter.config_flow.async_validate_pat",
            return_value={"login": "FaserF", "scopes": ["public_repo"]},
        ),
        patch("custom_components.issue_reporter.async_setup_entry", return_value=True),
    ):
        reauth_done = await hass.config_entries.flow.async_configure(
            reauth["flow_id"], {CONF_GITHUB_TOKEN: "ghp_new"}
        )
    assert reauth_done["type"] is FlowResultType.ABORT
    assert reauth_done["reason"] == "reauth_successful"


async def test_options_flow_menu_steps(hass) -> None:
    """Test OptionsFlow general, filters, redaction, and per-target edits."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        unique_id=DOMAIN,
        data={
            CONF_AUTH_METHOD: AUTH_PAT,
            CONF_GITHUB_TOKEN: "ghp_x",
            CONF_GITHUB_USER: "FaserF",
        },
        options={},
    )
    entry.add_to_hass(hass)
    entry.runtime_data = type(
        "DummyCoord",
        (),
        {
            "targets": {
                "integration:openwrt": TargetInfo(
                    target_key="integration:openwrt",
                    kind="integration",
                    identifier="openwrt",
                    short_name="openwrt",
                    name="OpenWrt",
                    version="2.5.7",
                    repo_owner="FaserF",
                    repo_name="ha-openwrt",
                    repo_url="https://github.com/FaserF/ha-openwrt",
                    enabled=True,
                )
            }
        },
    )()

    # Filters step
    opt1 = await hass.config_entries.options.async_init(entry.entry_id)
    assert opt1["type"] is FlowResultType.MENU
    f_step = await hass.config_entries.options.async_configure(
        opt1["flow_id"], {"next_step_id": "filters"}
    )
    f_done = await hass.config_entries.options.async_configure(
        f_step["flow_id"],
        {
            "ignore_network_errors": True,
            "ignore_auth_errors": True,
            "ignore_rate_limit_errors": True,
            "ignore_lifecycle_errors": True,
            CONF_CUSTOM_IGNORE_PATTERNS: "noise_line",
        },
    )
    assert f_done["type"] is FlowResultType.CREATE_ENTRY
    assert entry.options[CONF_CUSTOM_IGNORE_PATTERNS] == ["noise_line"]

    # Integrations target override step
    opt2 = await hass.config_entries.options.async_init(entry.entry_id)
    t_pick = await hass.config_entries.options.async_configure(
        opt2["flow_id"], {"next_step_id": "integrations"}
    )
    t_edit = await hass.config_entries.options.async_configure(
        t_pick["flow_id"], {"target_key": "integration:openwrt"}
    )
    assert t_edit["step_id"] == "edit_target"
    t_done = await hass.config_entries.options.async_configure(
        t_edit["flow_id"],
        {
            "enabled": False,
            "mode": MODE_APPROVAL,
            "min_severity": "CRITICAL",
            "repo_override": "FaserF/ha-openwrt",
            "ignore_patterns": "",
        },
    )
    assert t_done["type"] is FlowResultType.CREATE_ENTRY
    assert (
        entry.options["target_overrides"]["integration:openwrt"]["mode"]
        == MODE_APPROVAL
    )
