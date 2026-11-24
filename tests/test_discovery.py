"""Tests for dynamic integration & add-on discovery and owner policies."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

from custom_components.issue_reporter.const import (
    CONF_DRY_RUN,
    CONF_OWNER_ALLOWLIST,
    CONF_OWNER_FILTER_MODE,
    CONF_REQUIRE_APPROVAL,
    CONF_TARGET_OVERRIDES,
    MODE_APPROVAL,
    MODE_AUTO,
    MODE_DRY_RUN,
    OWNER_FILTER_CUSTOM,
    OWNER_FILTER_MANUAL,
    OWNER_FILTER_SELF,
)
from custom_components.issue_reporter.discovery import (
    apply_target_policies,
    async_discover_addons,
    async_discover_integrations,
    parse_github_repo,
    strip_addon_slug_prefix,
)


def test_parse_github_repo_and_slug_strip() -> None:
    """Test URL parsing and add-on slug prefix stripping."""
    assert parse_github_repo("https://github.com/FaserF/ha-openwrt/issues") == (
        "FaserF",
        "ha-openwrt",
    )
    assert parse_github_repo("https://github.com/FaserF/hassio-addons#edge") == (
        "FaserF",
        "hassio-addons",
    )
    assert parse_github_repo("https://github.com/hassio-addons/app-vscode.git") == (
        "hassio-addons",
        "app-vscode",
    )
    assert parse_github_repo("https://example.com/not-github") is None
    assert strip_addon_slug_prefix("edfe50eb_entramirror") == "entramirror"
    assert strip_addon_slug_prefix("605cee21_dbf") == "dbf"


async def test_discover_integrations_and_addons_separately(
    hass,
    mock_custom_components,
    mock_supervisor_client,
) -> None:
    """Test integrations map to integration repos and add-ons map strictly to add-on repos."""
    github = MagicMock()

    async def fake_repo_info(owner: str, repo: str):
        if f"{owner}/{repo}".lower() == "hassio-addons/repository":
            return {"has_issues": False}
        return {"has_issues": True}

    github.async_get_repo_info = AsyncMock(side_effect=fake_repo_info)

    with (
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
    ):
        integrations = await async_discover_integrations(hass)
        addons = await async_discover_addons(hass, github, include_core=False)

    # Integrations include issue_reporter itself for out-of-the-box self-reporting
    int_map = {t.target_key: t for t in integrations}
    assert "integration:issue_reporter" in int_map
    assert int_map["integration:issue_reporter"].full_repo == "FaserF/ha-issue-reporter"
    assert int_map["integration:openwrt"].full_repo == "FaserF/ha-openwrt"
    assert int_map["integration:localtuya"].full_repo == "xZetsubou/hass-localtuya"

    # Add-ons skip core_* and map FaserF add-ons strictly to hassio-addons (NOT ha-db_infoscreen!)
    add_map = {t.target_key: t for t in addons}
    assert "addon:core_mariadb" not in add_map
    assert add_map["addon:605cee21_dbf"].full_repo == "faserf/hassio-addons"
    assert add_map["addon:edfe50eb_entramirror"].full_repo == "FaserF/hassio-addons"
    assert add_map["addon:edfe50eb_entramirror"].channel == "edge"
    assert add_map["addon:edfe50eb_entramirror"].is_monorepo is True
    # Fallback when store repo hassio-addons/repository has has_issues=False
    assert add_map["addon:a0d7b954_vscode"].full_repo == "hassio-addons/app-vscode"


async def test_apply_target_policies_owner_filtering(
    hass,
    mock_custom_components,
    mock_supervisor_client,
) -> None:
    """Test self, custom, manual owner filtering and per-target overrides."""
    github = MagicMock()
    github.async_get_repo_info = AsyncMock(return_value={"has_issues": True})
    with (
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
    ):
        all_targets = await async_discover_integrations(
            hass
        ) + await async_discover_addons(hass, github)

    # Self mode with FaserF: enables only FaserF integrations & FaserF add-ons in auto mode
    res_self = apply_target_policies(
        all_targets,
        {CONF_OWNER_FILTER_MODE: OWNER_FILTER_SELF, CONF_DRY_RUN: False},
        authenticated_owner="FaserF",
    )
    assert res_self["integration:openwrt"].enabled is True
    assert res_self["integration:openwrt"].mode == MODE_AUTO
    assert res_self["addon:edfe50eb_entramirror"].enabled is True
    assert res_self["integration:localtuya"].enabled is False
    assert res_self["addon:a0d7b954_vscode"].enabled is False

    # Manual override enabling 3rd-party integration: mode is AUTO by default
    # (require_approval defaults to False; set True to get APPROVAL mode)
    res_override = apply_target_policies(
        all_targets,
        {
            CONF_OWNER_FILTER_MODE: OWNER_FILTER_CUSTOM,
            CONF_OWNER_ALLOWLIST: ["FaserF"],
            CONF_TARGET_OVERRIDES: {
                "integration:localtuya": {"enabled": True},
                "integration:openwrt": {"mode": MODE_DRY_RUN},
            },
        },
        authenticated_owner="FaserF",
    )
    assert res_override["integration:localtuya"].enabled is True
    assert res_override["integration:localtuya"].mode == MODE_AUTO
    assert res_override["integration:openwrt"].mode == MODE_DRY_RUN
    # With require_approval=True, all targets get APPROVAL mode
    res_approval = apply_target_policies(
        all_targets,
        {
            CONF_OWNER_FILTER_MODE: OWNER_FILTER_CUSTOM,
            CONF_OWNER_ALLOWLIST: ["FaserF"],
            CONF_REQUIRE_APPROVAL: True,
            CONF_TARGET_OVERRIDES: {"integration:localtuya": {"enabled": True}},
        },
        authenticated_owner="FaserF",
    )
    assert res_approval["integration:localtuya"].mode == MODE_APPROVAL

    # Manual mode starts everything disabled
    res_manual = apply_target_policies(
        all_targets,
        {CONF_OWNER_FILTER_MODE: OWNER_FILTER_MANUAL},
        authenticated_owner="FaserF",
    )
    assert all(not t.enabled for t in res_manual.values())
