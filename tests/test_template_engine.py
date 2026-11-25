"""Tests for GitHub Issue Template / Form parsing and variable mapping."""

from __future__ import annotations

import logging
from unittest.mock import AsyncMock, MagicMock, patch

from homeassistant.const import __version__ as HA_VERSION

from custom_components.issue_reporter.models import LogEvent, TargetInfo
from custom_components.issue_reporter.template_engine import IssueTemplateEngine

from .conftest import HA_OPENWRT_BUG_YML, HASSIO_ADDONS_BUG_YML, REPO_TEMPLATE_BUG_YML


async def test_render_repo_template_form(hass) -> None:
    """Test filling FaserF/repo-template bug_report.yml form."""
    github = MagicMock()
    github.async_fetch_bug_templates = AsyncMock(
        return_value=[
            {
                "name": "bug_report.yml",
                "path": ".github/ISSUE_TEMPLATE/bug_report.yml",
                "content": REPO_TEMPLATE_BUG_YML,
            }
        ]
    )
    engine = IssueTemplateEngine(github)
    target = TargetInfo(
        target_key="integration:aegisbot",
        kind="integration",
        identifier="aegisbot",
        short_name="aegisbot",
        name="AegisBot",
        version="1.0.3-beta1",
        repo_owner="FaserF",
        repo_name="ha-aegisbot",
        repo_url="https://github.com/FaserF/ha-aegisbot",
        channel="beta",
    )
    ev = LogEvent(
        target_key="integration:aegisbot",
        kind="integration",
        logger_name="custom_components.aegisbot",
        severity="WARNING",
        levelno=logging.WARNING,
        message="Deprecated via_device call",
        exception_type="DeprecationWarning",
    )

    with patch(
        "custom_components.issue_reporter.template_engine.async_get_system_info",
        return_value={"hassio": True, "installation_type": "Home Assistant OS"},
    ):
        rendered = await engine.async_render_issue(
            hass,
            target,
            ev,
            sanitized_message="Deprecated via_device call",
            sanitized_traceback="",
            fingerprint="abcdef1234567890",
            occurrences=2,
            first_seen="2026-11-24T10:00:00Z",
            last_seen="2026-11-24T10:05:00Z",
        )

    assert rendered.repo == "FaserF/ha-aegisbot"
    assert rendered.title.startswith("[Bug]: DeprecationWarning:")
    assert "### Version / Release\n\n1.0.3-beta1" in rendered.body
    assert f"Home Assistant {HA_VERSION} (Home Assistant OS" in rendered.body
    assert "- [x] I am using a Beta or Pre-release version" in rendered.body
    assert "- [x] I have checked existing issues" in rendered.body
    assert "```shell\n[WARNING]" in rendered.body
    assert "ha-issue-reporter:fingerprint=abcdef1234567890" in rendered.body


async def test_render_hassio_addons_monorepo_form(hass) -> None:
    """Test hassio-addons template: version disambiguation and app_name dropdown."""
    github = MagicMock()
    github.async_fetch_bug_templates = AsyncMock(
        return_value=[
            {
                "name": "bug_report.yml",
                "path": ".github/ISSUE_TEMPLATE/bug_report.yml",
                "content": HASSIO_ADDONS_BUG_YML,
            }
        ]
    )
    engine = IssueTemplateEngine(github)
    target = TargetInfo(
        target_key="addon:edfe50eb_entramirror",
        kind="addon",
        identifier="edfe50eb_entramirror",
        short_name="entramirror",
        name="EntraMirror",
        version="0.1.2-dev-20261122-0127-2e80491",
        repo_owner="FaserF",
        repo_name="hassio-addons",
        repo_url="https://github.com/FaserF/hassio-addons",
        channel="edge",
        is_monorepo=True,
    )
    ev = LogEvent(
        target_key="addon:edfe50eb_entramirror",
        kind="addon",
        logger_name="addon.entramirror",
        severity="ERROR",
        levelno=logging.ERROR,
        message="Supervisor reports add-on is in error state",
        exception_type="AddonStateError",
    )

    with patch(
        "custom_components.issue_reporter.template_engine.async_get_system_info",
        return_value={"hassio": True, "installation_type": "Home Assistant OS"},
    ):
        rendered = await engine.async_render_issue(
            hass,
            target,
            ev,
            sanitized_message="Supervisor reports add-on is in error state",
            sanitized_traceback="Container exited with code 1",
            fingerprint="1122334455667788",
            occurrences=1,
            first_seen="2026-11-24T10:00:00Z",
            last_seen="2026-11-24T10:00:00Z",
        )

    assert rendered.title.startswith("[Bug]: [entramirror]")
    assert (
        f"### What version of Home Assistant Core has the issue?\n\n{HA_VERSION}"
        in rendered.body
    )
    assert (
        "### What version of the app has the issue?\n\n0.1.2-dev-20261122-0127-2e80491"
        in rendered.body
    )
    assert "### App causing the issue\n\nEntraMirror" in rendered.body
    assert (
        "### What type of installation are you running?\n\nHome Assistant OS"
        in rendered.body
    )
    assert "```txt\n" in rendered.body


async def test_render_openwrt_and_fallback_templates(hass) -> None:
    """Test ha-openwrt form and fallback when target repo has no templates."""
    github = MagicMock()
    github.async_fetch_bug_templates = AsyncMock(
        side_effect=[
            [
                {
                    "name": "bug_report.yml",
                    "path": ".github/ISSUE_TEMPLATE/bug_report.yml",
                    "content": HA_OPENWRT_BUG_YML,
                }
            ],
            [],
        ]
    )
    engine = IssueTemplateEngine(github)
    target = TargetInfo(
        target_key="integration:openwrt",
        kind="integration",
        identifier="openwrt",
        short_name="openwrt",
        name="OpenWrt",
        version="2.5.7",
        repo_owner="FaserF",
        repo_name="ha-openwrt",
        repo_url="https://github.com/FaserF/ha-openwrt",
    )
    ev = LogEvent(
        target_key="integration:openwrt",
        kind="integration",
        logger_name="custom_components.openwrt",
        severity="ERROR",
        levelno=logging.ERROR,
        message="Parsing error",
        exception_type="ValueError",
    )

    with patch(
        "custom_components.issue_reporter.template_engine.async_get_system_info",
        return_value={"hassio": False, "docker": True},
    ):
        r1 = await engine.async_render_issue(
            hass,
            target,
            ev,
            sanitized_message="Parsing error",
            sanitized_traceback="",
            fingerprint="aaaabbbbccccdddd",
            occurrences=1,
            first_seen="t1",
            last_seen="t1",
        )
        r2 = await engine.async_render_issue(
            hass,
            target,
            ev,
            sanitized_message="Parsing error",
            sanitized_traceback="",
            fingerprint="aaaabbbbccccdddd",
            occurrences=1,
            first_seen="t1",
            last_seen="t1",
            regression_of=12,
        )

    assert "### Home Assistant Installation Type\n\nHome Assistant Container" in r1.body
    assert "### OpenWrt Version\n\n_Not automatically detected" in r1.body
    assert "```yaml\n" in r1.body
    assert r2.template_used == "default"
    assert "Previously closed in #12" in r2.body


async def test_render_valetudo_and_openwrt_with_ha_context(hass) -> None:
    """Test auto-detection of Valetudo/OpenWrt versions, models, variants, and connection types."""
    from homeassistant.helpers import device_registry as dr
    from pytest_homeassistant_custom_component.common import MockConfigEntry

    valetudo_yml = """
title: "[Bug]: "
body:
  - type: input
    id: integration_version
    attributes:
      label: Integration Version
  - type: input
    id: valetudo_version
    attributes:
      label: Valetudo Version
  - type: input
    id: robot_model
    attributes:
      label: Robot Model / Brand
  - type: dropdown
    id: valetudo_variant
    attributes:
      label: Valetudo Variant
      options:
        - Valetudo
        - Valetudo RE
        - Other
  - type: dropdown
    id: connection_type
    attributes:
      label: Connection Type
      options:
        - MQTT
        - REST API
        - Other
  - type: textarea
    id: diagnostics
    attributes:
      label: Diagnostic Information
"""

    valetudo_entry = MockConfigEntry(
        domain="valetudo",
        data={"connection_type": "MQTT"},
        entry_id="valetudo_entry_1",
    )
    valetudo_entry.add_to_hass(hass)

    openwrt_entry = MockConfigEntry(
        domain="openwrt",
        data={"use_ubus": True},
        entry_id="openwrt_entry_1",
    )
    openwrt_entry.add_to_hass(hass)

    dev_reg = dr.async_get(hass)
    dev_reg.async_get_or_create(
        config_entry_id=valetudo_entry.entry_id,
        identifiers={("valetudo", "robot_1")},
        manufacturer="Roborock",
        model="S7 MaxV",
        sw_version="2025.02.0",
    )
    # Also test OpenWrt with noisy tracked sub-devices alongside the primary router
    dev_reg.async_get_or_create(
        config_entry_id=openwrt_entry.entry_id,
        identifiers={("openwrt", "radio_1")},
        manufacturer="OpenWrt",
        model="Wireless Radio",
    )
    dev_reg.async_get_or_create(
        config_entry_id=openwrt_entry.entry_id,
        identifiers={("openwrt", "router_1")},
        manufacturer="GL.iNet",
        model="GL-MT6000",
        sw_version="24.10.0",
        hw_version="glinet,gl-mt6000",
    )

    openwrt_yml = """
title: "[Bug]: "
body:
  - type: input
    id: integration_version
    attributes:
      label: Integration Version
  - type: input
    id: openwrt_version
    attributes:
      label: OpenWrt Version
  - type: input
    id: router_model
    attributes:
      label: Router Model
  - type: dropdown
    id: connection_method
    attributes:
      label: Connection Method
      options:
        - ubus
        - SSH
        - LuCI RPC
  - type: textarea
    id: diagnostics
    attributes:
      label: Diagnostics
"""

    github = MagicMock()
    github.async_fetch_bug_templates = AsyncMock(
        side_effect=[
            [
                {
                    "name": "bug_report.yml",
                    "path": ".github/ISSUE_TEMPLATE/bug_report.yml",
                    "content": valetudo_yml,
                }
            ],
            [
                {
                    "name": "bug_report.yml",
                    "path": ".github/ISSUE_TEMPLATE/bug_report.yml",
                    "content": openwrt_yml,
                }
            ],
        ]
    )
    engine = IssueTemplateEngine(github)

    val_target = TargetInfo(
        target_key="integration:valetudo",
        kind="integration",
        identifier="valetudo",
        short_name="valetudo",
        name="Valetudo",
        version="2.1.0",
        repo_owner="FaserF",
        repo_name="hass-valetudo",
        repo_url="https://github.com/FaserF/hass-valetudo",
    )
    val_ev = LogEvent(
        target_key="integration:valetudo",
        kind="integration",
        logger_name="custom_components.valetudo",
        severity="ERROR",
        levelno=logging.ERROR,
        message="Map parse error",
        exception_type="KeyError",
    )
    ow_target = TargetInfo(
        target_key="integration:openwrt",
        kind="integration",
        identifier="openwrt",
        short_name="openwrt",
        name="OpenWrt",
        version="3.0.0",
        repo_owner="FaserF",
        repo_name="ha-openwrt",
        repo_url="https://github.com/FaserF/ha-openwrt",
    )
    ow_ev = LogEvent(
        target_key="integration:openwrt",
        kind="integration",
        logger_name="custom_components.openwrt",
        severity="ERROR",
        levelno=logging.ERROR,
        message="Ubus timeout",
        exception_type="TimeoutError",
    )

    with patch(
        "custom_components.issue_reporter.template_engine.async_get_system_info",
        return_value={"hassio": True, "installation_type": "Home Assistant OS"},
    ):
        r_val = await engine.async_render_issue(
            hass,
            val_target,
            val_ev,
            sanitized_message="Map parse error",
            sanitized_traceback="",
            fingerprint="1111222233334444",
            occurrences=1,
            first_seen="t1",
            last_seen="t1",
        )
        r_ow = await engine.async_render_issue(
            hass,
            ow_target,
            ow_ev,
            sanitized_message="Ubus timeout",
            sanitized_traceback="",
            fingerprint="5555666677778888",
            occurrences=1,
            first_seen="t1",
            last_seen="t1",
        )

    assert "### Valetudo Version\n\n2025.02.0" in r_val.body
    assert "### Robot Model / Brand\n\nRoborock S7 MaxV" in r_val.body
    assert "### Valetudo Variant\n\nValetudo" in r_val.body
    assert "### Connection Type\n\nMQTT" in r_val.body
    assert "Detected Device / Model: `Roborock S7 MaxV`" in r_val.body

    assert "### OpenWrt Version\n\n24.10.0" in r_ow.body
    assert "### Router Model\n\nGL.iNet GL-MT6000" in r_ow.body
    assert "### Connection Method\n\nubus" in r_ow.body
    assert "### Diagnostics\n\n- Home Assistant Core:" in r_ow.body
    assert "Detected Device / Model: `GL.iNet GL-MT6000`" in r_ow.body
