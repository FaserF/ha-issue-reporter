"""System Health registration for Issue Reporter (Spook-inspired)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from homeassistant.core import callback
from homeassistant.loader import async_get_loaded_integration

from .const import (
    CONF_DRY_RUN,
    DEFAULT_DRY_RUN,
    DOMAIN,
    TARGET_ADDON,
    TARGET_INTEGRATION,
)

if TYPE_CHECKING:
    from homeassistant.components import system_health
    from homeassistant.core import HomeAssistant


@callback
def async_register(
    hass: HomeAssistant,
    register: system_health.SystemHealthRegistration,
) -> None:
    """Register Issue Reporter info under Home Assistant System Information."""
    register.async_register_info(
        async_system_health_info,
        "/config/integrations/integration/issue_reporter",
    )


async def async_system_health_info(hass: HomeAssistant) -> dict[str, Any]:
    """Return operational summary for Home Assistant System Health."""
    integration = async_get_loaded_integration(hass, DOMAIN)
    entries = hass.config_entries.async_entries(DOMAIN)
    coordinator = entries[0].runtime_data if entries else None

    if coordinator is None:
        return {
            "version": str(integration.version),
            "configured": False,
        }

    enabled_integrations = sum(
        1
        for t in coordinator.targets.values()
        if t.kind == TARGET_INTEGRATION and t.enabled
    )
    enabled_addons = sum(
        1 for t in coordinator.targets.values() if t.kind == TARGET_ADDON and t.enabled
    )
    dry_run = bool(coordinator.config.get(CONF_DRY_RUN, DEFAULT_DRY_RUN))

    return {
        "version": str(integration.version),
        "auth_actor": coordinator.auth.get_actor_label(),
        "dry_run_mode": dry_run,
        "monitored_integrations": enabled_integrations,
        "monitored_addons": enabled_addons,
        "pending_drafts": len(coordinator.pending_drafts),
        "issues_created": coordinator.stats.issues_created,
        "duplicates_suppressed": coordinator.stats.duplicates_suppressed,
        "leak_guard_blocks": coordinator.stats.leak_guard_blocks,
        "github_api_remaining": coordinator.github.rate_limit_remaining,
    }
