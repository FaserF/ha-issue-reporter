"""The Issue Reporter helper integration."""

from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.typing import ConfigType

from .const import DOMAIN
from .coordinator import IssueReporterCoordinator
from .services import async_register_services

CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)
PLATFORMS: list[Platform] = [Platform.SENSOR]

type IssueReporterConfigEntry = ConfigEntry[IssueReporterCoordinator]


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Set up global Issue Reporter services."""
    async_register_services(hass)
    return True


async def async_setup_entry(
    hass: HomeAssistant, entry: IssueReporterConfigEntry
) -> bool:
    """Set up Issue Reporter from a config entry."""
    coordinator = IssueReporterCoordinator(hass, entry)
    await coordinator.async_setup()
    await coordinator.async_config_entry_first_refresh()

    entry.runtime_data = coordinator
    entry.async_on_unload(entry.add_update_listener(_async_reload_entry))

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(
    hass: HomeAssistant, entry: IssueReporterConfigEntry
) -> bool:
    """Unload Issue Reporter config entry and detach log handler."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    coordinator: IssueReporterCoordinator | None = getattr(entry, "runtime_data", None)
    if coordinator is not None:
        await coordinator.async_shutdown()
    return unload_ok


async def _async_reload_entry(
    hass: HomeAssistant, entry: IssueReporterConfigEntry
) -> None:
    """Reload config entry when options are updated."""
    await hass.config_entries.async_reload(entry.entry_id)
