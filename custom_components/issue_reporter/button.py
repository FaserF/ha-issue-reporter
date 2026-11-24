"""Action buttons for Issue Reporter (draft approval, scan, cooldown reset)."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from homeassistant.components.button import ButtonEntity, ButtonEntityDescription
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceEntryType, DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import IssueReporterConfigEntry
from .const import DOMAIN
from .coordinator import IssueReporterCoordinator

PARALLEL_UPDATES = 0


@dataclass(frozen=True, kw_only=True)
class ReporterButtonDescription(ButtonEntityDescription):
    """Describes an Issue Reporter action button."""

    press_fn: Callable[[IssueReporterCoordinator], Awaitable[None]]


async def _approve_latest(coord: IssueReporterCoordinator) -> None:
    """Approve and publish the most recent pending non-dry-run draft."""
    for draft in reversed(list(coord.pending_drafts.values())):
        if not draft.dry_run_only:
            await coord.async_approve_draft(draft.draft_id)
            return


async def _approve_all(coord: IssueReporterCoordinator) -> None:
    """Approve and publish all pending non-dry-run drafts."""
    for draft in list(coord.pending_drafts.values()):
        if not draft.dry_run_only:
            await coord.async_approve_draft(draft.draft_id)


async def _scan_now(coord: IssueReporterCoordinator) -> None:
    """Refresh discovery and poll Supervisor add-ons immediately."""
    await coord.async_request_refresh()


async def _clear_cooldowns(coord: IssueReporterCoordinator) -> None:
    """Clear all local deduplication cooldowns."""
    await coord.async_clear_cooldowns()


BUTTONS: tuple[ReporterButtonDescription, ...] = (
    ReporterButtonDescription(
        key="approve_latest_draft",
        translation_key="approve_latest_draft",
        icon="mdi:check-circle-outline",
        press_fn=_approve_latest,
    ),
    ReporterButtonDescription(
        key="approve_all_drafts",
        translation_key="approve_all_drafts",
        icon="mdi:check-all",
        press_fn=_approve_all,
    ),
    ReporterButtonDescription(
        key="scan_now",
        translation_key="scan_now",
        entity_category=EntityCategory.CONFIG,
        icon="mdi:refresh",
        press_fn=_scan_now,
    ),
    ReporterButtonDescription(
        key="clear_cooldowns",
        translation_key="clear_cooldowns",
        entity_category=EntityCategory.CONFIG,
        icon="mdi:broom",
        press_fn=_clear_cooldowns,
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: IssueReporterConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Issue Reporter buttons for a config entry."""
    coordinator = entry.runtime_data
    async_add_entities(
        IssueReporterButton(coordinator, entry, desc) for desc in BUTTONS
    )


class IssueReporterButton(CoordinatorEntity[IssueReporterCoordinator], ButtonEntity):
    """Action button for Issue Reporter."""

    entity_description: ReporterButtonDescription
    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: IssueReporterCoordinator,
        entry: IssueReporterConfigEntry,
        description: ReporterButtonDescription,
    ) -> None:
        """Initialize the button."""
        super().__init__(coordinator)
        self.entity_description = description
        self._attr_unique_id = f"{entry.entry_id}_{description.key}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            name="Issue Reporter",
            manufacturer="FaserF",
            model="Log Monitor & GitHub Reporter",
            entry_type=DeviceEntryType.SERVICE,
        )

    async def async_press(self) -> None:
        """Execute the button action."""
        await self.entity_description.press_fn(self.coordinator)
