"""Minimal diagnostic & operational sensors for Issue Reporter."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from homeassistant.components.sensor import (
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceEntryType, DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import IssueReporterConfigEntry
from .const import (
    CONF_DRY_RUN,
    CONF_OWNER_FILTER_MODE,
    DEFAULT_DRY_RUN,
    DOMAIN,
    OWNER_FILTER_SELF,
)
from .coordinator import IssueReporterCoordinator

PARALLEL_UPDATES = 0


@dataclass(frozen=True, kw_only=True)
class ReporterSensorDescription(SensorEntityDescription):
    """Describes an Issue Reporter status sensor."""

    value_fn: Callable[[IssueReporterCoordinator], int | None]
    attrs_fn: Callable[[IssueReporterCoordinator], dict[str, Any]] | None = None


def _monitored_attrs(coord: IssueReporterCoordinator) -> dict[str, Any]:
    data = coord.data or {}
    return {
        "integrations_enabled": data.get("integrations_enabled", 0),
        "integrations_total": data.get("integrations_total", 0),
        "addons_enabled": data.get("addons_enabled", 0),
        "addons_total": data.get("addons_total", 0),
        "dry_run": bool(coord.config.get(CONF_DRY_RUN, DEFAULT_DRY_RUN)),
        "owner_filter_mode": coord.config.get(
            CONF_OWNER_FILTER_MODE, OWNER_FILTER_SELF
        ),
        "auth_actor": coord.auth.get_actor_label(),
    }


def _drafts_attrs(coord: IssueReporterCoordinator) -> dict[str, Any]:
    return {
        "drafts": [
            {
                "draft_id": d.draft_id,
                "target": d.target_key,
                "repo": d.repo,
                "title": d.title,
                "severity": d.severity,
                "dry_run_only": d.dry_run_only,
            }
            for d in list(coord.pending_drafts.values())[:20]
        ]
    }


def _issues_attrs(coord: IssueReporterCoordinator) -> dict[str, Any]:
    return {
        "last_issue_url": coord.stats.last_issue_url,
        "comments_posted": coord.stats.comments_posted,
        "last_scan_at": coord.stats.last_scan_at,
    }


def _suppressed_attrs(coord: IssueReporterCoordinator) -> dict[str, Any]:
    return {
        "duplicates": coord.stats.duplicates_suppressed,
        "outdated": coord.stats.outdated_suppressed,
        "filtered_local": coord.stats.filtered_local,
        "rate_limited": coord.stats.rate_limited_suppressed,
    }


SENSORS: tuple[ReporterSensorDescription, ...] = (
    ReporterSensorDescription(
        key="monitored_targets",
        translation_key="monitored_targets",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda c: sum(1 for t in c.targets.values() if t.enabled),
        attrs_fn=_monitored_attrs,
    ),
    ReporterSensorDescription(
        key="pending_drafts",
        translation_key="pending_drafts",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda c: len(c.pending_drafts),
        attrs_fn=_drafts_attrs,
    ),
    ReporterSensorDescription(
        key="issues_created",
        translation_key="issues_created",
        state_class=SensorStateClass.TOTAL_INCREASING,
        value_fn=lambda c: c.stats.issues_created,
        attrs_fn=_issues_attrs,
    ),
    ReporterSensorDescription(
        key="duplicates_suppressed",
        translation_key="duplicates_suppressed",
        state_class=SensorStateClass.TOTAL_INCREASING,
        value_fn=lambda c: (
            c.stats.duplicates_suppressed
            + c.stats.outdated_suppressed
            + c.stats.filtered_local
            + c.stats.rate_limited_suppressed
        ),
        attrs_fn=_suppressed_attrs,
    ),
    ReporterSensorDescription(
        key="leak_guard_blocks",
        translation_key="leak_guard_blocks",
        entity_category=EntityCategory.DIAGNOSTIC,
        state_class=SensorStateClass.TOTAL_INCREASING,
        value_fn=lambda c: c.stats.leak_guard_blocks,
    ),
    ReporterSensorDescription(
        key="github_api_remaining",
        translation_key="github_api_remaining",
        entity_category=EntityCategory.DIAGNOSTIC,
        state_class=SensorStateClass.MEASUREMENT,
        entity_registry_enabled_default=False,
        value_fn=lambda c: c.github.rate_limit_remaining,
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: IssueReporterConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up minimal Issue Reporter sensors for a config entry."""
    coordinator = entry.runtime_data
    async_add_entities(
        IssueReporterSensor(coordinator, entry, desc) for desc in SENSORS
    )


class IssueReporterSensor(CoordinatorEntity[IssueReporterCoordinator], SensorEntity):
    """Status or diagnostic sensor for Issue Reporter."""

    entity_description: ReporterSensorDescription
    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: IssueReporterCoordinator,
        entry: IssueReporterConfigEntry,
        description: ReporterSensorDescription,
    ) -> None:
        """Initialize the sensor."""
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

    @property
    def native_value(self) -> int | None:
        """Return current sensor value."""
        return self.entity_description.value_fn(self.coordinator)

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        """Return optional summary attributes."""
        if self.entity_description.attrs_fn is None:
            return None
        return self.entity_description.attrs_fn(self.coordinator)
