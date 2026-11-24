"""Voluptuous schema builders for Issue Reporter options flow."""

from __future__ import annotations

from typing import Any

import voluptuous as vol
from homeassistant.helpers.selector import (
    SelectOptionDict,
    SelectSelector,
    SelectSelectorConfig,
    SelectSelectorMode,
    TextSelector,
    TextSelectorConfig,
)

from .const import (
    CONF_ADDON_POLL_MINUTES,
    CONF_ALLOW_DEV_EDGE,
    CONF_COMMENT_ON_NEWER_VERSION,
    CONF_COOLDOWN_HOURS,
    CONF_DRY_RUN,
    CONF_INCLUDE_CORE_ADDONS,
    CONF_MAX_ISSUES_PER_HOUR,
    CONF_MAX_ISSUES_PER_REPO_DAY,
    CONF_MIN_OCCURRENCES_ERROR,
    CONF_MIN_OCCURRENCES_WARNING,
    CONF_MIN_SEVERITY,
    CONF_OCCURRENCE_WINDOW_MINUTES,
    CONF_OWNER_ALLOWLIST,
    CONF_OWNER_FILTER_MODE,
    CONF_REQUIRE_APPROVAL,
    CONF_SKIP_OUTDATED,
    DEFAULT_ADDON_POLL_MINUTES,
    DEFAULT_ALLOW_DEV_EDGE,
    DEFAULT_COMMENT_ON_NEWER_VERSION,
    DEFAULT_COOLDOWN_HOURS,
    DEFAULT_DRY_RUN,
    DEFAULT_INCLUDE_CORE_ADDONS,
    DEFAULT_MAX_ISSUES_PER_HOUR,
    DEFAULT_MAX_ISSUES_PER_REPO_DAY,
    DEFAULT_MIN_OCCURRENCES_ERROR,
    DEFAULT_MIN_OCCURRENCES_WARNING,
    DEFAULT_MIN_SEVERITY,
    DEFAULT_OCCURRENCE_WINDOW_MINUTES,
    DEFAULT_REQUIRE_APPROVAL,
    DEFAULT_SKIP_OUTDATED,
    MODE_APPROVAL,
    MODE_AUTO,
    MODE_DRY_RUN,
    OWNER_FILTER_CUSTOM,
    OWNER_FILTER_MANUAL,
    OWNER_FILTER_SELF,
    SEVERITY_CRITICAL,
    SEVERITY_ERROR,
    SEVERITY_WARNING,
)
from .models import TargetInfo, TargetOverride


def build_general_schema(cfg: dict[str, Any]) -> vol.Schema:
    """Build schema for the general options step."""
    owners_str = ", ".join(cfg.get(CONF_OWNER_ALLOWLIST) or [])
    return vol.Schema(
        {
            vol.Required(
                CONF_OWNER_FILTER_MODE,
                default=cfg.get(CONF_OWNER_FILTER_MODE, OWNER_FILTER_SELF),
            ): SelectSelector(
                SelectSelectorConfig(
                    options=[
                        SelectOptionDict(
                            value=OWNER_FILTER_SELF,
                            label="Only authenticated owner",
                        ),
                        SelectOptionDict(
                            value=OWNER_FILTER_CUSTOM,
                            label="Custom owner allowlist",
                        ),
                        SelectOptionDict(
                            value=OWNER_FILTER_MANUAL,
                            label="Manual opt-in only",
                        ),
                    ],
                    mode=SelectSelectorMode.DROPDOWN,
                )
            ),
            vol.Optional(CONF_OWNER_ALLOWLIST, default=owners_str): str,
            vol.Required(
                CONF_DRY_RUN,
                default=bool(cfg.get(CONF_DRY_RUN, DEFAULT_DRY_RUN)),
            ): bool,
            vol.Required(
                CONF_REQUIRE_APPROVAL,
                default=bool(
                    cfg.get(CONF_REQUIRE_APPROVAL, DEFAULT_REQUIRE_APPROVAL)
                ),
            ): bool,
            vol.Required(
                CONF_MIN_SEVERITY,
                default=cfg.get(CONF_MIN_SEVERITY, DEFAULT_MIN_SEVERITY),
            ): SelectSelector(
                SelectSelectorConfig(
                    options=[SEVERITY_ERROR, SEVERITY_WARNING, SEVERITY_CRITICAL],
                    mode=SelectSelectorMode.DROPDOWN,
                )
            ),
            vol.Required(
                CONF_MIN_OCCURRENCES_ERROR,
                default=int(
                    cfg.get(CONF_MIN_OCCURRENCES_ERROR, DEFAULT_MIN_OCCURRENCES_ERROR)
                ),
            ): vol.All(int, vol.Range(min=1, max=50)),
            vol.Required(
                CONF_MIN_OCCURRENCES_WARNING,
                default=int(
                    cfg.get(
                        CONF_MIN_OCCURRENCES_WARNING, DEFAULT_MIN_OCCURRENCES_WARNING
                    )
                ),
            ): vol.All(int, vol.Range(min=1, max=50)),
            vol.Required(
                CONF_OCCURRENCE_WINDOW_MINUTES,
                default=int(
                    cfg.get(
                        CONF_OCCURRENCE_WINDOW_MINUTES,
                        DEFAULT_OCCURRENCE_WINDOW_MINUTES,
                    )
                ),
            ): vol.All(int, vol.Range(min=1, max=240)),
            vol.Required(
                CONF_COOLDOWN_HOURS,
                default=int(cfg.get(CONF_COOLDOWN_HOURS, DEFAULT_COOLDOWN_HOURS)),
            ): vol.All(int, vol.Range(min=1, max=720)),
            vol.Required(
                CONF_MAX_ISSUES_PER_HOUR,
                default=int(
                    cfg.get(CONF_MAX_ISSUES_PER_HOUR, DEFAULT_MAX_ISSUES_PER_HOUR)
                ),
            ): vol.All(int, vol.Range(min=1, max=50)),
            vol.Required(
                CONF_MAX_ISSUES_PER_REPO_DAY,
                default=int(
                    cfg.get(
                        CONF_MAX_ISSUES_PER_REPO_DAY, DEFAULT_MAX_ISSUES_PER_REPO_DAY
                    )
                ),
            ): vol.All(int, vol.Range(min=1, max=20)),
            vol.Required(
                CONF_SKIP_OUTDATED,
                default=bool(cfg.get(CONF_SKIP_OUTDATED, DEFAULT_SKIP_OUTDATED)),
            ): bool,
            vol.Required(
                CONF_ALLOW_DEV_EDGE,
                default=bool(cfg.get(CONF_ALLOW_DEV_EDGE, DEFAULT_ALLOW_DEV_EDGE)),
            ): bool,
            vol.Required(
                CONF_COMMENT_ON_NEWER_VERSION,
                default=bool(
                    cfg.get(
                        CONF_COMMENT_ON_NEWER_VERSION,
                        DEFAULT_COMMENT_ON_NEWER_VERSION,
                    )
                ),
            ): bool,
            vol.Required(
                CONF_ADDON_POLL_MINUTES,
                default=int(
                    cfg.get(CONF_ADDON_POLL_MINUTES, DEFAULT_ADDON_POLL_MINUTES)
                ),
            ): vol.All(int, vol.Range(min=1, max=120)),
            vol.Required(
                CONF_INCLUDE_CORE_ADDONS,
                default=bool(
                    cfg.get(CONF_INCLUDE_CORE_ADDONS, DEFAULT_INCLUDE_CORE_ADDONS)
                ),
            ): bool,
        }
    )


def build_target_schema(target: TargetInfo, current_ov: TargetOverride) -> vol.Schema:
    """Build schema for per-target overrides."""
    return vol.Schema(
        {
            vol.Required(
                "enabled",
                default=(
                    current_ov.enabled
                    if current_ov.enabled is not None
                    else target.enabled
                ),
            ): bool,
            vol.Required(
                "mode", default=current_ov.mode or target.mode
            ): SelectSelector(
                SelectSelectorConfig(
                    options=[
                        SelectOptionDict(value=MODE_AUTO, label="Auto-Create"),
                        SelectOptionDict(
                            value=MODE_APPROVAL, label="Approval Queue (HA Repair)"
                        ),
                        SelectOptionDict(
                            value=MODE_DRY_RUN, label="Dry-Run / Log Only"
                        ),
                    ],
                    mode=SelectSelectorMode.DROPDOWN,
                )
            ),
            vol.Required(
                "min_severity",
                default=current_ov.min_severity or target.min_severity,
            ): SelectSelector(
                SelectSelectorConfig(
                    options=[SEVERITY_ERROR, SEVERITY_WARNING, SEVERITY_CRITICAL],
                    mode=SelectSelectorMode.DROPDOWN,
                )
            ),
            vol.Optional(
                "repo_override",
                default=current_ov.repo_override or (target.full_repo or ""),
            ): str,
            vol.Optional(
                "ignore_patterns",
                default="\n".join(current_ov.ignore_patterns),
            ): TextSelector(TextSelectorConfig(multiline=True)),
        }
    )
