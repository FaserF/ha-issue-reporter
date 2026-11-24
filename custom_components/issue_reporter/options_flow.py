"""Options flow for Issue Reporter."""

from __future__ import annotations

import re
from typing import Any

import voluptuous as vol
from homeassistant.config_entries import ConfigFlowResult, OptionsFlow
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.selector import (
    SelectOptionDict,
    SelectSelector,
    SelectSelectorConfig,
    SelectSelectorMode,
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)

from .auth import GitHubAuthError, async_validate_pat
from .const import (
    AUTH_PAT,
    CONF_ADDON_POLL_MINUTES,
    CONF_ALLOW_DEV_EDGE,
    CONF_COMMENT_ON_NEWER_VERSION,
    CONF_COOLDOWN_HOURS,
    CONF_CUSTOM_IGNORE_PATTERNS,
    CONF_CUSTOM_REDACTION_REGEXES,
    CONF_CUSTOM_REDACTIONS,
    CONF_DRY_RUN,
    CONF_FALLBACK_AUTH_METHOD,
    CONF_FALLBACK_TOKEN,
    CONF_FALLBACK_USER,
    CONF_GITHUB_TOKEN,
    CONF_GITHUB_USER,
    CONF_IGNORE_AUTH_ERRORS,
    CONF_IGNORE_LIFECYCLE_ERRORS,
    CONF_IGNORE_NETWORK_ERRORS,
    CONF_IGNORE_RATE_LIMIT_ERRORS,
    CONF_INCLUDE_CORE_ADDONS,
    CONF_MAX_ISSUES_PER_HOUR,
    CONF_MAX_ISSUES_PER_REPO_DAY,
    CONF_MIN_OCCURRENCES_ERROR,
    CONF_MIN_OCCURRENCES_WARNING,
    CONF_MIN_SEVERITY,
    CONF_OCCURRENCE_WINDOW_MINUTES,
    CONF_OWNER_ALLOWLIST,
    CONF_OWNER_FILTER_MODE,
    CONF_SKIP_OUTDATED,
    CONF_STRICT_ENTROPY_GUARD,
    CONF_TARGET_OVERRIDES,
    DEFAULT_IGNORE_AUTH_ERRORS,
    DEFAULT_IGNORE_LIFECYCLE_ERRORS,
    DEFAULT_IGNORE_NETWORK_ERRORS,
    DEFAULT_IGNORE_RATE_LIMIT_ERRORS,
    DEFAULT_STRICT_ENTROPY_GUARD,
    TARGET_ADDON,
    TARGET_INTEGRATION,
)
from .flow_schemas import build_general_schema, build_target_schema
from .models import TargetOverride


def split_csv_or_lines(raw: Any) -> list[str]:
    """Split comma or newline separated entries into clean non-empty strings."""
    if isinstance(raw, list):
        return [str(x).strip() for x in raw if str(x).strip()]
    if isinstance(raw, str):
        return [x.strip() for x in re.split(r"[,\n]+", raw) if x.strip()]
    return []


class IssueReporterOptionsFlow(OptionsFlow):
    """Menu-based Options Flow for filters, redaction, and per-target control."""

    def __init__(self) -> None:
        """Initialize options flow state."""
        self._selected_target: str | None = None

    def _merged(self) -> dict[str, Any]:
        return {**self.config_entry.data, **self.config_entry.options}

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Display Options Flow main menu."""
        return self.async_show_menu(
            step_id="init",
            menu_options=[
                "general",
                "filters",
                "redaction",
                "integrations",
                "addons",
                "auth",
            ],
        )

    async def async_step_general(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Configure owner filter, global dry-run, severity, and deduplication limits."""
        cfg = self._merged()
        if user_input is not None:
            updated = dict(self.config_entry.options)
            updated.update(
                {
                    CONF_OWNER_FILTER_MODE: user_input[CONF_OWNER_FILTER_MODE],
                    CONF_OWNER_ALLOWLIST: split_csv_or_lines(
                        user_input.get(CONF_OWNER_ALLOWLIST)
                    ),
                    CONF_DRY_RUN: bool(user_input[CONF_DRY_RUN]),
                    CONF_MIN_SEVERITY: user_input[CONF_MIN_SEVERITY],
                    CONF_MIN_OCCURRENCES_ERROR: int(
                        user_input[CONF_MIN_OCCURRENCES_ERROR]
                    ),
                    CONF_MIN_OCCURRENCES_WARNING: int(
                        user_input[CONF_MIN_OCCURRENCES_WARNING]
                    ),
                    CONF_OCCURRENCE_WINDOW_MINUTES: int(
                        user_input[CONF_OCCURRENCE_WINDOW_MINUTES]
                    ),
                    CONF_COOLDOWN_HOURS: int(user_input[CONF_COOLDOWN_HOURS]),
                    CONF_MAX_ISSUES_PER_HOUR: int(user_input[CONF_MAX_ISSUES_PER_HOUR]),
                    CONF_MAX_ISSUES_PER_REPO_DAY: int(
                        user_input[CONF_MAX_ISSUES_PER_REPO_DAY]
                    ),
                    CONF_SKIP_OUTDATED: bool(user_input[CONF_SKIP_OUTDATED]),
                    CONF_ALLOW_DEV_EDGE: bool(user_input[CONF_ALLOW_DEV_EDGE]),
                    CONF_COMMENT_ON_NEWER_VERSION: bool(
                        user_input[CONF_COMMENT_ON_NEWER_VERSION]
                    ),
                    CONF_ADDON_POLL_MINUTES: int(user_input[CONF_ADDON_POLL_MINUTES]),
                    CONF_INCLUDE_CORE_ADDONS: bool(
                        user_input[CONF_INCLUDE_CORE_ADDONS]
                    ),
                }
            )
            return self.async_create_entry(title="", data=updated)

        return self.async_show_form(
            step_id="general",
            data_schema=build_general_schema(cfg),
        )

    async def async_step_filters(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Configure local/transient error filtering rules."""
        cfg = self._merged()
        errors: dict[str, str] = {}
        if user_input is not None:
            raw_pats = split_csv_or_lines(user_input.get(CONF_CUSTOM_IGNORE_PATTERNS))
            valid = True
            for pat in raw_pats:
                try:
                    re.compile(pat)
                except re.error:
                    errors["base"] = "invalid_regex"
                    valid = False
                    break
            if valid:
                updated = dict(self.config_entry.options)
                updated.update(
                    {
                        CONF_IGNORE_NETWORK_ERRORS: bool(
                            user_input[CONF_IGNORE_NETWORK_ERRORS]
                        ),
                        CONF_IGNORE_AUTH_ERRORS: bool(
                            user_input[CONF_IGNORE_AUTH_ERRORS]
                        ),
                        CONF_IGNORE_RATE_LIMIT_ERRORS: bool(
                            user_input[CONF_IGNORE_RATE_LIMIT_ERRORS]
                        ),
                        CONF_IGNORE_LIFECYCLE_ERRORS: bool(
                            user_input[CONF_IGNORE_LIFECYCLE_ERRORS]
                        ),
                        CONF_CUSTOM_IGNORE_PATTERNS: raw_pats,
                    }
                )
                return self.async_create_entry(title="", data=updated)

        pats_str = "\n".join(cfg.get(CONF_CUSTOM_IGNORE_PATTERNS) or [])
        return self.async_show_form(
            step_id="filters",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_IGNORE_NETWORK_ERRORS,
                        default=bool(
                            cfg.get(
                                CONF_IGNORE_NETWORK_ERRORS,
                                DEFAULT_IGNORE_NETWORK_ERRORS,
                            )
                        ),
                    ): bool,
                    vol.Required(
                        CONF_IGNORE_AUTH_ERRORS,
                        default=bool(
                            cfg.get(CONF_IGNORE_AUTH_ERRORS, DEFAULT_IGNORE_AUTH_ERRORS)
                        ),
                    ): bool,
                    vol.Required(
                        CONF_IGNORE_RATE_LIMIT_ERRORS,
                        default=bool(
                            cfg.get(
                                CONF_IGNORE_RATE_LIMIT_ERRORS,
                                DEFAULT_IGNORE_RATE_LIMIT_ERRORS,
                            )
                        ),
                    ): bool,
                    vol.Required(
                        CONF_IGNORE_LIFECYCLE_ERRORS,
                        default=bool(
                            cfg.get(
                                CONF_IGNORE_LIFECYCLE_ERRORS,
                                DEFAULT_IGNORE_LIFECYCLE_ERRORS,
                            )
                        ),
                    ): bool,
                    vol.Optional(
                        CONF_CUSTOM_IGNORE_PATTERNS, default=pats_str
                    ): TextSelector(TextSelectorConfig(multiline=True)),
                }
            ),
            errors=errors,
        )

    async def async_step_redaction(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Configure custom redaction literals, regexes, and entropy guard."""
        cfg = self._merged()
        errors: dict[str, str] = {}
        if user_input is not None:
            custom_words = split_csv_or_lines(user_input.get(CONF_CUSTOM_REDACTIONS))
            custom_regexes = [
                ln.strip()
                for ln in str(
                    user_input.get(CONF_CUSTOM_REDACTION_REGEXES) or ""
                ).splitlines()
                if ln.strip()
            ]
            valid = True
            for pat in custom_regexes:
                try:
                    re.compile(pat)
                except re.error:
                    errors["base"] = "invalid_regex"
                    valid = False
                    break
            if valid:
                updated = dict(self.config_entry.options)
                updated.update(
                    {
                        CONF_CUSTOM_REDACTIONS: custom_words,
                        CONF_CUSTOM_REDACTION_REGEXES: custom_regexes,
                        CONF_STRICT_ENTROPY_GUARD: bool(
                            user_input[CONF_STRICT_ENTROPY_GUARD]
                        ),
                    }
                )
                return self.async_create_entry(title="", data=updated)

        return self.async_show_form(
            step_id="redaction",
            data_schema=vol.Schema(
                {
                    vol.Optional(
                        CONF_CUSTOM_REDACTIONS,
                        default=", ".join(cfg.get(CONF_CUSTOM_REDACTIONS) or []),
                    ): TextSelector(TextSelectorConfig(multiline=True)),
                    vol.Optional(
                        CONF_CUSTOM_REDACTION_REGEXES,
                        default="\n".join(cfg.get(CONF_CUSTOM_REDACTION_REGEXES) or []),
                    ): TextSelector(TextSelectorConfig(multiline=True)),
                    vol.Required(
                        CONF_STRICT_ENTROPY_GUARD,
                        default=bool(
                            cfg.get(
                                CONF_STRICT_ENTROPY_GUARD, DEFAULT_STRICT_ENTROPY_GUARD
                            )
                        ),
                    ): bool,
                }
            ),
            errors=errors,
        )

    async def async_step_integrations(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Select a custom integration target to configure."""
        return await self._async_select_target_step(
            TARGET_INTEGRATION, "integrations", user_input
        )

    async def async_step_addons(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Select a Supervisor add-on target to configure."""
        return await self._async_select_target_step(TARGET_ADDON, "addons", user_input)

    async def _async_select_target_step(
        self, kind: str, step_id: str, user_input: dict[str, Any] | None
    ) -> ConfigFlowResult:
        """Render picker for discovered targets of a given kind."""
        if user_input is not None:
            self._selected_target = user_input["target_key"]
            return await self.async_step_edit_target()

        coord = getattr(self.config_entry, "runtime_data", None)
        targets = coord.targets if coord else {}
        opts = [
            SelectOptionDict(
                value=t.target_key,
                label=f"{t.name} ({t.full_repo or 'unmapped'}) [{'ON' if t.enabled else 'OFF'}]",
            )
            for t in sorted(targets.values(), key=lambda item: item.name.lower())
            if t.kind == kind
        ]
        if not opts:
            return self.async_abort(reason="no_targets_found")

        return self.async_show_form(
            step_id=step_id,
            data_schema=vol.Schema(
                {
                    vol.Required(
                        "target_key", default=opts[0]["value"]
                    ): SelectSelector(
                        SelectSelectorConfig(
                            options=opts, mode=SelectSelectorMode.DROPDOWN
                        )
                    )
                }
            ),
        )

    async def async_step_edit_target(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Edit per-target enable, mode, severity, and repository override."""
        tkey = self._selected_target or ""
        coord = getattr(self.config_entry, "runtime_data", None)
        target = coord.targets.get(tkey) if coord else None
        if target is None:
            return self.async_abort(reason="no_targets_found")

        overrides = dict(self.config_entry.options.get(CONF_TARGET_OVERRIDES) or {})
        current_ov = TargetOverride.from_dict(overrides.get(tkey))

        if user_input is not None:
            new_ov = TargetOverride(
                enabled=bool(user_input["enabled"]),
                mode=str(user_input["mode"]),
                min_severity=str(user_input["min_severity"]),
                repo_override=str(user_input.get("repo_override") or "").strip()
                or None,
                ignore_patterns=split_csv_or_lines(user_input.get("ignore_patterns")),
            )
            overrides[tkey] = new_ov.to_dict()
            updated = dict(self.config_entry.options)
            updated[CONF_TARGET_OVERRIDES] = overrides
            return self.async_create_entry(title="", data=updated)

        return self.async_show_form(
            step_id="edit_target",
            data_schema=build_target_schema(target, current_ov),
            description_placeholders={"target_name": target.name},
        )

    async def async_step_auth(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Rotate PAT or fallback credentials from Options Flow."""
        errors: dict[str, str] = {}
        if user_input is not None:
            new_data = dict(self.config_entry.data)
            session = async_get_clientsession(self.hass)
            pat = str(user_input.get(CONF_GITHUB_TOKEN) or "").strip()
            fb = str(user_input.get(CONF_FALLBACK_TOKEN) or "").strip()
            try:
                if pat:
                    info = await async_validate_pat(session, pat)
                    new_data[CONF_GITHUB_TOKEN] = pat
                    new_data[CONF_GITHUB_USER] = info.get("login", "")
                if fb:
                    fb_info = await async_validate_pat(session, fb)
                    new_data[CONF_FALLBACK_AUTH_METHOD] = AUTH_PAT
                    new_data[CONF_FALLBACK_TOKEN] = fb
                    new_data[CONF_FALLBACK_USER] = fb_info.get("login", "")
            except GitHubAuthError:
                errors["base"] = "invalid_auth"
            else:
                self.hass.config_entries.async_update_entry(
                    self.config_entry, data=new_data
                )
                return self.async_create_entry(
                    title="", data=dict(self.config_entry.options)
                )

        return self.async_show_form(
            step_id="auth",
            data_schema=vol.Schema(
                {
                    vol.Optional(CONF_GITHUB_TOKEN, default=""): TextSelector(
                        TextSelectorConfig(type=TextSelectorType.PASSWORD)
                    ),
                    vol.Optional(CONF_FALLBACK_TOKEN, default=""): TextSelector(
                        TextSelectorConfig(type=TextSelectorType.PASSWORD)
                    ),
                }
            ),
            errors=errors,
        )
