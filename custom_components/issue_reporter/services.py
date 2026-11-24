"""Service handlers for Issue Reporter."""

from __future__ import annotations

from typing import Any

import voluptuous as vol
from homeassistant.core import HomeAssistant, ServiceCall, SupportsResponse
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError
from homeassistant.helpers import config_validation as cv

from .const import (
    DOMAIN,
    SERVICE_APPROVE_DRAFT,
    SERVICE_CLEAR_COOLDOWNS,
    SERVICE_DISMISS_DRAFT,
    SERVICE_PREVIEW_DRAFT,
    SERVICE_SCAN_NOW,
    SERVICE_TEST_REDACTION,
)


def _get_coordinator(hass: HomeAssistant) -> Any:
    """Return active IssueReporterCoordinator or raise HomeAssistantError."""
    entries = hass.config_entries.async_entries(DOMAIN)
    if not entries:
        raise HomeAssistantError(
            translation_domain=DOMAIN,
            translation_key="not_configured",
        )
    coordinator = getattr(entries[0], "runtime_data", None)
    if coordinator is None:
        raise HomeAssistantError(
            translation_domain=DOMAIN,
            translation_key="not_loaded",
        )
    return coordinator


def async_register_services(hass: HomeAssistant) -> None:
    """Register Issue Reporter domain services."""
    if hass.services.has_service(DOMAIN, SERVICE_SCAN_NOW):
        return

    async def handle_scan_now(call: ServiceCall) -> None:
        coordinator = _get_coordinator(hass)
        await coordinator.async_scan_now()

    async def handle_test_redaction(call: ServiceCall) -> dict[str, Any]:
        coordinator = _get_coordinator(hass)
        text = str(call.data["text"])
        result = coordinator.redactor.redact(text)
        safe, reasons = coordinator.redactor.verify_no_leaks("", result.text)
        return {
            "redacted_text": result.text,
            "replacements_count": result.replacements_count,
            "matched_categories": result.matched_categories,
            "leak_guard_passed": safe,
            "leak_guard_reasons": reasons,
        }

    async def handle_preview_draft(call: ServiceCall) -> dict[str, Any]:
        coordinator = _get_coordinator(hass)
        try:
            return await coordinator.async_preview_draft(
                draft_id=call.data.get("draft_id"),
                target_key=call.data.get("target_key"),
                sample_message=call.data.get("sample_message"),
                severity=str(call.data.get("severity", "ERROR")),
            )
        except ValueError as err:
            raise ServiceValidationError(str(err)) from err

    async def handle_approve_draft(call: ServiceCall) -> None:
        coordinator = _get_coordinator(hass)
        try:
            await coordinator.async_approve_draft(str(call.data["draft_id"]))
        except ValueError as err:
            raise ServiceValidationError(str(err)) from err
        except Exception as err:
            raise HomeAssistantError(f"Failed publishing draft: {err}") from err

    async def handle_dismiss_draft(call: ServiceCall) -> None:
        coordinator = _get_coordinator(hass)
        await coordinator.async_dismiss_draft(str(call.data["draft_id"]))

    async def handle_clear_cooldowns(call: ServiceCall) -> None:
        coordinator = _get_coordinator(hass)
        await coordinator.async_clear_cooldowns(call.data.get("target_key"))

    hass.services.async_register(DOMAIN, SERVICE_SCAN_NOW, handle_scan_now)
    hass.services.async_register(
        DOMAIN,
        SERVICE_TEST_REDACTION,
        handle_test_redaction,
        schema=vol.Schema({vol.Required("text"): cv.string}),
        supports_response=SupportsResponse.ONLY,
    )
    hass.services.async_register(
        DOMAIN,
        SERVICE_PREVIEW_DRAFT,
        handle_preview_draft,
        schema=vol.Schema(
            {
                vol.Optional("draft_id"): cv.string,
                vol.Optional("target_key"): cv.string,
                vol.Optional("sample_message"): cv.string,
                vol.Optional("severity", default="ERROR"): cv.string,
            }
        ),
        supports_response=SupportsResponse.ONLY,
    )
    hass.services.async_register(
        DOMAIN,
        SERVICE_APPROVE_DRAFT,
        handle_approve_draft,
        schema=vol.Schema({vol.Required("draft_id"): cv.string}),
    )
    hass.services.async_register(
        DOMAIN,
        SERVICE_DISMISS_DRAFT,
        handle_dismiss_draft,
        schema=vol.Schema({vol.Required("draft_id"): cv.string}),
    )
    hass.services.async_register(
        DOMAIN,
        SERVICE_CLEAR_COOLDOWNS,
        handle_clear_cooldowns,
        schema=vol.Schema({vol.Optional("target_key"): cv.string}),
    )
