"""Privacy-first diagnostics export for Issue Reporter."""

from __future__ import annotations

from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import (
    CONF_FALLBACK_TOKEN,
    CONF_GITHUB_TOKEN,
    CONF_PRIVATE_KEY,
)

TO_REDACT = {
    CONF_GITHUB_TOKEN,
    CONF_FALLBACK_TOKEN,
    CONF_PRIVATE_KEY,
    "token",
    "private_key",
    "secret",
    "password",
    "authorization",
    "client_id",
}


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant,
    entry: ConfigEntry,
) -> dict[str, Any]:
    """Return strictly redacted diagnostics for the Issue Reporter config entry."""
    coordinator = getattr(entry, "runtime_data", None)
    entry_dict = {
        "entry_id": entry.entry_id,
        "title": entry.title,
        "version": entry.version,
        "data": async_redact_data(dict(entry.data), TO_REDACT),
        "options": async_redact_data(dict(entry.options), TO_REDACT),
    }

    if coordinator is None:
        return {"entry": entry_dict, "coordinator": None}

    targets_summary = [
        {
            "key": t.target_key,
            "kind": t.kind,
            "repo": t.full_repo,
            "version": t.version,
            "channel": t.channel,
            "enabled": t.enabled,
            "mode": t.mode,
            "owner_matched": t.owner_matched,
        }
        for t in coordinator.targets.values()
    ]

    return {
        "entry": entry_dict,
        "auth_actor": coordinator.auth.get_actor_label(),
        "stats": {
            "issues_created": coordinator.stats.issues_created,
            "comments_posted": coordinator.stats.comments_posted,
            "duplicates_suppressed": coordinator.stats.duplicates_suppressed,
            "outdated_suppressed": coordinator.stats.outdated_suppressed,
            "filtered_local": coordinator.stats.filtered_local,
            "rate_limited_suppressed": coordinator.stats.rate_limited_suppressed,
            "leak_guard_blocks": coordinator.stats.leak_guard_blocks,
            "pending_drafts": len(coordinator.pending_drafts),
            "last_issue_url": coordinator.stats.last_issue_url,
            "last_scan_at": coordinator.stats.last_scan_at,
        },
        "github_rate_limit_remaining": coordinator.github.rate_limit_remaining,
        "targets_summary": targets_summary,
    }
