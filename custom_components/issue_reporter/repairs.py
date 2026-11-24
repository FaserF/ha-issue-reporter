"""Interactive Home Assistant Repairs for draft approvals and leak-guard alerts."""

from __future__ import annotations

from typing import Any

import voluptuous as vol
from homeassistant import data_entry_flow
from homeassistant.components.repairs import ConfirmRepairFlow, RepairsFlow
from homeassistant.core import HomeAssistant
from homeassistant.helpers import issue_registry as ir

from .const import DOMAIN, LOGGER


def async_raise_draft_repair(
    hass: HomeAssistant,
    draft_id: str,
    repo: str,
    title: str,
    target_name: str,
    excerpt: str,
) -> None:
    """Create or update an actionable Repair for a pending GitHub issue draft."""
    ir.async_create_issue(
        hass,
        DOMAIN,
        f"draft_{draft_id}",
        is_fixable=True,
        is_persistent=True,
        severity=ir.IssueSeverity.WARNING,
        translation_key="pending_draft_approval",
        translation_placeholders={
            "target": target_name,
            "repo": repo,
            "title": title,
            "excerpt": excerpt[:400],
        },
        data={
            "kind": "draft",
            "draft_id": draft_id,
            "repo": repo,
            "title": title,
            "excerpt": excerpt[:600],
        },
    )


def async_raise_leak_guard_repair(
    hass: HomeAssistant,
    target_name: str,
    reasons: list[str],
) -> None:
    """Create a persistent Repair alert when Layer 4 Leak Guard aborts submission."""
    reason_str = ", ".join(reasons) if reasons else "suspected_secret"
    ir.async_create_issue(
        hass,
        DOMAIN,
        f"leak_guard_{target_name}",
        is_fixable=True,
        is_persistent=True,
        severity=ir.IssueSeverity.ERROR,
        translation_key="leak_guard_blocked",
        translation_placeholders={
            "target": target_name,
            "reasons": reason_str,
        },
        data={"kind": "leak_guard", "target": target_name, "reasons": reason_str},
    )


def async_clear_draft_repair(hass: HomeAssistant, draft_id: str) -> None:
    """Delete Repair notification for an approved or dismissed draft."""
    ir.async_delete_issue(hass, DOMAIN, f"draft_{draft_id}")


class PendingDraftRepairFlow(RepairsFlow):
    """Repair flow allowing 1-click publish or dismissal of a queued draft."""

    def __init__(self, issue_id: str, data: dict[str, Any] | None) -> None:
        """Initialize repair flow for a pending draft."""
        super().__init__()
        self._issue_id = issue_id
        self._data = data or {}

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> data_entry_flow.FlowResult:
        """Prompt user to approve, keep in queue, or dismiss the draft."""
        if user_input is not None:
            action = user_input["action"]
            draft_id = str(self._data.get("draft_id", ""))
            entries = self.hass.config_entries.async_entries(DOMAIN)
            coordinator = entries[0].runtime_data if entries else None

            if coordinator is not None and draft_id:
                try:
                    if action == "approve":
                        await coordinator.async_approve_draft(draft_id)
                    elif action == "dismiss":
                        await coordinator.async_dismiss_draft(draft_id)
                except Exception as err:
                    LOGGER.error("Draft repair action failed for %s: %s", draft_id, err)
                    return self.async_abort(reason="action_failed")

            return self.async_create_entry(data={})

        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Required("action", default="approve"): vol.In(
                        {
                            "approve": "Approve & create GitHub issue",
                            "dismiss": "Dismiss & ignore this error",
                        }
                    )
                }
            ),
            description_placeholders={
                "repo": str(self._data.get("repo", "")),
                "title": str(self._data.get("title", "")),
                "excerpt": str(self._data.get("excerpt", "")),
            },
        )


async def async_create_fix_flow(
    hass: HomeAssistant,
    issue_id: str,
    data: dict[str, Any] | None,
) -> RepairsFlow:
    """Create the appropriate Repair flow handler."""
    if data and data.get("kind") == "draft":
        return PendingDraftRepairFlow(issue_id, data)
    return ConfirmRepairFlow()
