"""Interactive notifications and mobile push actions for pending Issue Reporter drafts."""

from __future__ import annotations

import hmac
import html
from typing import Any
from urllib.parse import urlencode

from aiohttp import web
from homeassistant.components import persistent_notification
from homeassistant.components.http import HomeAssistantView
from homeassistant.core import Event, HomeAssistant

from .const import (
    DOMAIN,
    DRAFT_ACTION_URL_PATH,
    LOGGER,
    MOBILE_ACTION_APPROVE_PREFIX,
    MOBILE_ACTION_DISMISS_PREFIX,
    NOTIFICATION_ID_PREFIX,
)
from .models import PendingDraft

_HANDLERS_KEY = f"{DOMAIN}_draft_action_handlers_registered"


def draft_notification_id(draft_id: str) -> str:
    """Return deterministic notification ID for a pending draft."""
    return f"{NOTIFICATION_ID_PREFIX}{draft_id}"


def _parse_notify_service(notify_service: str) -> tuple[str, str] | None:
    """Parse optional Home Assistant notify service into (domain, service)."""
    cleaned = notify_service.strip()
    if not cleaned:
        return None
    if "." in cleaned:
        domain, service = cleaned.split(".", 1)
    else:
        domain, service = "notify", cleaned
    if not domain.strip() or not service.strip():
        return None
    return domain.strip(), service.strip()


def _draft_action_url(draft: PendingDraft, decision: str | None = None) -> str:
    """Build relative interactive review URL for a draft."""
    params: dict[str, str] = {
        "draft_id": draft.draft_id,
        "token": draft.action_token,
    }
    if decision:
        params["decision"] = decision
    return f"{DRAFT_ACTION_URL_PATH}?{urlencode(params)}"


def _get_coordinator_and_draft(
    hass: HomeAssistant, draft_id: str
) -> tuple[Any, PendingDraft | None]:
    """Look up active coordinator and matching draft by ID."""
    entries = hass.config_entries.async_entries(DOMAIN)
    for entry in entries:
        coord = getattr(entry, "runtime_data", None)
        if coord is not None and draft_id in coord.pending_drafts:
            return coord, coord.pending_drafts[draft_id]
    return (
        getattr(entries[0], "runtime_data", None) if entries else None,
        None,
    )


def _render_html_page(title: str, body_html: str) -> str:
    """Render a minimal, escaped HTML response for draft review links."""
    safe_title = html.escape(title)
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>{safe_title}</title>"
        "<style>"
        "body{font-family:system-ui,-apple-system,sans-serif;max-width:760px;"
        "margin:2rem auto;padding:0 1rem;background:#111827;color:#f3f4f6;}"
        ".card{background:#1f2937;border:1px solid #374151;border-radius:12px;padding:1.5rem;}"
        "pre{white-space:pre-wrap;background:#0f172a;padding:1rem;border-radius:8px;overflow:auto;}"
        ".actions{display:flex;gap:.75rem;flex-wrap:wrap;margin-top:1.25rem;}"
        "button{border:0;border-radius:8px;padding:.75rem 1.25rem;font-size:1rem;cursor:pointer;font-weight:600;}"
        ".approve{background:#16a34a;color:#fff;} .dismiss{background:#dc2626;color:#fff;}"
        "</style></head><body><div class='card'>"
        f"<h2>{safe_title}</h2>{body_html}</div></body></html>"
    )


class DraftActionView(HomeAssistantView):
    """Interactive HA HTTP endpoint for approving or rejecting drafts from notifications."""

    url = DRAFT_ACTION_URL_PATH
    name = "api:issue_reporter:draft_action"
    requires_auth = False

    async def get(self, request: web.Request) -> web.Response:
        """Render interactive draft approval/rejection page."""
        hass: HomeAssistant = request.app["hass"]
        draft_id = str(request.query.get("draft_id", "")).strip()
        token = str(request.query.get("token", "")).strip()
        decision = str(request.query.get("decision", "")).strip()

        _, draft = _get_coordinator_and_draft(hass, draft_id)
        if draft is None:
            return web.Response(
                status=404,
                content_type="text/html",
                text=_render_html_page(
                    "Draft Not Found",
                    "<p>This draft was already approved, dismissed, or removed.</p>",
                ),
            )
        if not hmac.compare_digest(token, draft.action_token):
            return web.Response(
                status=403,
                content_type="text/html",
                text=_render_html_page("Forbidden", "<p>Invalid action token.</p>"),
            )

        hint = ""
        if decision == "approve":
            hint = "<p><strong>Selected action:</strong> Approve &amp; publish GitHub issue.</p>"
        elif decision == "dismiss":
            hint = (
                "<p><strong>Selected action:</strong> Reject &amp; dismiss draft.</p>"
            )

        safe_repo = html.escape(draft.repo)
        safe_target = html.escape(draft.target_name)
        safe_issue_title = html.escape(draft.title)
        safe_body = html.escape(draft.body[:2500])
        safe_draft_id = html.escape(draft.draft_id)
        safe_token = html.escape(token)

        body_html = (
            f"<p><strong>Target:</strong> {safe_target} &middot; "
            f"<strong>Repository:</strong> {safe_repo}</p>"
            f"<p><strong>Issue Title:</strong> <code>{safe_issue_title}</code></p>"
            f"{hint}<pre>{safe_body}</pre>"
            f"<form method='post' action='{DRAFT_ACTION_URL_PATH}' class='actions'>"
            f"<input type='hidden' name='draft_id' value='{safe_draft_id}'>"
            f"<input type='hidden' name='token' value='{safe_token}'>"
            "<button class='approve' type='submit' name='decision' value='approve'>"
            "Approve &amp; Create GitHub Issue</button>"
            "<button class='dismiss' type='submit' name='decision' value='dismiss'>"
            "Reject &amp; Dismiss Draft</button></form>"
        )
        return web.Response(
            content_type="text/html",
            text=_render_html_page(f"Review Draft ({draft.target_name})", body_html),
        )

    async def post(self, request: web.Request) -> web.Response:
        """Execute approve or dismiss action submitted from interactive view."""
        hass: HomeAssistant = request.app["hass"]
        data = await request.post()
        draft_id = str(
            data.get("draft_id") or request.query.get("draft_id") or ""
        ).strip()
        token = str(data.get("token") or request.query.get("token") or "").strip()
        decision = str(
            data.get("decision") or request.query.get("decision") or ""
        ).strip()

        coord, draft = _get_coordinator_and_draft(hass, draft_id)
        if draft is None or coord is None:
            return web.Response(
                status=404,
                content_type="text/html",
                text=_render_html_page(
                    "Draft Not Found",
                    "<p>This draft was already approved, dismissed, or removed.</p>",
                ),
            )
        if not hmac.compare_digest(token, draft.action_token):
            return web.Response(
                status=403,
                content_type="text/html",
                text=_render_html_page("Forbidden", "<p>Invalid action token.</p>"),
            )

        if decision == "approve":
            try:
                created = await coord.async_approve_draft(draft_id)
            except Exception as err:
                LOGGER.error(
                    "Interactive draft approval failed for %s: %s", draft_id, err
                )
                return web.Response(
                    status=500,
                    content_type="text/html",
                    text=_render_html_page(
                        "Approval Failed",
                        f"<p>{html.escape(str(err))}</p>",
                    ),
                )
            issue_url = html.escape(str(created.get("html_url") or ""))
            link = (
                f"<p><a href='{issue_url}' style='color:#60a5fa'>{issue_url}</a></p>"
                if issue_url
                else ""
            )
            return web.Response(
                content_type="text/html",
                text=_render_html_page(
                    "Draft Approved",
                    f"<p>GitHub issue created and notification removed.</p>{link}",
                ),
            )

        if decision == "dismiss":
            await coord.async_dismiss_draft(draft_id)
            return web.Response(
                content_type="text/html",
                text=_render_html_page(
                    "Draft Dismissed",
                    "<p>Draft rejected, fingerprint suppressed, and notification removed.</p>",
                ),
            )

        return web.Response(
            status=400,
            content_type="text/html",
            text=_render_html_page("Invalid Action", "<p>Unsupported decision.</p>"),
        )


def async_register_draft_action_handlers(hass: HomeAssistant) -> None:
    """Register HTTP view and mobile notification action listener once."""
    if hass.data.get(_HANDLERS_KEY):
        return
    hass.data[_HANDLERS_KEY] = True

    if getattr(hass, "http", None) is not None:
        hass.http.register_view(DraftActionView())

    async def _handle_mobile_action(event: Event) -> None:
        action = str((event.data or {}).get("action") or "")
        if action.startswith(MOBILE_ACTION_APPROVE_PREFIX):
            draft_id = action.removeprefix(MOBILE_ACTION_APPROVE_PREFIX)
            coord, draft = _get_coordinator_and_draft(hass, draft_id)
            if coord is not None and draft is not None:
                try:
                    await coord.async_approve_draft(draft_id)
                except Exception as err:
                    LOGGER.error(
                        "Mobile notification approval failed for %s: %s",
                        draft_id,
                        err,
                    )
        elif action.startswith(MOBILE_ACTION_DISMISS_PREFIX):
            draft_id = action.removeprefix(MOBILE_ACTION_DISMISS_PREFIX)
            coord, draft = _get_coordinator_and_draft(hass, draft_id)
            if coord is not None and draft is not None:
                await coord.async_dismiss_draft(draft_id)

    hass.bus.async_listen("mobile_app_notification_action", _handle_mobile_action)


async def async_raise_draft_notification(
    hass: HomeAssistant,
    draft: PendingDraft,
    *,
    excerpt: str = "",
    notify_service: str = "",
) -> None:
    """Create a per-draft persistent notification (and optional push notification)."""
    notif_id = draft_notification_id(draft.draft_id)
    preview = (excerpt or draft.body or "").strip()[:400]
    review_url = _draft_action_url(draft)
    approve_url = _draft_action_url(draft, "approve")
    dismiss_url = _draft_action_url(draft, "dismiss")

    message = (
        f"Issue Reporter prepared a sanitized issue for **{draft.repo}** "
        f"(`{draft.target_name}`, severity `{draft.severity}`):\n\n"
        f"**`{draft.title}`**\n\n"
        f"```\n{preview}\n```\n\n"
        f"[Review Full Draft]({review_url}) | "
        f"[Approve & Publish]({approve_url}) | "
        f"[Reject / Dismiss]({dismiss_url})\n\n"
        f"Draft ID: `{draft.draft_id}`"
    )
    persistent_notification.async_create(
        hass,
        message=message,
        title=f"Review GitHub issue draft for {draft.target_name}",
        notification_id=notif_id,
    )

    parsed = _parse_notify_service(notify_service)
    if parsed and hass.services.has_service(*parsed):
        try:
            await hass.services.async_call(
                parsed[0],
                parsed[1],
                {
                    "title": f"Issue Reporter: {draft.target_name}",
                    "message": f"{draft.repo}: {draft.title}",
                    "data": {
                        "tag": notif_id,
                        "url": review_url,
                        "actions": [
                            {
                                "action": f"{MOBILE_ACTION_APPROVE_PREFIX}{draft.draft_id}",
                                "title": "Approve & Publish",
                            },
                            {
                                "action": f"{MOBILE_ACTION_DISMISS_PREFIX}{draft.draft_id}",
                                "title": "Reject",
                            },
                        ],
                    },
                },
                blocking=False,
            )
        except Exception as err:
            LOGGER.warning(
                "Failed sending mobile draft notification via %s.%s: %s",
                parsed[0],
                parsed[1],
                err,
            )


async def async_clear_draft_notification(
    hass: HomeAssistant,
    draft_id: str,
    *,
    notify_service: str = "",
) -> None:
    """Delete persistent (and optional mobile push) notification for a draft."""
    notif_id = draft_notification_id(draft_id)
    persistent_notification.async_dismiss(hass, notif_id)

    parsed = _parse_notify_service(notify_service)
    if parsed and hass.services.has_service(*parsed):
        try:
            await hass.services.async_call(
                parsed[0],
                parsed[1],
                {
                    "message": "clear_notification",
                    "data": {"tag": notif_id},
                },
                blocking=False,
            )
        except Exception as err:
            LOGGER.warning(
                "Failed clearing mobile draft notification via %s.%s: %s",
                parsed[0],
                parsed[1],
                err,
            )
