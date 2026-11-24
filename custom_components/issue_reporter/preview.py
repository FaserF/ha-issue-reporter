"""Preview and snapshot builders for Issue Reporter coordinator."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from .const import SEVERITY_LEVELS, TARGET_ADDON, TARGET_INTEGRATION
from .dedup import async_check_github_duplicate, compute_fingerprint
from .models import LogEvent, TargetInfo

if TYPE_CHECKING:
    from .coordinator import IssueReporterCoordinator


def build_coordinator_snapshot(coord: IssueReporterCoordinator) -> dict[str, Any]:
    """Build sensor-ready coordinator data snapshot."""
    enabled_int = sum(
        1 for t in coord.targets.values() if t.kind == TARGET_INTEGRATION and t.enabled
    )
    total_int = sum(1 for t in coord.targets.values() if t.kind == TARGET_INTEGRATION)
    enabled_add = sum(
        1 for t in coord.targets.values() if t.kind == TARGET_ADDON and t.enabled
    )
    total_add = sum(1 for t in coord.targets.values() if t.kind == TARGET_ADDON)
    return {
        "monitored_targets": enabled_int + enabled_add,
        "integrations_enabled": enabled_int,
        "integrations_total": total_int,
        "addons_enabled": enabled_add,
        "addons_total": total_add,
        "pending_drafts": len(coord.pending_drafts),
        "issues_created": coord.stats.issues_created,
        "comments_posted": coord.stats.comments_posted,
        "duplicates_suppressed": coord.stats.duplicates_suppressed,
        "outdated_suppressed": coord.stats.outdated_suppressed,
        "filtered_local": coord.stats.filtered_local,
        "rate_limited_suppressed": coord.stats.rate_limited_suppressed,
        "leak_guard_blocks": coord.stats.leak_guard_blocks,
        "github_api_remaining": coord.github.rate_limit_remaining,
        "last_issue_url": coord.stats.last_issue_url,
        "last_scan_at": coord.stats.last_scan_at,
    }


async def async_render_preview(
    coord: IssueReporterCoordinator,
    *,
    draft_id: str | None = None,
    target_key: str | None = None,
    sample_message: str | None = None,
    severity: str = "ERROR",
) -> dict[str, Any]:
    """Render a full sanitized issue preview without modifying GitHub."""
    if draft_id and draft_id in coord.pending_drafts:
        d = coord.pending_drafts[draft_id]
        safe, reasons = coord.redactor.verify_no_leaks(d.title, d.body)
        return {
            "draft_id": d.draft_id,
            "repo": d.repo,
            "title": d.title,
            "body": d.body,
            "labels": d.labels,
            "template_used": d.template_used,
            "leak_guard_passed": safe,
            "leak_guard_reasons": reasons,
            "duplicate_status": "cached_draft",
        }

    target: TargetInfo | None = coord.targets.get(target_key or "")
    if target is None or not target.full_repo:
        raise ValueError(f"Unknown or unmapped target_key: {target_key}")

    sanitized_msg = coord.redactor.redact(
        sample_message or "Sample automated error preview"
    ).text
    ev = LogEvent(
        target_key=target.target_key,
        kind=target.kind,
        logger_name=f"preview.{target.short_name}",
        severity=severity.upper(),
        levelno=SEVERITY_LEVELS.get(severity.upper(), 40),
        message=sanitized_msg,
        timestamp=datetime.now(UTC).isoformat(),
    )
    fp = compute_fingerprint(target, ev)
    dup = await async_check_github_duplicate(coord.github, target, ev, fp, coord.config)
    now_iso = datetime.now(UTC).isoformat()
    rendered = await coord.template_engine.async_render_issue(
        coord.hass,
        target,
        ev,
        sanitized_message=sanitized_msg,
        sanitized_traceback="",
        fingerprint=fp,
        occurrences=1,
        first_seen=now_iso,
        last_seen=now_iso,
        regression_of=dup.issue_number if dup.action == "regression_new" else None,
    )
    safe, reasons = coord.redactor.verify_no_leaks(rendered.title, rendered.body)
    return {
        "repo": rendered.repo,
        "title": rendered.title,
        "body": rendered.body,
        "labels": rendered.labels,
        "template_used": rendered.template_used,
        "fingerprint": fp,
        "duplicate_status": dup.action,
        "duplicate_issue_url": dup.issue_url,
        "leak_guard_passed": safe,
        "leak_guard_reasons": reasons,
    }
