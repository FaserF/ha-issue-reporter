"""DataUpdateCoordinator and orchestration pipeline for Issue Reporter."""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from homeassistant.components.hassio import get_supervisor_client
from homeassistant.config_entries import SIGNAL_CONFIG_ENTRY_CHANGED, ConfigEntry
from homeassistant.core import CALLBACK_TYPE, HomeAssistant, callback
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.hassio import is_hassio
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .auth import (
    GitHubAuthError,
    GitHubAuthManager,
    GitHubReauthRequiredError,
)
from .const import (
    CONF_ADDON_POLL_MINUTES,
    CONF_ALLOW_DEV_EDGE,
    CONF_DRY_RUN,
    CONF_INCLUDE_CORE_ADDONS,
    CONF_MIN_OCCURRENCES_ERROR,
    CONF_MIN_OCCURRENCES_WARNING,
    CONF_SKIP_OUTDATED,
    DEFAULT_ADDON_POLL_MINUTES,
    DEFAULT_ALLOW_DEV_EDGE,
    DEFAULT_DRY_RUN,
    DEFAULT_INCLUDE_CORE_ADDONS,
    DEFAULT_MIN_OCCURRENCES_DEPRECATION,
    DEFAULT_MIN_OCCURRENCES_ERROR,
    DEFAULT_MIN_OCCURRENCES_WARNING,
    DEFAULT_SKIP_OUTDATED,
    DOMAIN,
    LOGGER,
    MODE_APPROVAL,
    MODE_DRY_RUN,
    SEVERITY_LEVELS,
    TARGET_INTEGRATION,
)
from .dedup import (
    async_check_github_duplicate,
    compute_fingerprint,
    is_target_outdated,
)
from .discovery import (
    apply_target_policies,
    async_discover_addons,
    async_discover_integrations,
)
from .filters import ErrorFilter
from .github_client import GitHubClient
from .github_types import GitHubNetworkError, GitHubRateLimitError
from .log_monitor import (
    IN_REPORTER_PIPELINE,
    IntegrationLogHandler,
    async_fetch_core_logs,
    async_poll_addon_logs,
    parse_core_log_lines,
)
from .models import LogEvent, PendingDraft, ReporterStats, TargetInfo
from .preview import async_render_preview, build_coordinator_snapshot
from .redactor import PrivacyRedactor
from .repairs import (
    async_clear_draft_repair,
    async_raise_draft_repair,
    async_raise_leak_guard_repair,
)
from .state_store import ReporterStateStore
from .submission import (
    async_flush_retry_queue,
    async_handle_open_comment,
    async_submit_issue,
)
from .template_engine import IssueTemplateEngine


def _is_deterministic_deprecation_warning(event: LogEvent) -> bool:
    """Return True for deterministic HA Core deprecation warnings needing 1x reporting."""
    logger = (event.logger_name or "").lower()
    if logger.startswith("homeassistant.helpers.frame"):
        return True
    if logger.startswith("homeassistant.config_entries"):
        msg = (event.message or "").lower()
        return any(
            kw in msg
            for kw in (
                "deprecat",
                "will stop working",
                "will be removed",
                "detected that custom integration",
            )
        )
    return False


class IssueReporterCoordinator(DataUpdateCoordinator[dict[str, Any]]):
    """Coordinates log monitoring, redaction, deduplication, and issue creation."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        """Initialize the coordinator and sub-components."""
        self.entry = entry
        self.config: dict[str, Any] = {**entry.data, **entry.options}
        poll_minutes = max(
            1, int(self.config.get(CONF_ADDON_POLL_MINUTES, DEFAULT_ADDON_POLL_MINUTES))
        )
        super().__init__(
            hass,
            LOGGER,
            config_entry=entry,
            name=DOMAIN,
            update_interval=timedelta(minutes=poll_minutes),
        )
        session = async_get_clientsession(hass)
        self.auth = GitHubAuthManager(session, self.config)
        self.github = GitHubClient(session, self.auth)
        self.redactor = PrivacyRedactor(self.config)
        self.error_filter = ErrorFilter(self.config)
        self.template_engine = IssueTemplateEngine(self.github)
        self.store = ReporterStateStore(hass, self.config)

        self.targets: dict[str, TargetInfo] = {}
        self._log_handler = IntegrationLogHandler(hass.loop, self._schedule_log_drain)
        self._drain_task: asyncio.Task[None] | None = None
        self._process_lock = asyncio.Lock()
        self._in_flight_fps: set[str] = set()
        self._unsub_dispatcher: CALLBACK_TYPE | None = None
        self._handler_attached = False
        self._last_discovery_at: datetime | None = None

    @property
    def pending_drafts(self) -> dict[str, PendingDraft]:
        """Expose pending drafts from persistent store."""
        return self.store.pending_drafts

    @property
    def stats(self) -> ReporterStats:
        """Expose reporter metrics from persistent store."""
        return self.store.stats

    async def async_setup(self) -> None:
        """Load persisted state, validate auth, discover targets, and start capture."""
        await self.store.async_load()
        try:
            await self.auth.async_initialize()
        except GitHubReauthRequiredError as err:
            raise ConfigEntryAuthFailed(
                "GitHub authentication expired or was revoked"
            ) from err
        except GitHubAuthError as err:
            LOGGER.warning("GitHub initialization warning: %s", err)

        await self.async_refresh_discovery()
        await self.redactor.async_refresh_secrets(self.hass)

        logging.getLogger().addHandler(self._log_handler)
        self._handler_attached = True
        self._unsub_dispatcher = async_dispatcher_connect(
            self.hass, SIGNAL_CONFIG_ENTRY_CHANGED, self._handle_config_entry_changed
        )
        await self._async_startup_backfill()

    async def async_shutdown(self) -> None:
        """Detach log handler, cancel pending tasks, and persist state."""
        if self._handler_attached:
            logging.getLogger().removeHandler(self._log_handler)
            self._handler_attached = False
        if self._unsub_dispatcher is not None:
            self._unsub_dispatcher()
            self._unsub_dispatcher = None
        if self._drain_task is not None and not self._drain_task.done():
            self._drain_task.cancel()
        await self.store.async_save()

    @callback
    def _handle_config_entry_changed(self, *_: Any) -> None:
        """Refresh harvested secrets whenever another config entry changes."""
        self.hass.async_create_task(self.redactor.async_refresh_secrets(self.hass))

    @callback
    def _schedule_log_drain(self) -> None:
        """Debounce live log queue processing to avoid tight loops."""
        if self._drain_task is not None and not self._drain_task.done():
            return
        self._drain_task = self.hass.async_create_task(self._async_debounced_drain())

    async def _async_debounced_drain(self) -> None:
        """Wait briefly to coalesce burst log lines, then process queue."""
        try:
            await asyncio.sleep(2.0)
            await self._async_drain_log_queue()
            if self.store.dirty:
                await self.store.async_save()
                self.async_set_updated_data(self._build_snapshot())
        except asyncio.CancelledError:
            raise
        except Exception as err:
            LOGGER.warning("Error draining integration log queue: %s", err)

    async def _async_startup_backfill(self) -> None:
        """Scan recent core logs once at startup for early component failures."""
        core_lines = await async_fetch_core_logs(self.hass, lines=500)
        if not core_lines:
            return
        events = parse_core_log_lines(core_lines, self._integration_min_levels())
        for ev in events:
            self._log_handler.queue.append(ev)
        if events:
            await self._async_drain_log_queue()
            if self.store.dirty:
                await self.store.async_save()

    def _integration_min_levels(self) -> dict[str, int]:
        """Build mapping of enabled integration:<domain> -> minimum logging levelno."""
        return {
            t.target_key: SEVERITY_LEVELS.get(t.min_severity, 40)
            for t in self.targets.values()
            if t.kind == TARGET_INTEGRATION and t.enabled and t.full_repo
        }

    def _target_min_levelno(self, target: TargetInfo) -> int:
        """Return minimum numeric logging level for target."""
        return SEVERITY_LEVELS.get(target.min_severity, 40)

    async def async_refresh_discovery(self) -> None:
        """Discover installed custom integrations & add-ons and apply policies."""
        integrations = await async_discover_integrations(self.hass)
        include_core = bool(
            self.config.get(CONF_INCLUDE_CORE_ADDONS, DEFAULT_INCLUDE_CORE_ADDONS)
        )
        addons = await async_discover_addons(
            self.hass, self.github, include_core=include_core
        )
        owner = self.auth.get_authenticated_owner()
        self.targets = apply_target_policies(integrations + addons, self.config, owner)
        self.redactor.set_public_targets(self.targets.values(), owner=owner)
        self._log_handler.update_targets(self._integration_min_levels())
        self._last_discovery_at = datetime.now(UTC)

    async def _async_update_data(self) -> dict[str, Any]:
        """Periodic coordinator refresh: discovery, add-on logs, and queue drain."""
        now = datetime.now(UTC)
        if self._last_discovery_at is None or (
            now - self._last_discovery_at
        ) > timedelta(minutes=30):
            await self.async_refresh_discovery()
            await self.redactor.async_refresh_secrets(self.hass)

        addon_states: dict[str, str] = {}
        if is_hassio(self.hass):
            sup = get_supervisor_client(self.hass)
            if sup is not None:
                try:
                    for addon in await sup.addons.list():
                        slug = str(getattr(addon, "slug", "") or "")
                        if slug:
                            addon_states[slug] = str(getattr(addon, "state", "") or "")
                except Exception as err:
                    LOGGER.debug("Failed fetching Supervisor add-on states: %s", err)

        addon_events = await async_poll_addon_logs(
            self.hass,
            self.targets,
            self.store.seen_addon_hashes,
            self._target_min_levelno,
            addon_states=addon_states,
        )
        async with self._process_lock:
            for ev in addon_events:
                await self._async_process_event(ev)

        await self._async_drain_log_queue()
        await async_flush_retry_queue(self)
        self.stats.api_circuit_open = self.github.is_circuit_open
        self.stats.retry_queue_size = len(self.store.retry_queue)
        self.stats.last_scan_at = now.isoformat()
        self.store.dirty = True
        await self.store.async_save()
        return self._build_snapshot()

    async def _async_drain_log_queue(self) -> None:
        """Process all queued integration log events sequentially."""
        async with self._process_lock:
            while self._log_handler.queue:
                ev = self._log_handler.queue.popleft()
                await self._async_process_event(ev)

    async def async_scan_now(self) -> dict[str, Any]:
        """Force immediate discovery, secret refresh, and log scan."""
        await self.async_refresh_discovery()
        await self.redactor.async_refresh_secrets(self.hass)
        return await self._async_update_data()

    async def _async_process_event(self, event: LogEvent) -> str:
        """Filter, redact, deduplicate, template, guard, and route a LogEvent."""
        token = IN_REPORTER_PIPELINE.set(True)
        try:
            return await self._async_process_event_inner(event)
        finally:
            IN_REPORTER_PIPELINE.reset(token)

    async def _async_process_event_inner(self, event: LogEvent) -> str:
        """Inner event processing pipeline protected by re-entrancy guard."""
        target = self.targets.get(event.target_key)
        if target is None or not target.enabled or not target.full_repo:
            return "target_disabled"
        if event.levelno < self._target_min_levelno(target):
            return "below_severity"
        if self.store.is_target_flood_paused(target.target_key):
            self.stats.rate_limited_suppressed += 1
            return "flood_paused"

        ignored, _ = self.error_filter.should_ignore(event)
        if ignored:
            self.stats.filtered_local += 1
            self.store.dirty = True
            return "filtered"

        msg_res = self.redactor.redact(event.message)
        tb_res = self.redactor.redact(event.traceback)
        sanitized_event = LogEvent(
            target_key=event.target_key,
            kind=event.kind,
            logger_name=event.logger_name,
            severity=event.severity,
            levelno=event.levelno,
            message=msg_res.text,
            traceback=tb_res.text,
            exception_type=event.exception_type,
            location=event.location,
            timestamp=event.timestamp,
        )

        fp = compute_fingerprint(target, sanitized_event)
        if (
            fp in self._in_flight_fps
            or fp in self.store.dismissed_fps
            or fp in self.store.retry_queue
            or self.store.is_in_cooldown(fp)
        ):
            self.stats.duplicates_suppressed += 1
            self.store.dirty = True
            return "cooldown"

        self._in_flight_fps.add(fp)
        try:
            return await self._async_process_unique_event(
                target,
                sanitized_event,
                msg_res.text,
                tb_res.text,
                fp,
            )
        finally:
            self._in_flight_fps.discard(fp)

    async def _async_process_unique_event(
        self,
        target: TargetInfo,
        sanitized_event: LogEvent,
        sanitized_msg: str,
        sanitized_tb: str,
        fp: str,
    ) -> str:
        """Process a non-duplicate event through thresholds, dedup, guard, and routing."""
        assert target.full_repo is not None
        if self.store.record_target_unique_event(target.target_key, fp):
            LOGGER.warning(
                "Anti-flood breaker paused %s for 60m after burst of unique errors",
                target.target_key,
            )
            return "flood_paused"

        occurrences, first_seen, last_seen = self.store.record_occurrence(fp)
        if sanitized_event.levelno < 40:
            if _is_deterministic_deprecation_warning(sanitized_event):
                threshold = DEFAULT_MIN_OCCURRENCES_DEPRECATION
            else:
                threshold = int(
                    self.config.get(
                        CONF_MIN_OCCURRENCES_WARNING, DEFAULT_MIN_OCCURRENCES_WARNING
                    )
                )
        else:
            threshold = int(
                self.config.get(
                    CONF_MIN_OCCURRENCES_ERROR, DEFAULT_MIN_OCCURRENCES_ERROR
                )
            )
        if occurrences < max(1, threshold):
            return "below_threshold"

        if not self.store.within_rate_limits(
            target.full_repo,
            target_key=target.target_key,
            is_monorepo=target.is_monorepo,
        ):
            self.stats.rate_limited_suppressed += 1
            self.store.dirty = True
            return "rate_limited"

        if bool(self.config.get(CONF_SKIP_OUTDATED, DEFAULT_SKIP_OUTDATED)):
            allow_dev = bool(
                self.config.get(CONF_ALLOW_DEV_EDGE, DEFAULT_ALLOW_DEV_EDGE)
            )
            if (
                target.kind == TARGET_INTEGRATION
                and target.latest_version is None
                and target.repo_owner
                and target.repo_name
            ):
                target.latest_version = await self.github.async_get_latest_release(
                    target.repo_owner, target.repo_name
                )
            if is_target_outdated(
                target, target.latest_version, allow_dev_edge=allow_dev
            ):
                self.stats.outdated_suppressed += 1
                self.store.set_cooldown(fp)
                return "outdated"

        try:
            dup = await async_check_github_duplicate(
                self.github, target, sanitized_event, fp, self.config
            )
        except (GitHubRateLimitError, GitHubNetworkError) as err:
            self.stats.last_error = str(err)
            LOGGER.debug("Deferred dedup check for %s: %s", target.target_key, err)
            return "github_deferred"

        effective_mode = (
            MODE_DRY_RUN
            if bool(self.config.get(CONF_DRY_RUN, DEFAULT_DRY_RUN))
            else target.mode
        )

        if dup.action in ("skip_open", "skip_closed"):
            self.stats.duplicates_suppressed += 1
            self.store.set_cooldown(fp)
            return dup.action

        if dup.action == "comment_open" and dup.issue_number and dup.comment_body:
            return await async_handle_open_comment(
                self, target, fp, dup.issue_number, dup.comment_body, effective_mode
            )

        rendered = await self.template_engine.async_render_issue(
            self.hass,
            target,
            sanitized_event,
            sanitized_message=sanitized_msg,
            sanitized_traceback=sanitized_tb,
            fingerprint=fp,
            occurrences=occurrences,
            first_seen=first_seen,
            last_seen=last_seen,
            regression_of=dup.issue_number if dup.action == "regression_new" else None,
        )

        passed, reasons = self.redactor.verify_no_leaks(rendered.title, rendered.body)
        if not passed:
            self.stats.leak_guard_blocks += 1
            async_raise_leak_guard_repair(self.hass, target.name, reasons)
            LOGGER.warning(
                "Pre-flight Leak Guard aborted %s (%s)",
                target.target_key,
                ", ".join(reasons),
            )
            self.store.set_cooldown(fp)
            return "leak_guard_blocked"

        if effective_mode in (MODE_DRY_RUN, MODE_APPROVAL):
            draft = PendingDraft(
                draft_id=uuid.uuid4().hex[:10],
                target_key=target.target_key,
                target_name=target.name,
                kind=target.kind,
                repo=rendered.repo,
                title=rendered.title,
                body=rendered.body,
                labels=rendered.labels,
                fingerprint=fp,
                severity=sanitized_event.severity,
                version=target.version,
                created_at=datetime.now(UTC).isoformat(),
                occurrences=occurrences,
                template_used=rendered.template_used,
                dry_run_only=(effective_mode == MODE_DRY_RUN),
            )
            self.store.store_draft(draft)
            if effective_mode == MODE_APPROVAL:
                async_raise_draft_repair(
                    self.hass,
                    draft.draft_id,
                    draft.repo,
                    draft.title,
                    draft.target_name,
                    sanitized_msg,
                )
            self.store.set_cooldown(fp)
            return (
                "dry_run_draft" if effective_mode == MODE_DRY_RUN else "approval_queued"
            )

        return await async_submit_issue(self, target, rendered, fp)

    async def async_approve_draft(self, draft_id: str) -> dict[str, Any]:
        """Re-verify Layer 4 Leak Guard, publish draft to GitHub, and clear Repair."""
        draft = self.pending_drafts.get(draft_id)
        if draft is None:
            raise ValueError(f"Unknown draft ID: {draft_id}")

        passed, reasons = self.redactor.verify_no_leaks(draft.title, draft.body)
        if not passed:
            self.stats.leak_guard_blocks += 1
            async_raise_leak_guard_repair(self.hass, draft.target_name, reasons)
            raise ValueError(
                f"Leak Guard aborted draft {draft_id}: {', '.join(reasons)}"
            )

        owner, repo = draft.repo.split("/", 1)
        created = await self.github.async_create_issue(
            owner, repo, draft.title, draft.body, labels=draft.labels
        )
        self.pending_drafts.pop(draft_id, None)
        async_clear_draft_repair(self.hass, draft_id)
        self.stats.issues_created += 1
        self.stats.last_issue_url = str(created.get("html_url") or "") or None
        self.store.set_cooldown(draft.fingerprint)
        self.store.record_post_rate(draft.repo, target_key=draft.target_key)
        await self.store.async_save()
        self.async_set_updated_data(self._build_snapshot())
        return created

    async def async_dismiss_draft(self, draft_id: str) -> None:
        """Dismiss a draft, record its fingerprint, and clear its Repair."""
        draft = self.pending_drafts.pop(draft_id, None)
        async_clear_draft_repair(self.hass, draft_id)
        if draft is not None:
            self.store.dismissed_fps.add(draft.fingerprint)
            self.store.set_cooldown(draft.fingerprint)
        await self.store.async_save()
        self.async_set_updated_data(self._build_snapshot())

    async def async_clear_cooldowns(self, target_key: str | None = None) -> None:
        """Clear stored cooldowns and dismissals."""
        self.store.clear_cooldowns(target_key)
        await self.store.async_save()
        self.async_set_updated_data(self._build_snapshot())

    async def async_preview_draft(
        self,
        *,
        draft_id: str | None = None,
        target_key: str | None = None,
        sample_message: str | None = None,
        severity: str = "ERROR",
    ) -> dict[str, Any]:
        """Return full sanitized preview + leak guard + duplicate check without posting."""
        return await async_render_preview(
            self,
            draft_id=draft_id,
            target_key=target_key,
            sample_message=sample_message,
            severity=severity,
        )

    def _build_snapshot(self) -> dict[str, Any]:
        """Build sensor-ready coordinator data snapshot."""
        return build_coordinator_snapshot(self)
