"""Persistent state store, cooldowns, and rate limiting for Issue Reporter."""

from __future__ import annotations

import uuid
from collections import deque
from datetime import UTC, datetime, timedelta
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers.storage import Store

from .const import (
    CONF_COOLDOWN_HOURS,
    CONF_MAX_ISSUES_PER_HOUR,
    CONF_MAX_ISSUES_PER_REPO_DAY,
    CONF_OCCURRENCE_WINDOW_MINUTES,
    DEFAULT_COOLDOWN_HOURS,
    DEFAULT_MAX_ISSUES_PER_DAY,
    DEFAULT_MAX_ISSUES_PER_HOUR,
    DEFAULT_MAX_ISSUES_PER_REPO_DAY,
    DEFAULT_OCCURRENCE_WINDOW_MINUTES,
    FLOOD_BREAKER_MAX_UNIQUE,
    FLOOD_BREAKER_PAUSE_MINUTES,
    FLOOD_BREAKER_WINDOW_MINUTES,
    LOGGER,
    MAX_DRAFTS_STORED,
    MAX_RETRY_ATTEMPTS,
    MAX_RETRY_QUEUE_SIZE,
    MAX_SEEN_ADDON_LINES,
    MIN_SUBMISSION_INTERVAL_SECONDS,
    STORAGE_KEY,
    STORAGE_VERSION,
)
from .models import PendingDraft, QueuedSubmission, ReporterStats


def _parse_iso(raw: str) -> datetime:
    """Parse ISO timestamp string safely, returning epoch on failure."""
    try:
        dt = datetime.fromisoformat(raw)
        return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
    except ValueError:
        return datetime.fromtimestamp(0, tz=UTC)


class ReporterStateStore:
    """Manages persistent .storage state, cooldowns, drafts, and rate limits."""

    def __init__(self, hass: HomeAssistant, config: dict[str, Any]) -> None:
        """Initialize persistent store."""
        self._store: Store[dict[str, Any]] = Store(hass, STORAGE_VERSION, STORAGE_KEY)
        self._config = config
        self.pending_drafts: dict[str, PendingDraft] = {}
        self.retry_queue: dict[str, QueuedSubmission] = {}
        self.stats = ReporterStats()
        self.cooldowns: dict[str, str] = {}
        self.dismissed_fps: set[str] = set()
        self.hourly_posts: list[str] = []
        self.daily_posts: list[str] = []
        self.repo_daily_posts: dict[str, list[str]] = {}
        self.occurrence_windows: dict[str, list[datetime]] = {}
        self.seen_addon_hashes: dict[str, deque[str]] = {}
        self.target_paused_until: dict[str, str] = {}
        self._target_unique_fps: dict[str, list[tuple[datetime, str]]] = {}
        self.dirty = False

    def store_draft(self, draft: PendingDraft) -> None:
        """Store draft while keeping bounded history."""
        self.pending_drafts[draft.draft_id] = draft
        while len(self.pending_drafts) > MAX_DRAFTS_STORED:
            oldest = next(iter(self.pending_drafts))
            self.pending_drafts.pop(oldest, None)
        self.dirty = True

    def is_in_cooldown(self, fp: str) -> bool:
        """Check whether fingerprint was handled within cooldown window."""
        ts_raw = self.cooldowns.get(fp)
        if not ts_raw:
            return False
        hours = max(
            1, int(self._config.get(CONF_COOLDOWN_HOURS, DEFAULT_COOLDOWN_HOURS))
        )
        try:
            ts = datetime.fromisoformat(ts_raw)
        except ValueError:
            return False
        if (datetime.now(UTC) - ts) < timedelta(hours=hours):
            return True
        self.cooldowns.pop(fp, None)
        return False

    def set_cooldown(self, fp: str) -> None:
        """Mark fingerprint as recently processed."""
        self.cooldowns[fp] = datetime.now(UTC).isoformat()
        self.dirty = True

    def record_occurrence(self, fp: str) -> tuple[int, str, str]:
        """Track occurrence count inside sliding window."""
        now = datetime.now(UTC)
        win_mins = max(
            1,
            int(
                self._config.get(
                    CONF_OCCURRENCE_WINDOW_MINUTES, DEFAULT_OCCURRENCE_WINDOW_MINUTES
                )
            ),
        )
        cutoff = now - timedelta(minutes=win_mins)
        stamps = [t for t in self.occurrence_windows.get(fp, []) if t >= cutoff]
        stamps.append(now)
        self.occurrence_windows[fp] = stamps
        return len(stamps), stamps[0].isoformat(), stamps[-1].isoformat()

    def within_rate_limits(self, full_repo: str) -> bool:
        """Enforce global hourly, global daily, and per-repo daily submission limits."""
        now = datetime.now(UTC)
        hour_ago = now - timedelta(hours=1)
        day_ago = now - timedelta(days=1)

        self.hourly_posts = [
            ts for ts in self.hourly_posts if _parse_iso(ts) >= hour_ago
        ]
        max_hour = max(
            1,
            int(
                self._config.get(CONF_MAX_ISSUES_PER_HOUR, DEFAULT_MAX_ISSUES_PER_HOUR)
            ),
        )
        if len(self.hourly_posts) >= max_hour:
            return False

        self.daily_posts = [ts for ts in self.daily_posts if _parse_iso(ts) >= day_ago]
        if len(self.daily_posts) >= DEFAULT_MAX_ISSUES_PER_DAY:
            return False

        repo_list = [
            ts
            for ts in self.repo_daily_posts.get(full_repo.lower(), [])
            if _parse_iso(ts) >= day_ago
        ]
        self.repo_daily_posts[full_repo.lower()] = repo_list
        max_repo_day = max(
            1,
            int(
                self._config.get(
                    CONF_MAX_ISSUES_PER_REPO_DAY, DEFAULT_MAX_ISSUES_PER_REPO_DAY
                )
            ),
        )
        return len(repo_list) < max_repo_day

    def is_submission_spaced(self) -> bool:
        """Return True if minimum interval since last live GitHub write has elapsed."""
        if not self.hourly_posts:
            return True
        last_ts = _parse_iso(self.hourly_posts[-1])
        return (datetime.now(UTC) - last_ts) >= timedelta(
            seconds=MIN_SUBMISSION_INTERVAL_SECONDS
        )

    def is_target_flood_paused(self, target_key: str) -> bool:
        """Return True if target is temporarily paused by the anti-flood breaker."""
        raw = self.target_paused_until.get(target_key)
        if not raw:
            return False
        if datetime.now(UTC) < _parse_iso(raw):
            return True
        self.target_paused_until.pop(target_key, None)
        self.dirty = True
        return False

    def record_target_unique_event(self, target_key: str, fp: str) -> bool:
        """Track unique fingerprints per target; pause target on crash-loop storm."""
        now = datetime.now(UTC)
        cutoff = now - timedelta(minutes=FLOOD_BREAKER_WINDOW_MINUTES)
        entries = [
            (ts, f)
            for ts, f in self._target_unique_fps.get(target_key, [])
            if ts >= cutoff
        ]
        if not any(f == fp for _, f in entries):
            entries.append((now, fp))
        self._target_unique_fps[target_key] = entries
        if len(entries) >= FLOOD_BREAKER_MAX_UNIQUE:
            pause_until = now + timedelta(minutes=FLOOD_BREAKER_PAUSE_MINUTES)
            self.target_paused_until[target_key] = pause_until.isoformat()
            self.dirty = True
            return True
        return False

    def enqueue_retry(
        self,
        *,
        kind: str,
        target_key: str,
        repo: str,
        fingerprint: str,
        title: str,
        body: str,
        labels: list[str] | None = None,
        issue_number: int | None = None,
        error: str = "",
        reset_at: datetime | None = None,
    ) -> QueuedSubmission:
        """Buffer failed issue/comment in persistent outbox with exponential backoff."""
        now = datetime.now(UTC)
        existing = self.retry_queue.get(fingerprint)
        attempts = (existing.attempts + 1) if existing else 1
        backoff_secs = [120, 600, 1800, 7200, 21600][min(attempts - 1, 4)]
        next_at = now + timedelta(seconds=backoff_secs)
        if reset_at is not None:
            candidate = reset_at + timedelta(seconds=5)
            if candidate > next_at:
                next_at = candidate

        item = QueuedSubmission(
            queue_id=existing.queue_id if existing else uuid.uuid4().hex[:10],
            kind=kind,
            target_key=target_key,
            repo=repo,
            fingerprint=fingerprint,
            title=title,
            body=body,
            labels=list(labels or []),
            issue_number=issue_number,
            created_at=existing.created_at if existing else now.isoformat(),
            next_retry_at=next_at.isoformat(),
            attempts=attempts,
            last_error=error[:240],
        )
        self.retry_queue[fingerprint] = item
        while len(self.retry_queue) > MAX_RETRY_QUEUE_SIZE:
            oldest = next(iter(self.retry_queue))
            self.retry_queue.pop(oldest, None)
        self.stats.retry_queue_size = len(self.retry_queue)
        self.dirty = True
        return item

    def due_retries(self, limit: int = 3) -> list[QueuedSubmission]:
        """Return up to `limit` buffered submissions ready for retry."""
        now = datetime.now(UTC)
        due: list[QueuedSubmission] = []
        for fp, item in list(self.retry_queue.items()):
            if item.attempts >= MAX_RETRY_ATTEMPTS:
                self.retry_queue.pop(fp, None)
                self.dirty = True
                continue
            if _parse_iso(item.next_retry_at) <= now:
                due.append(item)
                if len(due) >= limit:
                    break
        self.stats.retry_queue_size = len(self.retry_queue)
        return due

    def remove_retry(self, fingerprint: str) -> None:
        """Remove a buffered submission after successful delivery or permanent drop."""
        if self.retry_queue.pop(fingerprint, None) is not None:
            self.stats.retry_queue_size = len(self.retry_queue)
            self.dirty = True

    def record_post_rate(self, full_repo: str) -> None:
        """Record timestamp of a created GitHub issue or comment for rate limiting."""
        now_iso = datetime.now(UTC).isoformat()
        self.hourly_posts.append(now_iso)
        self.daily_posts.append(now_iso)
        self.repo_daily_posts.setdefault(full_repo.lower(), []).append(now_iso)
        self.dirty = True

    def clear_cooldowns(self, target_key: str | None = None) -> None:
        """Clear cooldowns, occurrence windows, and optionally dismissals."""
        if target_key is None:
            self.cooldowns.clear()
            self.dismissed_fps.clear()
            self.occurrence_windows.clear()
        else:
            self.cooldowns.clear()
            self.occurrence_windows.clear()
        self.dirty = True

    async def async_load(self) -> None:
        """Restore persisted coordinator state from .storage."""
        data = await self._store.async_load()
        if not isinstance(data, dict):
            return
        self.cooldowns = dict(data.get("cooldowns") or {})
        self.dismissed_fps = set(data.get("dismissed_fps") or [])
        self.hourly_posts = list(data.get("hourly_posts") or [])
        self.daily_posts = list(data.get("daily_posts") or [])
        self.repo_daily_posts = {
            str(k): list(v) for k, v in (data.get("repo_daily_posts") or {}).items()
        }
        self.target_paused_until = {
            str(k): str(v) for k, v in (data.get("target_paused_until") or {}).items()
        }
        for fp_key, q_raw in (data.get("retry_queue") or {}).items():
            try:
                self.retry_queue[str(fp_key)] = QueuedSubmission.from_dict(q_raw)
            except Exception as err:
                LOGGER.debug("Skipping invalid stored retry item: %s", err)
        for d_raw in (data.get("pending_drafts") or {}).values():
            try:
                draft = PendingDraft.from_dict(d_raw)
                self.pending_drafts[draft.draft_id] = draft
            except Exception as err:
                LOGGER.debug("Skipping invalid stored draft: %s", err)
        for slug, hashes in (data.get("seen_addon_hashes") or {}).items():
            self.seen_addon_hashes[str(slug)] = deque(
                [str(h) for h in hashes], maxlen=MAX_SEEN_ADDON_LINES
            )
        st = data.get("stats") or {}
        self.stats = ReporterStats(
            issues_created=int(st.get("issues_created", 0)),
            comments_posted=int(st.get("comments_posted", 0)),
            duplicates_suppressed=int(st.get("duplicates_suppressed", 0)),
            outdated_suppressed=int(st.get("outdated_suppressed", 0)),
            filtered_local=int(st.get("filtered_local", 0)),
            rate_limited_suppressed=int(st.get("rate_limited_suppressed", 0)),
            leak_guard_blocks=int(st.get("leak_guard_blocks", 0)),
            retry_queue_size=len(self.retry_queue),
            last_issue_url=st.get("last_issue_url"),
            last_scan_at=st.get("last_scan_at"),
        )

    async def async_save(self) -> None:
        """Persist coordinator state to .storage."""
        payload = {
            "cooldowns": self.cooldowns,
            "dismissed_fps": sorted(self.dismissed_fps),
            "hourly_posts": self.hourly_posts[-100:],
            "daily_posts": self.daily_posts[-200:],
            "repo_daily_posts": self.repo_daily_posts,
            "target_paused_until": self.target_paused_until,
            "retry_queue": {k: v.to_dict() for k, v in self.retry_queue.items()},
            "pending_drafts": {k: v.to_dict() for k, v in self.pending_drafts.items()},
            "seen_addon_hashes": {
                k: list(v) for k, v in self.seen_addon_hashes.items()
            },
            "stats": {
                "issues_created": self.stats.issues_created,
                "comments_posted": self.stats.comments_posted,
                "duplicates_suppressed": self.stats.duplicates_suppressed,
                "outdated_suppressed": self.stats.outdated_suppressed,
                "filtered_local": self.stats.filtered_local,
                "rate_limited_suppressed": self.stats.rate_limited_suppressed,
                "leak_guard_blocks": self.stats.leak_guard_blocks,
                "last_issue_url": self.stats.last_issue_url,
                "last_scan_at": self.stats.last_scan_at,
            },
        }
        await self._store.async_save(payload)
        self.dirty = False
