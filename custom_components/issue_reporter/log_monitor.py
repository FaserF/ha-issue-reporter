"""Dual log monitoring engine for HA custom integrations and Supervisor add-ons."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import traceback as tb_mod
from collections import deque
from collections.abc import Callable
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers.hassio import is_hassio

from .const import (
    LOGGER,
    MAX_LOG_CHARS,
    MAX_LOG_QUEUE_SIZE,
    MAX_SEEN_ADDON_LINES,
    MAX_TRACEBACK_LINES,
    TARGET_ADDON,
    TARGET_INTEGRATION,
)
from .models import LogEvent, TargetInfo

IN_REPORTER_PIPELINE: ContextVar[bool] = ContextVar(
    "issue_reporter_in_pipeline", default=False
)

_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
_CUSTOM_LOGGER_RE = re.compile(r"^custom_components\.([a-z0-9_]+)(?:\.|$)")
_BLAME_INTEGRATION_RE = re.compile(
    r"custom integration '([a-z0-9_]+)'|"
    r"author of the '([a-z0-9_]+)' custom integration|"
    r"was used from ([a-z0-9_]+)|"
    r"custom_components\.([a-z0-9_]+)"
)
_CORE_LOG_LINE_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z)?)\s+"
    r"(WARNING|ERROR|CRITICAL)\s+\([^)]+\)\s+\[([^\]]+)\]\s*(.*)$"
)
_EXC_TYPE_RE = re.compile(
    r"\b([A-Z][A-Za-z0-9]+(?:Error|Exception|Warning|Timeout|Fault))\b"
)
_TS_PREFIX = (
    r"(?:\[?\d{4}[-/]\d{2}[-/]\d{2}(?:[T\s]\d{2}:\d{2}:\d{2}"
    r"(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)?\]?\s+)?"
    r"(?:\[\d{2}:\d{2}:\d{2}\]\s+)?"
)
_ADDON_BENIGN_LEVEL_RE = re.compile(
    rf"^{_TS_PREFIX}(?:[A-Za-z0-9_.-]+:\s+)?"
    r"(?:\[(?:info|notice|debug|trace)\]|"
    r"(?:INFO|NOTICE|DEBUG|TRACE)\s*[:|-]|"
    r"\b(?:INFO|NOTICE|DEBUG|TRACE)\b(?:\s|$))",
    re.IGNORECASE,
)
_ADDON_TEXT_LEVEL_RE = re.compile(
    r"(?i:\[(CRITICAL|FATAL|CRIT|ERROR|ERR|WARNING|WARN|PANIC)\])|"
    r"(?:^|\s)(CRITICAL|FATAL|ERROR|WARNING|PANIC)(?:\s*[:|-]|\s)|"
    rf"^{_TS_PREFIX}(?i:(critical|fatal|crit|error|err|warning|warn|panic))\s*[:|-]"
)
_UNPREFIXED_ADDON_ERROR_RE = re.compile(
    rf"^{_TS_PREFIX}"
    r"(?:"
    r"[A-Za-z0-9_./-][A-Za-z0-9_ ./-]{2,80}\s+failed:(?:\s+\S.*)?$|"
    r"failed\s+to\s+[^:\n]+:\s*\S.*$|"
    r"[A-Z][A-Za-z0-9]+(?:Error|Exception|Fault):\s+\S.*"
    r")",
    re.IGNORECASE,
)
_BENIGN_FAILED_ZERO_RE = re.compile(r"\bfailed\s*[:=]\s*0\b", re.IGNORECASE)
_STACK_START_RE = re.compile(
    r"^(?:Traceback \(most recent call last\):|UnhandledPromiseRejection|panic:|fatal error:)",
    re.IGNORECASE,
)
_STACK_CONT_RE = re.compile(r"^(?:\s{2,}|\t|File \"|Caused by:|goroutine \d+|at )")

_PINO_LEVEL_MAP: dict[int, tuple[int, str]] = {
    10: (logging.DEBUG, "DEBUG"),
    20: (logging.DEBUG, "DEBUG"),
    30: (logging.INFO, "INFO"),
    40: (logging.WARNING, "WARNING"),
    50: (logging.ERROR, "ERROR"),
    60: (logging.CRITICAL, "CRITICAL"),
}

_STR_LEVEL_MAP: dict[str, tuple[int, str]] = {
    "trace": (logging.DEBUG, "DEBUG"),
    "debug": (logging.DEBUG, "DEBUG"),
    "info": (logging.INFO, "INFO"),
    "warn": (logging.WARNING, "WARNING"),
    "warning": (logging.WARNING, "WARNING"),
    "err": (logging.ERROR, "ERROR"),
    "error": (logging.ERROR, "ERROR"),
    "fatal": (logging.CRITICAL, "CRITICAL"),
    "crit": (logging.CRITICAL, "CRITICAL"),
    "critical": (logging.CRITICAL, "CRITICAL"),
    "panic": (logging.CRITICAL, "CRITICAL"),
}


def _level_name(levelno: int) -> str:
    """Map numeric logging level to standard severity label."""
    if levelno >= logging.CRITICAL:
        return "CRITICAL"
    if levelno >= logging.ERROR:
        return "ERROR"
    return "WARNING"


def _extract_exception_type(message: str, traceback_text: str) -> str:
    """Extract likely exception or fault class name from message/traceback."""
    for source in (traceback_text, message):
        if not source:
            continue
        for line in reversed(source.splitlines()):
            match = _EXC_TYPE_RE.search(line)
            if match:
                return match.group(1)
    return ""


def _trim_traceback(raw_tb: str) -> str:
    """Keep traceback bounded for GitHub issue payload safety."""
    if not raw_tb:
        return ""
    lines = raw_tb.splitlines()
    if len(lines) > MAX_TRACEBACK_LINES:
        lines = lines[-MAX_TRACEBACK_LINES:]
    joined = "\n".join(lines)
    if len(joined) > MAX_LOG_CHARS:
        return joined[-MAX_LOG_CHARS:]
    return joined


def _resolve_domain_from_record(record: logging.LogRecord, message: str) -> str | None:
    """Identify custom integration domain from logger name, HA frame warning, or traceback."""
    logger_name = record.name or ""
    match = _CUSTOM_LOGGER_RE.match(logger_name)
    if match:
        return match.group(1)

    if logger_name == "homeassistant.components" or logger_name.startswith(
        (
            "homeassistant.helpers.frame",
            "homeassistant.helpers.entity",
            "homeassistant.setup",
            "homeassistant.config_entries",
            "homeassistant.loader",
            "homeassistant.bootstrap",
            "homeassistant.components.",
        )
    ):
        blame = _BLAME_INTEGRATION_RE.search(message)
        if blame:
            return blame.group(1) or blame.group(2) or blame.group(3) or blame.group(4)

    if record.levelno >= logging.ERROR and record.exc_info and record.exc_info[2]:
        tb_obj = record.exc_info[2]
        for frame in tb_mod.extract_tb(tb_obj):
            if "custom_components" in frame.filename:
                parts = frame.filename.replace("\\", "/").split("/custom_components/")
                if len(parts) > 1:
                    dom = parts[1].split("/", 1)[0]
                    if dom:
                        return dom
    return None


class IntegrationLogHandler(logging.Handler):
    """Low-overhead in-memory logging handler with O(1) active-target filtering."""

    def __init__(
        self,
        loop: asyncio.AbstractEventLoop,
        on_event: Callable[[], None],
    ) -> None:
        """Initialize handler bound to Home Assistant's event loop."""
        super().__init__(level=logging.WARNING)
        self._loop = loop
        self._on_event = on_event
        self._active_levels: dict[str, int] = {}
        self._min_global_level: int = logging.CRITICAL + 10
        self.queue: deque[LogEvent] = deque(maxlen=MAX_LOG_QUEUE_SIZE)

    def update_targets(self, active_levels: dict[str, int]) -> None:
        """Update map of enabled integration:<domain> -> minimum levelno."""
        self._active_levels = dict(active_levels)
        self._min_global_level = (
            min(active_levels.values()) if active_levels else logging.CRITICAL + 10
        )

    def emit(self, record: logging.LogRecord) -> None:
        """Fast-path filter and enqueue matching custom integration events."""
        if record.levelno < self._min_global_level or IN_REPORTER_PIPELINE.get():
            return

        try:
            message = record.getMessage()
        except Exception:
            message = str(record.msg)

        # Loop-breaker: never self-report issue_reporter submission/guard meta-errors
        if record.name.startswith("custom_components.issue_reporter") and any(
            skip in message
            for skip in (
                "Pre-flight Leak Guard aborted",
                "Failed creating issue on",
                "Failed posting version comment",
                "Error draining integration log queue",
            )
        ):
            return

        domain = _resolve_domain_from_record(record, message)
        if not domain:
            return

        target_key = f"{TARGET_INTEGRATION}:{domain}"
        required_level = self._active_levels.get(target_key)
        if required_level is None or record.levelno < required_level:
            return

        raw_tb = ""
        if record.exc_info and record.exc_info[0] is not None:
            raw_tb = _trim_traceback("".join(tb_mod.format_exception(*record.exc_info)))

        exc_type = (
            record.exc_info[0].__name__
            if record.exc_info and record.exc_info[0] is not None
            else _extract_exception_type(message, raw_tb)
        )
        location = f"{record.pathname}:{record.lineno}" if record.pathname else ""
        event = LogEvent(
            target_key=target_key,
            kind=TARGET_INTEGRATION,
            logger_name=record.name,
            severity=_level_name(record.levelno),
            levelno=record.levelno,
            message=message[:MAX_LOG_CHARS],
            traceback=raw_tb,
            exception_type=exc_type,
            location=location,
            timestamp=datetime.now(UTC).isoformat(),
        )
        self.queue.append(event)
        try:
            self._loop.call_soon_threadsafe(self._on_event)
        except RuntimeError:
            LOGGER.debug("Event loop closed while scheduling log processing")


def parse_core_log_lines(
    lines: list[str],
    active_levels: dict[str, int],
) -> list[LogEvent]:
    """Parse recent HA core log lines (used once at startup backfill)."""
    if not active_levels:
        return []

    events: list[LogEvent] = []
    current: dict[str, Any] | None = None

    def _flush() -> None:
        nonlocal current
        if current is None:
            return
        tb_text = _trim_traceback("\n".join(current["tb_lines"]))
        msg = current["message"]
        events.append(
            LogEvent(
                target_key=current["target_key"],
                kind=TARGET_INTEGRATION,
                logger_name=current["logger"],
                severity=current["severity"],
                levelno=current["levelno"],
                message=msg[:MAX_LOG_CHARS],
                traceback=tb_text,
                exception_type=_extract_exception_type(msg, tb_text),
                timestamp=current["timestamp"],
            )
        )
        current = None

    for raw in lines:
        clean = _ANSI_ESCAPE_RE.sub("", raw).rstrip("\r\n")
        match = _CORE_LOG_LINE_RE.match(clean)
        if match:
            _flush()
            ts, sev_str, logger_name, msg = match.groups()
            levelno = getattr(logging, sev_str, logging.ERROR)
            dom_match = _CUSTOM_LOGGER_RE.match(logger_name)
            domain = dom_match.group(1) if dom_match else None
            if not domain:
                blame = _BLAME_INTEGRATION_RE.search(msg)
                if blame:
                    domain = (
                        blame.group(1)
                        or blame.group(2)
                        or blame.group(3)
                        or blame.group(4)
                    )
            if not domain:
                continue
            target_key = f"{TARGET_INTEGRATION}:{domain}"
            req_level = active_levels.get(target_key)
            if req_level is None or levelno < req_level:
                continue
            current = {
                "target_key": target_key,
                "logger": logger_name,
                "severity": _level_name(levelno),
                "levelno": levelno,
                "message": msg,
                "tb_lines": [],
                "timestamp": ts,
            }
        elif current is not None and (
            _STACK_CONT_RE.match(clean)
            or clean.startswith("Traceback ")
            or _EXC_TYPE_RE.match(clean)
        ):
            current["tb_lines"].append(clean)
        else:
            _flush()

    _flush()
    return events


def _parse_json_log_line(clean: str) -> tuple[int, str, str, str] | None:
    """Parse structured JSON log (slog/zerolog/Pino) into (levelno, sev, msg, tb)."""
    try:
        obj = json.loads(clean)
    except ValueError:
        return None
    if not isinstance(obj, dict):
        return None

    raw_lvl = obj.get("level", obj.get("lvl", obj.get("severity")))
    mapped: tuple[int, str] | None = None
    if isinstance(raw_lvl, int):
        mapped = _PINO_LEVEL_MAP.get(raw_lvl)
    elif isinstance(raw_lvl, str):
        if raw_lvl.isdigit():
            mapped = _PINO_LEVEL_MAP.get(int(raw_lvl))
        else:
            mapped = _STR_LEVEL_MAP.get(raw_lvl.strip().lower())

    if mapped is None:
        return None

    levelno, sev_str = mapped
    msg = str(obj.get("msg") or obj.get("message") or obj.get("event") or "").strip()
    err_detail = str(obj.get("error") or obj.get("err") or "").strip()
    stack = str(obj.get("stack") or obj.get("traceback") or "").strip()
    if err_detail and err_detail not in msg:
        msg = f"{msg}: {err_detail}" if msg else err_detail
    if not msg:
        msg = clean[:300]
    return levelno, sev_str, msg, _trim_traceback(stack)


def parse_addon_log_lines(
    target: TargetInfo,
    raw_text: str,
    min_levelno: int,
    seen_hashes: deque[str],
) -> list[LogEvent]:
    """Parse multi-format Supervisor add-on logs into deduplicated LogEvents."""
    if not raw_text:
        return []

    events: list[LogEvent] = []
    pending_text: dict[str, Any] | None = None

    def _flush_pending() -> None:
        nonlocal pending_text
        if pending_text is None:
            return
        tb_text = _trim_traceback("\n".join(pending_text["tb_lines"]))
        msg = pending_text["message"]
        events.append(
            LogEvent(
                target_key=target.target_key,
                kind=TARGET_ADDON,
                logger_name=f"addon.{target.short_name}",
                severity=pending_text["severity"],
                levelno=pending_text["levelno"],
                message=msg[:MAX_LOG_CHARS],
                traceback=tb_text,
                exception_type=_extract_exception_type(msg, tb_text),
                timestamp=datetime.now(UTC).isoformat(),
            )
        )
        pending_text = None

    for raw in raw_text.splitlines():
        clean = _ANSI_ESCAPE_RE.sub("", raw).rstrip("\r\n")
        stripped = clean.strip()
        if not stripped:
            continue

        line_hash = hashlib.sha1(stripped.encode("utf-8", errors="ignore")).hexdigest()[
            :12
        ]
        already_seen = line_hash in seen_hashes
        if not already_seen:
            seen_hashes.append(line_hash)

        if pending_text is not None and (
            _STACK_CONT_RE.match(clean)
            or _EXC_TYPE_RE.match(stripped)
            or stripped.startswith("Traceback ")
        ):
            pending_text["tb_lines"].append(clean)
            continue

        if already_seen:
            _flush_pending()
            continue

        if stripped.startswith("{"):
            _flush_pending()
            parsed_json = _parse_json_log_line(stripped)
            if parsed_json is not None:
                lvl, sev_str, msg, stack = parsed_json
                if lvl >= min_levelno:
                    events.append(
                        LogEvent(
                            target_key=target.target_key,
                            kind=TARGET_ADDON,
                            logger_name=f"addon.{target.short_name}",
                            severity=sev_str,
                            levelno=lvl,
                            message=msg[:MAX_LOG_CHARS],
                            traceback=stack,
                            exception_type=_extract_exception_type(msg, stack),
                            timestamp=datetime.now(UTC).isoformat(),
                        )
                    )
            continue

        _flush_pending()

        if _ADDON_BENIGN_LEVEL_RE.match(stripped):
            continue

        lvl_match = _ADDON_TEXT_LEVEL_RE.search(stripped)
        if lvl_match:
            token = next(g for g in lvl_match.groups() if g is not None).lower()
            lvl, sev_str = _STR_LEVEL_MAP.get(token, (logging.ERROR, "ERROR"))
            if lvl >= min_levelno:
                pending_text = {
                    "levelno": lvl,
                    "severity": sev_str,
                    "message": stripped,
                    "tb_lines": [],
                }
        elif (
            _UNPREFIXED_ADDON_ERROR_RE.match(stripped)
            and not _BENIGN_FAILED_ZERO_RE.search(stripped)
            and logging.ERROR >= min_levelno
        ):
            pending_text = {
                "levelno": logging.ERROR,
                "severity": "ERROR",
                "message": stripped,
                "tb_lines": [],
            }
        elif _STACK_START_RE.match(stripped) and logging.ERROR >= min_levelno:
            pending_text = {
                "levelno": logging.ERROR,
                "severity": "ERROR",
                "message": stripped,
                "tb_lines": [],
            }

    _flush_pending()
    return events


async def async_fetch_core_logs(hass: HomeAssistant, lines: int = 500) -> list[str]:
    """Read recent Home Assistant Core logs via Supervisor API when running on HAOS."""
    if not is_hassio(hass):
        return []
    hassio = hass.data.get("hassio")
    if hassio is None:
        return []
    try:
        raw = await hassio.send_command(
            "/core/logs/latest",
            method="get",
            return_text=True,
            timeout=15,
            params={"lines": lines},
        )
        return str(raw).splitlines() if raw else []
    except Exception as err:
        LOGGER.debug("Core log backfill unavailable: %s", err)
        return []


async def async_poll_addon_logs(
    hass: HomeAssistant,
    targets: dict[str, TargetInfo],
    seen_map: dict[str, deque[str]],
    min_level_resolver: Callable[[TargetInfo], int],
    *,
    addon_states: dict[str, str] | None = None,
) -> list[LogEvent]:
    """Poll incremental logs and error states for enabled Supervisor add-ons."""
    if not is_hassio(hass):
        return []
    hassio = hass.data.get("hassio")
    if hassio is None:
        return []

    collected: list[LogEvent] = []
    for target in targets.values():
        if target.kind != TARGET_ADDON or not target.enabled:
            continue
        min_lvl = min_level_resolver(target)
        seen_hashes = seen_map.setdefault(
            target.identifier, deque(maxlen=MAX_SEEN_ADDON_LINES)
        )

        raw_text = ""
        for endpoint in (
            f"/addons/{target.identifier}/logs/latest",
            f"/addons/{target.identifier}/logs",
        ):
            try:
                resp = await hassio.send_command(
                    endpoint,
                    method="get",
                    return_text=True,
                    timeout=15,
                    params={"lines": 200},
                )
                raw_text = str(resp or "")
                break
            except Exception as err:
                LOGGER.debug("Log fetch on %s failed (%s)", endpoint, err)

        parsed = parse_addon_log_lines(target, raw_text, min_lvl, seen_hashes)
        if parsed:
            collected.extend(parsed)
        elif (
            addon_states
            and addon_states.get(target.identifier) == "error"
            and logging.ERROR >= min_lvl
        ):
            tail_excerpt = "\n".join(
                _ANSI_ESCAPE_RE.sub("", line) for line in raw_text.splitlines()[-30:]
            ).strip()
            collected.append(
                LogEvent(
                    target_key=target.target_key,
                    kind=TARGET_ADDON,
                    logger_name=f"addon.{target.short_name}",
                    severity="ERROR",
                    levelno=logging.ERROR,
                    message=f"Supervisor reports add-on '{target.name}' ({target.identifier}) is in error state",
                    traceback=tail_excerpt
                    or "No container error output returned by Supervisor logs endpoint.",
                    exception_type="AddonStateError",
                    timestamp=datetime.now(UTC).isoformat(),
                )
            )

    return collected
