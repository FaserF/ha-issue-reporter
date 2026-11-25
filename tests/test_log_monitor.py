"""Tests for dual HA integration + Supervisor add-on log monitoring."""

from __future__ import annotations

import asyncio
import logging
from collections import deque

from custom_components.issue_reporter.log_monitor import (
    IN_REPORTER_PIPELINE,
    IntegrationLogHandler,
    parse_addon_log_lines,
    parse_core_log_lines,
)
from custom_components.issue_reporter.models import TargetInfo


async def test_integration_log_handler_fast_path_and_frame_blame() -> None:
    """Test in-memory handler captures enabled integrations and ignores self/unmonitored."""
    loop = asyncio.get_running_loop()
    notified = 0

    def on_event() -> None:
        nonlocal notified
        notified += 1

    handler = IntegrationLogHandler(loop, on_event)
    handler.update_targets(
        {
            "integration:issue_reporter": logging.ERROR,
            "integration:aegisbot": logging.WARNING,
            "integration:openwrt": logging.ERROR,
        }
    )

    # 1a. Self-monitoring captures genuine errors from issue_reporter
    self_rec = logging.LogRecord(
        "custom_components.issue_reporter.discovery",
        logging.ERROR,
        __file__,
        10,
        "Unexpected discovery bug",
        None,
        None,
    )
    handler.emit(self_rec)
    assert len(handler.queue) == 1
    assert handler.queue[0].target_key == "integration:issue_reporter"
    handler.queue.clear()

    # 1b. Self-loop prevention: pipeline re-entrancy guard & loop-breaker messages
    token = IN_REPORTER_PIPELINE.set(True)
    try:
        handler.emit(self_rec)
    finally:
        IN_REPORTER_PIPELINE.reset(token)
    assert len(handler.queue) == 0

    leak_rec = logging.LogRecord(
        "custom_components.issue_reporter.coordinator",
        logging.ERROR,
        __file__,
        12,
        "Pre-flight Leak Guard aborted issue creation",
        None,
        None,
    )
    handler.emit(leak_rec)
    assert len(handler.queue) == 0

    # 2. Below target severity (WARNING on ERROR-only openwrt)
    warn_rec = logging.LogRecord(
        "custom_components.openwrt.coordinator",
        logging.WARNING,
        __file__,
        20,
        "Minor warning",
        None,
        None,
    )
    handler.emit(warn_rec)
    assert len(handler.queue) == 0

    # 3. HA Core frame warning blaming custom integration 'aegisbot'
    frame_rec = logging.LogRecord(
        "homeassistant.helpers.frame",
        logging.WARNING,
        __file__,
        30,
        "Detected that custom integration 'aegisbot' calls deprecated via_device",
        None,
        None,
    )
    handler.emit(frame_rec)
    assert len(handler.queue) == 1
    assert handler.queue[0].target_key == "integration:aegisbot"

    # 4. Standard custom integration error with exception
    try:
        raise ValueError("Broken parser")
    except ValueError as err:
        err_rec = logging.LogRecord(
            "custom_components.openwrt.api",
            logging.ERROR,
            __file__,
            40,
            "OpenWrt parse error",
            None,
            (type(err), err, err.__traceback__),
        )
        handler.emit(err_rec)

    assert len(handler.queue) == 2
    assert handler.queue[1].exception_type == "ValueError"
    assert "ValueError: Broken parser" in handler.queue[1].traceback


def test_parse_core_log_lines_backfill() -> None:
    """Test startup backfill parser on HA Core log format."""
    lines = [
        "2026-11-24 10:21:58.959+01:00 WARNING (MainThread) [homeassistant.helpers.frame] Detected that custom integration 'aegisbot' calls deprecated via_device",
        "2026-11-24 10:22:00.000+01:00 ERROR (MainThread) [custom_components.openwrt.sensor] Update failed",
        "Traceback (most recent call last):",
        '  File "/config/custom_components/openwrt/sensor.py", line 10, in async_update',
        "KeyError: 'missing_key'",
        "2026-11-24 10:22:01.000+01:00 ERROR (MainThread) [homeassistant.components.sonarr] Core integration error",
    ]
    events = parse_core_log_lines(
        lines,
        {"integration:aegisbot": logging.WARNING, "integration:openwrt": logging.ERROR},
    )
    assert len(events) == 2
    assert events[0].target_key == "integration:aegisbot"
    assert events[1].target_key == "integration:openwrt"
    assert events[1].exception_type == "KeyError"
    assert "KeyError: 'missing_key'" in events[1].traceback


def test_parse_addon_log_lines_json_pino_ansi_and_tracebacks() -> None:
    """Test JSON/Pino level filtering, ANSI stripping, and repeated traceback stitching."""
    target = TargetInfo(
        target_key="addon:edfe50eb_paseo",
        kind="addon",
        identifier="edfe50eb_paseo",
        short_name="paseo",
        name="Paseo",
        version="0.3.2",
        repo_owner="FaserF",
        repo_name="hassio-addons",
        repo_url="https://github.com/FaserF/hassio-addons",
    )
    seen: deque[str] = deque(maxlen=100)

    raw_logs = "\n".join(
        [
            # Pino level 30 INFO with "failed": 0 MUST be ignored!
            '{"level":30,"time":1795511692946,"msg":"ws_runtime_metrics","git":{"commands":{"failed":0}}}',
            # Go slog WARN should be ignored when min_level is ERROR
            '{"time":"2026-11-24T08:52:52Z","level":"WARN","msg":"Minor retry"}',
            # Pino level 50 ERROR must be captured
            '{"level":50,"time":1795511699999,"msg":"Daemon crash","err":"EADDRINUSE"}',
            # Colored ANSI traceback block
            "\x1b[31m2026-11-24 10:00:00 [ERROR] worker: Crash on step 1\x1b[0m",
            "Traceback (most recent call last):",
            '  File "/app/main.py", line 42, in run',
            "RuntimeError: Bad state",
            # Repeated traceback on new timestamp must STILL keep full traceback lines
            "2026-11-24 10:05:00 [ERROR] worker: Crash on step 2",
            "Traceback (most recent call last):",
            '  File "/app/main.py", line 42, in run',
            "RuntimeError: Bad state",
        ]
    )

    events = parse_addon_log_lines(target, raw_logs, logging.ERROR, seen)
    assert len(events) == 3
    assert "Daemon crash: EADDRINUSE" in events[0].message
    assert "Crash on step 1" in events[1].message
    assert "RuntimeError: Bad state" in events[1].traceback
    assert "Crash on step 2" in events[2].message
    assert "RuntimeError: Bad state" in events[2].traceback

    # Re-polling identical log lines produces 0 duplicate events
    assert parse_addon_log_lines(target, raw_logs, logging.ERROR, seen) == []


async def test_resolve_domain_extended_core_loggers() -> None:
    """Test _resolve_domain_from_record covers entity, components.*, and bootstrap."""
    loop = asyncio.get_running_loop()
    handler = IntegrationLogHandler(loop, lambda: None)
    handler.update_targets(
        {
            "integration:aegisbot": logging.WARNING,
            "integration:openwrt": logging.ERROR,
            "integration:mcphub": logging.ERROR,
        }
    )

    records = [
        logging.LogRecord(
            "homeassistant.helpers.entity",
            logging.ERROR,
            __file__,
            10,
            "Update for sensor.x fails on custom integration 'openwrt'",
            None,
            None,
        ),
        logging.LogRecord(
            "homeassistant.components.sensor",
            logging.ERROR,
            __file__,
            20,
            "Error adding entities for domain sensor in custom_components.mcphub.sensor",
            None,
            None,
        ),
        logging.LogRecord(
            "homeassistant.bootstrap",
            logging.WARNING,
            __file__,
            30,
            "Waiting on integrations to complete setup: custom integration 'aegisbot'",
            None,
            None,
        ),
    ]
    for rec in records:
        handler.emit(rec)

    assert len(handler.queue) == 3
    assert [ev.target_key for ev in handler.queue] == [
        "integration:openwrt",
        "integration:mcphub",
        "integration:aegisbot",
    ]


def test_addon_log_nginx_info_ignored_and_unprefixed_error_captured() -> None:
    """Ensure [info]/[notice]/[debug] lines aren't errors while unprefixed failures are."""
    target = TargetInfo(
        target_key="addon:edfe50eb_paseo",
        kind="addon",
        identifier="edfe50eb_paseo",
        short_name="paseo",
        name="Paseo",
        version="0.3.2",
        repo_owner="FaserF",
        repo_name="hassio-addons",
        repo_url="https://github.com/FaserF/hassio-addons",
    )
    seen: deque[str] = deque(maxlen=100)

    raw_logs = "\n".join(
        [
            # Benign nginx [info] with SSL error: substring must NOT trigger ERROR
            "2026/11/24 10:15:30 [info] 42#42: *123 SSL_write() failed (SSL: error:0A000126:SSL routines::unexpected eof while reading)",
            "2026/11/24 10:15:31 [notice] 42#42: using the epoll event method",
            "[debug] checking upstream error: none",
            "2026-11-24 10:15:32 INFO: Gateway status check failed: ignored in info",
            "Listening on port 8080",
            "Integration tests failed: 0",
            # Unprefixed genuine error line MUST be captured
            "Gateway status check failed: connection refused",
        ]
    )

    events = parse_addon_log_lines(target, raw_logs, logging.ERROR, seen)
    assert len(events) == 1
    assert events[0].severity == "ERROR"
    assert "Gateway status check failed: connection refused" in events[0].message
