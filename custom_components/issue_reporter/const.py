"""Constants for the Issue Reporter integration."""

from __future__ import annotations

import logging
from typing import Final

DOMAIN: Final = "issue_reporter"
LOGGER = logging.getLogger(__package__)

STORAGE_KEY: Final = "issue_reporter.state"
STORAGE_VERSION: Final = 1

# Authentication methods
AUTH_DEVICE_FLOW: Final = "device_flow"
AUTH_PAT: Final = "pat"
AUTH_GITHUB_APP: Final = "github_app"
AUTH_NONE: Final = "none"

# Public OAuth App Client ID (optional; users can supply their own in Config Flow)
DEFAULT_OAUTH_CLIENT_ID: Final = ""

# Config / Auth keys
CONF_AUTH_METHOD: Final = "auth_method"
CONF_GITHUB_TOKEN: Final = "github_token"
CONF_GITHUB_USER: Final = "github_user"
CONF_OAUTH_CLIENT_ID: Final = "oauth_client_id"
CONF_APP_ID: Final = "app_id"
CONF_INSTALLATION_ID: Final = "installation_id"
CONF_PRIVATE_KEY: Final = "private_key"
CONF_FALLBACK_AUTH_METHOD: Final = "fallback_auth_method"
CONF_FALLBACK_TOKEN: Final = "fallback_token"
CONF_FALLBACK_USER: Final = "fallback_user"

# Scope & Owner filtering
OWNER_FILTER_SELF: Final = "self"
OWNER_FILTER_CUSTOM: Final = "custom"
OWNER_FILTER_MANUAL: Final = "manual"

CONF_OWNER_FILTER_MODE: Final = "owner_filter_mode"
CONF_OWNER_ALLOWLIST: Final = "owner_allowlist"
CONF_DRY_RUN: Final = "dry_run"
CONF_REQUIRE_APPROVAL: Final = "require_approval"
CONF_MIN_SEVERITY: Final = "min_severity"
CONF_CUSTOM_REDACTIONS: Final = "custom_redactions"
CONF_CUSTOM_REDACTION_REGEXES: Final = "custom_redaction_regexes"
CONF_STRICT_ENTROPY_GUARD: Final = "strict_entropy_guard"

# Target submission modes
MODE_AUTO: Final = "auto"
MODE_APPROVAL: Final = "approval"
MODE_DRY_RUN: Final = "dry_run"

# Target kinds
TARGET_INTEGRATION: Final = "integration"
TARGET_ADDON: Final = "addon"

# Severities
SEVERITY_WARNING: Final = "WARNING"
SEVERITY_ERROR: Final = "ERROR"
SEVERITY_CRITICAL: Final = "CRITICAL"

SEVERITY_LEVELS: Final[dict[str, int]] = {
    SEVERITY_WARNING: logging.WARNING,
    SEVERITY_ERROR: logging.ERROR,
    SEVERITY_CRITICAL: logging.CRITICAL,
}

# Deduplication, filters, and rate limits
CONF_MIN_OCCURRENCES_ERROR: Final = "min_occurrences_error"
CONF_MIN_OCCURRENCES_WARNING: Final = "min_occurrences_warning"
CONF_OCCURRENCE_WINDOW_MINUTES: Final = "occurrence_window_minutes"
CONF_COOLDOWN_HOURS: Final = "cooldown_hours"
CONF_MAX_ISSUES_PER_HOUR: Final = "max_issues_per_hour"
CONF_MAX_ISSUES_PER_REPO_DAY: Final = "max_issues_per_repo_day"
CONF_SKIP_OUTDATED: Final = "skip_outdated"
CONF_ALLOW_DEV_EDGE: Final = "allow_dev_edge"
CONF_COMMENT_ON_NEWER_VERSION: Final = "comment_on_newer_version"
CONF_FUZZY_THRESHOLD: Final = "fuzzy_similarity_threshold"
CONF_ADDON_POLL_MINUTES: Final = "addon_poll_minutes"
CONF_INCLUDE_CORE_ADDONS: Final = "include_core_addons"

CONF_IGNORE_NETWORK_ERRORS: Final = "ignore_network_errors"
CONF_IGNORE_AUTH_ERRORS: Final = "ignore_auth_errors"
CONF_IGNORE_RATE_LIMIT_ERRORS: Final = "ignore_rate_limit_errors"
CONF_IGNORE_LIFECYCLE_ERRORS: Final = "ignore_lifecycle_errors"
CONF_CUSTOM_IGNORE_PATTERNS: Final = "custom_ignore_patterns"

CONF_TARGET_OVERRIDES: Final = "target_overrides"

DEFAULT_DRY_RUN: Final = False
DEFAULT_REQUIRE_APPROVAL: Final = False
DEFAULT_MIN_SEVERITY: Final = SEVERITY_ERROR
DEFAULT_MIN_OCCURRENCES_ERROR: Final = 1
DEFAULT_MIN_OCCURRENCES_WARNING: Final = 3
DEFAULT_MIN_OCCURRENCES_DEPRECATION: Final = 1
DEFAULT_OCCURRENCE_WINDOW_MINUTES: Final = 15
DEFAULT_COOLDOWN_HOURS: Final = 24
DEFAULT_MAX_ISSUES_PER_HOUR: Final = 5
DEFAULT_MAX_ISSUES_PER_DAY: Final = 15
DEFAULT_MAX_ISSUES_PER_REPO_DAY: Final = 2
DEFAULT_MAX_ISSUES_PER_MONOREPO_DAY: Final = 8
MIN_SUBMISSION_INTERVAL_SECONDS: Final = 30
FLOOD_BREAKER_MAX_UNIQUE: Final = 5
FLOOD_BREAKER_WINDOW_MINUTES: Final = 10
FLOOD_BREAKER_PAUSE_MINUTES: Final = 60
MAX_RETRY_QUEUE_SIZE: Final = 50
MAX_RETRY_ATTEMPTS: Final = 6
DEFAULT_SKIP_OUTDATED: Final = True
DEFAULT_ALLOW_DEV_EDGE: Final = True
DEFAULT_COMMENT_ON_NEWER_VERSION: Final = True
DEFAULT_FUZZY_THRESHOLD: Final = 0.65
DEFAULT_ADDON_POLL_MINUTES: Final = 10
DEFAULT_INCLUDE_CORE_ADDONS: Final = False
DEFAULT_STRICT_ENTROPY_GUARD: Final = True

DEFAULT_IGNORE_NETWORK_ERRORS: Final = True
DEFAULT_IGNORE_AUTH_ERRORS: Final = True
DEFAULT_IGNORE_RATE_LIMIT_ERRORS: Final = True
DEFAULT_IGNORE_LIFECYCLE_ERRORS: Final = True

FINGERPRINT_PREFIX: Final = "ha-issue-reporter:fingerprint="
MAX_LOG_QUEUE_SIZE: Final = 250
MAX_TRACEBACK_LINES: Final = 60
MAX_LOG_CHARS: Final = 8000
MAX_DRAFTS_STORED: Final = 50
MAX_SEEN_ADDON_LINES: Final = 400
GITHUB_API_BASE: Final = "https://api.github.com"
GITHUB_WEB_BASE: Final = "https://github.com"

SERVICE_SCAN_NOW: Final = "scan_now"
SERVICE_TEST_REDACTION: Final = "test_redaction"
SERVICE_PREVIEW_DRAFT: Final = "preview_draft"
SERVICE_APPROVE_DRAFT: Final = "approve_draft"
SERVICE_DISMISS_DRAFT: Final = "dismiss_draft"
SERVICE_CLEAR_COOLDOWNS: Final = "clear_cooldowns"
