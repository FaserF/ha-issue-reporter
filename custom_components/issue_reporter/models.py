"""Data models for the Issue Reporter integration."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class TargetOverride:
    """Per-target user configuration overrides."""

    enabled: bool | None = None
    mode: str | None = None
    min_severity: str | None = None
    repo_override: str | None = None
    ignore_patterns: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-safe dict."""
        return {
            "enabled": self.enabled,
            "mode": self.mode,
            "min_severity": self.min_severity,
            "repo_override": self.repo_override,
            "ignore_patterns": list(self.ignore_patterns),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> TargetOverride:
        """Deserialize from dict."""
        if not data:
            return cls()
        return cls(
            enabled=data.get("enabled"),
            mode=data.get("mode"),
            min_severity=data.get("min_severity"),
            repo_override=data.get("repo_override"),
            ignore_patterns=list(data.get("ignore_patterns") or []),
        )


@dataclass
class TargetInfo:
    """Normalized metadata for a monitored integration or Supervisor add-on."""

    target_key: str
    kind: str  # "integration" | "addon"
    identifier: str  # domain or addon slug
    short_name: str  # domain or stripped addon slug (without repo hash)
    name: str
    version: str
    repo_owner: str | None
    repo_name: str | None
    repo_url: str | None
    channel: str = "stable"
    update_available: bool = False
    is_monorepo: bool = False
    is_core: bool = False
    owner_matched: bool = False
    enabled: bool = False
    mode: str = "approval"
    min_severity: str = "ERROR"
    latest_version: str | None = None

    @property
    def full_repo(self) -> str | None:
        """Return owner/repo string if mapped."""
        if self.repo_owner and self.repo_name:
            return f"{self.repo_owner}/{self.repo_name}"
        return None


@dataclass
class LogEvent:
    """Captured error or warning event from HA Core logs or Supervisor add-ons."""

    target_key: str
    kind: str
    logger_name: str
    severity: str  # WARNING | ERROR | CRITICAL
    levelno: int
    message: str
    traceback: str = ""
    exception_type: str = ""
    location: str = ""
    timestamp: str = ""


@dataclass
class RedactionResult:
    """Result of the multi-layer redaction pipeline."""

    text: str
    replacements_count: int = 0
    matched_categories: list[str] = field(default_factory=list)


@dataclass
class DuplicateMatch:
    """Result of GitHub duplicate & version-intelligence check."""

    action: str  # none | skip_open | comment_open | skip_closed | regression_new
    issue_number: int | None = None
    issue_url: str | None = None
    reason: str = ""
    similarity: float = 0.0
    comment_body: str = ""


@dataclass
class RenderedIssue:
    """Rendered GitHub issue ready for Leak Guard and submission."""

    repo: str
    title: str
    body: str
    labels: list[str] = field(default_factory=list)
    template_used: str = "default"
    fingerprint: str = ""


@dataclass
class PendingDraft:
    """Pending or Dry-Run draft awaiting user review or preview."""

    draft_id: str
    target_key: str
    target_name: str
    kind: str
    repo: str
    title: str
    body: str
    labels: list[str]
    fingerprint: str
    severity: str
    version: str
    created_at: str
    occurrences: int
    template_used: str = "default"
    dry_run_only: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Serialize draft for persistent storage."""
        return {
            "draft_id": self.draft_id,
            "target_key": self.target_key,
            "target_name": self.target_name,
            "kind": self.kind,
            "repo": self.repo,
            "title": self.title,
            "body": self.body,
            "labels": list(self.labels),
            "fingerprint": self.fingerprint,
            "severity": self.severity,
            "version": self.version,
            "created_at": self.created_at,
            "occurrences": self.occurrences,
            "template_used": self.template_used,
            "dry_run_only": self.dry_run_only,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PendingDraft:
        """Deserialize draft from persistent storage."""
        return cls(
            draft_id=str(data["draft_id"]),
            target_key=str(data["target_key"]),
            target_name=str(data.get("target_name", "")),
            kind=str(data.get("kind", "integration")),
            repo=str(data["repo"]),
            title=str(data["title"]),
            body=str(data["body"]),
            labels=list(data.get("labels") or []),
            fingerprint=str(data["fingerprint"]),
            severity=str(data.get("severity", "ERROR")),
            version=str(data.get("version", "")),
            created_at=str(data.get("created_at", "")),
            occurrences=int(data.get("occurrences", 1)),
            template_used=str(data.get("template_used", "default")),
            dry_run_only=bool(data.get("dry_run_only", False)),
        )


@dataclass
class ReporterStats:
    """Operational metrics exposed via diagnostic sensors & system health."""

    issues_created: int = 0
    comments_posted: int = 0
    duplicates_suppressed: int = 0
    outdated_suppressed: int = 0
    filtered_local: int = 0
    rate_limited_suppressed: int = 0
    leak_guard_blocks: int = 0
    last_issue_url: str | None = None
    last_scan_at: str | None = None
    last_error: str | None = None
