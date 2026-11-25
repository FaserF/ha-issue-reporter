"""Fingerprinting, version intelligence, and cross-user GitHub deduplication."""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime, timedelta
from difflib import SequenceMatcher
from typing import Any

from packaging.version import InvalidVersion, Version

from .const import (
    CONF_COMMENT_ON_NEWER_VERSION,
    CONF_FUZZY_THRESHOLD,
    CONF_OWNER_FILTER_MODE,
    DEFAULT_ALLOW_DEV_EDGE,
    DEFAULT_FUZZY_THRESHOLD,
    FINGERPRINT_PREFIX,
    LOGGER,
    OWNER_FILTER_SELF,
)
from .github_client import GitHubClient
from .models import DuplicateMatch, LogEvent, TargetInfo

_VOLATILE_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"\b\d{4}[-/]\d{2}[-/]\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?\b"
        ),
        "<TS>",
    ),
    (re.compile(r"\[REDACTED_[A-Z_]+\]"), "<REDACT>"),
    (re.compile(r"\b\d+#\d+\b"), "<PID>"),
    (re.compile(r"(?<= )\*\d+\b"), "<CONN>"),
    (re.compile(r"\b0x[0-9a-fA-F]+\b"), "<HEX>"),
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b"), "<IP>"),
    (re.compile(r"\b\d{4,}\b"), "<NUM>"),
    (re.compile(r"'[^']{4,}'"), "'<STR>'"),
    (re.compile(r'"[^"]{4,}"'), '"<STR>"'),
)

_STOPWORDS: frozenset[str] = frozenset(
    {
        "error",
        "warning",
        "failed",
        "failure",
        "exception",
        "fetching",
        "updating",
        "coordinator",
        "custom",
        "integration",
        "component",
        "home",
        "assistant",
        "unexpected",
        "during",
        "calling",
        "while",
        "could",
        "unable",
        "detected",
    }
)

_VERSION_EXTRACT_RE = re.compile(
    r"\bv?(\d+\.\d+(?:\.\d+)?(?:[-._]?(?:dev|a|b|rc)\d*)?)\b", re.IGNORECASE
)


def normalize_error_text(text: str) -> str:
    """Normalize volatile tokens in error messages for stable fingerprinting."""
    cleaned = text.strip()
    for pat, repl in _VOLATILE_PATTERNS:
        cleaned = pat.sub(repl, cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned)
    return cleaned.strip().lower()


def compute_fingerprint(target: TargetInfo, event: LogEvent) -> str:
    """Generate a stable 16-char fingerprint for a target + error signature."""
    norm_msg = normalize_error_text(event.message)[:220]
    norm_logger = event.logger_name.lower()
    raw = "|".join(
        [
            target.kind,
            target.short_name.lower(),
            event.exception_type.lower(),
            norm_logger,
            norm_msg,
        ]
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def parse_comparable_version(raw: str | None) -> Version | None:
    """Parse loose release/integration/dev version tags into packaging Version."""
    if not raw:
        return None
    cleaned = raw.strip().lstrip("vV")
    # Convert 1.2.6-dev-20261124-0919-1faa6d0 -> 1.2.6.dev202611240919
    dev_match = re.match(r"^(\d+(?:\.\d+)+)-dev[-_]?(\d{8})?", cleaned, re.IGNORECASE)
    if dev_match:
        base = dev_match.group(1)
        stamp = dev_match.group(2) or "0"
        cleaned = f"{base}.dev{stamp}"
    try:
        return Version(cleaned)
    except InvalidVersion:
        m = re.search(r"(\d+(?:\.\d+)+)", cleaned)
        if m:
            try:
                return Version(m.group(1))
            except InvalidVersion:
                return None
    return None


def is_dev_or_edge(target: TargetInfo) -> bool:
    """Return True if target runs an edge, dev, alpha, beta, or rc build."""
    if target.channel in ("edge", "dev", "beta", "rc", "unsupported"):
        return True
    ver = target.version.lower()
    return any(tok in ver for tok in ("-dev", ".dev", "alpha", "beta", "-rc", "dev-"))


def is_target_outdated(
    target: TargetInfo,
    latest_release_tag: str | None,
    *,
    allow_dev_edge: bool = DEFAULT_ALLOW_DEV_EDGE,
) -> bool:
    """Return True if installed target version is behind latest available release."""
    if allow_dev_edge and is_dev_or_edge(target):
        return False

    if target.kind == "addon" and target.update_available:
        return True

    installed_v = parse_comparable_version(target.version)
    latest_v = parse_comparable_version(latest_release_tag)
    if installed_v and latest_v:
        return installed_v < latest_v
    return False


def _distinctive_tokens(text: str, limit: int = 4) -> list[str]:
    """Pick distinctive non-stopword alphanumeric tokens for GitHub issue search."""
    tokens = re.findall(r"[A-Za-z][A-Za-z0-9_]{3,}", text)
    seen: set[str] = set()
    picked: list[str] = []
    for tok in tokens:
        low = tok.lower()
        if low in _STOPWORDS or low in seen or low.startswith("redacted"):
            continue
        seen.add(low)
        picked.append(tok)
        if len(picked) >= limit:
            break
    return picked


def _combined_similarity(query_text: str, candidate_text: str) -> float:
    """Compute token Jaccard + SequenceMatcher similarity in [0, 1]."""
    q_norm = normalize_error_text(query_text)
    c_norm = normalize_error_text(candidate_text)
    if not q_norm or not c_norm:
        return 0.0

    q_words = set(re.findall(r"[a-z0-9_]{3,}", q_norm))
    c_words = set(re.findall(r"[a-z0-9_]{3,}", c_norm))
    jaccard = len(q_words & c_words) / max(1, len(q_words | c_words))
    seq = SequenceMatcher(None, q_norm[:500], c_norm[:500]).ratio()
    return 0.5 * jaccard + 0.5 * seq


def _extract_max_version(texts: list[str]) -> Version | None:
    """Find highest semantic version referenced in issue body or comments."""
    best: Version | None = None
    for text in texts:
        for match in _VERSION_EXTRACT_RE.finditer(text):
            v = parse_comparable_version(match.group(1))
            # Skip HA date versions (2025/2026/2027) unless small integration version
            if v and v.major < 2000 and (best is None or v > best):
                best = v
    return best


async def async_check_github_duplicate(
    github: GitHubClient,
    target: TargetInfo,
    event: LogEvent,
    fingerprint: str,
    config: dict[str, Any],
) -> DuplicateMatch:
    """Check GitHub for exact fingerprint and cross-user fuzzy duplicates."""
    if not target.repo_owner or not target.repo_name:
        return DuplicateMatch(action="none")

    owner, repo = target.repo_owner, target.repo_name
    threshold = float(config.get(CONF_FUZZY_THRESHOLD, DEFAULT_FUZZY_THRESHOLD))

    comment_allowed = bool(
        config.get(
            CONF_COMMENT_ON_NEWER_VERSION,
            target.owner_matched
            or config.get(CONF_OWNER_FILTER_MODE) == OWNER_FILTER_SELF,
        )
    )
    if not target.owner_matched and CONF_COMMENT_ON_NEWER_VERSION not in config:
        comment_allowed = False

    # Stage 0: ETag-cached local repository issue index (avoids 30 req/min Search API!)
    fp_marker = f"{FINGERPRINT_PREFIX}{fingerprint}"
    local_issues, may_have_more = await github.async_get_repo_issues(owner, repo)

    best_match: dict[str, Any] | None = None
    best_sim = 0.0
    for item in local_issues:
        if fp_marker in str(item.get("body") or ""):
            best_match = item
            best_sim = 1.0
            break

    query_blob = (
        f"{target.short_name if target.is_monorepo else ''} "
        f"{event.exception_type} {event.message}"
    )
    if best_match is None and local_issues:
        for item in local_issues:
            cand_title = str(item.get("title") or "")
            cand_body = str(item.get("body") or "")[:1500]
            if (
                target.is_monorepo
                and target.short_name.lower()
                not in (cand_title + " " + cand_body).lower()
            ):
                continue
            sim = max(
                _combined_similarity(event.message, cand_title),
                _combined_similarity(query_blob, f"{cand_title} {cand_body}"),
            )
            if sim > best_sim:
                best_sim = sim
                best_match = item
        if best_sim < threshold:
            best_match = None

    # Stage 1: Exact reporter fingerprint search (only if repo has >100 issues)
    if best_match is None and may_have_more:
        exact_items = await github.async_search_issues(
            owner, repo, f'"{fp_marker}"', per_page=5
        )
        if exact_items:
            best_match = exact_items[0]
            best_sim = 1.0

    # Stage 2: Cross-user fuzzy search (only if repo has >100 issues and no local match)
    if best_match is None and may_have_more:
        search_terms: list[str] = []
        if target.is_monorepo:
            search_terms.append(target.short_name)
        if event.exception_type:
            search_terms.append(event.exception_type)
        search_terms.extend(_distinctive_tokens(event.message, limit=4))

        if search_terms:
            query = " ".join(search_terms[:5])
            candidates = await github.async_search_issues(
                owner, repo, query, per_page=15
            )
            for item in candidates:
                if "pull_request" in item:
                    continue
                cand_title = str(item.get("title") or "")
                cand_body = str(item.get("body") or "")[:1500]
                if (
                    target.is_monorepo
                    and target.short_name.lower()
                    not in (cand_title + " " + cand_body).lower()
                ):
                    continue
                sim = max(
                    _combined_similarity(event.message, cand_title),
                    _combined_similarity(query_blob, f"{cand_title} {cand_body}"),
                )
                if sim > best_sim:
                    best_sim = sim
                    best_match = item

            if best_sim < threshold:
                best_match = None

    if best_match is None:
        return DuplicateMatch(action="none")

    issue_number = int(best_match["number"])
    issue_url = str(best_match.get("html_url") or "")
    state = str(best_match.get("state") or "open").lower()

    if state == "open":
        if not comment_allowed:
            return DuplicateMatch(
                action="skip_open",
                issue_number=issue_number,
                issue_url=issue_url,
                reason="open_duplicate",
                similarity=best_sim,
            )

        comments = await github.async_get_issue_comments(owner, repo, issue_number)
        marker = f"still observed on `{target.version}`"
        if any(marker.lower() in str(c.get("body") or "").lower() for c in comments):
            return DuplicateMatch(
                action="skip_open",
                issue_number=issue_number,
                issue_url=issue_url,
                reason="already_commented_version",
                similarity=best_sim,
            )

        installed_v = parse_comparable_version(target.version)
        texts = [str(best_match.get("body") or "")] + [
            str(c.get("body") or "") for c in comments
        ]
        max_existing_v = _extract_max_version(texts)
        if installed_v and max_existing_v and installed_v > max_existing_v:
            comment_body = (
                f"Reproduction note: still observed on `{target.version}` "
                f"({target.kind} `{target.short_name}`, severity `{event.severity}`)."
            )
            return DuplicateMatch(
                action="comment_open",
                issue_number=issue_number,
                issue_url=issue_url,
                reason="newer_version_reproduction",
                similarity=best_sim,
                comment_body=comment_body,
            )

        return DuplicateMatch(
            action="skip_open",
            issue_number=issue_number,
            issue_url=issue_url,
            reason="open_duplicate",
            similarity=best_sim,
        )

    # Closed issue handling: skip recently closed unless fixed version is older
    closed_at_raw = best_match.get("closed_at")
    closed_recent = True
    if closed_at_raw:
        try:
            closed_dt = datetime.fromisoformat(
                str(closed_at_raw).replace("Z", "+00:00")
            )
            closed_recent = (datetime.now(UTC) - closed_dt) < timedelta(days=90)
        except ValueError:
            closed_recent = True

    installed_v = parse_comparable_version(target.version)
    latest_tag = target.latest_version or await github.async_get_latest_release(
        owner, repo
    )
    latest_v = parse_comparable_version(latest_tag)
    closed_texts = [str(best_match.get("body") or "")]
    max_closed_v = _extract_max_version(closed_texts)

    is_newer_than_fix = bool(
        installed_v
        and (
            (max_closed_v and installed_v > max_closed_v)
            or (latest_v and installed_v > latest_v)
        )
    )

    if closed_recent and not is_newer_than_fix:
        return DuplicateMatch(
            action="skip_closed",
            issue_number=issue_number,
            issue_url=issue_url,
            reason="closed_duplicate",
            similarity=best_sim,
        )

    LOGGER.debug(
        "Closed match #%s in %s/%s qualifies for regression issue (installed=%s)",
        issue_number,
        owner,
        repo,
        target.version,
    )
    return DuplicateMatch(
        action="regression_new",
        issue_number=issue_number,
        issue_url=issue_url,
        reason="closed_regression_newer_version",
        similarity=best_sim,
    )
