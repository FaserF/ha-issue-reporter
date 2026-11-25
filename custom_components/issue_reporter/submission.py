"""Issue/comment submission and persistent outbox flushing for Issue Reporter."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .auth import GitHubReauthRequiredError, RepoNotAuthorizedError
from .const import LOGGER, MODE_AUTO
from .github_types import GitHubAPIError, GitHubNetworkError, GitHubRateLimitError
from .models import TargetInfo
from .repairs import async_raise_leak_guard_repair

if TYPE_CHECKING:
    from .coordinator import IssueReporterCoordinator


async def async_handle_open_comment(
    coord: IssueReporterCoordinator,
    target: TargetInfo,
    fp: str,
    issue_num: int,
    raw_comment: str,
    mode: str,
) -> str:
    """Handle posting a newer-version comment on an existing open issue."""
    if (
        mode != MODE_AUTO
        or not target.repo_owner
        or not target.repo_name
        or not target.full_repo
    ):
        coord.stats.duplicates_suppressed += 1
        coord.store.set_cooldown(fp)
        return "comment_skipped_dry_run"

    if not coord.store.within_rate_limits(
        target.full_repo,
        target_key=target.target_key,
        is_monorepo=target.is_monorepo,
    ):
        coord.stats.rate_limited_suppressed += 1
        return "rate_limited"

    comment_res = coord.redactor.redact(raw_comment)
    safe, reasons = coord.redactor.verify_no_leaks("", comment_res.text)
    if not safe:
        coord.stats.leak_guard_blocks += 1
        async_raise_leak_guard_repair(coord.hass, target.name, reasons)
        return "leak_guard_blocked"

    if not coord.store.is_submission_spaced():
        coord.store.enqueue_retry(
            kind="comment",
            target_key=target.target_key,
            repo=target.full_repo,
            fingerprint=fp,
            title="",
            body=comment_res.text,
            issue_number=issue_num,
            error="submission_spacing",
        )
        return "queued_retry"

    try:
        await coord.github.async_create_comment(
            target.repo_owner, target.repo_name, issue_num, comment_res.text
        )
        coord.stats.comments_posted += 1
        coord.store.set_cooldown(fp)
        coord.store.record_post_rate(target.full_repo, target_key=target.target_key)
        return "commented"
    except RepoNotAuthorizedError:
        return "not_authorized"
    except (GitHubRateLimitError, GitHubNetworkError) as err:
        reset_at = err.reset_at if isinstance(err, GitHubRateLimitError) else None
        coord.store.enqueue_retry(
            kind="comment",
            target_key=target.target_key,
            repo=target.full_repo,
            fingerprint=fp,
            title="",
            body=comment_res.text,
            issue_number=issue_num,
            error=str(err),
            reset_at=reset_at,
        )
        return "queued_retry"
    except GitHubAPIError as err:
        LOGGER.warning("Failed posting version comment: %s", err)
        return "github_error"


async def async_submit_issue(
    coord: IssueReporterCoordinator,
    target: TargetInfo,
    rendered: Any,
    fp: str,
) -> str:
    """Submit rendered issue to GitHub with fallback outbox on rate/network error."""
    if not target.repo_owner or not target.repo_name:
        return "missing_repo"
    if not coord.store.is_submission_spaced():
        coord.store.enqueue_retry(
            kind="issue",
            target_key=target.target_key,
            repo=rendered.repo,
            fingerprint=fp,
            title=rendered.title,
            body=rendered.body,
            labels=rendered.labels,
            error="submission_spacing",
        )
        return "queued_retry"
    try:
        created = await coord.github.async_create_issue(
            target.repo_owner,
            target.repo_name,
            rendered.title,
            rendered.body,
            labels=rendered.labels,
        )
    except RepoNotAuthorizedError as err:
        LOGGER.info("Skipping %s: %s", rendered.repo, err)
        return "not_authorized"
    except GitHubReauthRequiredError as err:
        coord.stats.last_error = str(err)
        coord.entry.async_start_reauth(coord.hass)
        return "reauth_required"
    except (GitHubRateLimitError, GitHubNetworkError) as err:
        coord.stats.last_error = str(err)
        reset_at = err.reset_at if isinstance(err, GitHubRateLimitError) else None
        coord.store.enqueue_retry(
            kind="issue",
            target_key=target.target_key,
            repo=rendered.repo,
            fingerprint=fp,
            title=rendered.title,
            body=rendered.body,
            labels=rendered.labels,
            error=str(err),
            reset_at=reset_at,
        )
        return "queued_retry"
    except GitHubAPIError as err:
        coord.stats.last_error = str(err)
        LOGGER.warning("Failed creating issue on %s: %s", rendered.repo, err)
        return "github_error"

    coord.stats.issues_created += 1
    coord.stats.last_issue_url = str(created.get("html_url") or "") or None
    coord.store.set_cooldown(fp)
    coord.store.record_post_rate(rendered.repo, target_key=target.target_key)
    return "created"


async def async_flush_retry_queue(coord: IssueReporterCoordinator) -> None:
    """Flush buffered outbox items when connectivity, quota, and limits allow."""
    for item in coord.store.due_retries(limit=3):
        if item.fingerprint in coord.store.dismissed_fps or coord.store.is_in_cooldown(
            item.fingerprint
        ):
            coord.store.remove_retry(item.fingerprint)
            continue
        target = coord.targets.get(item.target_key)
        if (
            not coord.store.within_rate_limits(
                item.repo,
                target_key=item.target_key,
                is_monorepo=bool(target and target.is_monorepo),
            )
            or not coord.store.is_submission_spaced()
        ):
            break
        passed, reasons = coord.redactor.verify_no_leaks(item.title, item.body)
        if not passed:
            coord.stats.leak_guard_blocks += 1
            async_raise_leak_guard_repair(coord.hass, item.target_key, reasons)
            coord.store.remove_retry(item.fingerprint)
            continue
        owner, repo = item.repo.split("/", 1)
        try:
            if item.kind == "comment" and item.issue_number:
                await coord.github.async_create_comment(
                    owner, repo, item.issue_number, item.body
                )
                coord.stats.comments_posted += 1
            else:
                created = await coord.github.async_create_issue(
                    owner, repo, item.title, item.body, labels=item.labels
                )
                coord.stats.issues_created += 1
                coord.stats.last_issue_url = str(created.get("html_url") or "") or None
            coord.store.set_cooldown(item.fingerprint)
            coord.store.record_post_rate(item.repo, target_key=item.target_key)
            coord.store.remove_retry(item.fingerprint)
        except (GitHubRateLimitError, GitHubNetworkError) as err:
            reset_at = err.reset_at if isinstance(err, GitHubRateLimitError) else None
            coord.store.enqueue_retry(
                kind=item.kind,
                target_key=item.target_key,
                repo=item.repo,
                fingerprint=item.fingerprint,
                title=item.title,
                body=item.body,
                labels=item.labels,
                issue_number=item.issue_number,
                error=str(err),
                reset_at=reset_at,
            )
            break
        except GitHubAPIError:
            coord.store.remove_retry(item.fingerprint)
