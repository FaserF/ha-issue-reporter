"""Async GitHub REST API client with ETag caching, rate-limit tracking, and circuit breaker."""

from __future__ import annotations

import base64
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

import aiohttp

from .auth import (
    GitHubAuthError,
    GitHubAuthManager,
    GitHubReauthRequiredError,
    RepoNotAuthorizedError,
)
from .const import GITHUB_API_BASE, LOGGER
from .github_types import (
    NOT_MODIFIED as _NOT_MODIFIED,
)
from .github_types import (
    ETagEntry as _ETagEntry,
)
from .github_types import (
    GitHubAPIError,
    GitHubNetworkError,
    GitHubRateLimitError,
    RateLimitTracker,
)


class GitHubClient:
    """Async GitHub client injected with HA ClientSession and auth manager."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        auth: GitHubAuthManager,
    ) -> None:
        """Initialize GitHub API client."""
        self._session = session
        self._auth = auth
        self._limits = RateLimitTracker()
        self._repo_cache: dict[str, _ETagEntry] = {}
        self._release_cache: dict[str, _ETagEntry] = {}
        self._template_cache: dict[str, _ETagEntry] = {}
        self._issues_cache: dict[str, _ETagEntry] = {}
        self._comments_cache: dict[str, _ETagEntry] = {}
        self._search_cache: dict[str, tuple[datetime, list[dict[str, Any]]]] = {}

    @property
    def rate_limit_remaining(self) -> int | None:
        """Return remaining GitHub Core API requests."""
        return self._limits.core_remaining

    @rate_limit_remaining.setter
    def rate_limit_remaining(self, value: int | None) -> None:
        """Set remaining GitHub Core API requests."""
        self._limits.core_remaining = value

    @property
    def rate_limit_reset(self) -> int | None:
        """Return GitHub Core API rate limit reset epoch."""
        return self._limits.core_reset

    @rate_limit_reset.setter
    def rate_limit_reset(self, value: int | None) -> None:
        """Set GitHub Core API rate limit reset epoch."""
        self._limits.core_reset = value

    @property
    def is_circuit_open(self) -> bool:
        """Return True when transient failure circuit breaker is active."""
        return self._limits.is_circuit_open

    def _update_rate_limit(self, headers: Mapping[Any, str]) -> None:
        """Track X-RateLimit headers per resource without failing on missing headers."""
        self._limits.update_from_headers(headers)

    async def _request_json(
        self,
        method: str,
        path: str,
        *,
        token: str | None = None,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        allow_404: bool = False,
        if_none_match: str | None = None,
        return_headers: bool = False,
    ) -> Any:
        """Execute a GitHub REST API call and return parsed JSON (or tuple with ETag)."""
        resource = "search" if path.startswith("/search/") else "core"
        self._limits.check_proactive_limits(resource)

        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "ha-issue-reporter",
        }
        if token:
            headers["Authorization"] = f"token {token}"
        if if_none_match:
            headers["If-None-Match"] = if_none_match

        url = path if path.startswith("http") else f"{GITHUB_API_BASE}{path}"
        try:
            async with self._session.request(
                method,
                url,
                headers=headers,
                params=params,
                json=json_body,
                timeout=aiohttp.ClientTimeout(total=20),
            ) as resp:
                self._limits.update_from_headers(resp.headers)
                if resp.status == 304:
                    self._limits.record_success()
                    return (
                        (_NOT_MODIFIED, resp.headers.get("ETag"))
                        if return_headers
                        else None
                    )
                if allow_404 and resp.status == 404:
                    self._limits.record_success()
                    return (None, None) if return_headers else None
                if resp.status == 401:
                    raise GitHubReauthRequiredError(
                        "GitHub API returned 401 Unauthorized"
                    )
                if resp.status == 429 or (
                    resp.status == 403
                    and (
                        resp.headers.get("Retry-After") is not None
                        or (resource == "search" and self._limits.search_remaining == 0)
                        or (resource == "core" and self._limits.core_remaining == 0)
                    )
                ):
                    retry_raw = resp.headers.get("Retry-After")
                    retry_after = (
                        int(retry_raw) if retry_raw and retry_raw.isdigit() else None
                    )
                    rst_ts = (
                        self._limits.search_reset
                        if resource == "search"
                        else self._limits.core_reset
                    )
                    reset_at = (
                        datetime.fromtimestamp(rst_ts, tz=UTC)
                        if rst_ts
                        else (
                            datetime.now(UTC) + timedelta(seconds=retry_after)
                            if retry_after
                            else datetime.now(UTC) + timedelta(minutes=5)
                        )
                    )
                    raise GitHubRateLimitError(
                        f"GitHub API rate limit exhausted ({resp.status})",
                        reset_at=reset_at,
                        retry_after=retry_after,
                        resource=resource,
                        is_secondary=(resp.status == 429 or retry_after is not None),
                    )
                if resp.status >= 500:
                    self._limits.record_failure()
                    text = await resp.text()
                    raise GitHubNetworkError(
                        f"GitHub API {method} {path} server error ({resp.status}): {text[:200]}"
                    )
                if resp.status >= 400:
                    text = await resp.text()
                    raise GitHubAPIError(
                        f"GitHub API {method} {path} failed ({resp.status}): {text[:240]}"
                    )
                self._limits.record_success()
                payload = {} if resp.status == 204 else await resp.json()
                if return_headers:
                    return payload, resp.headers.get("ETag")
                return payload
        except (aiohttp.ClientError, TimeoutError) as err:
            self._limits.record_failure()
            raise GitHubNetworkError(f"GitHub network error on {path}: {err}") from err

    async def _async_read_json(
        self,
        path: str,
        *,
        owner: str | None = None,
        repo: str | None = None,
        params: dict[str, Any] | None = None,
        allow_404: bool = False,
        if_none_match: str | None = None,
        return_headers: bool = False,
    ) -> Any:
        """Execute a read request using repo token, primary token, or public fallback."""
        token: str | None = None
        if owner and repo:
            try:
                token, _ = await self._auth.async_get_token_for_repo(owner, repo)
            except RepoNotAuthorizedError:
                token = await self._auth.async_get_any_read_token()
        else:
            token = await self._auth.async_get_any_read_token()

        try:
            return await self._request_json(
                "GET",
                path,
                token=token,
                params=params,
                allow_404=allow_404,
                if_none_match=if_none_match,
                return_headers=return_headers,
            )
        except GitHubReauthRequiredError:
            if token and self._auth.primary_method == "github_app":
                self._auth.invalidate_app_token()
                retry_token = await self._auth.async_get_any_read_token()
                return await self._request_json(
                    "GET",
                    path,
                    token=retry_token,
                    params=params,
                    allow_404=allow_404,
                    if_none_match=if_none_match,
                    return_headers=return_headers,
                )
            raise

    async def async_get_repo_info(self, owner: str, repo: str) -> dict[str, Any] | None:
        """Fetch repository metadata (has_issues, archived, default_branch) cached 24h."""
        key = f"{owner}/{repo}".lower()
        now = datetime.now(UTC)
        cached = self._repo_cache.get(key)
        if cached and (now - cached.fetched_at) < timedelta(hours=24):
            return cached.data

        try:
            data, etag = await self._async_read_json(
                f"/repos/{owner}/{repo}",
                owner=owner,
                repo=repo,
                allow_404=True,
                if_none_match=cached.etag if cached else None,
                return_headers=True,
            )
        except (GitHubAuthError, GitHubAPIError) as err:
            LOGGER.debug("Failed repo metadata fetch for %s: %s", key, err)
            return cached.data if cached else None

        if data is _NOT_MODIFIED and cached is not None:
            cached.fetched_at = now
            return cached.data
        if not isinstance(data, dict):
            return None
        info = {
            "full_name": data.get("full_name", f"{owner}/{repo}"),
            "has_issues": bool(data.get("has_issues", True)),
            "archived": bool(data.get("archived", False)),
            "disabled": bool(data.get("disabled", False)),
            "default_branch": str(data.get("default_branch", "main")),
            "html_url": str(data.get("html_url", f"https://github.com/{owner}/{repo}")),
        }
        self._repo_cache[key] = _ETagEntry(fetched_at=now, data=info, etag=etag)
        return info

    async def async_get_latest_release(self, owner: str, repo: str) -> str | None:
        """Fetch latest release tag name (cached 6h with ETag & stale fallback)."""
        key = f"{owner}/{repo}".lower()
        now = datetime.now(UTC)
        cached = self._release_cache.get(key)
        if cached and (now - cached.fetched_at) < timedelta(hours=6):
            return cached.data

        tag: str | None = None
        etag: str | None = None
        try:
            data, etag = await self._async_read_json(
                f"/repos/{owner}/{repo}/releases/latest",
                owner=owner,
                repo=repo,
                allow_404=True,
                if_none_match=cached.etag if cached else None,
                return_headers=True,
            )
            if data is _NOT_MODIFIED and cached is not None:
                cached.fetched_at = now
                return cached.data
            if isinstance(data, dict) and data.get("tag_name"):
                tag = str(data["tag_name"])
            else:
                tags = await self._async_read_json(
                    f"/repos/{owner}/{repo}/tags",
                    owner=owner,
                    repo=repo,
                    params={"per_page": 1},
                    allow_404=True,
                )
                if isinstance(tags, list) and tags:
                    tag = str(tags[0].get("name", "")) or None
        except (GitHubAuthError, GitHubAPIError) as err:
            LOGGER.debug("Could not fetch latest release for %s: %s", key, err)
            return cached.data if cached else None

        self._release_cache[key] = _ETagEntry(fetched_at=now, data=tag, etag=etag)
        return tag

    async def async_fetch_bug_templates(
        self, owner: str, repo: str
    ) -> list[dict[str, str]]:
        """Fetch raw issue templates from .github/ISSUE_TEMPLATE/ (cached 24h)."""
        key = f"{owner}/{repo}".lower()
        now = datetime.now(UTC)
        cached = self._template_cache.get(key)
        if cached and (now - cached.fetched_at) < timedelta(hours=24):
            return cached.data

        templates: list[dict[str, str]] = []
        try:
            listing, etag = await self._async_read_json(
                f"/repos/{owner}/{repo}/contents/.github/ISSUE_TEMPLATE",
                owner=owner,
                repo=repo,
                allow_404=True,
                if_none_match=cached.etag if cached else None,
                return_headers=True,
            )
        except (GitHubAuthError, GitHubAPIError) as err:
            LOGGER.debug("Failed listing issue templates for %s: %s", key, err)
            return cached.data if cached else []

        if listing is _NOT_MODIFIED and cached is not None:
            cached.fetched_at = now
            return cached.data

        if not isinstance(listing, list):
            self._template_cache[key] = _ETagEntry(
                fetched_at=now, data=templates, etag=etag
            )
            return templates

        candidates = [
            item
            for item in listing
            if isinstance(item, dict)
            and item.get("type") == "file"
            and str(item.get("name", "")).lower().endswith((".yml", ".yaml", ".md"))
            and str(item.get("name", "")).lower() != "config.yml"
        ]
        # Prefer bug report templates first
        candidates.sort(
            key=lambda item: (
                0 if "bug" in str(item.get("name", "")).lower() else 1,
                0
                if str(item.get("name", "")).lower().endswith((".yml", ".yaml"))
                else 1,
                str(item.get("name", "")).lower(),
            )
        )

        for item in candidates[:4]:
            path = str(item.get("path", ""))
            name = str(item.get("name", ""))
            if not path:
                continue
            try:
                file_obj = await self._async_read_json(
                    f"/repos/{owner}/{repo}/contents/{path}",
                    owner=owner,
                    repo=repo,
                    allow_404=True,
                )
            except (GitHubAuthError, GitHubAPIError):
                continue
            if isinstance(file_obj, dict) and file_obj.get("content"):
                try:
                    raw = base64.b64decode(str(file_obj["content"])).decode(
                        "utf-8", errors="replace"
                    )
                    templates.append({"name": name, "path": path, "content": raw})
                except ValueError as err:
                    LOGGER.debug("Invalid base64 in template %s/%s: %s", key, path, err)

        self._template_cache[key] = _ETagEntry(
            fetched_at=now, data=templates, etag=etag
        )
        return templates

    async def async_get_repo_issues(
        self, owner: str, repo: str, per_page: int = 100
    ) -> tuple[list[dict[str, Any]], bool]:
        """Fetch open + recently closed issues via ETag-cached REST list (0 Search quota).

        Returns (issues_without_prs, may_have_more).
        """
        key = f"{owner}/{repo}".lower()
        now = datetime.now(UTC)
        cached = self._issues_cache.get(key)
        if cached and (now - cached.fetched_at) < timedelta(minutes=15):
            return cached.data

        try:
            raw, etag = await self._async_read_json(
                f"/repos/{owner}/{repo}/issues",
                owner=owner,
                repo=repo,
                params={
                    "state": "all",
                    "sort": "updated",
                    "direction": "desc",
                    "per_page": per_page,
                },
                allow_404=True,
                if_none_match=cached.etag if cached else None,
                return_headers=True,
            )
        except (GitHubRateLimitError, GitHubNetworkError):
            if cached is not None:
                return cached.data
            raise
        except (GitHubAuthError, GitHubAPIError) as err:
            LOGGER.debug("Failed listing issues for %s: %s", key, err)
            return cached.data if cached else ([], False)

        if raw is _NOT_MODIFIED and cached is not None:
            cached.fetched_at = now
            return cached.data

        if not isinstance(raw, list):
            return [], False
        issues = [
            item
            for item in raw
            if isinstance(item, dict) and "pull_request" not in item
        ]
        result = (issues, len(raw) >= per_page)
        self._issues_cache[key] = _ETagEntry(fetched_at=now, data=result, etag=etag)
        return result

    async def async_search_issues(
        self,
        owner: str,
        repo: str,
        query: str,
        per_page: int = 15,
    ) -> list[dict[str, Any]]:
        """Search issues in a repository using GitHub Search API (10m cached)."""
        full_q = f"repo:{owner}/{repo} is:issue {query}".strip()
        cache_key = f"{full_q}|{per_page}"
        now = datetime.now(UTC)
        cached = self._search_cache.get(cache_key)
        if cached and (now - cached[0]) < timedelta(minutes=10):
            return cached[1]

        try:
            data = await self._async_read_json(
                "/search/issues",
                owner=owner,
                repo=repo,
                params={
                    "q": full_q,
                    "per_page": per_page,
                    "sort": "updated",
                    "order": "desc",
                },
            )
        except (GitHubRateLimitError, GitHubNetworkError):
            if cached is not None:
                return cached[1]
            raise
        except (GitHubAuthError, GitHubAPIError) as err:
            LOGGER.debug("GitHub issue search failed for %s/%s: %s", owner, repo, err)
            return []

        items = (
            [item for item in data["items"] if isinstance(item, dict)]
            if isinstance(data, dict) and isinstance(data.get("items"), list)
            else []
        )
        self._search_cache[cache_key] = (now, items)
        return items

    async def async_get_issue_comments(
        self,
        owner: str,
        repo: str,
        issue_number: int,
    ) -> list[dict[str, Any]]:
        """Fetch comments on an existing issue (10m ETag cached, up to 50)."""
        key = f"{owner}/{repo}#{issue_number}".lower()
        now = datetime.now(UTC)
        cached = self._comments_cache.get(key)
        if cached and (now - cached.fetched_at) < timedelta(minutes=10):
            return cached.data

        try:
            data, etag = await self._async_read_json(
                f"/repos/{owner}/{repo}/issues/{issue_number}/comments",
                owner=owner,
                repo=repo,
                params={"per_page": 50},
                allow_404=True,
                if_none_match=cached.etag if cached else None,
                return_headers=True,
            )
        except (GitHubAuthError, GitHubAPIError) as err:
            LOGGER.debug(
                "Could not fetch comments for %s/%s#%s: %s",
                owner,
                repo,
                issue_number,
                err,
            )
            return cached.data if cached else []

        if data is _NOT_MODIFIED and cached is not None:
            cached.fetched_at = now
            return cached.data

        comments = (
            [c for c in data if isinstance(c, dict)] if isinstance(data, list) else []
        )
        self._comments_cache[key] = _ETagEntry(fetched_at=now, data=comments, etag=etag)
        return comments

    async def async_create_issue(
        self,
        owner: str,
        repo: str,
        title: str,
        body: str,
        labels: list[str] | None = None,
    ) -> dict[str, Any]:
        """Create a GitHub issue, retrying without labels if permission denies them."""
        token, actor = await self._auth.async_get_token_for_repo(owner, repo)
        payload: dict[str, Any] = {"title": title, "body": body}
        if labels:
            payload["labels"] = labels

        try:
            result = await self._request_json(
                "POST", f"/repos/{owner}/{repo}/issues", token=token, json_body=payload
            )
        except GitHubReauthRequiredError:
            if self._auth.primary_method == "github_app":
                self._auth.invalidate_app_token()
                token, actor = await self._auth.async_get_token_for_repo(owner, repo)
                result = await self._request_json(
                    "POST",
                    f"/repos/{owner}/{repo}/issues",
                    token=token,
                    json_body=payload,
                )
            else:
                raise
        except GitHubAPIError as err:
            if labels and ("(403)" in str(err) or "(422)" in str(err)):
                LOGGER.debug(
                    "Retrying issue creation on %s/%s without labels", owner, repo
                )
                payload.pop("labels", None)
                result = await self._request_json(
                    "POST",
                    f"/repos/{owner}/{repo}/issues",
                    token=token,
                    json_body=payload,
                )
            else:
                raise

        if not isinstance(result, dict):
            raise GitHubAPIError("Unexpected non-object response when creating issue")
        result["actor"] = actor
        return result

    async def async_create_comment(
        self,
        owner: str,
        repo: str,
        issue_number: int,
        body: str,
    ) -> dict[str, Any]:
        """Post a comment on an existing GitHub issue."""
        token, _ = await self._auth.async_get_token_for_repo(owner, repo)
        result = await self._request_json(
            "POST",
            f"/repos/{owner}/{repo}/issues/{issue_number}/comments",
            token=token,
            json_body={"body": body},
        )
        return result if isinstance(result, dict) else {}
