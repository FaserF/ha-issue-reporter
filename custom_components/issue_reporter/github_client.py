"""Async GitHub REST API client with caching, rate-limit tracking, and safe retries."""

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


class GitHubAPIError(Exception):
    """Raised when a GitHub API request fails."""


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
        self.rate_limit_remaining: int | None = None
        self.rate_limit_reset: int | None = None
        self._repo_cache: dict[str, tuple[datetime, dict[str, Any]]] = {}
        self._release_cache: dict[str, tuple[datetime, str | None]] = {}
        self._template_cache: dict[str, tuple[datetime, list[dict[str, str]]]] = {}

    def _update_rate_limit(self, headers: Mapping[Any, str]) -> None:
        """Track X-RateLimit headers without failing on missing headers."""
        rem = headers.get("X-RateLimit-Remaining")
        rst = headers.get("X-RateLimit-Reset")
        if rem is not None and str(rem).isdigit():
            self.rate_limit_remaining = int(rem)
        if rst is not None and str(rst).isdigit():
            self.rate_limit_reset = int(rst)

    async def _request_json(
        self,
        method: str,
        path: str,
        *,
        token: str | None = None,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        allow_404: bool = False,
    ) -> Any:
        """Execute a GitHub REST API call and return parsed JSON."""
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "ha-issue-reporter",
        }
        if token:
            headers["Authorization"] = f"token {token}"

        url = path if path.startswith("http") else f"{GITHUB_API_BASE}{path}"
        async with self._session.request(
            method,
            url,
            headers=headers,
            params=params,
            json=json_body,
            timeout=aiohttp.ClientTimeout(total=20),
        ) as resp:
            self._update_rate_limit(resp.headers)
            if allow_404 and resp.status == 404:
                return None
            if resp.status == 401:
                raise GitHubReauthRequiredError("GitHub API returned 401 Unauthorized")
            if resp.status == 403 and self.rate_limit_remaining == 0:
                raise GitHubAPIError("GitHub API rate limit exhausted")
            if resp.status >= 400:
                text = await resp.text()
                raise GitHubAPIError(
                    f"GitHub API {method} {path} failed ({resp.status}): {text[:240]}"
                )
            if resp.status == 204:
                return {}
            return await resp.json()

    async def _async_read_json(
        self,
        path: str,
        *,
        owner: str | None = None,
        repo: str | None = None,
        params: dict[str, Any] | None = None,
        allow_404: bool = False,
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
                "GET", path, token=token, params=params, allow_404=allow_404
            )
        except GitHubReauthRequiredError:
            if token and self._auth.primary_method == "github_app":
                self._auth.invalidate_app_token()
                retry_token = await self._auth.async_get_any_read_token()
                return await self._request_json(
                    "GET", path, token=retry_token, params=params, allow_404=allow_404
                )
            raise

    async def async_get_repo_info(self, owner: str, repo: str) -> dict[str, Any] | None:
        """Fetch repository metadata (has_issues, archived, default_branch) cached 24h."""
        key = f"{owner}/{repo}".lower()
        now = datetime.now(UTC)
        cached = self._repo_cache.get(key)
        if cached and (now - cached[0]) < timedelta(hours=24):
            return cached[1]

        try:
            data = await self._async_read_json(
                f"/repos/{owner}/{repo}", owner=owner, repo=repo, allow_404=True
            )
        except GitHubAuthError as err:
            LOGGER.debug("Skipping repo metadata fetch for %s: %s", key, err)
            return None
        except GitHubAPIError as err:
            LOGGER.debug("Failed repo metadata fetch for %s: %s", key, err)
            return None

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
        self._repo_cache[key] = (now, info)
        return info

    async def async_get_latest_release(self, owner: str, repo: str) -> str | None:
        """Fetch latest release tag name (cached 6h)."""
        key = f"{owner}/{repo}".lower()
        now = datetime.now(UTC)
        cached = self._release_cache.get(key)
        if cached and (now - cached[0]) < timedelta(hours=6):
            return cached[1]

        tag: str | None = None
        try:
            data = await self._async_read_json(
                f"/repos/{owner}/{repo}/releases/latest",
                owner=owner,
                repo=repo,
                allow_404=True,
            )
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
            return None

        self._release_cache[key] = (now, tag)
        return tag

    async def async_fetch_bug_templates(
        self, owner: str, repo: str
    ) -> list[dict[str, str]]:
        """Fetch raw issue templates from .github/ISSUE_TEMPLATE/ (cached 24h)."""
        key = f"{owner}/{repo}".lower()
        now = datetime.now(UTC)
        cached = self._template_cache.get(key)
        if cached and (now - cached[0]) < timedelta(hours=24):
            return cached[1]

        templates: list[dict[str, str]] = []
        try:
            listing = await self._async_read_json(
                f"/repos/{owner}/{repo}/contents/.github/ISSUE_TEMPLATE",
                owner=owner,
                repo=repo,
                allow_404=True,
            )
        except (GitHubAuthError, GitHubAPIError) as err:
            LOGGER.debug("Failed listing issue templates for %s: %s", key, err)
            return []

        if not isinstance(listing, list):
            self._template_cache[key] = (now, templates)
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

        self._template_cache[key] = (now, templates)
        return templates

    async def async_search_issues(
        self,
        owner: str,
        repo: str,
        query: str,
        per_page: int = 15,
    ) -> list[dict[str, Any]]:
        """Search issues in a repository using GitHub Search API."""
        full_q = f"repo:{owner}/{repo} is:issue {query}".strip()
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
        except (GitHubAuthError, GitHubAPIError) as err:
            LOGGER.debug("GitHub issue search failed for %s/%s: %s", owner, repo, err)
            return []

        if isinstance(data, dict) and isinstance(data.get("items"), list):
            return [item for item in data["items"] if isinstance(item, dict)]
        return []

    async def async_get_issue_comments(
        self,
        owner: str,
        repo: str,
        issue_number: int,
    ) -> list[dict[str, Any]]:
        """Fetch comments on an existing issue (up to 50)."""
        try:
            data = await self._async_read_json(
                f"/repos/{owner}/{repo}/issues/{issue_number}/comments",
                owner=owner,
                repo=repo,
                params={"per_page": 50},
                allow_404=True,
            )
        except (GitHubAuthError, GitHubAPIError) as err:
            LOGGER.debug(
                "Could not fetch comments for %s/%s#%s: %s",
                owner,
                repo,
                issue_number,
                err,
            )
            return []
        return (
            [c for c in data if isinstance(c, dict)] if isinstance(data, list) else []
        )

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
