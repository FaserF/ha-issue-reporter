"""Tests for GitHubClient REST requests, caching, label retry, and rate limits."""

from __future__ import annotations

import base64
from typing import Any

from custom_components.issue_reporter.auth import AUTH_PAT, GitHubAuthManager
from custom_components.issue_reporter.const import (
    CONF_AUTH_METHOD,
    CONF_GITHUB_TOKEN,
    CONF_GITHUB_USER,
)
from custom_components.issue_reporter.github_client import GitHubClient


class _ClientMockResp:
    def __init__(
        self,
        payload: Any,
        *,
        status: int = 200,
        headers: dict[str, str] | None = None,
    ) -> None:
        self._payload = payload
        self.status = status
        self.headers = headers or {
            "X-RateLimit-Remaining": "4990",
            "X-RateLimit-Reset": "1800000000",
        }

    async def json(self) -> Any:
        return self._payload

    async def text(self) -> str:
        return str(self._payload)

    async def __aenter__(self) -> _ClientMockResp:
        return self

    async def __aexit__(self, *args: Any) -> None:
        return None


class _MockClientSession:
    def __init__(self, handlers: list[tuple[str, str, _ClientMockResp]]) -> None:
        self._handlers = list(handlers)
        self.calls: list[tuple[str, str, Any]] = []

    def request(self, method: str, url: str, **kwargs: Any) -> _ClientMockResp:
        self.calls.append((method, url, kwargs.get("json")))
        for idx, (m, substr, resp) in enumerate(self._handlers):
            if m == method and substr in url:
                self._handlers.pop(idx)
                return resp
        raise AssertionError(f"Unmatched request {method} {url}")


async def test_github_client_metadata_templates_and_label_retry() -> None:
    """Test repo info caching, template fetching, search, and label fallback."""
    encoded_tpl = base64.b64encode(b"name: Bug\nbody: []\n").decode("ascii")
    session = _MockClientSession(
        [
            (
                "GET",
                "/repos/FaserF/ha-openwrt",
                _ClientMockResp(
                    {
                        "full_name": "FaserF/ha-openwrt",
                        "has_issues": True,
                        "archived": False,
                        "default_branch": "main",
                    }
                ),
            ),
            (
                "GET",
                "/repos/FaserF/ha-openwrt/releases/latest",
                _ClientMockResp({"tag_name": "v2.5.7"}),
            ),
            (
                "GET",
                "/contents/.github/ISSUE_TEMPLATE",
                _ClientMockResp(
                    [
                        {
                            "type": "file",
                            "name": "bug_report.yml",
                            "path": ".github/ISSUE_TEMPLATE/bug_report.yml",
                        }
                    ]
                ),
            ),
            (
                "GET",
                "/contents/.github/ISSUE_TEMPLATE/bug_report.yml",
                _ClientMockResp({"content": encoded_tpl}),
            ),
            (
                "GET",
                "/search/issues",
                _ClientMockResp({"items": [{"number": 11, "title": "Match"}]}),
            ),
            # First POST with labels fails 422 -> auto-retries without labels!
            (
                "POST",
                "/repos/FaserF/ha-openwrt/issues",
                _ClientMockResp("Validation Failed", status=422),
            ),
            (
                "POST",
                "/repos/FaserF/ha-openwrt/issues",
                _ClientMockResp(
                    {
                        "number": 99,
                        "html_url": "https://github.com/FaserF/ha-openwrt/issues/99",
                    }
                ),
            ),
            (
                "POST",
                "/repos/FaserF/ha-openwrt/issues/99/comments",
                _ClientMockResp({"id": 1}),
            ),
        ]
    )

    auth = GitHubAuthManager(
        session,  # type: ignore[arg-type]
        {
            CONF_AUTH_METHOD: AUTH_PAT,
            CONF_GITHUB_TOKEN: "ghp_tok",
            CONF_GITHUB_USER: "FaserF",
        },
    )
    client = GitHubClient(session, auth)  # type: ignore[arg-type]

    info1 = await client.async_get_repo_info("FaserF", "ha-openwrt")
    info2 = await client.async_get_repo_info("FaserF", "ha-openwrt")
    assert info1 == info2
    assert info1 is not None and info1["has_issues"] is True
    assert client.rate_limit_remaining == 4990

    rel = await client.async_get_latest_release("FaserF", "ha-openwrt")
    assert rel == "v2.5.7"

    tpls = await client.async_fetch_bug_templates("FaserF", "ha-openwrt")
    assert len(tpls) == 1
    assert "name: Bug" in tpls[0]["content"]

    items = await client.async_search_issues("FaserF", "ha-openwrt", "KeyError")
    assert len(items) == 1

    created = await client.async_create_issue(
        "FaserF", "ha-openwrt", "Title", "Body", labels=["triage"]
    )
    assert created["number"] == 99
    assert session.calls[-2][2] == {"title": "Title", "body": "Body"}

    comment = await client.async_create_comment("FaserF", "ha-openwrt", 99, "Note")
    assert comment["id"] == 1


async def test_github_client_etag_304_and_proactive_rate_limit() -> None:
    """Test ETag 304 zero-quota refresh, stale fallback, and proactive rate-limit block."""
    from datetime import UTC, datetime, timedelta

    import pytest

    from custom_components.issue_reporter.github_types import GitHubRateLimitError

    session = _MockClientSession(
        [
            (
                "GET",
                "/repos/FaserF/ha-openwrt/issues",
                _ClientMockResp(
                    [{"number": 1, "title": "Bug"}],
                    headers={
                        "ETag": '"abc123"',
                        "X-RateLimit-Remaining": "4980",
                        "X-RateLimit-Reset": "1800000000",
                    },
                ),
            ),
            (
                "GET",
                "/repos/FaserF/ha-openwrt/issues",
                _ClientMockResp(
                    None,
                    status=304,
                    headers={
                        "ETag": '"abc123"',
                        "X-RateLimit-Remaining": "4980",
                        "X-RateLimit-Reset": "1800000000",
                    },
                ),
            ),
        ]
    )
    auth = GitHubAuthManager(
        session,  # type: ignore[arg-type]
        {
            CONF_AUTH_METHOD: AUTH_PAT,
            CONF_GITHUB_TOKEN: "ghp_tok",
            CONF_GITHUB_USER: "FaserF",
        },
    )
    client = GitHubClient(session, auth)  # type: ignore[arg-type]

    issues, more = await client.async_get_repo_issues("FaserF", "ha-openwrt")
    assert len(issues) == 1 and more is False

    # Force cache expiry -> triggers If-None-Match -> 304 Not Modified keeps cached issues
    client._issues_cache["faserf/ha-openwrt"].fetched_at = datetime.now(
        UTC
    ) - timedelta(hours=1)
    issues2, _ = await client.async_get_repo_issues("FaserF", "ha-openwrt")
    assert len(issues2) == 1

    # Proactive rate limit blocks new uncached request when remaining < reserve
    client.rate_limit_remaining = 5
    client.rate_limit_reset = int(
        (datetime.now(UTC) + timedelta(minutes=10)).timestamp()
    )
    with pytest.raises(GitHubRateLimitError):
        await client.async_create_issue("FaserF", "ha-openwrt", "T", "B")
