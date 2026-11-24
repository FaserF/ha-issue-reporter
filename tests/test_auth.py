"""Tests for multi-mode GitHub authentication and hybrid routing."""

from __future__ import annotations

from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from custom_components.issue_reporter.auth import (
    AUTH_DEVICE_FLOW,
    AUTH_GITHUB_APP,
    AUTH_NONE,
    AUTH_PAT,
    GitHubAuthManager,
    RepoNotAuthorizedError,
    async_poll_device_token,
    async_request_device_code,
    async_validate_github_app,
    async_validate_pat,
)
from custom_components.issue_reporter.const import (
    CONF_APP_ID,
    CONF_AUTH_METHOD,
    CONF_FALLBACK_AUTH_METHOD,
    CONF_FALLBACK_TOKEN,
    CONF_FALLBACK_USER,
    CONF_GITHUB_TOKEN,
    CONF_GITHUB_USER,
    CONF_INSTALLATION_ID,
    CONF_PRIVATE_KEY,
    GITHUB_API_BASE,
)


class _MockResponse:
    """Async context manager mocking aiohttp ClientResponse."""

    def __init__(
        self,
        payload: Any,
        *,
        status: int = 200,
        headers: dict[str, str] | None = None,
    ) -> None:
        self._payload = payload
        self.status = status
        self.headers = headers or {}

    async def json(self) -> Any:
        return self._payload

    async def text(self) -> str:
        return str(self._payload)

    async def __aenter__(self) -> _MockResponse:
        return self

    async def __aexit__(self, *args: Any) -> None:
        return None


class _FakeSession:
    """Minimal mock aiohttp.ClientSession dispatching queued responses."""

    def __init__(self, responses: list[tuple[str, str, _MockResponse]]) -> None:
        self._responses = list(responses)

    def _pop(self, method: str, url: str) -> _MockResponse:
        for idx, (m, u, resp) in enumerate(self._responses):
            if m == method and u == url:
                self._responses.pop(idx)
                return resp
        raise AssertionError(f"Unexpected HTTP {method} {url}")

    def get(self, url: str, **kwargs: Any) -> _MockResponse:
        return self._pop("GET", url)

    def post(self, url: str, **kwargs: Any) -> _MockResponse:
        return self._pop("POST", url)


def _generate_test_pem() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return pem.decode("ascii")


async def test_pat_and_device_flow_helpers() -> None:
    """Test PAT validation and OAuth Device Flow code + token polling."""
    session = _FakeSession(
        [
            (
                "GET",
                f"{GITHUB_API_BASE}/user",
                _MockResponse(
                    {"login": "FaserF"},
                    headers={"X-OAuth-Scopes": "public_repo"},
                ),
            ),
            (
                "POST",
                "https://github.com/login/device/code",
                _MockResponse(
                    {
                        "device_code": "dev123",
                        "user_code": "ABCD-1234",
                        "verification_uri": "https://github.com/login/device",
                        "interval": 1,
                    }
                ),
            ),
            (
                "POST",
                "https://github.com/login/oauth/access_token",
                _MockResponse({"error": "authorization_pending"}),
            ),
            (
                "POST",
                "https://github.com/login/oauth/access_token",
                _MockResponse({"access_token": "gho_testtoken123"}),
            ),
        ]
    )

    pat_info = await async_validate_pat(session, "ghp_test123")  # type: ignore[arg-type]
    assert pat_info["login"] == "FaserF"

    dev = await async_request_device_code(session, "client123")  # type: ignore[arg-type]
    assert dev["user_code"] == "ABCD-1234"
    tok = await async_poll_device_token(
        session,  # type: ignore[arg-type]
        "client123",
        "dev123",
        interval=0,
        timeout_seconds=10,
    )
    assert tok == "gho_testtoken123"


async def test_github_app_validation_and_hybrid_routing() -> None:
    """Test GitHub App JWT minting, token caching, and hybrid fallback routing."""
    test_pem = _generate_test_pem()
    inst_payload = [
        {
            "id": 99999,
            "account": {"login": "FaserF"},
            "repository_selection": "all",
        }
    ]
    app_payload = {"slug": "faserf-hermes-agent", "name": "Hermes Agent"}

    session = _FakeSession(
        [
            ("GET", f"{GITHUB_API_BASE}/app", _MockResponse(app_payload)),
            (
                "GET",
                f"{GITHUB_API_BASE}/app/installations",
                _MockResponse(inst_payload),
            ),
            ("GET", f"{GITHUB_API_BASE}/app", _MockResponse(app_payload)),
            (
                "GET",
                f"{GITHUB_API_BASE}/app/installations",
                _MockResponse(inst_payload),
            ),
            (
                "POST",
                f"{GITHUB_API_BASE}/app/installations/99999/access_tokens",
                _MockResponse({"token": "ghs_install_tok"}),
            ),
            ("GET", f"{GITHUB_API_BASE}/app", _MockResponse(app_payload)),
            (
                "GET",
                f"{GITHUB_API_BASE}/app/installations",
                _MockResponse(inst_payload),
            ),
            (
                "POST",
                f"{GITHUB_API_BASE}/app/installations/99999/access_tokens",
                _MockResponse({"token": "ghs_install_tok_2"}),
            ),
        ]
    )

    meta = await async_validate_github_app(session, "12345", test_pem)  # type: ignore[arg-type]
    assert meta["installation_id"] == "99999"
    assert meta["account_login"] == "FaserF"

    mgr = GitHubAuthManager(
        session,  # type: ignore[arg-type]
        {
            CONF_AUTH_METHOD: AUTH_GITHUB_APP,
            CONF_APP_ID: "12345",
            CONF_INSTALLATION_ID: "99999",
            CONF_PRIVATE_KEY: test_pem,
            CONF_FALLBACK_AUTH_METHOD: AUTH_NONE,
        },
    )
    await mgr.async_initialize()
    assert mgr.get_authenticated_owner() == "FaserF"

    tok_own, actor_own = await mgr.async_get_token_for_repo("FaserF", "ha-openwrt")
    assert tok_own == "ghs_install_tok"
    assert "github_app" in actor_own

    with pytest.raises(RepoNotAuthorizedError):
        await mgr.async_get_token_for_repo("other-owner", "some-repo")

    mgr.update_config(
        {
            CONF_AUTH_METHOD: AUTH_GITHUB_APP,
            CONF_APP_ID: "12345",
            CONF_INSTALLATION_ID: "99999",
            CONF_PRIVATE_KEY: test_pem,
            CONF_FALLBACK_AUTH_METHOD: AUTH_PAT,
            CONF_FALLBACK_TOKEN: "ghp_fallback",
            CONF_FALLBACK_USER: "helper_user",
        }
    )
    tok_3p, actor_3p = await mgr.async_get_token_for_repo("other-owner", "some-repo")
    assert tok_3p == "ghp_fallback"
    assert actor_3p == "fallback:helper_user"

    pat_mgr = GitHubAuthManager(
        session,  # type: ignore[arg-type]
        {
            CONF_AUTH_METHOD: AUTH_PAT,
            CONF_GITHUB_TOKEN: "ghp_primary",
            CONF_GITHUB_USER: "FaserF",
            CONF_FALLBACK_AUTH_METHOD: AUTH_DEVICE_FLOW,
        },
    )
    tok, actor = await pat_mgr.async_get_token_for_repo("any", "repo")
    assert tok == "ghp_primary"
    assert actor == "pat:FaserF"
