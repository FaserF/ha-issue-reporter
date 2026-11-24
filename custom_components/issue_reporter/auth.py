"""Multi-mode GitHub authentication manager for Issue Reporter."""

from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime, timedelta
from typing import Any

import aiohttp
import jwt

from .const import (
    AUTH_DEVICE_FLOW,
    AUTH_GITHUB_APP,
    AUTH_NONE,
    AUTH_PAT,
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
    LOGGER,
)

DEVICE_CODE_URL = "https://github.com/login/device/code"
DEVICE_TOKEN_URL = "https://github.com/login/oauth/access_token"


class GitHubAuthError(Exception):
    """Base error for GitHub authentication failures."""


class GitHubReauthRequiredError(GitHubAuthError):
    """Raised when stored credentials are invalid or revoked."""


class RepoNotAuthorizedError(GitHubAuthError):
    """Raised when configured credentials have no permission for target repo."""


def _github_headers(
    token: str | None = None, *, bearer_jwt: bool = False
) -> dict[str, str]:
    """Build standard GitHub REST API headers."""
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "ha-issue-reporter",
    }
    if token:
        scheme = "Bearer" if bearer_jwt else "token"
        headers["Authorization"] = f"{scheme} {token}"
    return headers


async def async_request_device_code(
    session: aiohttp.ClientSession,
    client_id: str,
    scope: str = "public_repo",
) -> dict[str, Any]:
    """Initiate GitHub OAuth Device Flow and return verification details."""
    if not client_id.strip():
        raise GitHubAuthError("OAuth Client ID is required for Device Flow")

    async with session.post(
        DEVICE_CODE_URL,
        headers={"Accept": "application/json", "User-Agent": "ha-issue-reporter"},
        data={"client_id": client_id.strip(), "scope": scope},
        timeout=aiohttp.ClientTimeout(total=15),
    ) as resp:
        data: dict[str, Any] = await resp.json()
        if resp.status >= 400 or "error" in data:
            msg = (
                data.get("error_description")
                or data.get("error")
                or f"HTTP {resp.status}"
            )
            raise GitHubAuthError(f"Device code request failed: {msg}")
        return data


async def async_poll_device_token(
    session: aiohttp.ClientSession,
    client_id: str,
    device_code: str,
    interval: int = 5,
    timeout_seconds: int = 300,
) -> str:
    """Poll GitHub OAuth Device Flow until user authorizes or flow expires."""
    deadline = time.monotonic() + timeout_seconds
    wait_seconds = max(1, interval)
    while time.monotonic() < deadline:
        await asyncio.sleep(wait_seconds)
        async with session.post(
            DEVICE_TOKEN_URL,
            headers={"Accept": "application/json", "User-Agent": "ha-issue-reporter"},
            data={
                "client_id": client_id.strip(),
                "device_code": device_code,
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            },
            timeout=aiohttp.ClientTimeout(total=15),
        ) as resp:
            data: dict[str, Any] = await resp.json()
            if "access_token" in data:
                return str(data["access_token"])
            err = data.get("error", "")
            if err == "authorization_pending":
                continue
            if err == "slow_down":
                wait_seconds += 5
                continue
            desc = data.get("error_description") or err or f"HTTP {resp.status}"
            raise GitHubAuthError(f"GitHub Device Flow failed: {desc}")

    raise GitHubAuthError("GitHub Device Flow timed out before user authorization")


async def async_validate_pat(
    session: aiohttp.ClientSession,
    token: str,
) -> dict[str, Any]:
    """Validate a GitHub PAT or OAuth token and return account metadata."""
    clean_token = token.strip()
    if not clean_token:
        raise GitHubAuthError("GitHub token cannot be empty")

    async with session.get(
        f"{GITHUB_API_BASE}/user",
        headers=_github_headers(clean_token),
        timeout=aiohttp.ClientTimeout(total=15),
    ) as resp:
        if resp.status in (401, 403):
            raise GitHubReauthRequiredError("GitHub token was rejected (unauthorized)")
        if resp.status >= 400:
            raise GitHubAuthError(f"GitHub token check failed with HTTP {resp.status}")
        data: dict[str, Any] = await resp.json()
        scopes_raw = resp.headers.get("X-OAuth-Scopes", "")
        scopes = [s.strip() for s in scopes_raw.split(",") if s.strip()]
        return {
            "login": str(data.get("login", "")),
            "scopes": scopes,
        }


def build_app_jwt(app_id: str, private_key_pem: str) -> str:
    """Create a short-lived RS256 JWT for GitHub App authentication."""
    now = int(time.time())
    payload = {
        "iat": now - 60,
        "exp": now + 540,
        "iss": str(app_id).strip(),
    }
    encoded = jwt.encode(payload, private_key_pem.strip(), algorithm="RS256")
    return str(encoded)


async def async_validate_github_app(
    session: aiohttp.ClientSession,
    app_id: str,
    private_key_pem: str,
    installation_id: str | int | None = None,
) -> dict[str, Any]:
    """Validate GitHub App credentials and resolve installation details."""
    if not str(app_id).strip() or "BEGIN" not in private_key_pem:
        raise GitHubAuthError("Valid App ID and PEM private key are required")

    try:
        app_jwt = build_app_jwt(str(app_id), private_key_pem)
    except Exception as err:
        raise GitHubAuthError("Invalid GitHub App private key PEM") from err

    async with session.get(
        f"{GITHUB_API_BASE}/app",
        headers=_github_headers(app_jwt, bearer_jwt=True),
        timeout=aiohttp.ClientTimeout(total=15),
    ) as resp:
        if resp.status in (401, 403):
            raise GitHubReauthRequiredError("GitHub App JWT rejected")
        if resp.status >= 400:
            raise GitHubAuthError(f"GitHub App lookup failed with HTTP {resp.status}")
        app_info: dict[str, Any] = await resp.json()

    async with session.get(
        f"{GITHUB_API_BASE}/app/installations",
        headers=_github_headers(app_jwt, bearer_jwt=True),
        timeout=aiohttp.ClientTimeout(total=15),
    ) as resp:
        if resp.status >= 400:
            raise GitHubAuthError(
                f"Failed to list GitHub App installations ({resp.status})"
            )
        installations: list[dict[str, Any]] = await resp.json()

    if not installations:
        raise GitHubAuthError("GitHub App has no active installations")

    chosen: dict[str, Any] | None = None
    wanted_id = str(installation_id).strip() if installation_id else ""
    if wanted_id:
        for inst in installations:
            if str(inst.get("id")) == wanted_id:
                chosen = inst
                break
        if chosen is None:
            raise GitHubAuthError(f"GitHub App installation {wanted_id} not found")
    else:
        chosen = installations[0]

    inst_id = int(chosen["id"])
    account_login = str((chosen.get("account") or {}).get("login", ""))
    repo_selection = str(chosen.get("repository_selection", "selected"))

    return {
        "app_slug": str(app_info.get("slug", "")),
        "app_name": str(app_info.get("name", "")),
        "installation_id": str(inst_id),
        "account_login": account_login,
        "repository_selection": repo_selection,
    }


class GitHubAuthManager:
    """Manages GitHub App, OAuth, and PAT tokens with hybrid routing."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        config: dict[str, Any],
    ) -> None:
        """Initialize auth manager from config entry data/options."""
        self._session = session
        self._config = dict(config)
        self._app_token: str | None = None
        self._app_token_expires_at: datetime | None = None
        self._app_account_login: str | None = None
        self._app_repo_selection: str = "selected"
        self._app_installed_repos: set[str] = set()
        self._app_scope_loaded_at: datetime | None = None
        self._lock = asyncio.Lock()

    def update_config(self, config: dict[str, Any]) -> None:
        """Update credential configuration and clear cached tokens."""
        self._config = dict(config)
        self._app_token = None
        self._app_token_expires_at = None
        self._app_scope_loaded_at = None
        self._app_installed_repos.clear()

    @property
    def primary_method(self) -> str:
        """Return configured primary authentication method."""
        return str(self._config.get(CONF_AUTH_METHOD, AUTH_PAT))

    @property
    def has_fallback(self) -> bool:
        """Return True if secondary user token is configured."""
        method = self._config.get(CONF_FALLBACK_AUTH_METHOD, AUTH_NONE)
        token = str(self._config.get(CONF_FALLBACK_TOKEN, "")).strip()
        return method in (AUTH_PAT, AUTH_DEVICE_FLOW) and bool(token)

    def get_authenticated_owner(self) -> str | None:
        """Return primary authenticated GitHub owner login for 'self' filtering."""
        if self.primary_method == AUTH_GITHUB_APP:
            return self._app_account_login or self._config.get(CONF_GITHUB_USER)
        owner = self._config.get(CONF_GITHUB_USER)
        return str(owner) if owner else None

    def get_actor_label(self) -> str:
        """Return human-readable label of primary actor (without secrets)."""
        if self.primary_method == AUTH_GITHUB_APP:
            owner = (
                self._app_account_login or self._config.get(CONF_GITHUB_USER) or "app"
            )
            return f"github-app ({owner})"
        user = self._config.get(CONF_GITHUB_USER) or "user"
        return f"{self.primary_method} ({user})"

    def invalidate_app_token(self) -> None:
        """Force regeneration of cached GitHub App installation token."""
        self._app_token = None
        self._app_token_expires_at = None

    async def async_initialize(self) -> None:
        """Validate primary credentials on startup."""
        if self.primary_method == AUTH_GITHUB_APP:
            await self._async_ensure_app_token(refresh_scope=True)
        else:
            token = str(self._config.get(CONF_GITHUB_TOKEN, "")).strip()
            info = await async_validate_pat(self._session, token)
            if not self._config.get(CONF_GITHUB_USER) and info.get("login"):
                self._config[CONF_GITHUB_USER] = info["login"]

    async def async_get_any_read_token(self) -> str | None:
        """Return a valid token for read-only public GitHub API calls if available."""
        try:
            if self.primary_method == AUTH_GITHUB_APP:
                return await self._async_ensure_app_token(refresh_scope=False)
            token = str(self._config.get(CONF_GITHUB_TOKEN, "")).strip()
            return token or None
        except GitHubAuthError as err:
            LOGGER.debug("Primary read token unavailable, trying fallback: %s", err)
            fallback = str(self._config.get(CONF_FALLBACK_TOKEN, "")).strip()
            return fallback or None

    async def async_get_token_for_repo(self, owner: str, repo: str) -> tuple[str, str]:
        """Return (token, actor_description) authorized for owner/repo."""
        full_repo = f"{owner}/{repo}".lower()
        if self.primary_method == AUTH_GITHUB_APP:
            app_token = await self._async_ensure_app_token(refresh_scope=False)
            if self._app_covers_repo(owner, full_repo):
                return app_token, f"github_app:{self._app_account_login or 'bot'}"
            if self.has_fallback:
                fb_token = str(self._config.get(CONF_FALLBACK_TOKEN, "")).strip()
                fb_user = str(self._config.get(CONF_FALLBACK_USER, "fallback"))
                return fb_token, f"fallback:{fb_user}"
            raise RepoNotAuthorizedError(
                f"GitHub App is not installed on {owner}/{repo} and no fallback auth is configured"
            )

        token = str(self._config.get(CONF_GITHUB_TOKEN, "")).strip()
        if not token:
            raise GitHubReauthRequiredError("Missing GitHub authentication token")
        user = str(self._config.get(CONF_GITHUB_USER, "user"))
        return token, f"{self.primary_method}:{user}"

    def _app_covers_repo(self, owner: str, full_repo_lower: str) -> bool:
        """Check whether the GitHub App installation covers owner/repo."""
        if (
            self._app_repo_selection == "all"
            and self._app_account_login
            and owner.lower() == self._app_account_login.lower()
        ):
            return True
        return full_repo_lower in self._app_installed_repos

    async def _async_ensure_app_token(self, *, refresh_scope: bool) -> str:
        """Mint or return cached GitHub App installation token."""
        async with self._lock:
            now = datetime.now(UTC)
            if (
                self._app_token
                and self._app_token_expires_at
                and now < (self._app_token_expires_at - timedelta(minutes=5))
                and not refresh_scope
            ):
                return self._app_token

            app_id = str(self._config.get(CONF_APP_ID, "")).strip()
            pem = str(self._config.get(CONF_PRIVATE_KEY, "")).strip()
            inst_id = str(self._config.get(CONF_INSTALLATION_ID, "")).strip() or None

            meta = await async_validate_github_app(self._session, app_id, pem, inst_id)
            resolved_inst_id = meta["installation_id"]
            self._app_account_login = meta["account_login"] or None
            self._app_repo_selection = meta["repository_selection"]

            app_jwt = build_app_jwt(app_id, pem)
            async with self._session.post(
                f"{GITHUB_API_BASE}/app/installations/{resolved_inst_id}/access_tokens",
                headers=_github_headers(app_jwt, bearer_jwt=True),
                json={},
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                if resp.status in (401, 403):
                    raise GitHubReauthRequiredError(
                        "GitHub App failed to mint installation token"
                    )
                if resp.status >= 400:
                    raise GitHubAuthError(
                        f"Installation token creation failed with HTTP {resp.status}"
                    )
                data: dict[str, Any] = await resp.json()

            token = str(data.get("token", ""))
            if not token:
                raise GitHubAuthError("GitHub App returned empty installation token")
            self._app_token = token
            self._app_token_expires_at = now + timedelta(minutes=58)

            should_load_scope = (
                refresh_scope
                or self._app_scope_loaded_at is None
                or (now - self._app_scope_loaded_at) > timedelta(hours=1)
            )
            if should_load_scope and self._app_repo_selection != "all":
                await self._async_refresh_installed_repos(token)
            elif should_load_scope:
                self._app_scope_loaded_at = now

            return token

    async def _async_refresh_installed_repos(self, token: str) -> None:
        """Fetch paginated list of repositories accessible to the installation."""
        repos: set[str] = set()
        page = 1
        while page <= 10:
            async with self._session.get(
                f"{GITHUB_API_BASE}/installation/repositories",
                headers=_github_headers(token),
                params={"per_page": 100, "page": page},
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                if resp.status >= 400:
                    break
                payload: dict[str, Any] = await resp.json()
                items = payload.get("repositories") or []
                for item in items:
                    full_name = item.get("full_name")
                    if full_name:
                        repos.add(str(full_name).lower())
                if len(items) < 100:
                    break
                page += 1
        self._app_installed_repos = repos
        self._app_scope_loaded_at = datetime.now(UTC)
