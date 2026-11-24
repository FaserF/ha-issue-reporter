"""Dynamic discovery and repo mapping for custom integrations & Supervisor add-ons."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from homeassistant.components.hassio import get_supervisor_client
from homeassistant.core import HomeAssistant
from homeassistant.helpers.hassio import is_hassio
from homeassistant.loader import async_get_custom_components

from .const import (
    CONF_DRY_RUN,
    CONF_MIN_SEVERITY,
    CONF_OWNER_ALLOWLIST,
    CONF_OWNER_FILTER_MODE,
    CONF_REQUIRE_APPROVAL,
    CONF_TARGET_OVERRIDES,
    DEFAULT_DRY_RUN,
    DEFAULT_INCLUDE_CORE_ADDONS,
    DEFAULT_MIN_SEVERITY,
    DEFAULT_REQUIRE_APPROVAL,
    LOGGER,
    MODE_APPROVAL,
    MODE_AUTO,
    MODE_DRY_RUN,
    OWNER_FILTER_MANUAL,
    OWNER_FILTER_SELF,
    TARGET_ADDON,
    TARGET_INTEGRATION,
)
from .github_client import GitHubClient
from .models import TargetInfo, TargetOverride

_SLUG_HASH_RE = re.compile(r"^[0-9a-f]{6,12}_(.+)$", re.IGNORECASE)


def parse_github_repo(url: str | None) -> tuple[str, str] | None:
    """Extract (owner, repo) from a GitHub URL if valid."""
    if not url or not isinstance(url, str):
        return None
    cleaned = url.strip()
    if "github.com" not in cleaned.lower():
        return None
    parsed = urlparse(cleaned)
    host = parsed.netloc.lower()
    if host not in ("github.com", "www.github.com"):
        return None
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 2:
        return None
    owner = parts[0].strip()
    repo = parts[1].strip()
    if repo.endswith(".git"):
        repo = repo[:-4]
    if not owner or not repo or owner.lower() in ("orgs", "users", "topics", "apps"):
        return None
    return owner, repo


def parse_addon_channel(repo_source: str | None, version: str | None) -> str:
    """Determine release channel (edge, beta, dev, unsupported, stable)."""
    src = (repo_source or "").lower()
    if "#" in src:
        fragment = src.split("#", 1)[1].strip()
        if fragment in ("edge", "beta", "dev", "unsupported"):
            return fragment
    ver = (version or "").lower()
    if "-dev" in ver or "dev-" in ver:
        return "dev"
    if "beta" in ver or "-b" in ver:
        return "beta"
    if "alpha" in ver or "-rc" in ver:
        return "rc"
    return "stable"


def strip_addon_slug_prefix(slug: str) -> str:
    """Strip Supervisor 8-char repository hash prefix from add-on slug."""
    match = _SLUG_HASH_RE.match(slug.strip())
    return match.group(1) if match else slug.strip()


def normalize_owner_list(raw: Any) -> list[str]:
    """Parse owner allowlist from list or comma-separated string."""
    if isinstance(raw, list):
        return [str(x).strip().lower() for x in raw if str(x).strip()]
    if isinstance(raw, str):
        return [part.strip().lower() for part in raw.split(",") if part.strip()]
    return []


async def async_discover_integrations(hass: HomeAssistant) -> list[TargetInfo]:
    """Discover installed Home Assistant custom integrations and map to GitHub repos."""
    targets: list[TargetInfo] = []
    try:
        custom = await async_get_custom_components(hass)
    except Exception as err:
        LOGGER.warning("Failed to discover custom components: %s", err)
        return []

    for domain, integration in sorted(custom.items()):
        manifest = getattr(integration, "manifest", {}) or {}
        name = str(manifest.get("name") or domain)
        version = str(manifest.get("version") or "0.0.0")
        issue_tracker = manifest.get("issue_tracker")
        documentation = manifest.get("documentation")

        parsed = parse_github_repo(issue_tracker) or parse_github_repo(documentation)
        owner = parsed[0] if parsed else None
        repo = parsed[1] if parsed else None
        repo_url = f"https://github.com/{owner}/{repo}" if owner and repo else None

        targets.append(
            TargetInfo(
                target_key=f"{TARGET_INTEGRATION}:{domain}",
                kind=TARGET_INTEGRATION,
                identifier=domain,
                short_name=domain,
                name=name,
                version=version,
                repo_owner=owner,
                repo_name=repo,
                repo_url=repo_url,
                channel=parse_addon_channel(None, version),
            )
        )
    return targets


async def async_discover_addons(
    hass: HomeAssistant,
    github_client: GitHubClient,
    *,
    include_core: bool = DEFAULT_INCLUDE_CORE_ADDONS,
) -> list[TargetInfo]:
    """Discover installed Supervisor add-ons mapped strictly to their add-on repository."""
    if not is_hassio(hass):
        return []

    supervisor = get_supervisor_client(hass)
    if supervisor is None:
        LOGGER.debug("Supervisor client unavailable despite is_hassio=True")
        return []

    try:
        repositories = await supervisor.store.repositories_list()
        addons = await supervisor.addons.list()
    except Exception as err:
        LOGGER.warning("Failed to query Supervisor add-ons/repositories: %s", err)
        return []

    repo_sources: dict[str, str] = {}
    for repo_obj in repositories:
        slug = str(getattr(repo_obj, "slug", "") or "")
        source = str(getattr(repo_obj, "source", "") or "")
        if slug:
            repo_sources[slug] = source

    targets: list[TargetInfo] = []
    # Count add-ons per mapped store repo to accurately identify monorepos
    repo_counts: dict[str, int] = {}
    preliminary: list[tuple[Any, str, tuple[str, str] | None]] = []

    for addon in addons:
        repo_slug = str(getattr(addon, "repository", "") or "")
        is_core = repo_slug == "core"
        if is_core and not include_core:
            continue

        store_source = repo_sources.get(repo_slug, "")
        store_parsed = parse_github_repo(store_source)
        addon_url_parsed = parse_github_repo(getattr(addon, "url", None))

        chosen: tuple[str, str] | None = None
        if store_parsed:
            info = await github_client.async_get_repo_info(
                store_parsed[0], store_parsed[1]
            )
            if (
                info is not None
                and not info.get("has_issues", True)
                and addon_url_parsed
            ):
                chosen = addon_url_parsed
            else:
                chosen = store_parsed
        elif addon_url_parsed:
            chosen = addon_url_parsed

        if chosen:
            repo_key = f"{chosen[0]}/{chosen[1]}".lower()
            repo_counts[repo_key] = repo_counts.get(repo_key, 0) + 1
        preliminary.append((addon, store_source, chosen))

    for addon, store_source, chosen in preliminary:
        slug = str(getattr(addon, "slug", "") or "")
        if not slug:
            continue
        repo_slug = str(getattr(addon, "repository", "") or "")
        name = str(getattr(addon, "name", "") or slug)
        version = str(getattr(addon, "version", "") or "0.0.0")
        update_available = bool(getattr(addon, "update_available", False))
        short_name = strip_addon_slug_prefix(slug)

        owner = chosen[0] if chosen else None
        repo = chosen[1] if chosen else None
        repo_url = f"https://github.com/{owner}/{repo}" if owner and repo else None

        store_parsed = parse_github_repo(store_source)
        is_monorepo = False
        if chosen:
            repo_key = f"{chosen[0]}/{chosen[1]}".lower()
            is_monorepo = (
                repo_counts.get(repo_key, 0) > 1
                or (
                    store_parsed is not None
                    and (chosen[0].lower(), chosen[1].lower())
                    == (store_parsed[0].lower(), store_parsed[1].lower())
                )
                or "addons" in chosen[1].lower()
            )

        targets.append(
            TargetInfo(
                target_key=f"{TARGET_ADDON}:{slug}",
                kind=TARGET_ADDON,
                identifier=slug,
                short_name=short_name,
                name=name,
                version=version,
                repo_owner=owner,
                repo_name=repo,
                repo_url=repo_url,
                channel=parse_addon_channel(store_source, version),
                update_available=update_available,
                is_monorepo=is_monorepo,
                is_core=repo_slug == "core",
            )
        )

    return targets


def apply_target_policies(
    discovered: list[TargetInfo],
    config: dict[str, Any],
    authenticated_owner: str | None,
) -> dict[str, TargetInfo]:
    """Apply owner filter, global defaults, and per-target overrides."""
    filter_mode = str(config.get(CONF_OWNER_FILTER_MODE, OWNER_FILTER_SELF))
    allowlist = set(normalize_owner_list(config.get(CONF_OWNER_ALLOWLIST)))
    if filter_mode == OWNER_FILTER_SELF and authenticated_owner:
        allowlist = {authenticated_owner.strip().lower()}
    elif filter_mode == OWNER_FILTER_MANUAL:
        allowlist = set()

    global_dry_run = bool(config.get(CONF_DRY_RUN, DEFAULT_DRY_RUN))
    require_approval = bool(
        config.get(CONF_REQUIRE_APPROVAL, DEFAULT_REQUIRE_APPROVAL)
    )
    default_severity = str(config.get(CONF_MIN_SEVERITY, DEFAULT_MIN_SEVERITY))
    raw_overrides = config.get(CONF_TARGET_OVERRIDES) or {}

    result: dict[str, TargetInfo] = {}
    for target in discovered:
        override = TargetOverride.from_dict(raw_overrides.get(target.target_key))
        if override.repo_override:
            parsed = parse_github_repo(
                override.repo_override
                if "github.com" in override.repo_override.lower()
                else f"https://github.com/{override.repo_override.strip('/')}"
            )
            if parsed:
                target.repo_owner, target.repo_name = parsed
                target.repo_url = f"https://github.com/{parsed[0]}/{parsed[1]}"

        owner_matched = bool(
            target.repo_owner and target.repo_owner.lower() in allowlist
        )
        target.owner_matched = owner_matched

        if override.enabled is not None:
            target.enabled = bool(override.enabled)
        elif filter_mode == OWNER_FILTER_MANUAL:
            target.enabled = False
        else:
            target.enabled = owner_matched and target.full_repo is not None

        if override.mode is not None:
            target.mode = override.mode
        elif global_dry_run:
            target.mode = MODE_DRY_RUN
        elif require_approval:
            target.mode = MODE_APPROVAL
        else:
            target.mode = MODE_AUTO

        target.min_severity = override.min_severity or default_severity
        result[target.target_key] = target

    return result
