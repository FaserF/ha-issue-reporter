"""4-layer zero-leak privacy redactor and pre-flight leak guard."""

from __future__ import annotations

import base64
import math
import re
from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from typing import Any
from urllib.parse import quote

import yaml
from homeassistant.components.hassio import get_supervisor_client
from homeassistant.core import HomeAssistant
from homeassistant.helpers.hassio import is_hassio

from .const import (
    CONF_CUSTOM_REDACTION_REGEXES,
    CONF_CUSTOM_REDACTIONS,
    CONF_FALLBACK_TOKEN,
    CONF_FALLBACK_USER,
    CONF_GITHUB_TOKEN,
    CONF_OWNER_ALLOWLIST,
    CONF_PRIVATE_KEY,
    CONF_STRICT_ENTROPY_GUARD,
    DEFAULT_STRICT_ENTROPY_GUARD,
    DOMAIN,
    FINGERPRINT_PREFIX,
    LOGGER,
)
from .models import RedactionResult, TargetInfo
from .redactor_rules import (
    HIGH_ENTROPY_CANDIDATE_RE,
    LEAK_CHECK_PATTERNS,
    NON_SENSITIVE_KEYS,
    PLACEHOLDER_TOKENS,
    PUBLIC_GITHUB_REPO_URL_RE,
    SAFE_HARVEST_STOPWORDS,
    SCRUBBER_RULES,
    SENSITIVE_KEY_KEYWORDS,
)


def _shannon_entropy(value: str) -> float:
    """Compute Shannon entropy in bits per character."""
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _is_non_sensitive_key(key: str) -> bool:
    """Return True if dict key holds public metadata such as owner/repo/domain."""
    lowered = key.lower()
    if lowered in NON_SENSITIVE_KEYS:
        return True
    return lowered.endswith(
        ("_repo", "_repository", "_repo_url", "_repository_url", "_owner")
    )


def _is_sensitive_key(key: str) -> bool:
    """Return True if dict key name suggests sensitive configuration data."""
    if _is_non_sensitive_key(key):
        return False
    lowered = key.lower()
    return any(word in lowered for word in SENSITIVE_KEY_KEYWORDS)


def _is_public_github_url(val: str) -> bool:
    """Return True if value is a credential-free public GitHub URL."""
    if "://" not in val:
        return False
    after_scheme = val.split("://", 1)[1]
    authority = after_scheme.split("/", 1)[0]
    if "@" in authority:
        return False
    host = authority.split(":", 1)[0].lower()
    return host in ("github.com", "www.github.com")


def _walk_sensitive_values(
    obj: Any, *, key_hint: str = "", force_all: bool = False, from_secrets: bool = False
) -> set[str]:
    """Recursively harvest sensitive string literals from dicts/lists."""
    found: set[str] = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            k_str = str(k)
            if not from_secrets and _is_non_sensitive_key(k_str):
                child_force = False
            else:
                child_force = force_all or _is_sensitive_key(k_str)
            found.update(
                _walk_sensitive_values(
                    v,
                    key_hint=k_str,
                    force_all=child_force,
                    from_secrets=from_secrets,
                )
            )
    elif isinstance(obj, list):
        for item in obj:
            found.update(
                _walk_sensitive_values(
                    item,
                    key_hint=key_hint,
                    force_all=force_all,
                    from_secrets=from_secrets,
                )
            )
    elif isinstance(obj, str) and force_all:
        val = obj.strip()
        if not from_secrets and _is_public_github_url(val):
            return found
        if len(val) >= 6 and val.lower() not in SAFE_HARVEST_STOPWORDS:
            if not re.fullmatch(r"\d{1,5}", val):
                found.add(val)
            # Harvest email local-part + prefix and private URL hosts
            if "@" in val:
                local = val.split("@", 1)[0].strip()
                if len(local) >= 4:
                    found.add(f"{local}@")
            if "://" in val:
                host = (
                    val.split("://", 1)[1].split("/", 1)[0].split("@")[-1].split(":")[0]
                )
                if len(host) >= 6 and host.lower() not in SAFE_HARVEST_STOPWORDS:
                    found.add(host)
    return found


def _read_secrets_yaml(path: Path) -> set[str]:
    """Load /config/secrets.yaml synchronously inside executor."""
    if not path.is_file():
        return set()
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace"))
    except Exception as err:
        LOGGER.debug("Could not parse %s for secret harvesting: %s", path, err)
        return set()
    if not isinstance(raw, dict):
        return set()
    return _walk_sensitive_values(raw, force_all=True, from_secrets=True)


class PrivacyRedactor:
    """4-layer secret harvester, regex scrubber, custom rules, and leak guard."""

    def __init__(self, config: dict[str, Any]) -> None:
        """Initialize redactor with user custom rules."""
        self._harvested_literals: set[str] = set()
        self._harvested_pattern: re.Pattern[str] | None = None
        self._custom_literals: list[str] = []
        self._custom_literal_patterns: list[re.Pattern[str]] = []
        self._custom_regexes: list[re.Pattern[str]] = []
        self._strict_entropy = DEFAULT_STRICT_ENTROPY_GUARD
        self._public_github_user = ""
        self._public_github_users: set[str] = set()
        self._public_github_repos: set[str] = {"faserf/ha-issue-reporter"}
        self._target_public_values: set[str] = set()
        self.update_config(config)

    def update_config(self, config: dict[str, Any]) -> None:
        """Reload user custom redaction words, domains, regexes, and guard mode."""
        self._public_github_user = str(config.get("github_user") or "").strip()
        public_users: set[str] = set()
        for raw_user in (
            self._public_github_user,
            str(config.get(CONF_FALLBACK_USER) or "").strip(),
        ):
            if raw_user:
                public_users.add(raw_user.lower())
        raw_allowlist = config.get(CONF_OWNER_ALLOWLIST)
        if isinstance(raw_allowlist, list):
            public_users.update(
                str(x).strip().lower() for x in raw_allowlist if str(x).strip()
            )
        elif isinstance(raw_allowlist, str):
            public_users.update(
                part.strip().lower()
                for part in raw_allowlist.split(",")
                if part.strip()
            )
        self._public_github_users = public_users
        self._strict_entropy = bool(
            config.get(CONF_STRICT_ENTROPY_GUARD, DEFAULT_STRICT_ENTROPY_GUARD)
        )
        raw_words = config.get(CONF_CUSTOM_REDACTIONS) or []
        if isinstance(raw_words, str):
            words = [w.strip() for w in re.split(r"[,\n]+", raw_words) if w.strip()]
        else:
            words = [str(w).strip() for w in raw_words if str(w).strip()]

        self._custom_literals = words
        self._custom_literal_patterns = []
        for word in sorted(words, key=len, reverse=True):
            escaped = re.escape(word)
            if "." in word and not word.startswith("."):
                self._custom_literal_patterns.append(
                    re.compile(rf"(?:[a-zA-Z0-9-]+\.)*{escaped}", re.IGNORECASE)
                )
            else:
                self._custom_literal_patterns.append(re.compile(escaped, re.IGNORECASE))

        raw_regexes = config.get(CONF_CUSTOM_REDACTION_REGEXES) or []
        if isinstance(raw_regexes, str):
            regex_list = [r.strip() for r in raw_regexes.splitlines() if r.strip()]
        else:
            regex_list = [str(r).strip() for r in raw_regexes if str(r).strip()]
        self._custom_regexes = []
        for pat in regex_list:
            try:
                self._custom_regexes.append(re.compile(pat, re.IGNORECASE))
            except re.error as err:
                LOGGER.warning(
                    "Ignoring invalid custom redaction regex %r: %s", pat, err
                )

    def set_public_targets(
        self,
        targets: Iterable[TargetInfo],
        *,
        owner: str | None = None,
    ) -> None:
        """Register public GitHub owners, repos, and integration domains to ignore."""
        public_vals: set[str] = set()
        public_repos: set[str] = {"faserf/ha-issue-reporter"}
        if owner and owner.strip():
            clean_owner = owner.strip().lower()
            public_vals.add(clean_owner)
            self._public_github_users.add(clean_owner)
        for target in targets:
            for val in (
                target.repo_owner,
                target.repo_name,
                target.full_repo,
                target.repo_url,
                target.short_name,
                target.identifier,
                target.name,
            ):
                if val and val.strip():
                    public_vals.add(val.strip().lower())
            if target.full_repo:
                public_repos.add(target.full_repo.strip().lower())
        self._target_public_values = public_vals
        self._public_github_repos = public_repos

    def _public_exclusion_set(self, extra_domains: Iterable[str] = ()) -> set[str]:
        """Return lowercased public owner/repo/domain literals never treated as secrets."""
        exclusions: set[str] = set(self._target_public_values)
        exclusions.update(self._public_github_users)
        if self._public_github_user:
            exclusions.add(self._public_github_user.lower())
        for repo in self._public_github_repos:
            exclusions.add(repo)
            exclusions.add(f"https://github.com/{repo}")
            if "/" in repo:
                owner, name = repo.split("/", 1)
                exclusions.add(owner)
                exclusions.add(name)
        for dom in extra_domains:
            if dom and dom.strip():
                exclusions.add(dom.strip().lower())
        return exclusions

    async def async_refresh_secrets(self, hass: HomeAssistant) -> int:
        """Layer 1: Harvest sensitive values from config entries, secrets.yaml, and add-ons."""
        collected: set[str] = set()
        entry_domains: set[str] = set()

        for entry in hass.config_entries.async_entries():
            if entry.domain:
                entry_domains.add(entry.domain)
            if entry.domain == DOMAIN:
                for key in (CONF_GITHUB_TOKEN, CONF_FALLBACK_TOKEN, CONF_PRIVATE_KEY):
                    val = entry.data.get(key)
                    if isinstance(val, str) and len(val.strip()) >= 6:
                        collected.add(val.strip())
                continue
            collected.update(_walk_sensitive_values(dict(entry.data)))
            collected.update(_walk_sensitive_values(dict(entry.options)))

        secrets_path = Path(hass.config.path("secrets.yaml"))
        collected.update(
            await hass.async_add_executor_job(_read_secrets_yaml, secrets_path)
        )

        if is_hassio(hass):
            supervisor = get_supervisor_client(hass)
            if supervisor is not None:
                try:
                    addons = await supervisor.addons.list()
                    for addon in addons:
                        slug = getattr(addon, "slug", "")
                        if not slug:
                            continue
                        try:
                            info = await supervisor.addons.addon_info(slug)
                            opts = getattr(info, "options", None)
                            if isinstance(opts, dict):
                                collected.update(_walk_sensitive_values(opts))
                        except Exception as err:
                            LOGGER.debug(
                                "Skipping options harvest for add-on %s: %s", slug, err
                            )
                except Exception as err:
                    LOGGER.debug("Supervisor secret harvest skipped: %s", err)

        public_lower = self._public_exclusion_set(entry_domains)
        filtered_collected = {
            item for item in collected if item.lower() not in public_lower
        }

        expanded: set[str] = set()
        for item in filtered_collected:
            expanded.add(item)
            url_enc = quote(item, safe="")
            if url_enc != item and len(url_enc) >= 8:
                expanded.add(url_enc)
            if len(item) >= 8:
                b64 = base64.b64encode(item.encode("utf-8", errors="ignore")).decode(
                    "ascii"
                )
                if len(b64) >= 12:
                    expanded.add(b64)

        self._harvested_literals = {
            lit for lit in expanded if lit.lower() not in public_lower
        }
        if self._harvested_literals:
            ordered = sorted(self._harvested_literals, key=len, reverse=True)
            self._harvested_pattern = re.compile(
                "|".join(re.escape(lit) for lit in ordered)
            )
        else:
            self._harvested_pattern = None
        return len(self._harvested_literals)

    def redact(self, text: str) -> RedactionResult:
        """Apply Layers 1, 2, and 3 to sanitize text."""
        if not text:
            return RedactionResult(text="", replacements_count=0)

        current = text
        count = 0
        categories: list[str] = []

        # Layer 1: Harvested config/secret literals
        if self._harvested_pattern is not None:
            current, n = self._harvested_pattern.subn("[REDACTED_SECRET]", current)
            if n:
                count += n
                categories.append("harvested_secret")

        # Layer 2: Built-in regex scrubbers
        for name, pattern, replacement in SCRUBBER_RULES:
            current, n = pattern.subn(replacement, current)
            if n:
                count += n
                if name not in categories:
                    categories.append(name)

        # Layer 3: User custom literals & regexes
        for pattern in self._custom_literal_patterns:
            current, n = pattern.subn("[REDACTED_CUSTOM]", current)
            if n:
                count += n
                if "custom_literal" not in categories:
                    categories.append("custom_literal")

        for pattern in self._custom_regexes:
            current, n = pattern.subn("[REDACTED_CUSTOM]", current)
            if n:
                count += n
                if "custom_regex" not in categories:
                    categories.append("custom_regex")

        return RedactionResult(
            text=current,
            replacements_count=count,
            matched_categories=categories,
        )

    def redact_rendered_issue(self, title: str, body: str) -> tuple[str, str]:
        """Sanitize rendered issue title and body while preserving fingerprint markers."""
        clean_title = self.redact(title).text
        if not body:
            return clean_title, body

        marker_re = re.compile(rf"<!--\s*{re.escape(FINGERPRINT_PREFIX)}[^\n]*-->")
        preserved: list[str] = []

        def _stash(match: re.Match[str]) -> str:
            idx = len(preserved)
            preserved.append(match.group(0))
            return f"__HA_IR_MARKER_{idx}__"

        stashed = marker_re.sub(_stash, body)
        clean_body = self.redact(stashed).text
        for idx, original in enumerate(preserved):
            clean_body = clean_body.replace(f"__HA_IR_MARKER_{idx}__", original)
        return clean_title, clean_body

    def _strip_public_github_urls(self, text: str) -> str:
        """Remove known public GitHub owner/repo URLs before harvested/entropy checks."""
        public_owners = set(self._public_github_users)
        if self._public_github_user:
            public_owners.add(self._public_github_user.lower())

        def _repl(match: re.Match[str]) -> str:
            owner = match.group(1).lower()
            repo = match.group(2).lower()
            full_repo = f"{owner}/{repo}"
            if full_repo in self._public_github_repos or owner in public_owners:
                return " "
            return match.group(0)

        return PUBLIC_GITHUB_REPO_URL_RE.sub(_repl, text)

    def verify_no_leaks(self, title: str, body: str) -> tuple[bool, list[str]]:
        """Layer 4: Fail-closed verification ensuring zero secrets survive."""
        combined = f"{title}\n{body}"
        # Exclude our deterministic HTML fingerprint metadata line from entropy checks
        without_marker = re.sub(
            rf"<!--\s*{re.escape(FINGERPRINT_PREFIX)}[^\n]*-->",
            "",
            combined,
        )
        reasons: list[str] = []

        public_scrubbed = self._strip_public_github_urls(without_marker)
        scrubbed_no_ph = public_scrubbed
        for ph in PLACEHOLDER_TOKENS:
            scrubbed_no_ph = scrubbed_no_ph.replace(ph, " ")

        for word in self._custom_literals:
            if (
                word
                and word.lower() not in self._target_public_values
                and word.lower() in scrubbed_no_ph.lower()
            ):
                reasons.append("custom_redaction_survived")
                break

        for name, pattern in LEAK_CHECK_PATTERNS:
            if pattern.search(without_marker):
                reasons.append(f"pattern_survived:{name}")

        for lit in self._harvested_literals:
            if (
                lit
                and lit.lower() not in self._target_public_values
                and lit in public_scrubbed
            ):
                reasons.append("harvested_secret_survived")
                break

        if self._strict_entropy:
            scrubbed = scrubbed_no_ph
            for match in HIGH_ENTROPY_CANDIDATE_RE.finditer(scrubbed):
                tok = match.group(0)
                if re.fullmatch(r"[0-9a-fA-F]{32,64}", tok):
                    continue
                if "_" in tok and tok.islower():
                    continue
                if _shannon_entropy(tok) > 4.55:
                    reasons.append("high_entropy_token_suspected")
                    break

        return len(reasons) == 0, reasons
