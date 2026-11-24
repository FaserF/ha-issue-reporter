"""4-layer zero-leak privacy redactor and pre-flight leak guard."""

from __future__ import annotations

import base64
import math
import re
from collections import Counter
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
    CONF_GITHUB_TOKEN,
    CONF_PRIVATE_KEY,
    CONF_STRICT_ENTROPY_GUARD,
    DEFAULT_STRICT_ENTROPY_GUARD,
    DOMAIN,
    FINGERPRINT_PREFIX,
    LOGGER,
)
from .models import RedactionResult

SENSITIVE_KEY_KEYWORDS: tuple[str, ...] = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "key",
    "auth",
    "cookie",
    "session",
    "bearer",
    "pin",
    "passphrase",
    "webhook",
    "email",
    "mail",
    "phone",
    "mobile",
    "username",
    "user",
    "login",
    "host",
    "hostname",
    "ip",
    "url",
    "uri",
    "endpoint",
    "dsn",
    "cert",
    "private",
    "client_id",
    "client_secret",
    "iban",
    "account",
    "latitude",
    "longitude",
    "lat",
    "lon",
)

SAFE_HARVEST_STOPWORDS: frozenset[str] = frozenset(
    {
        "true",
        "false",
        "none",
        "null",
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "homeassistant",
        "home-assistant",
        "default",
        "stable",
        "warning",
        "error",
        "critical",
        "debug",
        "info",
        "https",
        "http",
        "github.com",
        "api.github.com",
    }
)

PLACEHOLDER_TOKENS: frozenset[str] = frozenset(
    {
        "[REDACTED_SECRET]",
        "[REDACTED_TOKEN]",
        "[REDACTED_PRIVATE_KEY]",
        "[REDACTED_CRED]",
        "[REDACTED_HOST]",
        "[REDACTED_EMAIL]",
        "[REDACTED_PHONE]",
        "[REDACTED_IBAN]",
        "[REDACTED_IP]",
        "[REDACTED_MAC]",
        "[REDACTED_GPS]",
        "[REDACTED_UUID]",
        "[REDACTED_PATH]",
        "[REDACTED_CUSTOM]",
    }
)

SCRUBBER_RULES: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        "private_key",
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
            re.MULTILINE,
        ),
        "[REDACTED_PRIVATE_KEY]",
    ),
    (
        "github_token",
        re.compile(
            r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,255}\b|\bgithub_pat_[A-Za-z0-9_]{20,255}\b"
        ),
        "[REDACTED_TOKEN]",
    ),
    (
        "jwt",
        re.compile(
            r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
        ),
        "[REDACTED_TOKEN]",
    ),
    (
        "known_api_token",
        re.compile(
            r"\b(?:sk-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|\d{8,10}:[A-Za-z0-9_-]{35})\b"
        ),
        "[REDACTED_TOKEN]",
    ),
    (
        "auth_header",
        re.compile(
            r"((?:Authorization|X-Api-Key|X-Auth-Token|Cookie|Set-Cookie)\s*[:=]\s*(?:Bearer|Basic|Token)?\s*)([^\r\n;\"']+)",
            re.IGNORECASE,
        ),
        r"\1[REDACTED_TOKEN]",
    ),
    (
        "bearer_inline",
        re.compile(r"(\bBearer\s+)([A-Za-z0-9._~+/=-]{8,})", re.IGNORECASE),
        r"\1[REDACTED_TOKEN]",
    ),
    (
        "url_credentials",
        re.compile(r"\b([a-zA-Z][a-zA-Z0-9+.-]*://)([^:@/\s]+):([^@/\s]+)@"),
        r"\1[REDACTED_CRED]@",
    ),
    (
        "kv_secret",
        re.compile(
            r"((?:password|passwd|pwd|secret|token|api[_-]?key|access_token|refresh_token|client_secret|pin|passphrase|session_id|session_token|cookie)\s*[:=]\s*['\"]?)([^\s'\",;}\]]+)",
            re.IGNORECASE,
        ),
        r"\1[REDACTED_SECRET]",
    ),
    (
        "private_domain",
        re.compile(
            r"\b[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9-]+)*\.(?:tailnet\.[a-zA-Z0-9.-]+|ts\.net|local|lan|home\.arpa|internal|fritz\.box)\b",
            re.IGNORECASE,
        ),
        "[REDACTED_HOST]",
    ),
    (
        "email_full",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        "[REDACTED_EMAIL]",
    ),
    (
        "email_partial",
        re.compile(r"(?<=[\s>:(])[A-Za-z0-9][A-Za-z0-9._%+-]{2,}@(?=\s|$|[,;)\]])"),
        "[REDACTED_EMAIL]",
    ),
    (
        "phone_e164",
        re.compile(r"(?<!\w)\+[1-9]\d{1,2}[\s.-]?\d{2,4}[\s.-]?\d{3,10}\b"),
        "[REDACTED_PHONE]",
    ),
    (
        "iban",
        re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"),
        "[REDACTED_IBAN]",
    ),
    (
        "ipv4",
        re.compile(
            r"(?<![vV\d.])\b(?!0\.0\.0\.0\b)(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b(?![\d.])"
        ),
        "[REDACTED_IP]",
    ),
    (
        "ipv6",
        re.compile(
            r"(?<![:\w])(?:[0-9a-fA-F]{1,4}:){3,7}[0-9a-fA-F]{1,4}(?![:\w])|(?<![:\w])(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F:]{1,20}(?![:\w])"
        ),
        "[REDACTED_IP]",
    ),
    (
        "mac",
        re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"),
        "[REDACTED_MAC]",
    ),
    (
        "gps",
        re.compile(
            r"((?:lat(?:itude)?|lon(?:gitude)?)\s*[:=]\s*['\"]?)(-?\d{1,3}\.\d{4,})",
            re.IGNORECASE,
        ),
        r"\1[REDACTED_GPS]",
    ),
    (
        "uuid",
        re.compile(
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
        ),
        "[REDACTED_UUID]",
    ),
    (
        "os_user_path",
        re.compile(r"(?:/home/|/Users/|C:\\Users\\)([^/\\\s'\"]+)", re.IGNORECASE),
        r"/home/[REDACTED_PATH]",
    ),
)

LEAK_CHECK_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private_key_marker", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
    (
        "github_token",
        re.compile(
            r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}|\bgithub_pat_[A-Za-z0-9_]{20,}"
        ),
    ),
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    ),
    (
        "bearer",
        re.compile(r"\bBearer\s+(?!\[REDACTED)[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE),
    ),
    ("url_cred", re.compile(r"://[^:@/\s\[]+:[^@/\s\]]+@")),
    (
        "tailnet_host",
        re.compile(r"\.(?:tailnet\.[a-zA-Z0-9.-]+|ts\.net)\b", re.IGNORECASE),
    ),
    (
        "private_ip",
        re.compile(
            r"(?<![vV\d.])\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3})\b(?![\d.])"
        ),
    ),
)

_HIGH_ENTROPY_CANDIDATE_RE = re.compile(r"(?<![/\w.-])[A-Za-z0-9+/_=-]{28,}(?![\w./-])")


def _shannon_entropy(value: str) -> float:
    """Compute Shannon entropy in bits per character."""
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _is_sensitive_key(key: str) -> bool:
    """Return True if dict key name suggests sensitive configuration data."""
    lowered = key.lower()
    if lowered in (
        "version",
        "ha_version",
        "domain",
        "name",
        "title",
        "slug",
        "channel",
    ):
        return False
    return any(word in lowered for word in SENSITIVE_KEY_KEYWORDS)


def _walk_sensitive_values(
    obj: Any, *, key_hint: str = "", force_all: bool = False
) -> set[str]:
    """Recursively harvest sensitive string literals from dicts/lists."""
    found: set[str] = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            k_str = str(k)
            child_force = force_all or _is_sensitive_key(k_str)
            found.update(
                _walk_sensitive_values(v, key_hint=k_str, force_all=child_force)
            )
    elif isinstance(obj, list):
        for item in obj:
            found.update(
                _walk_sensitive_values(item, key_hint=key_hint, force_all=force_all)
            )
    elif isinstance(obj, str) and force_all:
        val = obj.strip()
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
    return _walk_sensitive_values(raw, force_all=True)


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
        self.update_config(config)

    def update_config(self, config: dict[str, Any]) -> None:
        """Reload user custom redaction words, domains, regexes, and guard mode."""
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

    async def async_refresh_secrets(self, hass: HomeAssistant) -> int:
        """Layer 1: Harvest sensitive values from config entries, secrets.yaml, and add-ons."""
        collected: set[str] = set()

        for entry in hass.config_entries.async_entries():
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

        expanded: set[str] = set()
        for item in collected:
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

        self._harvested_literals = expanded
        if expanded:
            ordered = sorted(expanded, key=len, reverse=True)
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

        for lit in self._harvested_literals:
            if lit and lit in without_marker:
                reasons.append("harvested_secret_survived")
                break

        for word in self._custom_literals:
            if word and word.lower() in without_marker.lower():
                reasons.append("custom_redaction_survived")
                break

        for name, pattern in LEAK_CHECK_PATTERNS:
            if pattern.search(without_marker):
                reasons.append(f"pattern_survived:{name}")

        if self._strict_entropy:
            scrubbed = without_marker
            for ph in PLACEHOLDER_TOKENS:
                scrubbed = scrubbed.replace(ph, " ")
            for match in _HIGH_ENTROPY_CANDIDATE_RE.finditer(scrubbed):
                tok = match.group(0)
                if re.fullmatch(r"[0-9a-fA-F]{32,64}", tok):
                    continue
                if "_" in tok and tok.islower():
                    continue
                if _shannon_entropy(tok) > 4.55:
                    reasons.append("high_entropy_token_suspected")
                    break

        return len(reasons) == 0, reasons
