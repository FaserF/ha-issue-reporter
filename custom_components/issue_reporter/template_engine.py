"""Intelligent GitHub Issue Template / Form parser and variable mapper."""

from __future__ import annotations

import platform
import re
from typing import Any

import yaml
from homeassistant.const import __version__ as HA_VERSION
from homeassistant.core import HomeAssistant
from homeassistant.helpers.system_info import async_get_system_info

from .const import FINGERPRINT_PREFIX, LOGGER, TARGET_ADDON
from .dedup import is_dev_or_edge
from .github_client import GitHubClient
from .models import LogEvent, RenderedIssue, TargetInfo


def _infer_install_type(sys_info: dict[str, Any]) -> str:
    """Map Home Assistant system_info flags to canonical installation type label."""
    if sys_info.get("hassio"):
        os_name = str(sys_info.get("installation_type") or "")
        if "supervised" in os_name.lower():
            return "Home Assistant Supervised"
        return "Home Assistant OS"
    inst = str(sys_info.get("installation_type") or "")
    if "container" in inst.lower() or sys_info.get("docker"):
        return "Home Assistant Container"
    return inst or "Home Assistant Core"


def _match_dropdown_option(options: list[str], candidates: list[str]) -> str:
    """Match the best dropdown option case-insensitively, preferring 'Other' fallback."""
    if not options:
        return candidates[0] if candidates else ""

    norm_map = {opt.strip().lower(): opt for opt in options}
    # 1. Exact match
    for cand in candidates:
        c_low = cand.strip().lower()
        if c_low in norm_map:
            return norm_map[c_low]

    # 2. Normalized underscore/hyphen match
    slug_map = {re.sub(r"[^a-z0-9]", "", opt.lower()): opt for opt in options}
    for cand in candidates:
        c_slug = re.sub(r"[^a-z0-9]", "", cand.lower())
        if c_slug and c_slug in slug_map:
            return slug_map[c_slug]

    # 3. Substring containment match
    for cand in candidates:
        c_low = cand.strip().lower()
        if len(c_low) < 3:
            continue
        for opt in options:
            opt_low = opt.strip().lower()
            if opt_low != "other" and (c_low in opt_low or opt_low in c_low):
                return opt

    for opt in options:
        if opt.strip().lower() == "other":
            return opt
    return options[0]


def _build_concise_summary(message: str, exc_type: str) -> str:
    """Create a concise one-line title summary from sanitized error text."""
    first_line = next(
        (ln.strip() for ln in message.splitlines() if ln.strip()),
        "Unexpected error",
    )
    first_line = re.sub(r"\s+", " ", first_line)
    if exc_type and exc_type.lower() not in first_line.lower():
        summary = f"{exc_type}: {first_line}"
    else:
        summary = first_line
    return summary[:88].rstrip(" .:-")


def _select_bug_template(raw_templates: list[dict[str, str]]) -> dict[str, Any] | None:
    """Select and parse the most appropriate bug report YAML or Markdown template."""
    for tmpl in raw_templates:
        name = tmpl["name"].lower()
        if not name.endswith((".yml", ".yaml")):
            continue
        if any(skip in name for skip in ("feature", "security", "config")):
            continue
        try:
            parsed = yaml.safe_load(tmpl["content"])
        except Exception as err:
            LOGGER.debug("Failed parsing YAML issue template %s: %s", tmpl["path"], err)
            continue
        if isinstance(parsed, dict) and isinstance(parsed.get("body"), list):
            return {"kind": "yaml_form", "path": tmpl["path"], "data": parsed}

    for tmpl in raw_templates:
        name = tmpl["name"].lower()
        if name.endswith(".md") and "feature" not in name:
            return {
                "kind": "markdown",
                "path": tmpl["path"],
                "content": tmpl["content"],
            }

    return None


def _resolve_field_value(
    item: dict[str, Any],
    ctx: dict[str, Any],
) -> tuple[str, str] | None:
    """Resolve (label, rendered_value) for a GitHub Issue Form field."""
    ftype = str(item.get("type") or "")
    if ftype == "markdown":
        return None

    fid = str(item.get("id") or "").lower()
    attrs = item.get("attributes") or {}
    label = str(attrs.get("label") or fid or "Details").strip()
    label_low = label.lower()
    desc_low = str(attrs.get("description") or "").lower()

    if ftype == "dropdown":
        opts = [str(o) for o in (attrs.get("options") or [])]
        if any(k in fid or k in label_low for k in ("install", "installation")):
            return label, _match_dropdown_option(opts, [ctx["ha_install_type"]])
        if any(
            k in fid or k in label_low for k in ("app", "addon", "add-on", "component")
        ):
            return label, _match_dropdown_option(
                opts, [ctx["target_short_name"], ctx["target_name"]]
            )
        return label, _match_dropdown_option(
            opts, [ctx["target_channel"], ctx["severity"]]
        )

    if ftype == "checkboxes":
        opts = attrs.get("options") or []
        rendered_opts: list[str] = []
        for opt in opts:
            opt_lbl = (
                str(opt.get("label") or "").strip()
                if isinstance(opt, dict)
                else str(opt)
            )
            opt_low = opt_lbl.lower()
            checked = False
            if any(
                k in opt_low
                for k in ("beta", "pre-release", "prerelease", "dev", "edge")
            ):
                checked = bool(ctx["is_prerelease"])
            elif any(
                k in opt_low
                for k in (
                    "duplicate",
                    "existing",
                    "free time",
                    "understand",
                    "latest",
                    "version",
                    "redacted",
                )
            ):
                checked = True
            rendered_opts.append(f"- [{'x' if checked else ' '}] {opt_lbl}")
        return label, "\n".join(rendered_opts)

    if ftype == "input":
        is_ha_ver = (
            (
                fid in ("ha_version", "core_version", "homeassistant_version")
                or "home assistant" in label_low
            )
            and "integration" not in label_low
            and "app" not in label_low
        )
        if fid in ("env_version", "environment"):
            return label, (
                f"Home Assistant {ctx['ha_version']} "
                f"({ctx['ha_install_type']}, Python {ctx['python_version']})"
            )
        if is_ha_ver:
            return label, ctx["ha_version"]
        is_target_ver = (
            fid
            in (
                "version",
                "integration_version",
                "version_integration",
                "addon_version",
                "component_version",
                "app_version",
            )
            or label_low in ("version", "version / release")
            or any(
                phrase in label_low
                for phrase in (
                    "integration version",
                    "app version",
                    "add-on version",
                    "component version",
                    "version of the app",
                    "version of this repository",
                )
            )
        )
        if is_target_ver:
            return label, ctx["target_version"]
        return label, "_Not automatically detected (automated log report)_"

    if ftype == "textarea":
        render_lang = str(attrs.get("render") or "").strip()
        if any(
            k in fid or k in label_low for k in ("log", "traceback", "stack")
        ) or render_lang in ("shell", "txt", "text", "log", "python"):
            lang = render_lang or "text"
            return label, f"```{lang}\n{ctx['logs_block']}\n```"
        if any(k in fid or k in label_low for k in ("reproduc", "steps")):
            return label, (
                f"1. Run {ctx['target_kind_label']} **{ctx['target_name']}** "
                f"(`{ctx['target_version']}` / channel `{ctx['target_channel']}`) "
                f"on Home Assistant `{ctx['ha_version']}`.\n"
                f"2. Observed `{ctx['severity']}` in `{ctx['logger_name']}` "
                f"({ctx['occurrences']}x between {ctx['first_seen']} and {ctx['last_seen']})."
            )
        if any(k in fid or k in label_low for k in ("expected",)):
            return label, (
                f"{ctx['target_name']} should operate without logging `{ctx['severity']}` errors."
            )
        if any(
            k in fid or k in label_low
            for k in ("problem", "describe", "description", "bug")
        ):
            return label, ctx["problem_summary"]
        if "additional" in label_low or "context" in desc_low:
            return label, ctx["additional_context"]
        return label, ctx["problem_summary"]

    return None


class IssueTemplateEngine:
    """Fetches target issue templates and renders variable-filled bug reports."""

    def __init__(self, github: GitHubClient) -> None:
        """Initialize template engine."""
        self._github = github

    async def async_render_issue(
        self,
        hass: HomeAssistant,
        target: TargetInfo,
        event: LogEvent,
        *,
        sanitized_message: str,
        sanitized_traceback: str,
        fingerprint: str,
        occurrences: int,
        first_seen: str,
        last_seen: str,
        regression_of: int | None = None,
    ) -> RenderedIssue:
        """Render title, labels, and Markdown body matching target repo's issue form."""
        owner = target.repo_owner or ""
        repo = target.repo_name or ""
        full_repo = f"{owner}/{repo}"

        sys_info = await async_get_system_info(hass)
        ha_install_type = _infer_install_type(sys_info)

        logs_parts = [f"[{event.severity}] [{event.logger_name}] {sanitized_message}"]
        if sanitized_traceback:
            logs_parts.append(sanitized_traceback)
        logs_block = "\n".join(logs_parts).strip()

        target_kind_label = (
            "Supervisor add-on" if target.kind == TARGET_ADDON else "custom integration"
        )
        problem_lines = [
            f"Automated error detection for {target_kind_label} **{target.name}** (`{target.short_name}`).",
            "",
            f"- **Severity:** `{event.severity}`",
            f"- **Version:** `{target.version}` (channel: `{target.channel}`)",
            f"- **Logger:** `{event.logger_name}`",
            f"- **Occurrences:** `{occurrences}` (first: `{first_seen}`, last: `{last_seen}`)",
            f"- **Summary:** {sanitized_message.splitlines()[0][:240]}",
        ]
        if regression_of:
            problem_lines.append(
                f"- **Regression Notice:** Previously closed in #{regression_of}, still occurring on `{target.version}`."
            )

        additional_lines = [
            f"- Home Assistant Core: `{HA_VERSION}` ({ha_install_type})",
            f"- Python: `{platform.python_version()}`",
            f"- Target identifier: `{target.identifier}`",
        ]

        ctx: dict[str, Any] = {
            "ha_version": HA_VERSION,
            "ha_install_type": ha_install_type,
            "python_version": platform.python_version(),
            "target_name": target.name,
            "target_short_name": target.short_name,
            "target_kind_label": target_kind_label,
            "target_version": target.version,
            "target_channel": target.channel,
            "is_prerelease": is_dev_or_edge(target),
            "severity": event.severity,
            "logger_name": event.logger_name,
            "occurrences": occurrences,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "logs_block": logs_block,
            "problem_summary": "\n".join(problem_lines),
            "additional_context": "\n".join(additional_lines),
        }

        raw_templates = await self._github.async_fetch_bug_templates(owner, repo)
        selected = _select_bug_template(raw_templates)

        concise = _build_concise_summary(sanitized_message, event.exception_type)
        labels: list[str] = ["bug"]
        title_prefix = "[Bug]: "
        body_sections: list[str] = []
        template_used = "default"

        if selected and selected["kind"] == "yaml_form":
            template_used = selected["path"]
            form = selected["data"]
            raw_prefix = str(form.get("title") or "[Bug]: ")
            title_prefix = raw_prefix if raw_prefix.endswith(" ") else f"{raw_prefix} "
            raw_labels = form.get("labels")
            if isinstance(raw_labels, list) and raw_labels:
                labels = [str(lbl) for lbl in raw_labels if str(lbl).strip()]

            for item in form.get("body", []):
                if not isinstance(item, dict):
                    continue
                resolved = _resolve_field_value(item, ctx)
                if resolved:
                    field_label, field_val = resolved
                    body_sections.append(f"### {field_label}\n\n{field_val}")
        elif selected and selected["kind"] == "markdown":
            template_used = selected["path"]
            body_sections.extend(
                [
                    f"### Describe the bug\n\n{ctx['problem_summary']}",
                    f"### Environment\n\n{ctx['additional_context']}",
                    f"### Diagnostic Logs\n\n```text\n{logs_block}\n```",
                ]
            )
        else:
            body_sections.extend(
                [
                    f"### Summary\n\n{ctx['problem_summary']}",
                    f"### Environment\n\n{ctx['additional_context']}",
                    f"### Sanitized Logs\n\n```text\n{logs_block}\n```",
                ]
            )

        monorepo_prefix = f"[{target.short_name}] " if target.is_monorepo else ""
        full_title = f"{title_prefix}{monorepo_prefix}{concise}".strip()[:120]

        marker = (
            f"<!-- {FINGERPRINT_PREFIX}{fingerprint} "
            f"version={target.version} target={target.target_key} -->"
        )
        footer = (
            "---\n"
            "*Reported automatically by [ha-issue-reporter](https://github.com/FaserF/ha-issue-reporter). "
            "All credentials, tokens, hosts, and personal identifiers were redacted prior to submission.*\n"
            f"{marker}"
        )
        body_sections.append(footer)

        return RenderedIssue(
            repo=full_repo,
            title=full_title,
            body="\n\n".join(body_sections),
            labels=labels,
            template_used=template_used,
            fingerprint=fingerprint,
        )
