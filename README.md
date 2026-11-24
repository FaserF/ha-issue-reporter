# Home Assistant Issue Reporter

[![CI](https://github.com/FaserF/ha-issue-reporter/actions/workflows/ci.yml/badge.svg)](https://github.com/FaserF/ha-issue-reporter/actions/workflows/ci.yml)
[![Linter](https://github.com/FaserF/ha-issue-reporter/actions/workflows/linter.yml/badge.svg)](https://github.com/FaserF/ha-issue-reporter/actions/workflows/linter.yml)
[![GitHub Release](https://img.shields.io/github/v/release/FaserF/ha-issue-reporter?style=flat-square)](https://github.com/FaserF/ha-issue-reporter/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A **Spook-inspired Home Assistant helper integration** that monitors custom integration logs and Supervisor add-on logs with minimal overhead, filters out local/transient errors, masks sensitive secrets & PII across 4 security layers, deduplicates across existing GitHub issues with version intelligence, and automatically fills target repositories' GitHub Issue Templates.

> [!NOTE]
> **Target Audience — Integration & Add-on Developers:**
> Issue Reporter is primarily designed for **Home Assistant integration and add-on developers** to automatically monitor their own repositories, `-dev` / `#edge` builds, and test/staging instances. While end-users can use it in **Dry-Run** or **Approval** mode, automated issue submission should be restricted to repositories you maintain or actively test.

---

## Features

- **Dual Low-Overhead Log Monitoring**
  - **Custom Integrations:** Attaches an in-memory `logging.Handler` with an O(1) logger-name & level fast path (zero log-file tailing or disk polling). Also captures HA Core attribution warnings (e.g., `homeassistant.helpers.frame` deprecation notices).
  - **Supervisor Add-ons (Separate Pipeline):** Incrementally polls Supervisor add-on logs (`/addons/{slug}/logs/latest`) and container `error` states, parsing ANSI text, structured JSON (`slog`/`zerolog`), and Pino numeric log levels (`level: 30` ignored vs `50` error) without false positives.
- **Dynamic Discovery & Strict Separation**
  - Discovers installed custom integrations from `manifest.json` (`issue_tracker` -> `documentation`) and Supervisor add-ons strictly from their Supervisor add-on repository (falling back to add-on `url` only when the store repository has GitHub issues disabled or is local).
  - **Owner Allowlist Filter:** Optionally restrict monitoring automatically to your own repositories (`self` / authenticated owner) or specific owners (e.g., `FaserF`).
- **4-Layer Zero-Leak Privacy & Redaction Pipeline**
  1. **Dynamic Secret Harvester:** Collects secret literals (tokens, passwords, keys, webhooks, coordinates, emails, partial email prefixes, hostnames) from Home Assistant Config Entries, `secrets.yaml`, and Supervisor add-on options.
  2. **Built-in Regex Scrubbers:** Masks Bearer/JWT/GitHub/API/AWS/Telegram tokens, PEM private keys, key-value secrets, URL credentials, IPv4/IPv6, MAC addresses, Tailnet/local hostnames, emails, phone numbers, IBANs, UUIDs, GPS coordinates, and OS user paths.
  3. **Custom User Rules:** Add custom literal domains/words or regexes (e.g., private domains) via Options Flow.
  4. **Pre-Flight Leak Guard (Fail-Closed):** Scans every rendered title & body before GitHub submission; if any secret, private IP, Tailnet domain, or suspicious high-entropy token survives, submission is **aborted** and an HA Repair alert is created.
- **Anti-Spam, Deduplication & Version Intelligence**
  - Skips outdated integration/add-on versions by default (while supporting `-dev` / `#edge` pre-releases).
  - Searches both exact reporter fingerprints and cross-user fuzzy matches across open and recently closed GitHub issues.
  - Never duplicates open issues; optionally posts a single concise reproduction comment if your installed version is newer.
  - Enforces configurable occurrence thresholds, per-fingerprint cooldowns, hourly global caps, and daily per-repo caps.
- **GitHub Issue Template / Form Support**
  - Fetches `.github/ISSUE_TEMPLATE/bug_report.yml` (and `.md` fallback) from the target repository and intelligently populates version fields, Home Assistant version, installation type dropdown, monorepo add-on dropdown (`app_name`), pre-release checkboxes, fenced log blocks, and verified checklists.
- **Flexible Authentication & Hybrid Mode**
  - Supports **GitHub OAuth Device Flow**, **Personal Access Token (PAT)**, and **GitHub App (Bot PEM)** — plus Hybrid Mode (primary GitHub App for installed repos + optional secondary user token for 3rd-party repos).
- **Spook-Grade Minimal Footprint**
  - Exposes 6 concise status/diagnostic sensors on a single device (no per-target entity clutter), interactive HA Repair flows for draft approval & leak alerts, System Health registration, privacy-safe Diagnostics download, and rich services.

---

## Supported Functions & Services

| Service | Description |
|---|---|
| `issue_reporter.scan_now` | Immediately refresh discovery, secrets, and add-on logs. |
| `issue_reporter.test_redaction` | Test the 4-layer redaction + leak guard on sample text (returns response). |
| `issue_reporter.preview_draft` | Render a full sanitized issue preview & duplicate check without posting (returns response). |
| `issue_reporter.approve_draft` | Approve and publish a queued draft from Approval Queue or Dry-Run mode. |
| `issue_reporter.dismiss_draft` | Dismiss a queued draft so it will not be prompted again. |
| `issue_reporter.clear_cooldowns` | Clear local deduplication cooldowns (optionally for a single target). |

---

## Configuration & Options

### Initial Setup (Config Flow)
1. Go to **Settings -> Devices & services -> Add Integration -> Issue Reporter**.
2. Choose primary GitHub authentication: **GitHub App (Bot PEM)**, **GitHub OAuth Device Flow**, or **Personal Access Token (PAT)**.
3. *(Optional, for GitHub App)* Configure a fallback PAT / OAuth token for 3rd-party repositories where the App is not installed, or skip to restrict strictly to installed repos.
4. Choose **Scope & Safety Defaults**:
   - **Owner Filter Mode:** `self` (only repos owned by authenticated user/app), `custom` (explicit owner list such as `FaserF`), or `manual` (opt-in per target).
   - **Minimum Severity:** `ERROR` (recommended), `WARNING`, or `CRITICAL`.
   - **Global Dry-Run Mode:** Recommended to verify redaction and template mapping before enabling live submission.
   - **Custom Redactions:** Comma-separated private domains or keywords to always mask.

### Options Flow Parameters
- **General & Safety:** Owner filter mode/list, global dry-run, default minimum severity, minimum occurrences & window, cooldown hours, hourly & per-repo daily caps, skip outdated versions, allow dev/edge builds, comment on newer version, add-on poll interval.
- **Local Error Filters:** Toggle ignore rules for Network/Timeout/DNS/502–504 errors, Authentication/401/403 errors, Rate Limits (429), Lifecycle/Shutdown cancellations, plus custom ignore regex patterns.
- **Privacy & Redaction:** Custom literal domains/words, custom redaction regexes, and Strict High-Entropy Leak Guard toggle.
- **Manage Integrations & Add-ons:** Independently enable/disable targets, set per-target mode (`auto`, `approval`, `dry_run`), override minimum severity, or override target GitHub repository (`owner/repo`).

---

## Installation

### Via HACS (Recommended)
1. Open HACS in Home Assistant -> **Integrations** -> 3-dot menu -> **Custom repositories**.
2. Add `https://github.com/FaserF/ha-issue-reporter` with category **Integration**.
3. Install **Issue Reporter** and restart Home Assistant.

### Manual Installation
1. Download the latest `issue_reporter.zip` from [Releases](https://github.com/FaserF/ha-issue-reporter/releases).
2. Extract into `<config>/custom_components/issue_reporter/`.
3. Restart Home Assistant.

---

## Removal
1. Go to **Settings -> Devices & services -> Issue Reporter** -> 3-dot menu -> **Delete**.
2. Uninstall via HACS or delete `<config>/custom_components/issue_reporter/` and restart Home Assistant.

---

## Known Limitations & Data Updates
- Custom integration logs are captured live in memory after Home Assistant starts (plus a one-time recent core log backfill on startup on HAOS).
- Add-on log monitoring requires Home Assistant Supervisor (`Home Assistant OS` or `Supervised`).
- Supervisor add-ons are polled on a configurable interval (default: 10 minutes), while GitHub repository metadata and issue templates are cached locally for 24 hours (6 hours for latest release tags).

---

## Troubleshooting
- **Pending Drafts not posting:** Check if **Global Dry-Run** is enabled or the target is set to `approval` mode (check **Settings -> System -> Repairs**).
- **Target skipped with `outdated_version`:** Update the integration or add-on to the latest release, or enable *Allow dev/edge builds* / disable *Skip outdated versions* in Options.
- **Leak Guard aborted an issue:** Open the Repair notification or run `issue_reporter.test_redaction` to identify the unmasked string and add a custom redaction rule if needed.

---

## Contributing & License
Contributions are welcome! Distributed under the [MIT License](LICENSE).
