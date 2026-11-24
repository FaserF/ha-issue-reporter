"""Shared pytest fixtures for Issue Reporter tests."""

from __future__ import annotations

from collections.abc import Generator
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

REPO_TEMPLATE_BUG_YML = """name: 🐛 Bug Report
description: Create a report to help improve this project.
title: "[Bug]: "
labels: ["bug"]
body:
  - type: markdown
    attributes:
      value: |
        Thanks for opening an issue!
  - type: input
    id: version
    attributes:
      label: Version / Release
      description: Which version of this repository/component are you using?
    validations:
      required: true
  - type: input
    id: env_version
    attributes:
      label: Environment Version (Home Assistant / Python / OS)
    validations:
      required: false
  - type: checkboxes
    id: pre_release
    attributes:
      label: Release Channel
      options:
        - label: I am using a Beta or Pre-release version
          required: false
  - type: textarea
    id: description
    attributes:
      label: Describe the bug
    validations:
      required: true
  - type: textarea
    id: reproduction
    attributes:
      label: Steps to Reproduce
    validations:
      required: true
  - type: textarea
    id: expected
    attributes:
      label: Expected Behavior
    validations:
      required: true
  - type: textarea
    id: logs
    attributes:
      label: Diagnostic Logs & Tracebacks
      render: shell
    validations:
      required: false
  - type: checkboxes
    id: checklist
    attributes:
      label: Checklist
      options:
        - label: I have checked existing issues and documentation for duplicates.
          required: true
"""

HASSIO_ADDONS_BUG_YML = """name: Report an issue
description: Report an issue with one of FaserF's Custom App's
title: '[Bug]: '
labels:
  - bug
body:
  - type: textarea
    validations:
      required: true
    attributes:
      label: The problem
  - type: input
    id: version
    validations:
      required: true
    attributes:
      label: What version of Home Assistant Core has the issue?
  - type: input
    id: version_integration
    validations:
      required: true
    attributes:
      label: What version of the app has the issue?
  - type: dropdown
    id: installation_type
    validations:
      required: true
    attributes:
      label: What type of installation are you running?
      options:
        - Home Assistant OS
        - Home Assistant Container
        - Home Assistant Supervised
        - Home Assistant Core
      default: 0
  - type: dropdown
    id: app_name
    validations:
      required: true
    attributes:
      label: App causing the issue
      options:
        - Other
        - AegisBot
        - EntraMirror
        - ShieldDNS
        - dbf
        - nginx
        - traderepublic
        - whatsapp
  - type: textarea
    id: log_information
    attributes:
      label: Log information
      render: txt
"""

HA_OPENWRT_BUG_YML = """name: Bug Report
title: '[Bug]: '
labels: ['bug', 'triage']
body:
  - type: input
    id: integration_version
    attributes:
      label: Integration Version
    validations:
      required: true
  - type: input
    id: ha_version
    attributes:
      label: Home Assistant Version
    validations:
      required: true
  - type: dropdown
    id: ha_install_type
    attributes:
      label: Home Assistant Installation Type
      options:
        - Home Assistant OS
        - Home Assistant Container
        - Home Assistant Supervised
        - Home Assistant Core
    validations:
      required: true
  - type: input
    id: openwrt_version
    attributes:
      label: OpenWrt Version
    validations:
      required: true
  - type: textarea
    id: logs
    attributes:
      label: Logs
      render: yaml
"""


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(
    enable_custom_integrations: None,
) -> Generator[None]:
    """Enable custom integrations across all tests."""
    yield


@pytest.fixture
def mock_custom_components() -> dict[str, SimpleNamespace]:
    """Return sample discovered custom components."""
    return {
        "openwrt": SimpleNamespace(
            manifest={
                "domain": "openwrt",
                "name": "OpenWrt",
                "version": "2.5.7",
                "issue_tracker": "https://github.com/FaserF/ha-openwrt/issues",
                "documentation": "https://github.com/FaserF/ha-openwrt",
            }
        ),
        "aegisbot": SimpleNamespace(
            manifest={
                "domain": "aegisbot",
                "name": "AegisBot",
                "version": "1.0.3",
                "issue_tracker": "https://github.com/FaserF/ha-aegisbot/issues",
                "documentation": "https://github.com/FaserF/ha-aegisbot",
            }
        ),
        "localtuya": SimpleNamespace(
            manifest={
                "domain": "localtuya",
                "name": "Local Tuya",
                "version": "2026.10.0",
                "issue_tracker": "https://github.com/xZetsubou/hass-localtuya/issues",
                "documentation": "https://github.com/xZetsubou/hass-localtuya/",
            }
        ),
        "issue_reporter": SimpleNamespace(
            manifest={
                "domain": "issue_reporter",
                "name": "Issue Reporter",
                "version": "0.1.0",
                "issue_tracker": "https://github.com/FaserF/ha-issue-reporter/issues",
            }
        ),
    }


@pytest.fixture
def mock_supervisor_client() -> SimpleNamespace:
    """Return mock Supervisor client with sample repositories and add-ons."""
    repos = [
        SimpleNamespace(slug="core", source="core"),
        SimpleNamespace(
            slug="edfe50eb",
            source="https://github.com/FaserF/hassio-addons#edge",
        ),
        SimpleNamespace(
            slug="605cee21",
            source="https://github.com/faserf/hassio-addons",
        ),
        SimpleNamespace(
            slug="a0d7b954",
            source="https://github.com/hassio-addons/repository",
        ),
    ]
    addons = [
        SimpleNamespace(
            slug="core_mariadb",
            name="MariaDB",
            version="4.0.0",
            repository="core",
            url="https://github.com/home-assistant/app-mariadb",
            update_available=False,
            state="started",
            options={},
        ),
        SimpleNamespace(
            slug="edfe50eb_entramirror",
            name="EntraMirror",
            version="0.1.2-dev-20261122-0127-2e80491",
            repository="edfe50eb",
            url="https://github.com/FaserF/EntraMirror",
            update_available=False,
            state="error",
            options={"client_secret": "SuperSecretClient123!"},
        ),
        SimpleNamespace(
            slug="605cee21_dbf",
            name="DB Infoscreen",
            version="1.1.12",
            repository="605cee21",
            url="https://github.com/FaserF/ha-db_infoscreen",
            update_available=False,
            state="started",
            options={},
        ),
        SimpleNamespace(
            slug="a0d7b954_vscode",
            name="Studio Code Server",
            version="7.2.0",
            repository="a0d7b954",
            url="https://github.com/hassio-addons/app-vscode",
            update_available=False,
            state="started",
            options={},
        ),
    ]
    return SimpleNamespace(
        store=SimpleNamespace(repositories_list=AsyncMock(return_value=repos)),
        addons=SimpleNamespace(
            list=AsyncMock(return_value=addons),
            addon_info=AsyncMock(
                return_value=SimpleNamespace(
                    options={"client_secret": "SuperSecretClient123!"}
                )
            ),
        ),
    )


@pytest.fixture
def patch_hassio_unavailable():
    """Patch is_hassio to False when testing non-HAOS discovery."""
    with patch(
        "custom_components.issue_reporter.discovery.is_hassio", return_value=False
    ):
        yield
