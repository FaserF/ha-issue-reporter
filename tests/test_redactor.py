"""Tests for the 4-layer privacy redactor and pre-flight leak guard."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.issue_reporter.const import (
    CONF_CUSTOM_REDACTION_REGEXES,
    CONF_CUSTOM_REDACTIONS,
    CONF_STRICT_ENTROPY_GUARD,
)
from custom_components.issue_reporter.redactor import PrivacyRedactor


async def test_regex_scrubber_layers(hass) -> None:
    """Test Layer 2 + Layer 3 regex and custom domain redaction."""
    redactor = PrivacyRedactor(
        {
            CONF_CUSTOM_REDACTIONS: ["private-home.example"],
            CONF_CUSTOM_REDACTION_REGEXES: [r"ACCOUNT-[0-9]{4}"],
        }
    )

    sample = (
        "Bearer mysecretbearertoken12345 "
        "token=ghp_abcdefghijklmnopqrstuvwxyz123456 "
        "jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk "
        "url=https://alice:hunter2pass@router.local:8443/api "
        "host=node1.tailnet.example.invalid "
        "custom=sub.private-home.example "
        "email=alice@example.org partial=> bob_user@ "
        "phone=+4915112345678 iban=DE89370400440532013000 "
        "ip=192.168.178.42 ipv6=fe80::1a2b:3c4d mac=aa:bb:cc:dd:ee:ff "
        "uuid=550e8400-e29b-41d4-a716-446655440000 "
        "latitude=48.137154 path=/home/alice/secrets acct=ACCOUNT-9876"
    )

    res = redactor.redact(sample)
    assert "mysecretbearertoken12345" not in res.text
    assert "ghp_abcdefghijklmnopqrstuvwxyz123456" not in res.text
    assert "eyJhbGciOiJIUzI1NiJ9" not in res.text
    assert "hunter2pass" not in res.text
    assert "router.local" not in res.text
    assert "node1.tailnet.example.invalid" not in res.text
    assert "private-home.example" not in res.text
    assert "alice@example.org" not in res.text
    assert "bob_user@" not in res.text
    assert "+4915112345678" not in res.text
    assert "DE89370400440532013000" not in res.text
    assert "192.168.178.42" not in res.text
    assert "fe80::1a2b:3c4d" not in res.text
    assert "aa:bb:cc:dd:ee:ff" not in res.text
    assert "550e8400-e29b-41d4-a716-446655440000" not in res.text
    assert "48.137154" not in res.text
    assert "/home/alice/" not in res.text
    assert "ACCOUNT-9876" not in res.text

    ok, reasons = redactor.verify_no_leaks("Safe title v2.5.7", res.text)
    assert ok is True
    assert reasons == []


async def test_harvest_secrets_from_config_entries_and_yaml(
    hass, tmp_path: Path
) -> None:
    """Test Layer 1 dynamic harvesting from HA config entries and secrets.yaml."""
    entry = MockConfigEntry(
        domain="dummy_integration",
        data={
            "api_key": "UltraUniqueApiKeyXYZ789",
            "email": "testuser99@example.com",
            "host": "https://my-secret-service.example.net:9000",
        },
        options={"webhook_token": "MyWebhookSecret456"},
    )
    entry.add_to_hass(hass)

    secrets_file = tmp_path / "secrets.yaml"
    secrets_file.write_text("my_db_pass: VerySecretYamlPass!\n", encoding="utf-8")

    redactor = PrivacyRedactor({})
    with (
        patch.object(hass.config, "path", return_value=str(secrets_file)),
        patch(
            "custom_components.issue_reporter.redactor.is_hassio", return_value=False
        ),
    ):
        count = await redactor.async_refresh_secrets(hass)

    assert count >= 4
    leaked = (
        "Failed calling https://my-secret-service.example.net:9000 "
        "with UltraUniqueApiKeyXYZ789 and testuser99@ and MyWebhookSecret456 "
        "or VerySecretYamlPass!"
    )
    res = redactor.redact(leaked)
    assert "UltraUniqueApiKeyXYZ789" not in res.text
    assert "my-secret-service.example.net" not in res.text
    assert "testuser99@" not in res.text
    assert "MyWebhookSecret456" not in res.text
    assert "VerySecretYamlPass!" not in res.text


async def test_leak_guard_fail_closed_aborts_unredacted_secrets(hass) -> None:
    """Test Layer 4 Pre-Flight Leak Guard blocks unmasked tokens, private IPs, and entropy."""
    redactor = PrivacyRedactor({CONF_STRICT_ENTROPY_GUARD: True})

    # Unredacted GitHub token
    ok, reasons = redactor.verify_no_leaks(
        "Title", "Leaked ghp_1234567890abcdefghij1234567890"
    )
    assert not ok
    assert "pattern_survived:github_token" in reasons

    # Unredacted private IP
    ok2, reasons2 = redactor.verify_no_leaks("Title", "Host 10.24.0.5 failed")
    assert not ok2
    assert "pattern_survived:private_ip" in reasons2

    # Unredacted high-entropy secret string
    ok3, reasons3 = redactor.verify_no_leaks(
        "Title", "raw_blob=a9ZkQ7mP2xR8vN4wL6tY1uJ3bH5cK8sD0"
    )
    assert not ok3
    assert "high_entropy_token_suspected" in reasons3

    # Normal version tags and fingerprint comment must pass cleanly
    ok4, reasons4 = redactor.verify_no_leaks(
        "[Bug]: [entramirror] AddonStateError on 0.1.2-dev-20261122-0127-2e80491",
        "Version: 0.1.2-dev-20261122-0127-2e80491\n<!-- ha-issue-reporter:fingerprint=abcdef1234567890 version=0.1.2 -->",
    )
    assert ok4 is True
    assert reasons4 == []
