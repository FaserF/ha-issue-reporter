"""On-demand, resource-efficient Home Assistant registry & metadata collector for issue templates."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er

from .const import DOMAIN, LOGGER, TARGET_ADDON
from .models import TargetInfo

_IGNORED_STATES = frozenset({"", "unknown", "unavailable", "none", "null"})
_GENERIC_SUBDEVICES = (
    "wireless radio",
    "wireless ssid",
    "tracked device",
    "home assistant app",
)


def _is_generic_device(dev: Any) -> bool:
    """Return True for non-primary sub-devices or HACS/marketplace entries."""
    mdl = (getattr(dev, "model", None) or "").strip().lower()
    if mdl in ("integration", "app", "add-on"):
        return True
    return any(g in mdl for g in _GENERIC_SUBDEVICES)


def _format_device_model(dev: Any) -> str:
    """Format manufacturer + model cleanly without duplicating manufacturer."""
    mfg = _clean_str(getattr(dev, "manufacturer", None))
    mdl = _clean_str(getattr(dev, "model", None))
    if mdl:
        if mfg and mfg.lower() not in mdl.lower():
            return f"{mfg} {mdl}"
        return mdl
    return mfg


_SAFE_CONNECTION_KEYS = (
    "connection_method",
    "connection_type",
    "setup_type",
    "transport",
    "protocol",
    "mode",
)
_SAFE_VARIANT_KEYS = ("valetudo_variant", "variant")
_SAFE_PLAN_KEYS = ("shielddns_plan", "plan", "tier")


def _clean_str(val: Any) -> str:
    """Return stripped string if meaningful, else empty string."""
    if val is None or isinstance(val, (dict, list, bool)):
        return ""
    text = str(val).strip()
    if text.lower() in _IGNORED_STATES:
        return ""
    return text


def _dedup_join(items: list[str], limit: int = 3) -> str:
    """Deduplicate preserving order and join with comma."""
    seen: set[str] = set()
    unique: list[str] = []
    for item in items:
        cleaned = item.strip()
        low = cleaned.lower()
        if cleaned and low not in seen:
            seen.add(low)
            unique.append(cleaned)
            if len(unique) >= limit:
                break
    return ", ".join(unique)


def _extract_entry_metadata(
    entries: list[Any],
) -> tuple[list[str], list[str], list[str], dict[str, str]]:
    """Extract strictly non-secret metadata from ConfigEntry data/options."""
    connections: list[str] = []
    variants: list[str] = []
    plans: list[str] = []
    extras: dict[str, str] = {}

    for entry in entries:
        merged: dict[str, Any] = {}
        raw_data = getattr(entry, "data", None)
        if isinstance(raw_data, Mapping):
            merged.update(raw_data)
        raw_options = getattr(entry, "options", None)
        if isinstance(raw_options, Mapping):
            merged.update(raw_options)

        for key in _SAFE_CONNECTION_KEYS:
            val = _clean_str(merged.get(key))
            if val:
                connections.append(val)
        if merged.get("use_ubus") is True:
            connections.append("ubus")
        if merged.get("use_ssh") is True:
            connections.append("SSH")

        for key in _SAFE_VARIANT_KEYS:
            val = _clean_str(merged.get(key))
            if val:
                variants.append(val)

        for key in _SAFE_PLAN_KEYS:
            val = _clean_str(merged.get(key))
            if val:
                plans.append(val)

        for key in ("departure_type", "api_endpoint"):
            val = _clean_str(merged.get(key))
            if val and "://" not in val:
                extras.setdefault(key, val)

        for key in ("num_departures", "limit", "max_departures"):
            raw_num = merged.get(key)
            if isinstance(raw_num, int) and not isinstance(raw_num, bool):
                extras.setdefault("num_departures", str(raw_num))

    return connections, variants, plans, extras


def _find_related_addon_version(hass: HomeAssistant, short_name: str) -> str:
    """Find version of a matching Supervisor add-on if tracked by Issue Reporter."""
    entries_data = hass.data.get(DOMAIN)
    if not isinstance(entries_data, dict):
        return ""
    for coord in entries_data.values():
        targets = getattr(coord, "targets", None)
        if not isinstance(targets, dict):
            continue
        for t in targets.values():
            if getattr(t, "kind", None) == TARGET_ADDON and short_name in getattr(
                t, "short_name", ""
            ):
                ver = _clean_str(getattr(t, "version", ""))
                if ver and ver != "unknown":
                    return ver
    return ""


def collect_ha_target_context(
    hass: HomeAssistant,
    target: TargetInfo,
) -> dict[str, Any]:
    """Collect safe device, software, and config metadata from HA registries on demand."""
    domain = target.short_name
    models: list[str] = []
    sw_versions: list[str] = []
    hw_versions: list[str] = []
    connections: list[str] = []
    variants: list[str] = []
    plans: list[str] = []
    extras: dict[str, str] = {}

    try:
        entries = list(hass.config_entries.async_entries(domain))
    except Exception as err:
        LOGGER.debug("Could not read config entries for %s: %s", domain, err)
        entries = []

    entry_ids = {e.entry_id for e in entries if getattr(e, "entry_id", None)}
    c_conn, c_var, c_plan, c_extras = _extract_entry_metadata(entries)
    connections.extend(c_conn)
    variants.extend(c_var)
    plans.extend(c_plan)
    extras.update(c_extras)

    # 1. Device Registry (in-memory, zero network I/O)
    try:
        dev_reg = dr.async_get(hass)
        matched_devs: list[Any] = []
        for eid in entry_ids:
            matched_devs.extend(dr.async_entries_for_config_entry(dev_reg, eid))

        # Fallback for MQTT/hybrid integrations (e.g. valetudo) whose devices
        # live under another config entry (e.g. mqtt) with manufacturer==domain
        if not matched_devs:
            all_devs = (
                dev_reg.devices.values()
                if isinstance(dev_reg.devices, Mapping)
                else dev_reg.devices
            )
            for dev in all_devs:
                if _is_generic_device(dev):
                    continue
                mfg_low = (dev.manufacturer or "").strip().lower()
                if mfg_low == domain or any(
                    domain in str(ident).lower() for ident in dev.identifiers
                ):
                    matched_devs.append(dev)

        primary_devs = [
            d
            for d in matched_devs
            if (d.sw_version or d.hw_version) and not _is_generic_device(d)
        ]
        chosen_devs = primary_devs or [
            d for d in matched_devs if not _is_generic_device(d)
        ]
        for dev in chosen_devs:
            formatted = _format_device_model(dev)
            if formatted:
                models.append(formatted)
            sw = _clean_str(dev.sw_version)
            if sw:
                sw_versions.append(sw)
            hw = _clean_str(dev.hw_version)
            if hw:
                hw_versions.append(hw)
    except Exception as err:
        LOGGER.debug("Device registry lookup failed for %s: %s", domain, err)

    # 2. Entity Registry + current states for version/model/plan/connection sensors
    try:
        ent_reg = er.async_get(hass)
        seen_eids: set[str] = set()
        ent_list = []
        for eid in entry_ids:
            for ent in er.async_entries_for_config_entry(ent_reg, eid):
                if ent.entity_id not in seen_eids:
                    seen_eids.add(ent.entity_id)
                    ent_list.append(ent)
        for ent in ent_list:
            eid_low = ent.entity_id.lower()
            state_obj = hass.states.get(ent.entity_id)
            if state_obj is None:
                continue
            if ent.domain == "update":
                installed = _clean_str(state_obj.attributes.get("installed_version"))
                if installed:
                    sw_versions.append(installed)
                continue
            if ent.domain != "sensor":
                continue
            sval = _clean_str(state_obj.state)
            if not sval:
                continue
            if any(
                k in eid_low
                for k in (
                    "valetudo_version",
                    "openwrt_version",
                    "firmware_version",
                    "sw_version",
                    "addon_version",
                    "app_version",
                )
            ) or eid_low.endswith("_version"):
                sw_versions.append(sval)
            elif any(
                k in eid_low
                for k in ("robot_model", "router_model", "device_model", "_model")
            ):
                models.append(sval)
            elif "variant" in eid_low:
                variants.append(sval)
            elif any(k in eid_low for k in ("_plan", "_tier")):
                plans.append(sval)
            elif any(
                k in eid_low
                for k in ("connection_type", "connection_method", "setup_type")
            ):
                connections.append(sval)
    except Exception as err:
        LOGGER.debug("Entity registry lookup failed for %s: %s", domain, err)

    related_addon_ver = _find_related_addon_version(hass, domain)
    if related_addon_ver and not connections and domain == "whatsapp":
        connections.append("Home Assistant Add-on")

    # Infer Valetudo variant if sw_version / hw_version gives a hint
    sw_joined = _dedup_join(sw_versions)
    if not variants and domain == "valetudo" and sw_joined:
        variants.append("Valetudo RE" if "re" in sw_joined.lower() else "Valetudo")

    result: dict[str, Any] = {
        "device_model": _dedup_join(models),
        "app_sw_version": sw_joined,
        "hw_version": _dedup_join(hw_versions),
        "variant": _dedup_join(variants),
        "connection_method": _dedup_join(connections),
        "plan": _dedup_join(plans),
        "related_addon_version": related_addon_ver,
        "departure_type": extras.get("departure_type", ""),
        "num_departures": extras.get("num_departures", ""),
        "api_endpoint": extras.get("api_endpoint", ""),
    }

    diag_bullets: list[str] = []
    if result["device_model"]:
        diag_bullets.append(f"- Detected Device / Model: `{result['device_model']}`")
    if result["app_sw_version"]:
        diag_bullets.append(
            f"- Detected Software / Firmware Version: `{result['app_sw_version']}`"
        )
    if result["hw_version"]:
        diag_bullets.append(f"- Detected Hardware Version: `{result['hw_version']}`")
    if result["variant"]:
        diag_bullets.append(f"- Detected Variant: `{result['variant']}`")
    if result["connection_method"]:
        diag_bullets.append(
            f"- Detected Connection / Setup Method: `{result['connection_method']}`"
        )
    if result["plan"]:
        diag_bullets.append(f"- Detected Plan / Tier: `{result['plan']}`")
    if result["related_addon_version"]:
        diag_bullets.append(
            f"- Related Supervisor Add-on Version: `{result['related_addon_version']}`"
        )
    result["extra_diagnostic_bullets"] = diag_bullets
    return result
