import os
from typing import Any

from django.conf import settings
from django.db.models.fields.files import FieldFile
from extra_settings.models import Setting

from orochi.website.defaults import (
    SERVICE_ABUSEIPDB,
    SERVICE_CAPE,
    SERVICE_EMAIL,
    SERVICE_GREYNOISE,
    SERVICE_MISP,
    SERVICE_OLLAMA,
    SERVICE_OTX,
    SERVICE_SIEM,
    SERVICE_SLACK,
    SERVICE_THEHIVE,
    SERVICE_VIRUSTOTAL,
    SERVICE_WEBHOOK,
)
from orochi.website.models import Service

SERVICE_NAME_MAP: dict[str, int] = {
    "virustotal": SERVICE_VIRUSTOTAL,
    "vt": SERVICE_VIRUSTOTAL,
    "misp": SERVICE_MISP,
    "ollama": SERVICE_OLLAMA,
    "webhook": SERVICE_WEBHOOK,
    "slack": SERVICE_SLACK,
    "email": SERVICE_EMAIL,
    "abuseipdb": SERVICE_ABUSEIPDB,
    "otx": SERVICE_OTX,
    "greynoise": SERVICE_GREYNOISE,
    "siem": SERVICE_SIEM,
    "splunk": SERVICE_SIEM,
    "thehive": SERVICE_THEHIVE,
    "cortex": SERVICE_THEHIVE,
    "cape": SERVICE_CAPE,
    "cuckoo": SERVICE_CAPE,
    "sandbox": SERVICE_CAPE,
}


def get_runtime_setting(name: str, default: Any = None) -> Any:
    """
    Unified configuration accessor (Issues #256 / #1576).
    Resolves settings in priority order:
    1. Dynamic database `extra_settings.models.Setting`
    2. `django.conf.settings` attribute
    3. OS environment variable
    4. Provided `default`
    """
    try:
        val = Setting.get(name, default=None)
        if val is not None:
            return val
    except Exception:
        pass

    if hasattr(settings, name):
        return getattr(settings, name)

    if name in os.environ:
        return os.environ[name]

    return default


def set_runtime_setting(
    name: str,
    value: Any,
    setting_type: str = Setting.TYPE_STRING,
    description: str = "",
) -> Setting:
    """Create or update a runtime setting in `extra_settings`."""
    obj, _ = Setting.objects.get_or_create(
        name=name,
        defaults={
            "value_type": setting_type,
            "description": description,
        },
    )
    obj.value = value
    if description:
        obj.description = description
    obj.save()
    return obj


def get_service_config(service_id_or_name: int | str) -> dict[str, Any] | None:
    """
    Retrieve external service configuration with automatic AES-GCM key decryption.
    Accepts either integer constant (e.g. `SERVICE_MISP`) or string alias (e.g. `'misp'`).
    """
    if isinstance(service_id_or_name, str) and not service_id_or_name.isdigit():
        service_id = SERVICE_NAME_MAP.get(service_id_or_name.strip().lower())
    else:
        try:
            service_id = int(service_id_or_name)
        except (ValueError, TypeError):
            service_id = None

    if not service_id:
        return None

    svc = Service.objects.filter(name=service_id).first()
    if not svc:
        return None

    return {
        "id": svc.name,
        "name": svc.get_name_display(),
        "url": svc.url,
        "key": svc.decrypted_key,
        "proxy": svc.proxy if isinstance(svc.proxy, dict) else None,
    }


def export_unified_settings() -> dict[str, Any]:
    """
    Return a consolidated snapshot of runtime settings and external services
    (with masked secrets) for administrative inspection.
    """
    runtime_settings = {}
    for s in Setting.objects.all().order_by("name"):
        value = s.value
        if isinstance(value, FieldFile):
            # File and image settings (e.g. CUSTOM_LOGO): expose the stored name only
            value = value.name or None
        runtime_settings[s.name] = {
            "value": value,
            "type": s.value_type,
            "description": s.description,
        }

    services_summary = []
    for svc in Service.objects.all().order_by("name"):
        raw = svc.decrypted_key
        masked = f"{raw[:4]}...{raw[-2:]}" if raw and len(raw) > 6 else ("***" if raw else "")
        services_summary.append(
            {
                "id": svc.name,
                "name": svc.get_name_display(),
                "url": svc.url,
                "has_key": bool(raw),
                "masked_key": masked,
                "encrypted_at_rest": bool(svc.key and svc.key.startswith("enc:")),
                "has_proxy": bool(svc.proxy),
            }
        )

    return {
        "runtime_settings": runtime_settings,
        "services": services_summary,
    }
