"""Settings an administrator can change at runtime (Admin › Extra settings), read when they are used.

The environment variable of the same name is only the initial value: ``EXTRA_SETTINGS_DEFAULTS`` creates the row on the
first ``migrate`` and from then on the database value wins. Without a row, ``Setting.get`` falls back to the Django
setting of the same name.
"""

from __future__ import annotations

from django.conf import settings


def _get(name: str, default=None):
    from extra_settings.models import Setting

    try:
        value = Setting.get(name, default=None)
    except Exception:
        value = None
    return getattr(settings, name, default) if value is None else value


def remote_isf_url() -> str | None:
    """Remote banners index used by Volatility for Linux/Mac ISF; ``None`` disables it (air-gapped)."""
    value = (_get("VOLATILITY_REMOTE_ISF_URL", "") or "").strip()
    return value or None


def apply_remote_isf_url() -> str | None:
    """Push the current remote ISF index to Volatility before building a context (runs, symbol checks)."""
    from volatility3.framework import constants as vol_constants

    vol_constants.REMOTE_ISF_URL = remote_isf_url()
    return vol_constants.REMOTE_ISF_URL


def regipy_plugins() -> list[str]:
    """Names of the regipy plugins run on registry hives (comma separated in the admin)."""
    value = _get("REGIPY_PLUGINS", [])
    if isinstance(value, str):
        value = value.split(",")
    return [name.strip() for name in value or [] if name and name.strip()]


def storage_cache_max_bytes() -> int:
    """Size above which locally cached remote dumps are evicted (0 = never)."""
    from extra_settings.models import Setting

    try:
        gigabytes = Setting.get("STORAGE_CACHE_MAX_GB", default=None)
    except Exception:
        gigabytes = None
    if gigabytes is None:
        return int(getattr(settings, "STORAGE_CACHE_MAX_BYTES", 0) or 0)
    return max(0, int(gigabytes)) * 1024**3
