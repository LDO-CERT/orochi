"""Settings changed from Admin › Extra settings apply without restart."""

import pytest
from extra_settings.models import Setting
from volatility3.framework import constants as vol_constants

from orochi.website import runtime_settings

pytestmark = pytest.mark.django_db


def _set(name, value_type, value):
    Setting.set_defaults([{"name": name, "type": value_type, "value": value}])
    row = Setting.objects.get(name=name)
    row.value = value
    row.save()


def test_remote_isf_url_follows_the_admin_value(settings):
    settings.VOLATILITY_REMOTE_ISF_URL = "https://env.example/banners.json"
    Setting.objects.filter(name="VOLATILITY_REMOTE_ISF_URL").delete()
    assert runtime_settings.apply_remote_isf_url() == "https://env.example/banners.json"

    _set("VOLATILITY_REMOTE_ISF_URL", "string", "")
    assert runtime_settings.apply_remote_isf_url() is None  # air-gapped
    assert vol_constants.REMOTE_ISF_URL is None

    _set("VOLATILITY_REMOTE_ISF_URL", "string", "https://admin.example/banners.json")
    assert runtime_settings.apply_remote_isf_url() == "https://admin.example/banners.json"


def test_regipy_plugins_accept_a_comma_separated_admin_value(settings):
    settings.REGIPY_PLUGINS = ["computer_name"]
    Setting.objects.filter(name="REGIPY_PLUGINS").delete()
    assert runtime_settings.regipy_plugins() == ["computer_name"]
    _set("REGIPY_PLUGINS", "string", "computer_name, host_domain_name,,network_drives_plugin")
    assert runtime_settings.regipy_plugins() == ["computer_name", "host_domain_name", "network_drives_plugin"]


def test_storage_cache_size_in_gb(settings):
    settings.STORAGE_CACHE_MAX_BYTES = 5
    Setting.objects.filter(name="STORAGE_CACHE_MAX_GB").delete()
    assert runtime_settings.storage_cache_max_bytes() == 5
    _set("STORAGE_CACHE_MAX_GB", "int", 2)
    assert runtime_settings.storage_cache_max_bytes() == 2 * 1024**3
