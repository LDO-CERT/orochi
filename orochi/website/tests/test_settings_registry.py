import pytest
from extra_settings.models import Setting

from orochi.website.defaults import SERVICE_MISP, SERVICE_THEHIVE
from orochi.website.models import Service
from orochi.website.settings_registry import (
    export_unified_settings,
    get_runtime_setting,
    get_service_config,
    set_runtime_setting,
)

pytestmark = pytest.mark.django_db


def test_runtime_setting_resolution_order(settings, monkeypatch):
    monkeypatch.setenv("OROCHI_TEST_ONLY_ENV", "from-env")
    assert get_runtime_setting("OROCHI_TEST_ONLY_ENV") == "from-env"
    assert get_runtime_setting("OROCHI_TEST_MISSING", default=7) == 7

    settings.OROCHI_TEST_ONLY_ENV = "from-settings"
    assert get_runtime_setting("OROCHI_TEST_ONLY_ENV") == "from-settings"

    set_runtime_setting("OROCHI_TEST_ONLY_ENV", "from-db", description="test")
    assert get_runtime_setting("OROCHI_TEST_ONLY_ENV") == "from-db"
    assert Setting.objects.get(name="OROCHI_TEST_ONLY_ENV").description == "test"


def test_service_config_by_alias_or_id():
    Service.objects.create(name=SERVICE_MISP, url="https://misp.local", key="secret-key", proxy={"https": "p"})
    by_alias = get_service_config("MISP")
    assert by_alias == get_service_config(SERVICE_MISP) == get_service_config(str(SERVICE_MISP))
    assert by_alias["key"] == "secret-key"
    assert by_alias["proxy"] == {"https": "p"}
    assert get_service_config("thehive") is None
    assert get_service_config("unknown") is None


def test_export_masks_secrets():
    Service.objects.create(name=SERVICE_MISP, url="https://misp.local", key="supersecretvalue")
    Service.objects.create(name=SERVICE_THEHIVE, url="https://hive.local", key="")
    services = {s["id"]: s for s in export_unified_settings()["services"]}

    misp = services[SERVICE_MISP]
    assert misp["masked_key"] == "supe...ue"
    assert misp["encrypted_at_rest"] is True
    assert "supersecretvalue" not in str(misp)
    assert services[SERVICE_THEHIVE]["has_key"] is False


def test_admin_settings_endpoint_requires_superuser(client, user, admin):
    Service.objects.create(name=SERVICE_MISP, url="https://misp.local", key="supersecretvalue")
    client.force_login(user)
    assert client.get("/api/admin/settings").status_code in (401, 403)

    client.force_login(admin)
    resp = client.get("/api/admin/settings")
    assert resp.status_code == 200
    assert "supersecretvalue" not in resp.content.decode()
