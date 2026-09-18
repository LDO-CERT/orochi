import io
import zipfile
from unittest.mock import MagicMock, patch

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile

from orochi.website.models import Plugin, Result, UserPlugin

pytestmark = pytest.mark.django_db


def make_test_plugin_zip(plugin_filename="custom_demo.py", py_content=None):
    if py_content is None:
        py_content = (
            "from volatility3.framework import interfaces\n"
            "class CustomDemo(interfaces.plugins.PluginInterface):\n"
            "    '''Custom demo plugin documentation.'''\n"
            "    _required_framework_version = (2, 0, 0)\n"
            "    def run(self): pass\n"
        )
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(plugin_filename, py_content)
        zf.writestr("requirements.txt", "requests\n")
    bio.seek(0)
    return bio.getvalue()


def test_plugin_upload_success(client, admin, dump):
    client.force_login(admin)
    zip_bytes = make_test_plugin_zip("custom_test.py")
    upload = SimpleUploadedFile("custom_test.zip", zip_bytes, content_type="application/zip")

    with patch("orochi.api.routers.plugins.plugin_install") as mock_install:
        mock_cls = MagicMock()
        mock_cls.__doc__ = "A mock plugin for testing"
        mock_install.return_value = [{"custom.custom_test.CustomTest": mock_cls}]

        resp = client.post(
            "/api/plugins/upload",
            data={
                "plugin_file": upload,
                "operating_system": "Linux",
                "comment": "Custom Linux Test Plugin",
            },
        )
        assert resp.status_code == 200, resp.content
        data = resp.json()
        assert "custom.custom_test.CustomTest" in data["installed_plugins"]

        # Verify DB records created
        plug = Plugin.objects.get(name="custom.custom_test.CustomTest")
        assert plug.local is True
        assert plug.operating_system == "Linux"
        assert UserPlugin.objects.filter(plugin=plug, user=admin).exists()
        assert Result.objects.filter(plugin=plug, dump=dump).exists()


def test_plugin_upload_validation_non_zip(client, admin):
    client.force_login(admin)
    upload = SimpleUploadedFile("invalid.txt", b"not a zip file", content_type="text/plain")

    resp = client.post(
        "/api/plugins/upload",
        data={
            "plugin_file": upload,
            "operating_system": "Linux",
        },
    )
    assert resp.status_code == 400
    assert "zip" in resp.json()["errors"].lower()


def test_plugin_upload_validation_no_python_file(client, admin):
    client.force_login(admin)
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as zf:
        zf.writestr("readme.txt", "hello world")
    upload = SimpleUploadedFile("empty.zip", bio.getvalue(), content_type="application/zip")

    resp = client.post(
        "/api/plugins/upload",
        data={
            "plugin_file": upload,
            "operating_system": "Linux",
        },
    )
    assert resp.status_code == 400
    assert "at least one .py" in resp.json()["errors"].lower()


def test_plugin_upload_analyst_forbidden(client, analyst_user):
    client.force_login(analyst_user)
    zip_bytes = make_test_plugin_zip()
    upload = SimpleUploadedFile("plugin.zip", zip_bytes, content_type="application/zip")

    resp = client.post(
        "/api/plugins/upload",
        data={"plugin_file": upload, "operating_system": "Other"},
    )
    assert resp.status_code == 403


def test_plugin_get_source(client, admin, tmp_path):
    client.force_login(admin)
    # Create a dummy plugin in DB
    plug = Plugin.objects.create(name="custom.mock_src", operating_system="Other", local=True)

    test_file = tmp_path / "mock_src.py"
    test_file.write_text("# Mock plugin source code\nprint('hello')\n")

    with patch("orochi.api.routers.plugins.find_plugin_file", return_value=(test_file, "mock_src.py")):
        resp = client.get(f"/api/plugins/{plug.name}/source")
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == plug.name
        assert data["filename"] == "mock_src.py"
        assert "Mock plugin source code" in data["source"]


def test_plugin_get_source_not_found(client, admin):
    client.force_login(admin)
    with patch("orochi.api.routers.plugins.find_plugin_file", return_value=(None, None)):
        resp = client.get("/api/plugins/non_existent_plugin/source")
        assert resp.status_code == 404


def test_plugin_export_zip(client, admin, tmp_path):
    client.force_login(admin)
    test_file = tmp_path / "export_demo.py"
    test_file.write_text("# Plugin export test\n")

    with patch("orochi.api.routers.plugins.find_plugin_file", return_value=(test_file, "export_demo.py")):
        resp = client.get("/api/plugins/custom.export_demo/export")
        assert resp.status_code == 200
        assert resp["Content-Type"] == "application/zip"
        assert "custom_export_demo.zip" in resp["Content-Disposition"]

        # Validate ZIP content
        bio = io.BytesIO(resp.content)
        with zipfile.ZipFile(bio, "r") as zf:
            assert "export_demo.py" in zf.namelist()
            assert zf.read("export_demo.py").decode("utf-8") == "# Plugin export test\n"


def test_plugin_delete_local_success(client, admin, tmp_path):
    client.force_login(admin)
    plug = Plugin.objects.create(name="custom.to_delete", operating_system="Other", local=True)
    up = UserPlugin.objects.create(user=admin, plugin=plug)

    dummy_file = tmp_path / "to_delete.py"
    dummy_file.write_text("# to delete")

    with (
        patch("orochi.api.routers.plugins.find_plugin_file", return_value=(dummy_file, "to_delete.py")),
        patch("distributed.Client") as _,
    ):
        resp = client.delete(f"/api/plugins/{plug.name}")
        assert resp.status_code == 200
        assert "uninstalled" in resp.json()["message"].lower()

        assert not Plugin.objects.filter(name="custom.to_delete").exists()
        assert not UserPlugin.objects.filter(pk=up.pk).exists()
        assert not dummy_file.exists()


def test_plugin_delete_builtin_blocked(client, admin):
    client.force_login(admin)
    # Core plugin has local=False
    plug = Plugin.objects.create(name="windows.pslist.PsList", operating_system="Windows", local=False)

    resp = client.delete(f"/api/plugins/{plug.name}")
    assert resp.status_code == 400
    assert "built-in" in resp.json()["errors"].lower()
    assert Plugin.objects.filter(pk=plug.pk).exists()


def test_plugin_sync_endpoint(client, admin):
    client.force_login(admin)
    with patch("orochi.website.tasks.sync_volatility_plugins") as mock_task:
        mock_task.enqueue.return_value = MagicMock(id="sync-task-999")

        resp = client.post("/api/plugins/sync")
        assert resp.status_code == 200
        assert "sync-task-999" in resp.json()["message"]
        mock_task.enqueue.assert_called_once()
