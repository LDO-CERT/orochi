import json

import pytest

from orochi.website.models import Bookmark, Case, Folder, Host

pytestmark = pytest.mark.django_db


def test_list_folders(client, admin, folder):
    client.force_login(admin)
    url = "/api/folders/"  # Using hardcoded url to be safe

    response = client.get(url)
    print(response.json())
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert any(f["name"] == folder.name for f in data)


def test_create_folder(client, admin):
    client.force_login(admin)
    url = "/api/folders/"

    data = {"name": "api_test_folder"}
    response = client.post(url, json.dumps(data), content_type="application/json")

    assert response.status_code == 201
    assert Folder.objects.filter(name="api_test_folder", user=admin).exists()

    # Re-posting existing folder returns 200 OK (idempotent, like hosts & cases)
    resp_again = client.post(url, json.dumps(data), content_type="application/json")
    assert resp_again.status_code == 200


def test_delete_folder(client, admin, folder):
    client.force_login(admin)
    url = f"/api/folders/{folder.name}"

    response = client.delete(url)
    print(response.json())
    assert response.status_code == 200
    assert not Folder.objects.filter(name=folder.name, user=admin).exists()


def test_list_hosts(client, admin):
    client.force_login(admin)
    Host.objects.create(name="workstation-alpha")
    url = "/api/hosts/"

    response = client.get(url)
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert any(h["name"] == "workstation-alpha" for h in data)


def test_create_host(client, admin):
    client.force_login(admin)
    url = "/api/hosts/"

    # Create new host
    data = {"name": "server-beta"}
    response = client.post(url, json.dumps(data), content_type="application/json")
    assert response.status_code == 201
    assert Host.objects.filter(name="server-beta").exists()

    # Posting existing host returns 200 with existing object
    response_dup = client.post(url, json.dumps(data), content_type="application/json")
    assert response_dup.status_code == 200
    assert response_dup.json()["name"] == "server-beta"


def test_delete_host(client, admin):
    client.force_login(admin)
    Host.objects.create(name="server-gamma")
    url = "/api/hosts/server-gamma"

    response = client.delete(url)
    assert response.status_code == 200
    assert not Host.objects.filter(name="server-gamma").exists()


def test_list_cases(client, admin):
    client.force_login(admin)
    Case.objects.create(name="Incident-Alpha", user=admin)
    url = "/api/cases/"

    response = client.get(url)
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert any(c["name"] == "Incident-Alpha" for c in data)


def test_create_case(client, admin):
    client.force_login(admin)
    url = "/api/cases/"

    # Create new case
    data = {"name": "Incident-Beta"}
    response = client.post(url, json.dumps(data), content_type="application/json")
    assert response.status_code == 201
    assert Case.objects.filter(name="Incident-Beta", user=admin).exists()

    # Posting existing case returns 200 with existing object
    response_dup = client.post(url, json.dumps(data), content_type="application/json")
    assert response_dup.status_code == 200
    assert response_dup.json()["name"] == "Incident-Beta"


def test_delete_case(client, admin):
    client.force_login(admin)
    case = Case.objects.create(name="Incident-Gamma", user=admin)
    url = f"/api/cases/{case.pk}"

    response = client.delete(url)
    assert response.status_code == 200
    assert not Case.objects.filter(name="Incident-Gamma", user=admin).exists()


def test_update_case(client, admin, user):
    client.force_login(admin)
    case = Case.objects.create(name="Incident-Delta", user=admin)
    url = f"/api/cases/{case.pk}"

    # Update status to Closed and add collaborator
    update_data = {
        "status": "Closed",
        "collaborators": [user.pk],
        "description": "Resolved incident",
    }
    response = client.patch(url, json.dumps(update_data), content_type="application/json")
    assert response.status_code == 200
    res_data = response.json()
    assert res_data["status"] == "Closed"
    assert user.pk in res_data["collaborators"]
    assert res_data["description"] == "Resolved incident"

    case.refresh_from_db()
    assert case.status == "Closed"
    assert user in case.collaborators.all()

    # Invalid status returns 400
    bad_resp = client.patch(url, json.dumps({"status": "Invalid"}), content_type="application/json")
    assert bad_resp.status_code == 400

    # Non-existent case returns 404
    not_found_resp = client.patch(
        "/api/cases/999999",
        json.dumps({"status": "Open"}),
        content_type="application/json",
    )
    assert not_found_resp.status_code == 404


def test_list_bookmarks(client, admin, bookmark):
    client.force_login(admin)
    url = "/api/bookmarks/"

    response = client.get(url)
    print(response.json())
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert any(b["name"] == bookmark.name for b in data)


def test_delete_bookmark(client, admin, bookmark):
    client.force_login(admin)
    url = f"/api/bookmarks/{bookmark.pk}"

    response = client.delete(url)
    print(response.json())
    assert response.status_code == 200
    assert not Bookmark.objects.filter(pk=bookmark.pk).exists()


def test_reload_symbols(client, admin, dump):
    client.force_login(admin)
    dump.banner = "Linux version 5.4.0"
    dump.save()
    url = f"/api/dumps/{dump.index}/reload_symbols"

    # Needs to be a GET according to our HTMX
    response = client.get(url)
    print(response.json())
    assert response.status_code == 200
    assert "message" in response.json()


def test_delete_dump(client, admin, dump):
    client.force_login(admin)
    url = f"/api/dumps/{dump.index}"

    response = client.delete(url)
    print(response.json())
    assert response.status_code == 200
    assert "message" in response.json()
    from orochi.website.models import Dump

    assert not Dump.objects.filter(index=dump.index).exists()


def test_dumps_plugin_execute(client, admin, dump, plugin, monkeypatch):
    from orochi.website.models import Result, UserPlugin

    monkeypatch.setattr("orochi.api.routers.dumps.plugin_f_and_f", lambda *args, **kwargs: None)
    Result.objects.create(dump=dump, plugin=plugin, result=1)
    UserPlugin.objects.create(plugin=plugin, user=admin)
    client.force_login(admin)
    url = f"/api/dumps/{dump.index}/plugin/{plugin.name}/execute"

    response = client.post(url, data={"payload": "{}"})
    print(response.json())
    assert response.status_code == 200
    assert "message" in response.json()


@pytest.mark.django_db(transaction=True)
def test_create_dump_folder_formats(client, admin, monkeypatch, tmpdir):
    from django.core.files.uploadedfile import SimpleUploadedFile

    from orochi.website.models import Dump

    client.force_login(admin)
    monkeypatch.setattr("orochi.api.routers.dumps.index_f_and_f", lambda *args, **kwargs: None)

    test_cases = [
        ({"name": "test_folder_dict"}, "test_folder_dict"),
        ("test_folder_str", "test_folder_str"),
        (None, None),
        ("", None),
        (12345, "12345"),
    ]

    for idx, (folder_input, expected_folder_name) in enumerate(test_cases):
        payload = {
            "operating_system": "Linux",
            "name": f"test_dump_{idx}",
            "color": "#bfef45",
        }
        if folder_input is not None:
            payload["folder"] = folder_input

        upload = SimpleUploadedFile(f"dump_{idx}.raw", b"test_content")
        response = client.post(
            "/api/dumps/",
            data={"payload": json.dumps(payload), "upload": upload},
        )
        assert response.status_code == 200, response.json()
        dump_data = response.json()
        dump_obj = Dump.objects.get(index=dump_data["index"])

        if expected_folder_name is None:
            assert dump_obj.folder is None
        else:
            assert dump_obj.folder is not None
            assert dump_obj.folder.name == expected_folder_name


def test_edit_dump_folder(client, admin, dump, folder):

    client.force_login(admin)
    url = f"/api/dumps/{dump.index}"

    # Update folder using dict format
    res = client.patch(
        url,
        json.dumps({"folder": {"name": "updated_dict_folder"}}),
        content_type="application/json",
    )
    assert res.status_code == 200, res.json()
    dump.refresh_from_db()
    assert dump.folder.name == "updated_dict_folder"

    # Update folder using string format
    res = client.patch(
        url,
        json.dumps({"folder": "updated_str_folder"}),
        content_type="application/json",
    )
    assert res.status_code == 200, res.json()
    dump.refresh_from_db()
    assert dump.folder.name == "updated_str_folder"

    # Clear folder by sending None
    res = client.patch(
        url,
        json.dumps({"folder": None}),
        content_type="application/json",
    )
    assert res.status_code == 200, res.json()
    dump.refresh_from_db()
    assert dump.folder is None


@pytest.mark.django_db
def test_dask_status_live_tasks_and_kill(client, admin, dump):
    from orochi.website.defaults import DUMP_STATUS_ERROR, DUMP_STATUS_UNZIPPING
    from orochi.website.models import TaskLog

    client.force_login(admin)

    # 1. Test Dask status initially
    res = client.get("/api/utils/dask_status")
    assert res.status_code == 200, res.json()
    data = res.json()
    assert "workers" in data
    assert "live_tasks" in data
    assert "recent_tasks" in data

    # 2. Set dump status to unzipping (simulating unzip task)
    dump.status = DUMP_STATUS_UNZIPPING
    dump.save()

    res = client.get("/api/utils/dask_status")
    assert res.status_code == 200
    data = res.json()
    matching_tasks = [t for t in data["live_tasks"] if t["task_id"] == f"dump_{dump.pk}"]
    assert len(matching_tasks) == 1
    t = matching_tasks[0]
    assert t["task_type"] == "unzip"
    assert t["state"] == "Unzipping"
    assert t["dump_id"] == dump.pk

    # 3. Test task info endpoint
    res = client.get(f"/api/utils/tasks/info/dump_{dump.pk}")
    assert res.status_code == 200, res.json()
    info = res.json()
    assert info["task_id"] == f"dump_{dump.pk}"
    assert info["state"] == "Unzipping"
    assert info["dump_name"] == dump.name

    # 4. Test kill endpoint for dump
    res = client.post(f"/api/utils/tasks/kill/dump_{dump.pk}")
    assert res.status_code == 200, res.json()
    dump.refresh_from_db()
    assert dump.status == DUMP_STATUS_ERROR
    assert dump.comment == "Cancelled by user"

    # 5. Test kill endpoint for TaskLog
    tlog = TaskLog.objects.create(task_id="mock-task-123", name="test_job", status="Running")
    res = client.post(f"/api/utils/tasks/kill/{tlog.task_id}")
    assert res.status_code == 200, res.json()
    tlog.refresh_from_db()
    assert tlog.status == "Failed"
    assert tlog.error == "Killed by user"


@pytest.mark.django_db
def test_dumps_plugin_execute_with_file_and_json_params(client, admin, dump, plugin, monkeypatch, tmpdir):
    from django.core.files.uploadedfile import SimpleUploadedFile

    from orochi.website.models import Result, UserPlugin

    captured_calls = []

    def fake_plugin_f_and_f(dump_pk, plugin_pk, params=None, user_pk=None):
        captured_calls.append({"dump_pk": dump_pk, "plugin_pk": plugin_pk, "params": params, "user_pk": user_pk})

    monkeypatch.setattr("orochi.api.routers.dumps.plugin_f_and_f", fake_plugin_f_and_f)
    monkeypatch.setattr(
        "orochi.api.routers.dumps.get_parameters",
        lambda name: [
            {"name": "yara-file", "type": "file", "mode": "single"},
            {"name": "pid", "type": "int", "mode": "list"},
            {"name": "dump", "type": "bool", "mode": "single"},
            {"name": "offset", "type": "int", "mode": "single"},
        ],
    )

    Result.objects.get_or_create(dump=dump, plugin=plugin, defaults={"result": 1})
    UserPlugin.objects.get_or_create(plugin=plugin, user=admin)
    client.force_login(admin)
    url = f"/api/dumps/{dump.index}/plugin/{plugin.name}/execute"

    # 1. Multipart upload with file parameter + payload string
    yara_upload = SimpleUploadedFile("custom.yar", b"rule test { condition: true }")
    payload = {"pid": "100, 200", "dump": "true", "offset": "0x10"}
    res = client.post(url, data={"payload": json.dumps(payload), "yara-file": yara_upload})
    assert res.status_code == 200, res.json()
    assert len(captured_calls) == 1
    params = captured_calls[0]["params"]
    assert params["pid"] == [100, 200]
    assert params["dump"] is True
    assert params["offset"] == 16
    assert params["yara-file"].endswith("custom.yar")

    # 2. Direct application/json body with native JSON list/bool/int types
    captured_calls.clear()
    json_body = {"pid": [300, 400], "dump": False, "offset": 32}
    res2 = client.post(url, data=json.dumps(json_body), content_type="application/json")
    assert res2.status_code == 200, res2.json()
    assert len(captured_calls) == 1
    params2 = captured_calls[0]["params"]
    assert params2["pid"] == [300, 400]
    assert params2["dump"] is False
    assert params2["offset"] == 32


@pytest.mark.django_db
def test_admin_router_endpoints(client, admin, monkeypatch):
    called_commands = []
    monkeypatch.setattr(
        "orochi.api.routers.admin.management.call_command",
        lambda cmd, **kwargs: called_commands.append(cmd),
    )

    client.force_login(admin)

    res_plugins = client.get("/api/admin/plugins/update")
    assert res_plugins.status_code == 200
    assert res_plugins.json()["message"] == "Sync Plugin started"

    res_symbols = client.get("/api/admin/symbols/update")
    assert res_symbols.status_code == 200
    assert res_symbols.json()["message"] == "Sync Symbols started"

    res_rules = client.get("/api/admin/rules/update")
    assert res_rules.status_code == 200
    assert res_rules.json()["message"] == "Sync Rules started"

    res_gen = client.get("/api/admin/rules/generate")
    assert res_gen.status_code == 200
    assert res_gen.json()["message"] == "Default Rule created"
    assert called_commands == ["plugins_sync", "symbols_sync", "rules_sync", "generate_default_rule"]


@pytest.mark.django_db
def test_plugin_install_and_community_catalog(client, admin, dump, monkeypatch, tmp_path):
    import io
    import zipfile

    from django.core.files.uploadedfile import SimpleUploadedFile

    from orochi.utils.plugin_install import plugin_install
    from orochi.website.forms import PluginCreateAdminForm
    from orochi.website.models import Plugin, Result, UserPlugin

    # Point VOLATILITY_PLUGIN_PATH to an isolated temp directory
    plugin_dir = tmp_path / "custom_plugins"
    plugin_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr("extra_settings.models.Setting.get", lambda key, *a, **kw: str(plugin_dir))

    # Build a valid Volatility 3 plugin archive with two plugins inside a top-level wrapper folder
    plugin_source_1 = """from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements

class OrochiTestPluginOne(interfaces.plugins.PluginInterface):
    \"\"\"First test community plugin for Orochi.\"\"\"
    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return []

    def run(self):
        return renderers.TreeGrid([("Name", str)], [])
"""
    plugin_source_2 = """from volatility3.framework import interfaces, renderers

class OrochiTestPluginTwo(interfaces.plugins.PluginInterface):
    \"\"\"Second test community plugin for Orochi.\"\"\"
    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return []

    def run(self):
        return renderers.TreeGrid([("Value", str)], [])
"""
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("__MACOSX/._orochi_test_one.py", b"ignored")
        zf.writestr("repo-main/orochi_test_one.py", plugin_source_1.encode("utf-8"))
        zf.writestr("repo-main/orochi_test_two.py", plugin_source_2.encode("utf-8"))
    zip_bytes = zip_buf.getvalue()
    zip_file_path = tmp_path / "test_bundle.zip"
    zip_file_path.write_bytes(zip_bytes)

    # 1. Direct plugin_install extracts flattened .py files and discovers both Volatility 3 plugin classes
    discovered = plugin_install(str(zip_file_path))
    discovered_names = [list(item.keys())[0] for item in discovered]
    assert any("orochi_test_one.OrochiTestPluginOne" in n for n in discovered_names), discovered_names
    assert any("orochi_test_two.OrochiTestPluginTwo" in n for n in discovered_names), discovered_names
    assert (plugin_dir / "orochi_test_one.py").exists()
    assert (plugin_dir / "orochi_test_two.py").exists()

    # 2. POST /api/plugins/upload (synchronous mode) installs and registers both plugins in DB
    client.force_login(admin)
    upload_file = SimpleUploadedFile("community_bundle.zip", zip_bytes, content_type="application/zip")
    res_upload = client.post(
        "/api/plugins/upload",
        data={
            "plugin_file": upload_file,
            "operating_system": dump.operating_system,
            "comment": "Bundled test plugins",
            "async_mode": "false",
        },
    )
    assert res_upload.status_code == 200, res_upload.json()
    installed_list = res_upload.json()["installed_plugins"]
    assert len(installed_list) >= 2
    for plg_name in installed_list:
        plg_obj = Plugin.objects.get(name=plg_name)
        assert plg_obj.local is True
        assert UserPlugin.objects.filter(user=admin, plugin=plg_obj).exists()
        assert Result.objects.filter(dump=dump, plugin=plg_obj).exists()

    # 3. GET /api/plugins/catalog returns enriched community catalog and marks installed plugin as installed=True
    class FakeCatalogResp:
        ok = True

        @staticmethod
        def json():
            return {
                "data": [
                    [
                        "dadokkio",
                        "orochi_test_one",
                        "https://github.com/dadokkio/orochi_plugins",
                        "orochi_test_one.zip",
                        "2026/05/01",
                        "Linux",
                    ],
                    [
                        "other_author",
                        "unpackaged_plugin",
                        "https://github.com/example/unpackaged",
                        "",
                        "2026/05/01",
                        "Windows",
                        "Upstream catalog description",
                    ],
                    [
                        "orochi_plugins",
                        "screenshot",
                        "https://github.com/dadokkio/orochi_plugins",
                        "screenshot.zip",
                        "[2025-02-09] Generates wireframe PNG screenshots of Windows desktops",
                        "Windows",
                    ],
                ]
            }

    monkeypatch.setattr("orochi.api.routers.plugins.requests.get", lambda *a, **kw: FakeCatalogResp())
    res_cat = client.get("/api/plugins/catalog")
    assert res_cat.status_code == 200, res_cat.json()
    cat_data = res_cat.json()
    assert len(cat_data["items"]) == 3
    assert cat_data["items"][0]["name"] == "orochi_test_one"
    assert cat_data["items"][0]["installed"] is True
    assert cat_data["items"][1]["name"] == "unpackaged_plugin"
    assert cat_data["items"][1]["installed"] is False
    assert cat_data["items"][1]["download_url"] is None
    assert cat_data["items"][1]["description"] == "Upstream catalog description"
    assert cat_data["data"][1][8] == "Upstream catalog description"
    assert cat_data["items"][2]["name"] == "screenshot"
    assert cat_data["items"][2]["last_update"] == "2025-02-09"
    assert cat_data["data"][2][4] == "2025-02-09"
    assert cat_data["items"][2]["description"] == "Generates wireframe PNG screenshots of Windows desktops"
    assert cat_data["data"][2][8] == "Generates wireframe PNG screenshots of Windows desktops"

    # 4. POST /api/plugins/install with async_mode=False downloads and installs from URL
    class FakeZipResp:
        ok = True
        content = zip_bytes

    monkeypatch.setattr("orochi.api.routers.plugins.validate_public_https_url", lambda u: u)
    monkeypatch.setattr("orochi.api.routers.plugins.requests.get", lambda *a, **kw: FakeZipResp())
    res_inst = client.post(
        "/api/plugins/install",
        data=json.dumps(
            {
                "plugin_url": "https://github.com/dadokkio/orochi_plugins/raw/main/orochi_test_one.zip",
                "operating_system": "Linux",
                "async_mode": False,
            }
        ),
        content_type="application/json",
    )
    assert res_inst.status_code == 200, res_inst.json()
    assert len(res_inst.json()["installed_plugins"]) >= 2

    # 5. PluginCreateAdminForm registers all plugins in a multi-plugin archive
    Plugin.objects.filter(name__icontains="orochi_test_").delete()
    form = PluginCreateAdminForm(
        data={
            "operating_system": "Linux",
            "comment": "Admin multi-plugin upload",
            "disabled": False,
            "local_dump": False,
            "vt_check": False,
            "clamav_check": False,
            "regipy_check": False,
            "maxmind_check": False,
        }
    )
    form.cleaned_data = {
        "plugin": SimpleUploadedFile("bundle.zip", zip_bytes),
        "operating_system": "Linux",
        "comment": "Admin multi-plugin upload",
        "disabled": False,
        "local_dump": False,
        "vt_check": False,
        "clamav_check": False,
        "regipy_check": False,
        "maxmind_check": False,
    }
    form._errors = {}
    form._installed_plugins = discovered
    form.save_m2m = lambda: None
    saved_primary = form.save(commit=True)
    assert saved_primary.pk is not None
    assert Plugin.objects.filter(name__icontains="orochi_test_").count() == 2


@pytest.mark.django_db
def test_non_uuid_dump_index_urls_and_parameters(client, admin, dump, plugin):
    from django.urls import reverse
    from guardian.shortcuts import assign_perm

    from orochi.website.models import Dump, Result, UserPlugin

    slug_dump = Dump.objects.create(
        name="WIN11-FINANCE-WS04.dmp",
        index="showcase-win11-incident",
        operating_system="Windows",
        upload="uploads/showcase.dmp",
        author=admin,
        status=3,
    )
    assign_perm("website.can_see", admin, slug_dump)
    Result.objects.get_or_create(dump=slug_dump, plugin=plugin, defaults={"result": 2})
    Result.objects.get_or_create(dump=dump, plugin=plugin, defaults={"result": 2})
    UserPlugin.objects.get_or_create(plugin=plugin, user=admin)

    client.force_login(admin)

    # Single non-UUID dump info & plugins endpoints
    res_info = client.get(f"/api/dumps/{slug_dump.index}")
    assert res_info.status_code == 200, res_info.content

    res_plugins_single = client.get(f"/api/dumps/{slug_dump.index}/plugins")
    assert res_plugins_single.status_code == 200, res_plugins_single.content
    assert any(item["name"] == plugin.name for item in res_plugins_single.json())

    # Combined UUID + non-UUID dump indices
    combined = f"{dump.index},{slug_dump.index}"
    res_plugins_multi = client.get(f"/api/dumps/{combined}/plugins")
    assert res_plugins_multi.status_code == 200, res_plugins_multi.content

    # Parameters view (HTMX) reverses dumps_plugin_execute without NoReverseMatch
    res_params = client.get(
        reverse("website:parameters"),
        {"selected_plugin": plugin.name, "selected_indexes[]": [str(dump.index), slug_dump.index]},
        HTTP_HX_REQUEST="true",
    )
    assert res_params.status_code == 200, res_params.content
    assert f"/api/dumps/{combined}/plugin/{plugin.name}/execute" in res_params.content.decode()
