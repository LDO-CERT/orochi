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


def test_dumps_plugin_execute(client, admin, dump, plugin):
    from orochi.website.models import Result, UserPlugin

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
    monkeypatch.setattr(
        "orochi.api.routers.dumps.index_f_and_f", lambda *args, **kwargs: None
    )

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
    matching_tasks = [
        t for t in data["live_tasks"] if t["task_id"] == f"dump_{dump.pk}"
    ]
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
    tlog = TaskLog.objects.create(
        task_id="mock-task-123", name="test_job", status="Running"
    )
    res = client.post(f"/api/utils/tasks/kill/{tlog.task_id}")
    assert res.status_code == 200, res.json()
    tlog.refresh_from_db()
    assert tlog.status == "Failed"
    assert tlog.error == "Killed by user"
