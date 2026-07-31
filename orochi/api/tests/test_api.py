import json

import pytest

from orochi.website.models import Bookmark, Folder

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
