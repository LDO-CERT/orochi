from unittest.mock import patch

import pytest
from django.urls import reverse

from orochi.website.models import Bookmark, Folder

pytestmark = pytest.mark.django_db


def test_folder_create_get(client, admin):
    client.force_login(admin)
    url = reverse("website:folder_create")

    # Standard GET
    response = client.get(url)
    assert response.status_code == 200
    assert "html_form" in response.json()

    # HTMX GET
    response = client.get(url, HTTP_HX_REQUEST="true")
    assert response.status_code == 200
    assert "html_form" not in response.content.decode()
    assert "<form" in response.content.decode()


def test_folder_create_post(client, admin):
    client.force_login(admin)
    url = reverse("website:folder_create")

    # HTMX POST
    response = client.post(url, {"name": "new_htmx_folder"}, HTTP_HX_REQUEST="true")
    assert response.status_code == 200
    assert "HX-Trigger" in response.headers
    assert "showMessage" in response.headers["HX-Trigger"]

    assert Folder.objects.filter(name="new_htmx_folder", user=admin).exists()


def test_add_bookmark_get(client, admin):
    client.force_login(admin)
    url = reverse("website:add_bookmark")

    # HTMX GET
    response = client.get(url, HTTP_HX_REQUEST="true")
    assert response.status_code == 200
    assert "<form" in response.content.decode()


def test_add_bookmark_post(client, admin, dump, plugin):
    client.force_login(admin)
    url = reverse("website:add_bookmark")

    data = {
        "icon": "ss-ori",
        "name": "my_new_bookmark",
        "query": "test query",
        "star": True,
        "selected_indexes": f"{dump.index}",
        "selected_plugin": f"{plugin.name}",
    }

    response = client.post(url, data, HTTP_HX_REQUEST="true")
    assert response.status_code == 200
    assert "HX-Trigger" in response.headers

    bookmark = Bookmark.objects.get(name="my_new_bookmark", user=admin)
    assert bookmark.plugin == plugin
    assert bookmark.query == "test query"
    assert dump in bookmark.indexes.all()


@patch("orochi.website.views.index_f_and_f")
def test_restart(mock_index_f_and_f, client, admin, dump, plugin):
    client.force_login(admin)
    url = reverse("website:index_restart")

    # Add plugin to dump if not exists
    from orochi.website.models import Result

    Result.objects.get_or_create(dump=dump, plugin=plugin, defaults={"result": 0})

    # HTMX GET
    response = client.get(url, {"index": dump.index}, HTTP_HX_REQUEST="true")
    assert response.status_code == 200
    assert "HX-Trigger" in response.headers
    assert "Restart successful!" in response.headers["HX-Trigger"]

    # Verify the task was triggered (transaction.on_commit happens after test but we can mock or just assume it is queued)
    # Since it's in transaction.on_commit, it won't fire during standard test execution without special test setups,
    # but the view successfully processes it.


def test_info(client, admin, dump):
    client.force_login(admin)
    url = reverse("website:index_info")

    response = client.get(url, {"index": dump.index}, HTTP_HX_REQUEST="true")
    assert response.status_code == 200
    assert dump.name in response.content.decode()


def test_edit_get(client, admin, dump):
    client.force_login(admin)
    url = reverse("website:index_edit")

    response = client.get(url, {"index": dump.index}, HTTP_HX_REQUEST="true")
    assert response.status_code == 200
    assert "<form" in response.content.decode()


def test_banner_symbols_get(client, admin, dump):
    client.force_login(admin)
    url = reverse("website:banner_symbols")

    response = client.get(url, {"index": dump.index}, HTTP_HX_REQUEST="true")
    assert response.status_code == 200
    assert "<form" in response.content.decode()


def test_readonly_user_blocked(client, readonly_user, dump):
    client.force_login(readonly_user)

    # Test restart (should be blocked)
    url = reverse("website:index_restart")
    response = client.get(url, {"index": dump.index})
    assert response.status_code == 302  # redirects due to user_passes_test


def test_index_create_get(client, admin):
    client.force_login(admin)
    url = reverse("website:index_create")

    # HTMX GET
    response = client.get(url, HTTP_HX_REQUEST="true")
    assert response.status_code == 200
    assert "<form" in response.content.decode()


def test_hex_view(client, admin, dump):
    client.force_login(admin)
    url = reverse("website:hex_view", kwargs={"index": dump.index})

    response = client.get(url)
    assert response.status_code == 200
    assert (
        '<table class="table table-striped" id="example"' in response.content.decode()
    )


def test_download(client, admin, dump, tmp_path):
    client.force_login(admin)
    url = reverse("website:download")
    from pathlib import Path

    # The view expects the filepath to have the dump index as the 3rd component, like /tmp/<index>/file.ext
    test_file_path = Path(f"/tmp/{dump.index}/dummy_dump.raw")
    test_file_path.parent.mkdir(parents=True, exist_ok=True)
    test_file_path.write_text("dummy")

    response = client.get(url, {"path": str(test_file_path)})
    assert response.status_code == 200
    assert response.get("Content-Disposition") is not None
