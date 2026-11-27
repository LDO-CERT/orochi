"""Recycle bin: deleted dumps are hidden, restorable for DUMP_RETENTION_DAYS, then purged with their files."""

import json
from datetime import timedelta
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import pytest
from django.conf import settings
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
from django.utils import timezone
from guardian.shortcuts import get_objects_for_user

from orochi.website.defaults import DUMP_STATUS_COMPLETED, DUMP_STATUS_DELETED, DUMP_STATUS_ERROR
from orochi.website.models import Dump, Result
from orochi.website.recycle_bin import deleted_dumps, purge_expired

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def no_background_purge():
    with patch("orochi.website.recycle_bin.schedule_purge"), patch("orochi.api.routers.dumps.schedule_purge"):
        yield


def _retention(days):
    return patch("orochi.website.recycle_bin._get", side_effect=lambda name, default=None: days)


def _media_dir(dump) -> Path:
    path = Path(settings.MEDIA_ROOT) / dump.index
    path.mkdir(parents=True, exist_ok=True)
    (path / "symbols.json").write_text("{}")
    return path


def test_deleted_dump_is_hidden_but_kept(dump, admin, plugin):
    dump.status = DUMP_STATUS_COMPLETED
    dump.save()
    Result.objects.create(dump=dump, plugin=plugin, result=2)

    dump.soft_delete(admin)

    assert not Dump.objects.filter(pk=dump.pk).exists()
    assert dump not in get_objects_for_user(admin, "website.can_see")
    kept = Dump.all_objects.get(pk=dump.pk)
    assert kept.is_deleted and kept.deleted_by == admin and kept.deleted_at is not None
    assert kept.status_before_delete == DUMP_STATUS_COMPLETED
    assert Result.objects.filter(dump_id=dump.pk).exists()


def test_restore_brings_back_the_previous_status(dump, admin):
    dump.status = DUMP_STATUS_ERROR
    dump.save()
    dump.soft_delete(admin)

    dump.restore()

    restored = Dump.objects.get(pk=dump.pk)
    assert restored.status == DUMP_STATUS_ERROR
    assert restored.deleted_at is None and restored.deleted_by is None and restored.status_before_delete is None


def test_stale_instance_cannot_resurrect_a_deleted_dump(dump, admin):
    stale = Dump.objects.get(pk=dump.pk)  # e.g. the upload task, still processing
    dump.soft_delete(admin)

    stale.status = DUMP_STATUS_COMPLETED
    stale.save()

    row = Dump.all_objects.get(pk=dump.pk)
    assert row.status == DUMP_STATUS_DELETED and row.deleted_by == admin
    assert row.status_before_delete == DUMP_STATUS_COMPLETED  # restored as Completed later


def test_purge_expired_removes_only_old_dumps_with_files(dump, admin, folder, plugin):
    old_dir = _media_dir(dump)
    Result.objects.create(dump=dump, plugin=plugin, result=2)
    dump.soft_delete(admin)
    Dump.all_objects.filter(pk=dump.pk).update(deleted_at=timezone.now() - timedelta(days=8))
    recent = Dump.objects.create(
        operating_system="Linux", name="recent", index="recent-index", author=admin, folder=folder
    )
    recent.soft_delete(admin)

    with _retention(7):
        assert purge_expired() == 1

    assert not Dump.all_objects.filter(pk=dump.pk).exists()
    assert not Result.objects.filter(dump_id=dump.pk).exists()
    assert not old_dir.exists()
    assert list(deleted_dumps()) == [Dump.all_objects.get(pk=recent.pk)]


def test_command_empties_the_bin(dump, admin):
    dump.soft_delete(admin)
    out = StringIO()
    call_command("purge_recycle_bin", "--all", stdout=out)
    assert "Purged 1 dump(s); 0 left" in out.getvalue()
    assert not Dump.all_objects.filter(pk=dump.pk).exists()


def test_api_delete_moves_to_the_bin_and_restore(client, admin, dump):
    client.force_login(admin)
    with _retention(7):
        resp = client.delete(f"/api/dumps/{dump.index}")
    assert resp.status_code == 200, resp.content
    assert "recycle bin" in resp.json()["message"] and "7 day" in resp.json()["message"]
    assert Dump.all_objects.get(pk=dump.pk).is_deleted

    listing = client.get("/api/dumps/recycle_bin").json()
    assert [item["index"] for item in listing] == [dump.index]
    assert listing[0]["deleted_by"] == admin.username and listing[0]["purge_at"]

    resp = client.post(f"/api/dumps/{dump.index}/restore")
    assert resp.status_code == 200, resp.content
    assert Dump.objects.filter(pk=dump.pk).exists()


@pytest.mark.parametrize(("days", "query"), [(0, ""), (7, "?permanent=true")])
def test_api_delete_is_permanent_without_retention_or_on_request(client, admin, dump, days, query):
    media = _media_dir(dump)
    client.force_login(admin)
    with _retention(days):
        resp = client.delete(f"/api/dumps/{dump.index}{query}")
    assert resp.status_code == 200, resp.content
    assert "permanently" in resp.json()["message"]
    assert not Dump.all_objects.filter(pk=dump.pk).exists()
    assert not media.exists()


def test_api_purge_only_works_on_deleted_dumps(client, admin, dump):
    client.force_login(admin)
    assert client.delete(f"/api/dumps/{dump.index}/purge").status_code == 404
    dump.soft_delete(admin)
    resp = client.delete(f"/api/dumps/{dump.index}/purge")
    assert resp.status_code == 200, resp.content
    assert not Dump.all_objects.filter(pk=dump.pk).exists()


def test_bin_actions_need_permission_on_the_dump(client, analyst_user, dump, admin):
    dump.soft_delete(admin)
    client.force_login(analyst_user)
    assert client.get("/api/dumps/recycle_bin").json() == []
    assert client.post(f"/api/dumps/{dump.index}/restore").status_code == 404
    assert client.delete(f"/api/dumps/{dump.index}/purge").status_code == 404
    assert Dump.all_objects.get(pk=dump.pk).is_deleted


def test_readonly_users_cannot_delete(client, readonly_user, dump):
    from guardian.shortcuts import assign_perm

    assign_perm("can_see", readonly_user, dump)
    client.force_login(readonly_user)
    assert client.delete(f"/api/dumps/{dump.index}").status_code == 403
    assert Dump.objects.filter(pk=dump.pk).exists()


def test_new_dump_cannot_reuse_the_name_of_a_deleted_one(client, admin, dump):
    dump.soft_delete(admin)
    client.force_login(admin)
    resp = client.post(
        "/api/dumps/",
        {
            "payload": json.dumps({"name": dump.name, "operating_system": "Linux"}),
            "upload": SimpleUploadedFile("sample.raw", b"MZ"),
        },
    )
    assert resp.status_code == 400, resp.content
    assert "recycle bin" in resp.json()["errors"]


def test_recycle_bin_modal_lists_deleted_dumps(client, admin, dump):
    dump.soft_delete(admin)
    client.force_login(admin)
    with patch("orochi.website.views.recycle_bin.schedule_purge") as scheduled:
        resp = client.get("/recycle_bin")
    scheduled.assert_called_once()
    body = resp.content.decode()
    assert resp.status_code == 200
    assert dump.name in body and f"/api/dumps/{dump.index}/restore" in body
    assert dump.name not in client.get("/indices").content.decode()
