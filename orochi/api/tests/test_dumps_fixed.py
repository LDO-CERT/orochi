import json
import os
from pathlib import Path

import pytest
from django.conf import settings
from django.core.files.uploadedfile import SimpleUploadedFile

from orochi.conftest import SORPRESA_ZIP_PATH
from orochi.website.models import Bookmark, Dump, Result, Value

pytestmark = pytest.mark.django_db


def test_api_create_dump_with_synthetic_vmem(client, admin, monkeypatch, synthetic_vmem):
    """Test creating dump via API with a synthetic fixed .vmem file upload."""
    client.force_login(admin)
    monkeypatch.setattr("orochi.api.routers.dumps.index_f_and_f", lambda *args, **kwargs: None)

    payload = {
        "operating_system": "Linux",
        "name": "api_fixed_sample",
        "color": "#00aaee",
    }
    upload = SimpleUploadedFile("sample.vmem", synthetic_vmem.read_bytes())

    response = client.post(
        "/api/dumps/",
        data={"payload": json.dumps(payload), "upload": upload},
    )
    assert response.status_code == 200, response.json()
    dump_data = response.json()

    dump = Dump.objects.get(index=dump_data["index"])
    assert dump.name == "api_fixed_sample"
    assert dump.operating_system == "Linux"
    assert dump.color == "#00aaee"

    # Verify file saved on disk
    assert os.path.exists(dump.upload.path)
    assert Path(dump.upload.path).name == "sample.vmem"


@pytest.mark.skipif(not SORPRESA_ZIP_PATH.exists(), reason="sorpresa.zip not found")
def test_api_create_dump_with_sorpresa_zip(client, admin, monkeypatch):
    """Test creating dump via API with real sorpresa.zip file upload."""
    client.force_login(admin)
    monkeypatch.setattr("orochi.api.routers.dumps.index_f_and_f", lambda *args, **kwargs: None)

    payload = {
        "operating_system": "Linux",
        "name": "api_sorpresa_dump",
        "color": "#336699",
    }
    with open(SORPRESA_ZIP_PATH, "rb") as f:
        upload = SimpleUploadedFile("sorpresa.zip", f.read())

    response = client.post(
        "/api/dumps/",
        data={"payload": json.dumps(payload), "upload": upload},
    )
    assert response.status_code == 200, response.json()
    dump_data = response.json()

    dump = Dump.objects.get(index=dump_data["index"])
    assert dump.name == "api_sorpresa_dump"
    assert dump.operating_system == "Linux"
    assert os.path.exists(dump.upload.path)


def test_api_get_dump_info_and_patch(client, admin, dump):
    """Test retrieving and updating dump metadata via API."""
    client.force_login(admin)

    # 1. GET dump info
    res = client.get(f"/api/dumps/{dump.index}")
    assert res.status_code == 200
    info = res.json()
    assert info["name"] == dump.name
    assert info["operating_system"] == dump.operating_system

    # 2. PATCH dump color
    patch_res = client.patch(
        f"/api/dumps/{dump.index}",
        json.dumps({"color": "#998877"}),
        content_type="application/json",
    )
    assert patch_res.status_code == 200
    dump.refresh_from_db()
    assert dump.color == "#998877"


def test_api_reload_symbols_fixed(client, admin, dump, plugin):
    """Test reloading symbols for a Linux dump."""
    client.force_login(admin)
    dump.banner = "Linux version 5.4.0-generic"
    dump.save()

    url = f"/api/dumps/{dump.index}/reload_symbols"
    response = client.get(url)
    assert response.status_code == 200
    assert "message" in response.json()


def test_api_delete_dump_with_disk_cleanup(client, admin, dump):
    """Test deleting dump via API cleans up both database and media directory."""
    client.force_login(admin)
    dump_dir = Path(settings.MEDIA_ROOT) / dump.index
    dump_dir.mkdir(parents=True, exist_ok=True)
    test_file = dump_dir / "sample_data.bin"
    test_file.write_bytes(b"temp_data")

    res = client.delete(f"/api/dumps/{dump.index}")
    assert res.status_code == 200
    assert not Dump.objects.filter(index=dump.index).exists()
    assert not dump_dir.exists()


def test_api_delete_dump_deletes_related_bookmarks_and_results(client, admin, dump, plugin):
    """Test deleting dump via API removes related bookmarks and dump results (Result/Value)."""
    client.force_login(admin)

    # 1. Create a second dump
    dump2 = Dump.objects.create(
        name="secondary_dump",
        author=admin,
        index="secondary-dump-idx-1234",
    )

    # 2. Create results & values for both dumps
    res1 = Result.objects.create(dump=dump, plugin=plugin, result=1)
    val1 = Value.objects.create(result=res1, value={"Plugin": plugin.name, "dump": 1})

    res2 = Result.objects.create(dump=dump2, plugin=plugin, result=1)
    val2 = Value.objects.create(result=res2, value={"Plugin": plugin.name, "dump": 2})

    # 3. Create bookmarks:
    # bm1: associated with dump only
    bm1 = Bookmark.objects.create(user=admin, plugin=plugin, name="bm_dump1_only")
    bm1.indexes.add(dump)

    # bm_shared: associated with both dump and dump2
    bm_shared = Bookmark.objects.create(user=admin, plugin=plugin, name="bm_shared_dump")
    bm_shared.indexes.add(dump, dump2)

    # bm_other: associated with dump2 only
    bm_other = Bookmark.objects.create(user=admin, plugin=plugin, name="bm_dump2_only")
    bm_other.indexes.add(dump2)

    # 4. Create dump media dir
    dump_dir = Path(settings.MEDIA_ROOT) / dump.index
    dump_dir.mkdir(parents=True, exist_ok=True)
    (dump_dir / "plugin_result.raw").write_bytes(b"results_data")

    # 5. Call API DELETE
    res = client.delete(f"/api/dumps/{dump.index}")
    assert res.status_code == 200

    # 6. Verify dump is deleted
    assert not Dump.objects.filter(index=dump.index).exists()
    assert not dump_dir.exists()

    # 7. Verify related bookmarks are deleted
    assert not Bookmark.objects.filter(pk=bm1.pk).exists()
    assert not Bookmark.objects.filter(pk=bm_shared.pk).exists()
    assert Bookmark.objects.filter(pk=bm_other.pk).exists()

    # 8. Verify dump results (Result and Value) are deleted for dump, kept for dump2
    assert not Result.objects.filter(pk=res1.pk).exists()
    assert not Value.objects.filter(pk=val1.pk).exists()
    assert Result.objects.filter(pk=res2.pk).exists()
    assert Value.objects.filter(pk=val2.pk).exists()


def test_orm_delete_dump_deletes_related_bookmarks_and_results(admin, dump, plugin):
    """Test directly deleting dump via ORM triggers pre_delete signal to clean bookmarks and results."""
    dump2 = Dump.objects.create(
        name="secondary_dump_orm",
        author=admin,
        index="secondary-dump-orm-5678",
    )

    res1 = Result.objects.create(dump=dump, plugin=plugin, result=1)
    val1 = Value.objects.create(result=res1, value={"key": "val1"})

    res2 = Result.objects.create(dump=dump2, plugin=plugin, result=1)
    val2 = Value.objects.create(result=res2, value={"key": "val2"})

    bm1 = Bookmark.objects.create(user=admin, plugin=plugin, name="bm_orm_dump1")
    bm1.indexes.add(dump)

    bm_other = Bookmark.objects.create(user=admin, plugin=plugin, name="bm_orm_dump2")
    bm_other.indexes.add(dump2)

    dump_dir = Path(settings.MEDIA_ROOT) / dump.index
    dump_dir.mkdir(parents=True, exist_ok=True)
    (dump_dir / "output.txt").write_text("sample")

    # Trigger dump.delete()
    dump.delete()

    assert not Dump.objects.filter(index=dump.index).exists()
    assert not dump_dir.exists()
    assert not Bookmark.objects.filter(pk=bm1.pk).exists()
    assert Bookmark.objects.filter(pk=bm_other.pk).exists()
    assert not Result.objects.filter(pk=res1.pk).exists()
    assert not Value.objects.filter(pk=val1.pk).exists()
    assert Result.objects.filter(pk=res2.pk).exists()
    assert Value.objects.filter(pk=val2.pk).exists()
