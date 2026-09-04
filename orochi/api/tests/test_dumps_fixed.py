import json
import os
from pathlib import Path

import pytest
from django.conf import settings
from django.core.files.uploadedfile import SimpleUploadedFile

from orochi.conftest import SORPRESA_ZIP_PATH
from orochi.website.models import Dump

pytestmark = pytest.mark.django_db


def test_api_create_dump_with_synthetic_vmem(
    client, admin, monkeypatch, synthetic_vmem
):
    """Test creating dump via API with a synthetic fixed .vmem file upload."""
    client.force_login(admin)
    monkeypatch.setattr(
        "orochi.api.routers.dumps.index_f_and_f", lambda *args, **kwargs: None
    )

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
    monkeypatch.setattr(
        "orochi.api.routers.dumps.index_f_and_f", lambda *args, **kwargs: None
    )

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
