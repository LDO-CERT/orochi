"""Create dump: an uploaded file and a server file are mutually exclusive."""

import json

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile

pytestmark = pytest.mark.django_db


def test_upload_and_server_file_together_are_rejected(client, admin):
    client.force_login(admin)
    resp = client.post(
        "/api/dumps/",
        {
            "payload": json.dumps({"name": "both", "operating_system": "Linux", "local_folder": "/uploads/sample.raw"}),
            "upload": SimpleUploadedFile("sample.raw", b"MZ"),
        },
    )
    assert resp.status_code == 400, resp.content
    assert "not both" in resp.json()["errors"]


def test_a_source_is_required(client, admin):
    client.force_login(admin)
    resp = client.post("/api/dumps/", {"payload": json.dumps({"name": "none", "operating_system": "Linux"})})
    assert resp.status_code == 400, resp.content
    assert "Upload a file" in resp.json()["errors"]
