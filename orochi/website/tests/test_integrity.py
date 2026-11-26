"""Evidence integrity: hash on receipt, kept original, verification on demand (#1674 FR-1, FR-2)."""

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile

from orochi.utils.volatility_dask_elk import manage_upload
from orochi.website.integrity import sha256_of, verify_dump
from orochi.website.models import Dump, IntegrityCheck

pytestmark = pytest.mark.django_db


@pytest.fixture
def uploaded_dump(admin, folder, synthetic_zip, settings, tmp_path):
    settings.MEDIA_ROOT = str(tmp_path)
    dump = Dump.objects.create(
        operating_system="Windows",
        name="evidence",
        index="evid_idx",
        author=admin,
        folder=folder,
        upload=SimpleUploadedFile("evidence.zip", synthetic_zip.read_bytes()),
    )
    received = sha256_of(dump.upload.path)
    with (
        patch("orochi.utils.volatility_dask_elk.close_old_connections"),
        patch("orochi.utils.volatility_dask_elk.get_client", return_value=SimpleNamespace()),  # unzip runs inline
        patch("orochi.utils.volatility_dask_elk.check_runnable", return_value=True),
        patch("orochi.utils.volatility_dask_elk.dispatch_automatic_plugins"),
        patch("orochi.utils.volatility_dask_elk.trigger_auto_playbooks"),
    ):
        manage_upload(dump.pk, admin.pk, password=None, restart=None, move=True)
    dump.refresh_from_db()
    return dump, received


def test_upload_is_hashed_as_received_and_kept(uploaded_dump):
    dump, received = uploaded_dump
    assert dump.received_sha256 == received and dump.received_name == "evidence.zip"
    assert Path(dump.original_path).is_file() and sha256_of(dump.original_path) == received
    kinds = list(dump.integrity_checks.order_by("checked_at").values_list("kind", flat=True))
    assert kinds == ["received", "image"]
    assert dump.integrity_checks.get(kind="image").actual_sha256 == dump.sha256


def test_verification_passes_then_detects_tampering(uploaded_dump, admin):
    dump, _ = uploaded_dump
    assert verify_dump(dump, user=admin).ok is True

    with open(dump.upload.path, "ab") as fh:
        fh.write(b"tampered")
    with patch("orochi.website.notifier.notify_dump_users") as notify:
        check = verify_dump(dump, user=admin)
    assert check.ok is False and "memory image hash" in check.detail
    notify.assert_called_once()
    assert IntegrityCheck.objects.filter(dump=dump, kind="verify").count() == 2


def test_verify_api_and_history(client, admin, uploaded_dump):
    dump, _ = uploaded_dump
    client.force_login(admin)
    with patch("orochi.website.tasks.verify_dump_integrity_task") as task:
        resp = client.post(f"/api/dumps/{dump.index}/verify")
    assert resp.status_code == 200
    task.enqueue.assert_called_once_with(dump_pk=dump.pk, user_pk=admin.pk)
    checks = client.get(f"/api/dumps/{dump.index}/integrity").json()
    assert {c["kind"] for c in checks} == {"received", "image"}
