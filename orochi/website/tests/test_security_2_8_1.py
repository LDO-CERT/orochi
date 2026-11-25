"""Regression tests for the 2.8.1 security fixes (CodeQL path-injection, XSS and error-exposure alerts)."""

import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest
from django.conf import settings
from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse
from guardian.shortcuts import assign_perm

from orochi.users.models import APIToken
from orochi.website.defaults import SERVICE_MISP
from orochi.website.models import Case, Dump, Plugin, Service
from orochi.website.views.common import resolve_dump_file

pytestmark = pytest.mark.django_db


@pytest.fixture
def dump_file(dump):
    """A JSON file extracted inside the dump folder."""
    target_dir = Path(settings.MEDIA_ROOT) / dump.index / "windows.dumpfiles"
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / "file.exe.vt.json"
    target.write_text(json.dumps({"positives": 3, "total": 70}))
    return target


@pytest.fixture
def outside_dir(tmp_path_factory):
    """A directory guaranteed to be outside MEDIA_ROOT (which is the per-test tmpdir)."""
    outside = tmp_path_factory.mktemp("outside_media")
    assert not str(os.path.realpath(outside)).startswith(os.path.realpath(settings.MEDIA_ROOT))
    return outside


@pytest.fixture
def outside_file(outside_dir):
    """A secret JSON file outside MEDIA_ROOT."""
    secret = outside_dir / "secret.json"
    secret.parent.mkdir(parents=True, exist_ok=True)
    secret.write_text(json.dumps({"SECRET_TOKEN": "do-not-leak"}))
    return secret


@pytest.fixture
def other_dump(admin, folder):
    """A dump the plain `user` fixture has no permission on."""
    return Dump.objects.create(
        operating_system="Windows",
        name="other_dump",
        index=str(uuid4()),
        author=admin,
        folder=folder,
        upload=SimpleUploadedFile("other.raw", b"other"),
    )


# ---------------------------------------------------------------------------
# resolve_dump_file helper
# ---------------------------------------------------------------------------
def test_resolve_dump_file_accepts_file_in_visible_dump(admin, dump, dump_file):
    real, found = resolve_dump_file(str(dump_file), admin)
    assert real == Path(os.path.realpath(dump_file))
    assert found == dump


def test_resolve_dump_file_accepts_media_relative_path(admin, dump, dump_file):
    rel = os.path.relpath(dump_file, settings.MEDIA_ROOT)
    real, found = resolve_dump_file(rel, admin)
    assert real == Path(os.path.realpath(dump_file))
    assert found == dump


def test_resolve_dump_file_rejects_outside_media_root(admin, outside_file):
    assert resolve_dump_file(str(outside_file), admin) == (None, None)


def test_resolve_dump_file_rejects_traversal(admin, dump, dump_file, outside_file):
    sneaky = f"{settings.MEDIA_ROOT}/{dump.index}/../../{outside_file.relative_to(outside_file.anchor)}"
    assert resolve_dump_file(sneaky, admin) == (None, None)


def test_resolve_dump_file_rejects_symlink_escape(admin, dump, outside_file):
    link_dir = Path(settings.MEDIA_ROOT) / dump.index
    link_dir.mkdir(parents=True, exist_ok=True)
    link = link_dir / "evil.json"
    link.symlink_to(outside_file)
    assert resolve_dump_file(str(link), admin) == (None, None)


def test_resolve_dump_file_rejects_dump_without_permission(user, other_dump):
    target = Path(settings.MEDIA_ROOT) / other_dump.index / "x.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("{}")
    assert resolve_dump_file(str(target), user) == (None, None)


def test_resolve_dump_file_rejects_non_dump_media_folder(admin):
    target = Path(settings.MEDIA_ROOT) / "uploads" / "x.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("{}")
    assert resolve_dump_file(str(target), admin) == (None, None)


# ---------------------------------------------------------------------------
# Views
# ---------------------------------------------------------------------------
def test_vt_view_does_not_read_files_outside_dump(client, user, outside_file):
    client.force_login(user)
    resp = client.get(reverse("website:vt"), {"path": str(outside_file)})
    assert resp.status_code == 200
    body = resp.content.decode()
    assert "do-not-leak" not in body
    assert "VT report not found" in body


def test_vt_view_requires_dump_permission(client, user, other_dump):
    target = Path(settings.MEDIA_ROOT) / other_dump.index / "f.exe.vt.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps({"SECRET_TOKEN": "do-not-leak"}))
    client.force_login(user)
    resp = client.get(reverse("website:vt"), {"path": str(target)})
    assert "do-not-leak" not in resp.content.decode()


def test_json_view_blocks_existing_file_without_permission(client, user, other_dump):
    """Regression: json_view served any existing file because the permission check was inverted."""
    target = Path(settings.MEDIA_ROOT) / other_dump.index / "hive.regipy.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps({"SECRET_TOKEN": "do-not-leak"}))
    client.force_login(user)
    resp = client.get(reverse("website:json_view", kwargs={"filepath": str(target)}))
    assert resp.status_code == 404


def test_json_view_blocks_files_outside_media(client, admin, dump, outside_file):
    client.force_login(admin)
    fake = f"/x/{dump.index}/../../..{outside_file}"
    resp = client.get(reverse("website:json_view", kwargs={"filepath": fake}))
    assert resp.status_code == 404


def test_download_blocks_files_outside_media_with_dump_index(client, admin, dump, outside_dir):
    """Regression: a path outside MEDIA_ROOT that contains a dump index was served."""
    outside = outside_dir / dump.index / "secret.raw"
    outside.parent.mkdir(parents=True, exist_ok=True)
    outside.write_bytes(b"SECRET")
    client.force_login(admin)
    resp = client.get(reverse("website:download"), {"path": f"/{outside.relative_to(outside.anchor)}"})
    assert resp.status_code == 404


def test_download_rejects_missing_file_with_404(client, admin, dump):
    client.force_login(admin)
    resp = client.get(reverse("website:download"), {"path": f"{settings.MEDIA_ROOT}/{dump.index}/missing.raw"})
    assert resp.status_code == 404


def test_misp_export_does_not_read_arbitrary_file(client, admin, dump, outside_file):
    """Regression: passing dump+plugin let any file on disk be uploaded to MISP."""
    Plugin.objects.get_or_create(name="windows.dumpfiles")
    Service.objects.create(name=SERVICE_MISP, url="https://misp.example.com", key="k")
    client.force_login(admin)
    mock_misp = MagicMock()
    with patch("orochi.website.views.PyMISP", return_value=mock_misp):
        resp = client.get(
            reverse("website:export"),
            {"path": str(outside_file), "dump": dump.index, "plugin": "windows.dumpfiles"},
        )
    assert resp.status_code == 400
    mock_misp.add_event.assert_not_called()


def test_misp_export_rejects_file_of_other_dump(client, admin, dump, other_dump):
    Plugin.objects.get_or_create(name="windows.dumpfiles")
    Service.objects.create(name=SERVICE_MISP, url="https://misp.example.com", key="k")
    target = Path(settings.MEDIA_ROOT) / other_dump.index / "windows.dumpfiles" / "x.exe"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(b"MZ")
    client.force_login(admin)
    mock_misp = MagicMock()
    with patch("orochi.website.views.PyMISP", return_value=mock_misp):
        resp = client.get(
            reverse("website:export"),
            {"path": str(target), "dump": dump.index, "plugin": "windows.dumpfiles"},
        )
    assert resp.status_code == 400
    mock_misp.add_event.assert_not_called()


def test_misp_export_error_hides_exception_text(client, admin, dump):
    Plugin.objects.get_or_create(name="windows.dumpfiles")
    Service.objects.create(name=SERVICE_MISP, url="https://misp.example.com", key="k")
    target = Path(settings.MEDIA_ROOT) / dump.index / "windows.dumpfiles" / "x.exe"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(b"MZ")
    client.force_login(admin)
    with patch("orochi.website.views.PyMISP", side_effect=RuntimeError("internal-host:8443 secret")):
        resp = client.get(
            reverse("website:export"),
            {"path": str(target), "dump": dump.index, "plugin": "windows.dumpfiles"},
        )
    assert resp.status_code == 400
    assert "secret" not in resp.content.decode()


def test_parameters_does_not_reflect_plugin_name(client, readonly_user):
    payload = "<script>alert(1)</script>"
    client.force_login(readonly_user)
    resp = client.get(reverse("website:parameters"), {"selected_plugin": payload})
    assert payload not in resp.content.decode()


def test_dump_playbooks_does_not_reflect_playbook_id(client, admin, dump):
    payload = "<img src=x onerror=alert(1)>"
    client.force_login(admin)
    resp = client.post(reverse("website:dump_playbooks", kwargs={"index": dump.index}), {"playbook_id": payload})
    assert resp.status_code == 400
    assert payload not in resp.content.decode()


def test_case_export_errors_hide_exception_text(client, user):
    _, raw_token = APIToken.generate_token(user=user, name="t")
    headers = {"HTTP_AUTHORIZATION": f"Bearer {raw_token}"}
    case = Case.objects.create(name="c", user=user)
    for fmt, target in (("pdf", "export_case_to_pdf"), ("stix", "export_case_to_stix")):
        with patch(f"orochi.api.routers.cases.{target}", side_effect=RuntimeError("<b>/etc/secret</b>")):
            resp = client.get(f"/api/cases/{case.pk}/export?format={fmt}", **headers)
        assert resp.status_code == 400
        assert "/etc/secret" not in resp.content.decode()
        assert "errors" in resp.json()


def test_vt_view_renders_report_inside_dump(client, admin, dump, dump_file):
    assign_perm("website.can_see", admin, dump)
    client.force_login(admin)
    resp = client.get(reverse("website:vt"), {"path": str(dump_file)})
    assert resp.status_code == 200
    assert "positives" in resp.content.decode()
