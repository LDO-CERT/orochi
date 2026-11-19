import zipfile
from pathlib import Path

import pytest
from django.conf import settings
from django.contrib.auth import forms as auth_forms
from django.urls import reverse

from orochi.users.forms import UserCreationForm
from orochi.website.defaults import SERVICE_CAPE
from orochi.website.forms import EvidenceForm
from orochi.website.integrations import submit_file_to_sandbox
from orochi.website.models import Service

pytestmark = pytest.mark.django_db


def test_restart_requires_can_see(client, analyst_user, dump):
    client.force_login(analyst_user)
    resp = client.get(
        reverse("website:index_restart"),
        {"index": dump.index},
        HTTP_X_REQUESTED_WITH="XMLHttpRequest",
    )
    assert resp.status_code == 404


def test_restart_allowed_with_can_see(client, admin, dump):
    client.force_login(admin)
    resp = client.get(
        reverse("website:index_restart"),
        {"index": dump.index},
        HTTP_X_REQUESTED_WITH="XMLHttpRequest",
    )
    assert resp.status_code == 200


def test_evidence_form_rejects_dump_not_visible(analyst_user, dump):
    form = EvidenceForm(analyst_user, data={"name": "ev", "case": "my case", "dump": dump.index})
    assert not form.is_valid()
    assert "dump" in form.errors


def test_evidence_form_accepts_visible_dump(admin, dump):
    form = EvidenceForm(admin, data={"name": "ev", "case": "my case", "dump": dump.index})
    assert "dump" not in form.errors


@pytest.fixture
def cape_service(db):
    return Service.objects.create(name=SERVICE_CAPE, url="https://cape.local", key="token")


def test_sandbox_rejects_files_outside_dump_folder(cape_service, dump, tmp_path):
    outside = tmp_path / "secret.txt"
    outside.write_text("secret")
    for filepath in (str(outside), "/etc/passwd", f"{dump.index}/../../secret.txt", str(dump.index)):
        with pytest.raises(ValueError):
            submit_file_to_sandbox(dump, filepath=filepath)


def test_sandbox_submits_extracted_file(cape_service, dump, monkeypatch):
    extracted = Path(settings.MEDIA_ROOT) / str(dump.index) / "pslist" / "evil.exe"
    extracted.parent.mkdir(parents=True)
    extracted.write_bytes(b"MZ")
    calls = {}

    class FakeResponse:
        status_code = 200
        content = b"{}"

        @staticmethod
        def json():
            return {"task_id": 42}

    def fake_post(url, **kwargs):
        calls["url"], calls["verify"] = url, kwargs["verify"]
        return FakeResponse()

    monkeypatch.setattr("orochi.website.integrations.requests.post", fake_post)
    res = submit_file_to_sandbox(dump, filepath=f"{dump.index}/pslist/evil.exe")
    assert res["task_id"] == 42
    assert calls["verify"] is True  # new services verify TLS by default


def test_plugin_install_blocks_zip_slip(tmp_path, monkeypatch):
    from orochi.utils import plugin_install as module

    plugin_dir = tmp_path / "plugins"
    plugin_dir.mkdir()
    archive = tmp_path / "evil.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("../escaped.py", "print('pwned')")
    monkeypatch.setattr(module.Setting, "get", staticmethod(lambda name, default=None: str(plugin_dir)))

    assert module.plugin_install(str(archive)) == []
    assert not (tmp_path / "escaped.py").exists()


def test_signup_closed_by_default(client):
    resp = client.get(reverse("account_signup"))
    assert "account/signup_closed.html" in [t.name for t in resp.templates]


def test_signup_open_when_enabled(client, settings):
    settings.ACCOUNT_ALLOW_REGISTRATION = True
    resp = client.get(reverse("account_signup"))
    assert "account/signup_closed.html" not in [t.name for t in resp.templates]


def test_user_creation_form_does_not_mutate_django_messages():
    assert "duplicate_username" in UserCreationForm.error_messages
    assert "duplicate_username" not in auth_forms.UserCreationForm.error_messages


def test_login_page_hides_signup_link_when_closed(client, settings):
    page = client.get(reverse("account_login")).content.decode()
    assert reverse("account_signup") not in page

    settings.ACCOUNT_ALLOW_REGISTRATION = True
    page = client.get(reverse("account_login")).content.decode()
    assert reverse("account_signup") in page
