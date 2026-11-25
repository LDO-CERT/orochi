import json
from pathlib import Path

import pytest
from django.contrib.auth import get_user_model

from orochi.users.models import APIToken
from orochi.website.models import Case

pytestmark = pytest.mark.django_db


def test_bearer_token_authentication_flow(client, user):
    """Test full Bearer token authentication flow and last_used_at update."""
    api_token, raw_token = APIToken.generate_token(user=user, name="CI Automation Token")
    assert api_token.last_used_at is None

    # Authenticate to dual_auth protected endpoint
    Case.objects.create(name="Bearer-Auth-Case", user=user)
    resp = client.get("/api/cases/", HTTP_AUTHORIZATION=f"Bearer {raw_token}")
    assert resp.status_code == 200
    cases = resp.json()
    assert any(c["name"] == "Bearer-Auth-Case" for c in cases)

    # Verify last_used_at timestamp updated
    api_token.refresh_from_db()
    assert api_token.last_used_at is not None


def test_bearer_token_invalid_and_inactive(client, user):
    """Test that nonexistent and inactive tokens are rejected with 401."""
    # 1. Nonexistent Token
    resp_fake = client.get("/api/cases/", HTTP_AUTHORIZATION="Bearer oro_nonexistenttoken12345")
    assert resp_fake.status_code == 401

    # 2. Inactive Token
    api_token, raw_token = APIToken.generate_token(user=user, name="Revoked Token")
    api_token.is_active = False
    api_token.save()

    resp_inactive = client.get("/api/cases/", HTTP_AUTHORIZATION=f"Bearer {raw_token}")
    assert resp_inactive.status_code == 401


def test_auth_tokens_api_crud(client, user):
    """Test /api/auth/tokens/ endpoints for listing, creating, and revoking personal tokens."""
    client.force_login(user)

    # 1. Create Token via API
    resp_create = client.post(
        "/api/auth/tokens/",
        data=json.dumps({"name": "Integration Test Token"}),
        content_type="application/json",
    )
    assert resp_create.status_code == 201
    created_data = resp_create.json()
    assert "token" in created_data
    assert created_data["token"].startswith("oro_")
    token_id = created_data["id"]

    # 2. List Tokens
    resp_list = client.get("/api/auth/tokens/")
    assert resp_list.status_code == 200
    tokens = resp_list.json()
    assert len(tokens) >= 1
    assert any(t["id"] == token_id for t in tokens)
    # Ensure sensitive raw token is never exposed in list
    assert "token" not in tokens[0]

    # 3. Revoke Token
    resp_del = client.delete(f"/api/auth/tokens/{token_id}/")
    assert resp_del.status_code == 200
    assert not APIToken.objects.filter(pk=token_id).exists()


def test_auth_tokens_isolation_between_users(client, user):
    """Test that a user cannot revoke another user's API token."""
    User = get_user_model()
    other_user = User.objects.create_user(username="other_dev", password="password123")

    other_token, _ = APIToken.generate_token(user=other_user, name="Other Dev Token")

    client.force_login(user)
    resp_del = client.delete(f"/api/auth/tokens/{other_token.pk}/")
    assert resp_del.status_code == 404
    assert APIToken.objects.filter(pk=other_token.pk).exists()


def test_case_crud_edge_cases_and_permissions(client, user):
    """Test case validation edge cases and unauthorized access restrictions."""
    client.force_login(user)

    # 1. Reject empty case name
    resp_empty = client.post(
        "/api/cases/",
        data=json.dumps({"name": "   "}),
        content_type="application/json",
    )
    assert resp_empty.status_code == 400

    # 2. Create valid case
    case = Case.objects.create(name="Edge-Case-Alpha", user=user)

    # 3. Reject invalid status
    resp_bad_status = client.patch(
        f"/api/cases/{case.pk}",
        data=json.dumps({"status": "InvalidStatusXYZ"}),
        content_type="application/json",
    )
    assert resp_bad_status.status_code == 400

    # 4. Successfully toggle CTF mode and description
    resp_patch = client.patch(
        f"/api/cases/{case.pk}",
        data=json.dumps({"is_ctf": True, "description": "CTF Challenge Case"}),
        content_type="application/json",
    )
    assert resp_patch.status_code == 200
    case.refresh_from_db()
    assert case.is_ctf is True
    assert case.description == "CTF Challenge Case"

    # 5. Non-collaborator access rejection
    User = get_user_model()
    intruder = User.objects.create_user(username="intruder", password="password123")
    client.force_login(intruder)

    resp_unauth = client.patch(
        f"/api/cases/{case.pk}",
        data=json.dumps({"name": "Hacked Name"}),
        content_type="application/json",
    )
    assert resp_unauth.status_code == 404


def test_case_reporting_edge_cases(client, user):
    """Test multi-format case export handling empty cases, unicode, and unsupported formats."""
    _, raw_token = APIToken.generate_token(user=user, name="Report Token")
    headers = {"HTTP_AUTHORIZATION": f"Bearer {raw_token}"}

    # Empty case with non-ASCII unicode
    unicode_case = Case.objects.create(
        name="Case 🚨 テスト Investigation [2026]",
        user=user,
        description="Special chars: <>&'\" e acuti: è, é, à, ò.",
    )

    # Markdown export of empty unicode case
    resp_md = client.get(f"/api/cases/{unicode_case.pk}/export?format=markdown", **headers)
    assert resp_md.status_code == 200
    assert "No evidence attached to this case" in resp_md.content.decode("utf-8")

    # HTML export of empty unicode case
    resp_html = client.get(f"/api/cases/{unicode_case.pk}/export?format=html", **headers)
    assert resp_html.status_code == 200
    assert "No findings recorded" in resp_html.content.decode("utf-8")

    # PDF export of empty unicode case
    resp_pdf = client.get(f"/api/cases/{unicode_case.pk}/export?format=pdf", **headers)
    assert resp_pdf.status_code == 200
    assert resp_pdf.content.startswith(b"%PDF")

    # STIX 2.1 export of empty unicode case
    resp_stix = client.get(f"/api/cases/{unicode_case.pk}/export?format=stix", **headers)
    assert resp_stix.status_code == 200
    stix_json = json.loads(resp_stix.content)
    assert stix_json["type"] == "bundle"

    # Unsupported format rejection
    resp_invalid = client.get(f"/api/cases/{unicode_case.pk}/export?format=docx", **headers)
    assert resp_invalid.status_code == 400
    assert "Unsupported export format" in resp_invalid.content.decode("utf-8")


def test_folders_and_hosts_api_with_bearer(client, user):
    """Test Folders and Hosts API endpoints authenticated via Bearer token."""
    _, raw_token = APIToken.generate_token(user=user, name="API Client")
    headers = {"HTTP_AUTHORIZATION": f"Bearer {raw_token}"}

    # 1. Folders
    resp_f_create = client.post(
        "/api/folders/",
        data=json.dumps({"name": "Forensic-Artifacts-Folder"}),
        content_type="application/json",
        **headers,
    )
    assert resp_f_create.status_code == 200 or resp_f_create.status_code == 201

    resp_f_list = client.get("/api/folders/", **headers)
    assert resp_f_list.status_code == 200
    folders = resp_f_list.json()
    assert any(f["name"] == "Forensic-Artifacts-Folder" for f in folders)

    # 2. Hosts
    resp_h_create = client.post(
        "/api/hosts/",
        data=json.dumps({"name": "domain-controller-01", "description": "Primary Active Directory Server"}),
        content_type="application/json",
        **headers,
    )
    assert resp_h_create.status_code == 200 or resp_h_create.status_code == 201

    resp_h_list = client.get("/api/hosts/", **headers)
    assert resp_h_list.status_code == 200
    hosts = resp_h_list.json()
    assert any(h["name"] == "domain-controller-01" for h in hosts)


def test_p0_signals_bootstrap_user_and_dump_can_see(client, plugin, analyst_user, monkeypatch):
    """Ensure WebsiteConfig registers signals for new users and non-admin dump authors."""
    from django.core.files.uploadedfile import SimpleUploadedFile

    from orochi.website.models import Dump, UserPlugin
    from orochi.ya.models import Ruleset

    User = get_user_model()
    new_user = User.objects.create_user(username="signal_tester", email="sig@example.com", password="Password123!")
    assert UserPlugin.objects.filter(user=new_user, plugin=plugin).exists()
    assert Ruleset.objects.filter(user=new_user, name="signal_tester-Ruleset").exists()

    monkeypatch.setattr("orochi.api.routers.dumps.index_f_and_f", lambda *args, **kwargs: None)
    client.force_login(analyst_user)
    upload = SimpleUploadedFile("analyst_sample.raw", b"RAW_MEM_CONTENT")
    resp = client.post(
        "/api/dumps/",
        data={
            "payload": json.dumps({"name": "analyst_owned_dump", "operating_system": "Linux"}),
            "upload": upload,
        },
    )
    assert resp.status_code == 200, resp.json()
    idx = resp.json()["index"]
    assert Dump.objects.filter(index=idx, author=analyst_user).exists()

    resp_list = client.get("/api/dumps/")
    assert resp_list.status_code == 200
    assert any(d["index"] == idx for d in resp_list.json())

    resp_detail = client.get(f"/api/dumps/{idx}")
    assert resp_detail.status_code == 200


def test_p0_create_dump_local_folder_and_handle_uploaded_file_traversal(
    client, analyst_user, tmp_path, monkeypatch, settings
):
    """Block arbitrary file moves via local_folder and traversal via handle_uploaded_file."""
    from types import SimpleNamespace

    from orochi.api.routers.dumps import handle_uploaded_file
    from orochi.website.models import Dump

    monkeypatch.setattr("orochi.api.routers.dumps.index_f_and_f", lambda *args, **kwargs: None)
    client.force_login(analyst_user)

    outside_file = tmp_path / "outside_secret.txt"
    outside_file.write_text("SECRET")
    resp_bad = client.post(
        "/api/dumps/",
        data={
            "payload": json.dumps(
                {
                    "name": "traversal_attempt",
                    "operating_system": "Linux",
                    "local_folder": str(outside_file),
                }
            ),
        },
    )
    assert resp_bad.status_code == 400
    assert outside_file.exists()

    staged_dir = Path(settings.MEDIA_ROOT) / "tmp"
    staged_dir.mkdir(parents=True, exist_ok=True)
    staged_file = staged_dir / "staged_sample.raw"
    staged_file.write_bytes(b"STAGED")
    resp_ok = client.post(
        "/api/dumps/",
        data={
            "payload": json.dumps(
                {
                    "name": "staged_dump",
                    "operating_system": "Linux",
                    "local_folder": str(staged_file),
                    "original_name": "renamed.raw",
                }
            ),
        },
    )
    assert resp_ok.status_code == 200, resp_ok.json()
    dump = Dump.objects.get(index=resp_ok.json()["index"])
    assert dump.upload.name == f"{dump.index}/renamed.raw"

    for bad_name in ("../../etc/passwd", "/tmp/evil.yar", "..", "."):
        bad_file = SimpleNamespace(name=bad_name, chunks=lambda: [b"data"])
        with pytest.raises(ValueError):
            handle_uploaded_file(dump.index, "test_plugin", bad_file)

    staged_file_2 = staged_dir / "staged_sample_2.raw"
    staged_file_2.write_bytes(b"STAGED2")
    resp_bad_orig = client.post(
        "/api/dumps/",
        data={
            "payload": json.dumps(
                {
                    "name": "bad_orig_dump",
                    "operating_system": "Linux",
                    "local_folder": str(staged_file_2),
                    "original_name": "../../etc/cron.d/pwn",
                }
            ),
        },
    )
    assert resp_bad_orig.status_code == 400
    assert staged_file_2.exists()


def test_p0_rules_and_customrules_isolation_and_path_hardening(client, rf, admin, analyst_user, tmp_path, monkeypatch):
    """Ensure rules endpoints auto-create Ruleset safely and enforce ownership/path checks."""
    from types import SimpleNamespace

    from django.core.files.uploadedfile import SimpleUploadedFile

    from orochi.api.routers.rules import upload_rule
    from orochi.website.models import CustomRule
    from orochi.ya.models import Rule, Ruleset

    yara_dir = tmp_path / "yara"
    yara_dir.mkdir()
    monkeypatch.setattr("orochi.api.routers.rules.Setting.get", lambda key, default=None: str(yara_dir))
    monkeypatch.setattr("orochi.api.routers.customrules.Setting.get", lambda key, default=None: str(yara_dir))

    # Delete analyst_user's auto-created Ruleset to verify fallback creation on upload
    Ruleset.objects.filter(user=analyst_user).delete()

    client.force_login(analyst_user)
    resp_up = client.post(
        "/api/rules/",
        data={"files": SimpleUploadedFile("demo.yar", b"rule Demo { condition: true }")},
    )
    assert resp_up.status_code == 200, resp_up.json()
    assert Ruleset.objects.filter(user=analyst_user).exists()

    req = rf.post("/api/rules/")
    req.user = analyst_user
    for bad_rule_name in ("../escape.yar", "/tmp/evil.yar", "..", "."):
        fake_upload = SimpleNamespace(name=bad_rule_name, read=lambda: b"rule Bad { condition: true }")
        res_bad_up = upload_rule(req, files=[fake_upload])
        assert res_bad_up.status_code == 400

    # Admin creates a private rule and private CustomRule
    adm_ruleset = Ruleset.objects.create(name="adm-private-set", user=admin, enabled=True)
    priv_rule_file = yara_dir / "priv.yar"
    priv_rule_file.write_text("rule Priv { condition: true }")
    priv_rule = Rule.objects.create(ruleset=adm_ruleset, path=str(priv_rule_file), rule="rule Priv { condition: true }")
    priv_custom = CustomRule.objects.create(user=admin, name="adm_priv", path=str(priv_rule_file), public=False)

    # Analyst cannot download, edit, build with, or copy admin's private rules
    assert client.get(f"/api/rules/{priv_rule.pk}/download").status_code == 400
    assert (
        client.patch(
            f"/api/rules/{priv_rule.pk}",
            data=json.dumps({"text": "rule Hax { condition: true }"}),
            content_type="application/json",
        ).status_code
        == 400
    )
    assert (
        client.post(
            "/api/rules/build",
            data=json.dumps({"rule_ids": [priv_rule.pk], "rulename": "steal"}),
            content_type="application/json",
        ).status_code
        == 400
    )
    assert (
        client.post(
            "/api/rules/build",
            data=json.dumps({"rule_ids": [resp_up.json()[0]["id"]], "rulename": "../escape"}),
            content_type="application/json",
        ).status_code
        == 400
    )
    assert client.post(f"/api/customrules/{priv_custom.pk}/default").status_code == 403
    assert client.get(f"/api/customrules/{priv_custom.pk}/download").status_code == 400


def test_p0_admin_role_enforced_on_users_and_upload_packages(client, admin, analyst_user, readonly_user, tmp_path):
    """Non-admins must not enumerate users or call symbols upload_packages."""
    for non_admin in (readonly_user, analyst_user):
        client.force_login(non_admin)
        assert client.get("/api/users/").status_code == 403
        assert (
            client.post(
                "/api/symbols/upload_packages",
                data={"payload": json.dumps({"info": []})},
            ).status_code
            == 403
        )

    client.force_login(admin)
    assert client.get("/api/users/").status_code == 200

    outside = tmp_path / "not_allowed.deb"
    outside.write_bytes(b"pkg")
    resp_bad_pkg = client.post(
        "/api/symbols/upload_packages",
        data={"payload": json.dumps({"info": [{"local_folder": str(outside), "original_name": "../../pwn.deb"}]})},
    )
    assert resp_bad_pkg.status_code == 400
