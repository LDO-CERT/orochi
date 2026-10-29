import json

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
