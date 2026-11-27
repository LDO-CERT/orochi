"""Permission errors answer 403 and missing objects 404 (not 400/401) on the dump lifecycle and admin APIs."""

import pytest
from guardian.shortcuts import assign_perm

from orochi.users.models import APIToken


@pytest.mark.django_db
def test_admin_api_403_for_signed_in_non_superusers_401_for_anonymous(client, analyst_user, admin):
    assert client.get("/api/admin/settings").status_code == 401
    client.force_login(analyst_user)
    res = client.get("/api/admin/settings")
    assert res.status_code == 403
    assert "superuser" in res.json()["detail"]
    client.force_login(admin)
    assert client.get("/api/admin/settings").status_code == 200


@pytest.mark.django_db
def test_admin_api_bearer_tokens(client, analyst_user, admin):
    _, analyst_token = APIToken.generate_token(analyst_user, "t")
    _, admin_token = APIToken.generate_token(admin, "t")
    assert client.get("/api/admin/settings", headers={"Authorization": "Bearer oro_unknown"}).status_code == 401
    assert client.get("/api/admin/settings", headers={"Authorization": f"Bearer {analyst_token}"}).status_code == 403
    assert client.get("/api/admin/settings", headers={"Authorization": f"Bearer {admin_token}"}).status_code == 200


@pytest.mark.django_db
def test_dump_info_403_without_permission_404_when_missing(client, analyst_user, dump):
    client.force_login(analyst_user)
    assert client.get(f"/api/dumps/{dump.index}").status_code == 403
    assert client.get("/api/dumps/00000000-0000-0000-0000-000000000000").status_code == 404
    assign_perm("website.can_see", analyst_user, dump)
    assert client.get(f"/api/dumps/{dump.index}").status_code == 200


@pytest.mark.django_db
def test_dump_lifecycle_403_for_reviewer_404_when_not_visible(client, reviewer_user, analyst_user, dump):
    assign_perm("website.can_see", reviewer_user, dump)
    client.force_login(reviewer_user)
    assert client.delete(f"/api/dumps/{dump.index}").status_code == 403
    client.force_login(analyst_user)
    assert client.delete(f"/api/dumps/{dump.index}").status_code == 404
    assert client.post(f"/api/dumps/{dump.index}/restore").status_code == 404
