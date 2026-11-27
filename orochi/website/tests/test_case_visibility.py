"""A case owned by the user and shared with several collaborators must resolve to one row.

``Q(user=u) | Q(collaborators=u)`` joins the collaborators table, so without ``.distinct()``
the owner matches once per collaborator: ``get()`` / ``get_object_or_404()`` then raise
``MultipleObjectsReturned`` (HTTP 500) and lists show the case twice.
"""

import json

import pytest
from django.urls import reverse
from guardian.shortcuts import assign_perm

from orochi.users.tests.factories import UserFactory
from orochi.website.models import Case, DumpSecret, Finding


@pytest.fixture
def shared_case(db, analyst_user):
    case = Case.objects.create(name="Shared-Incident", user=analyst_user)
    case.collaborators.add(UserFactory(), UserFactory())
    return case


@pytest.fixture
def secret(db, analyst_user, dump):
    assign_perm("website.can_see", analyst_user, dump)
    return DumpSecret.objects.create(
        dump=dump,
        category="aws",
        rule_name="Secret_AWS_Access_Key",
        matched_data="AKIAIOSFODNN7EXAMPLE",
        masked_data="AKIA...MPLE",
        pid=123,
        process_name="powershell.exe",
    )


def test_visible_to_returns_each_case_once(shared_case, analyst_user):
    collaborator = shared_case.collaborators.first()
    assert list(Case.objects.visible_to(analyst_user)) == [shared_case]
    assert list(Case.objects.visible_to(collaborator)) == [shared_case]
    assert not Case.objects.visible_to(UserFactory()).exists()


def test_visible_to_superuser_flag(shared_case, admin):
    assert not Case.objects.visible_to(admin).exists()
    assert list(Case.objects.visible_to(admin, all_for_superuser=True)) == [shared_case]


def test_promote_to_finding_on_case_with_two_collaborators(client, analyst_user, shared_case, secret):
    client.force_login(analyst_user)
    res = client.post(
        reverse("website:promote_to_finding"),
        {"item_type": "secret", "item_id": secret.id, "case_id": shared_case.id, "severity": "High"},
    )
    assert res.status_code == 200
    assert Finding.objects.filter(case=shared_case).count() == 1


def test_add_to_case_from_search_on_case_with_two_collaborators(client, analyst_user, shared_case, dump):
    assign_perm("website.can_see", analyst_user, dump)
    client.force_login(analyst_user)
    res = client.post(
        reverse("website:add_to_case_from_search"),
        {"case_mode": "existing", "case_id": shared_case.id, "selected_dumps[]": [dump.pk], "ajax": "1"},
    )
    assert res.status_code == 200, res.content
    assert res.json()["evidences_count"] == 1


def test_add_to_case_from_search_ignores_non_numeric_ids(client, analyst_user, shared_case, dump):
    assign_perm("website.can_see", analyst_user, dump)
    client.force_login(analyst_user)
    res = client.post(
        reverse("website:add_to_case_from_search"),
        {
            "case_mode": "existing",
            "case_id": shared_case.id,
            "selected_dumps[]": [dump.index],
            "selected_values[]": ["not-a-pk"],
            "ajax": "1",
        },
    )
    assert res.status_code == 200, res.content
    assert res.json()["evidences_count"] == 0


def test_api_promote_finding_on_case_with_two_collaborators(client, analyst_user, shared_case, secret):
    client.force_login(analyst_user)
    res = client.post(
        "/api/dumps/promote_finding",
        data=json.dumps({"item_type": "secret", "item_id": secret.id, "case_id": shared_case.id}),
        content_type="application/json",
    )
    assert res.status_code == 201, res.content


def test_outsider_cannot_promote_into_someone_elses_case(client, shared_case, secret):
    outsider = UserFactory()
    client.force_login(outsider)
    res = client.post(
        "/api/dumps/promote_finding",
        data=json.dumps({"item_type": "secret", "item_id": secret.id, "case_id": shared_case.id}),
        content_type="application/json",
    )
    assert res.status_code == 404
    assert not Finding.objects.exists()
