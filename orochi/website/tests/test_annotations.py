import json

import pytest
from django.urls import reverse
from guardian.shortcuts import assign_perm

from orochi.website.defaults import RESULT_STATUS_SUCCESS
from orochi.website.models import Result, Value, ValueAnnotation

pytestmark = pytest.mark.django_db


@pytest.fixture
def result_and_value(db, admin, dump, plugin):
    """Creates a successful Result and Value for testing annotations."""
    result = Result.objects.create(
        dump=dump,
        plugin=plugin,
        result=RESULT_STATUS_SUCCESS,
        description="Completed successfully",
    )
    val = Value.objects.create(
        result=result,
        value={
            "PID": 1024,
            "Name": "malicious.exe",
            "ImageFileName": "malicious.exe",
            "Offset": "0x85400000",
        },
    )
    return result, val


# =====================================================================
# 1. Model Tests
# =====================================================================
def test_value_annotation_model(admin, result_and_value):
    """Test ValueAnnotation creation, default values, __str__, and cascading delete."""
    _, val = result_and_value
    annotation = ValueAnnotation.objects.create(
        value=val,
        user=admin,
        comment="Suspicious process injected thread detected",
        status="suspicious",
    )

    assert annotation.pk is not None
    assert annotation.status == "suspicious"
    assert annotation.comment == "Suspicious process injected thread detected"
    assert annotation.user == admin
    assert annotation.value == val
    assert "Annotation #" in str(annotation)
    assert f"on Value {val.pk}" in str(annotation)

    # Test cascade delete when Value is deleted
    val_pk = val.pk
    val.delete()
    assert not ValueAnnotation.objects.filter(value_id=val_pk).exists()


def test_value_annotation_default_status(admin, result_and_value):
    """Test ValueAnnotation defaults to 'comment' status."""
    _, val = result_and_value
    annotation = ValueAnnotation.objects.create(
        value=val,
        user=admin,
        comment="Standard forensic analyst observation",
    )
    assert annotation.status == "comment"


# =====================================================================
# 2. UI View Tests (website:value_annotations)
# =====================================================================
def test_get_value_annotations_modal(client, admin, result_and_value):
    """Test GET website:value_annotations returns partial modal with row summary."""
    _, val = result_and_value
    client.force_login(admin)

    # Add an initial annotation
    ValueAnnotation.objects.create(
        value=val,
        user=admin,
        status="false_positive",
        comment="Known benign maintenance service",
    )

    url = reverse("website:value_annotations", kwargs={"value_id": val.pk})
    response = client.get(url)

    assert response.status_code == 200
    assert "website/partial_value_annotations.html" in [
        t.name for t in response.templates
    ]
    assert response.context["value"] == val
    assert "PID: 1024" in response.context["row_summary"]
    assert "malicious.exe" in response.context["row_summary"]
    assert b"Known benign maintenance service" in response.content
    assert b"False Positive" in response.content


def test_get_value_annotations_unauthorized(client, user, result_and_value):
    """Test GET website:value_annotations returns 403 if user lacks can_see on dump."""
    _, val = result_and_value
    client.force_login(user)

    url = reverse("website:value_annotations", kwargs={"value_id": val.pk})
    response = client.get(url)
    assert response.status_code == 403


def test_post_value_annotation_success(client, admin, result_and_value):
    """Test POST website:value_annotations creates new annotation and returns updated modal."""
    _, val = result_and_value
    client.force_login(admin)

    url = reverse("website:value_annotations", kwargs={"value_id": val.pk})
    response = client.post(
        url,
        data={"status": "verified_threat", "comment": "Confirmed Cobalt Strike beacon"},
    )

    assert response.status_code == 200
    annotation = ValueAnnotation.objects.get(value=val)
    assert annotation.status == "verified_threat"
    assert annotation.comment == "Confirmed Cobalt Strike beacon"
    assert annotation.user == admin
    assert b"Confirmed Cobalt Strike beacon" in response.content
    assert b"Verified Threat" in response.content


def test_post_value_annotation_readonly_forbidden(
    client, readonly_user, dump, result_and_value
):
    """Test POST website:value_annotations returns 403 for read-only user."""
    _, val = result_and_value
    assign_perm("can_see", readonly_user, dump)
    client.force_login(readonly_user)

    url = reverse("website:value_annotations", kwargs={"value_id": val.pk})
    response = client.post(
        url,
        data={"status": "comment", "comment": "Readonly attempt"},
    )
    assert response.status_code == 403
    assert not ValueAnnotation.objects.filter(value=val).exists()


def test_post_value_annotation_empty_comment_ignored(client, admin, result_and_value):
    """Test POST website:value_annotations with blank comment does not create annotation."""
    _, val = result_and_value
    client.force_login(admin)

    url = reverse("website:value_annotations", kwargs={"value_id": val.pk})
    response = client.post(url, data={"status": "comment", "comment": "   "})

    assert response.status_code == 200
    assert not ValueAnnotation.objects.filter(value=val).exists()


# =====================================================================
# 3. UI View Tests (website:delete_value_annotation)
# =====================================================================
def test_delete_value_annotation_author_success(client, admin, result_and_value):
    """Test author can delete their own annotation."""
    _, val = result_and_value
    annotation = ValueAnnotation.objects.create(
        value=val,
        user=admin,
        status="comment",
        comment="Comment to delete",
    )
    client.force_login(admin)

    url = reverse("website:delete_value_annotation", kwargs={"pk": annotation.pk})
    response = client.post(url)

    assert response.status_code == 302
    assert not ValueAnnotation.objects.filter(pk=annotation.pk).exists()


def test_delete_value_annotation_superuser_success(
    client, admin, user, result_and_value
):
    """Test superuser can delete any user's annotation."""
    _, val = result_and_value
    annotation = ValueAnnotation.objects.create(
        value=val,
        user=user,
        status="comment",
        comment="User comment deleted by superuser",
    )
    client.force_login(admin)  # admin fixture is superuser

    url = reverse("website:delete_value_annotation", kwargs={"pk": annotation.pk})
    response = client.post(url)

    assert response.status_code == 302
    assert not ValueAnnotation.objects.filter(pk=annotation.pk).exists()


def test_delete_value_annotation_non_author_forbidden(
    client, user, admin, result_and_value
):
    """Test non-author regular user cannot delete another user's annotation."""
    _, val = result_and_value
    annotation = ValueAnnotation.objects.create(
        value=val,
        user=admin,
        status="comment",
        comment="Admin comment protected from user",
    )
    client.force_login(user)

    url = reverse("website:delete_value_annotation", kwargs={"pk": annotation.pk})
    response = client.post(url)

    assert response.status_code == 403
    assert ValueAnnotation.objects.filter(pk=annotation.pk).exists()


# =====================================================================
# 4. Datatables generate View Integration
# =====================================================================
def test_generate_view_renders_annotation_badges(
    client, admin, dump, plugin, result_and_value
):
    """Test datatables generate endpoint includes annotation status classes in row_actions."""
    _, val = result_and_value
    client.force_login(admin)

    # 1. Without annotation -> renders default zinc button
    gen_url = reverse("website:generate")
    params = {
        "draw": "1",
        "start": "0",
        "length": "10",
        "plugin": plugin.name,
        "indexes[]": [dump.index],
        "columns[]": ["actions", "PID", "Name"],
    }
    resp = client.get(
        gen_url,
        params,
        HTTP_X_REQUESTED_WITH="XMLHttpRequest",
    )
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["data"]) == 1
    actions_cell = data["data"][0][0]
    assert "fa-regular fa-comment" in actions_cell
    assert "text-zinc-600" in actions_cell

    # 2. Add 'verified_threat' annotation -> renders rose badge & status label
    ValueAnnotation.objects.create(
        value=val,
        user=admin,
        status="verified_threat",
        comment="Identified as credential harvester",
    )

    resp2 = client.get(
        gen_url,
        params,
        HTTP_X_REQUESTED_WITH="XMLHttpRequest",
    )
    assert resp2.status_code == 200
    data2 = resp2.json()
    actions_cell2 = data2["data"][0][0]
    assert "text-rose-700" in actions_cell2
    assert "Verified Threat" in actions_cell2
    assert "fa-solid fa-comment-dots" in actions_cell2


# =====================================================================
# 5. REST API Endpoints (/api/dumps/...)
# =====================================================================
def test_api_get_value_annotations(client, admin, dump, result_and_value):
    """Test GET /api/dumps/values/{value_id}/annotations returns annotations list."""
    _, val = result_and_value
    client.force_login(admin)

    anno = ValueAnnotation.objects.create(
        value=val,
        user=admin,
        status="suspicious",
        comment="API test suspicious note",
    )

    url = f"/api/dumps/values/{val.pk}/annotations"
    response = client.get(url)

    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["id"] == anno.pk
    assert data[0]["value_id"] == val.pk
    assert data[0]["user"] == admin.username
    assert data[0]["status"] == "suspicious"
    assert data[0]["comment"] == "API test suspicious note"
    assert "created_at" in data[0]


def test_api_get_value_annotations_not_found(client, admin):
    """Test GET annotations for non-existent value returns 404."""
    client.force_login(admin)
    response = client.get("/api/dumps/values/999999/annotations")
    assert response.status_code == 404


def test_api_get_value_annotations_unauthorized(client, user, result_and_value):
    """Test GET annotations without can_see on dump returns 403."""
    _, val = result_and_value
    client.force_login(user)
    response = client.get(f"/api/dumps/values/{val.pk}/annotations")
    assert response.status_code == 403


def test_api_create_value_annotation(client, admin, result_and_value):
    """Test POST /api/dumps/values/{value_id}/annotations creates annotation via API."""
    _, val = result_and_value
    client.force_login(admin)

    payload = {
        "status": "false_positive",
        "comment": "Safe operating system daemon",
    }
    url = f"/api/dumps/values/{val.pk}/annotations"
    response = client.post(
        url,
        data=json.dumps(payload),
        content_type="application/json",
    )

    assert response.status_code == 201
    data = response.json()
    assert data["value_id"] == val.pk
    assert data["status"] == "false_positive"
    assert data["comment"] == "Safe operating system daemon"
    assert data["user"] == admin.username
    assert ValueAnnotation.objects.filter(pk=data["id"]).exists()


def test_api_create_value_annotation_validation_errors(client, admin, result_and_value):
    """Test API POST rejects empty comments and invalid statuses."""
    _, val = result_and_value
    client.force_login(admin)
    url = f"/api/dumps/values/{val.pk}/annotations"

    # Empty comment
    res1 = client.post(
        url,
        data=json.dumps({"status": "comment", "comment": "   "}),
        content_type="application/json",
    )
    assert res1.status_code == 400

    # Invalid status
    res2 = client.post(
        url,
        data=json.dumps({"status": "non_existent_status", "comment": "Note"}),
        content_type="application/json",
    )
    assert res2.status_code == 400


def test_api_create_value_annotation_readonly_forbidden(
    client, readonly_user, dump, result_and_value
):
    """Test API POST returns 403 for read-only user."""
    _, val = result_and_value
    assign_perm("can_see", readonly_user, dump)
    client.force_login(readonly_user)

    url = f"/api/dumps/values/{val.pk}/annotations"
    response = client.post(
        url,
        data=json.dumps({"status": "comment", "comment": "Readonly test"}),
        content_type="application/json",
    )
    assert response.status_code == 403


def test_api_delete_value_annotation(client, admin, user, result_and_value):
    """Test DELETE /api/dumps/annotations/{id} permissions and deletion."""
    _, val = result_and_value
    anno = ValueAnnotation.objects.create(
        value=val,
        user=user,
        status="comment",
        comment="Note to delete via API",
    )

    # 1. Non-author regular user gets 403
    from orochi.users.tests.factories import UserFactory

    other_user = UserFactory()
    client.force_login(other_user)
    res = client.delete(f"/api/dumps/annotations/{anno.pk}")
    assert res.status_code == 403
    assert ValueAnnotation.objects.filter(pk=anno.pk).exists()

    # 2. Author can delete
    client.force_login(user)
    res = client.delete(f"/api/dumps/annotations/{anno.pk}")
    assert res.status_code == 200
    assert not ValueAnnotation.objects.filter(pk=anno.pk).exists()

    # 3. 404 for deleted or non-existent
    res_404 = client.delete(f"/api/dumps/annotations/{anno.pk}")
    assert res_404.status_code == 404
