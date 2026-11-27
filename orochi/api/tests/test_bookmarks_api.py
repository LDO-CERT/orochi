"""/api/bookmarks/: create, list, read, edit, star and delete, each limited to the owner."""

import json

import pytest
from guardian.shortcuts import assign_perm

from orochi.users.tests.factories import UserFactory
from orochi.website.models import Bookmark


def _json(client, method, path, payload=None):
    return getattr(client, method)(path, data=json.dumps(payload or {}), content_type="application/json")


@pytest.fixture
def owner(db, analyst_user, dump, plugin):
    assign_perm("website.can_see", analyst_user, dump)
    return analyst_user


@pytest.mark.django_db
def test_create_only_with_visible_dumps(client, owner, dump, plugin):
    client.force_login(owner)
    body = {"selected_indexes": dump.index, "name": "ps", "selected_plugin": plugin.name, "query": "bash"}
    res = _json(client, "post", "/api/bookmarks/", body)
    assert res.status_code == 201, res.content
    assert res.json()["name"] == "ps"
    assert Bookmark.objects.get(name="ps").indexes.get() == dump
    assert Bookmark.objects.get(name="ps").icon  # default icon when the client sends none

    assert (
        _json(client, "post", "/api/bookmarks/", dict(body, name=" ")).json()["errors"] == "Bookmark name is required"
    )

    # Same name again
    res = _json(client, "post", "/api/bookmarks/", body)
    assert res.status_code == 400 and res.json()["errors"] == "Bookmark name already used"
    # A dump the user cannot see is ignored, so nothing is left to bookmark
    client.force_login(UserFactory())
    res = _json(client, "post", "/api/bookmarks/", dict(body, name="other"))
    assert res.status_code == 400
    assert "No valid indexes" in res.json()["errors"]


@pytest.mark.django_db
def test_read_edit_star_delete_and_isolation(client, owner, dump, plugin):
    bookmark = Bookmark.objects.create(user=owner, plugin=plugin, name="mine", query="q")
    bookmark.indexes.add(dump)
    stranger = UserFactory()

    client.force_login(stranger)
    assert client.get(f"/api/bookmarks/{bookmark.pk}").status_code == 404
    assert _json(client, "patch", f"/api/bookmarks/{bookmark.pk}", {"name": "x"}).status_code == 404
    assert client.post(f"/api/bookmarks/{bookmark.pk}/star/true").status_code == 404
    assert client.delete(f"/api/bookmarks/{bookmark.pk}").status_code == 404
    assert client.get("/api/bookmarks/").json() == []

    client.force_login(owner)
    assert [b["name"] for b in client.get("/api/bookmarks/").json()] == ["mine"]
    assert client.get(f"/api/bookmarks/{bookmark.pk}").json()["query"] == "q"
    res = _json(client, "patch", f"/api/bookmarks/{bookmark.pk}", {"name": "renamed"})
    assert res.status_code == 200 and res.json()["name"] == "renamed"
    assert client.post(f"/api/bookmarks/{bookmark.pk}/star/true").json()["message"] == "Bookmark renamed starred"
    bookmark.refresh_from_db()
    assert bookmark.star is True
    assert "unstarred" in client.post(f"/api/bookmarks/{bookmark.pk}/star/false").json()["message"]
    assert client.delete(f"/api/bookmarks/{bookmark.pk}").status_code == 200
    assert not Bookmark.objects.filter(pk=bookmark.pk).exists()
    assert client.post(f"/api/bookmarks/{bookmark.pk}/star/true").status_code == 404
