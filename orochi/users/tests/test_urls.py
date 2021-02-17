import pytest
from django.urls import resolve, reverse

from orochi.users.models import User

pytestmark = pytest.mark.django_db


def test_detail(user: User):
    assert (
        reverse("users:bookmarks", kwargs={"username": user.username})
        == f"/users/{user.username}/bookmarks/"
    )
    assert resolve(f"/users/{user.username}/plugins/").view_name == "users:plugins"
    assert resolve(f"/users/{user.username}/bookmarks/").view_name == "users:bookmarks"


def test_redirect():
    assert reverse("users:redirect") == "/users/~redirect/"
    assert resolve("/users/~redirect/").view_name == "users:redirect"
