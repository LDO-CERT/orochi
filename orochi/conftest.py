import pytest

from orochi.users.models import User
from orochi.users.tests.factories import AdminFactory, UserFactory


@pytest.fixture(autouse=True)
def media_storage(settings, tmpdir):
    settings.MEDIA_ROOT = tmpdir.strpath


@pytest.fixture
def user() -> User:
    return UserFactory()


@pytest.fixture
def admin() -> User:
    return AdminFactory()


from uuid import uuid4

from django.contrib.auth.models import Group
from django.core.files.uploadedfile import SimpleUploadedFile
from guardian.shortcuts import assign_perm

from orochi.website.models import Bookmark, Dump, Folder, Plugin


@pytest.fixture
def readonly_user(db):
    user = User.objects.create_user("readonly", "readonly@example.com", "password")
    group, _ = Group.objects.get_or_create(name="ReadOnly")
    user.groups.add(group)
    return user


@pytest.fixture
def plugin(db):
    return Plugin.objects.create(name="test_plugin", operating_system="Linux")


@pytest.fixture
def folder(db, admin):
    return Folder.objects.create(name="test_folder", user=admin)


@pytest.fixture
def dump(db, admin, folder):
    dump = Dump.objects.create(
        operating_system="Linux",
        name="test_dump",
        index=str(uuid4()),
        author=admin,
        folder=folder,
        upload=SimpleUploadedFile("test.raw", b"file_content"),
    )
    assign_perm("can_see", admin, dump)
    return dump


@pytest.fixture
def bookmark(db, admin, dump, plugin):
    bookmark = Bookmark.objects.create(
        user=admin,
        name="test_bookmark",
        plugin=plugin,
        query="test",
    )
    bookmark.indexes.add(dump)
    return bookmark
