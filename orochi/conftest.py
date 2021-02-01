import pytest

from orochi.users.models import User
from orochi.users.tests.factories import UserFactory, AdminFactory


@pytest.fixture(autouse=True)
def media_storage(settings, tmpdir):
    settings.MEDIA_ROOT = tmpdir.strpath


@pytest.fixture
def user() -> User:
    return UserFactory()


@pytest.fixture
def admin() -> User:
    return AdminFactory()
