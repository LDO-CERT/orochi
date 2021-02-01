import pytest
from django.test import RequestFactory

from orochi.users.api.views import UserViewSet
from orochi.users.models import User
from orochi.users.api.serializers import CreateUserSerializer, UserSerializer

pytestmark = pytest.mark.django_db


class TestUserViewSet:
    def test_get_queryset(self, user: User, rf: RequestFactory):
        view = UserViewSet()
        view.action = "list"
        view.format_kwarg = None
        request = rf.get("/fake-url/")
        request.user = user
        view.request = request

        response = view.list(request)
        assert user in view.get_queryset()
        assert (
            UserSerializer(request.user, context={"request": request}).data
            in response.data
        )

    def test_me(self, user: User, rf: RequestFactory):
        view = UserViewSet()
        request = rf.get("/fake-url/")
        request.user = user

        view.request = request

        response = view.me(request)

        assert response.data == {
            "username": user.username,
            "email": user.email,
            "url": f"http://testserver/api/users/{user.username}/",
            "is_active": user.is_active,
            "is_staff": user.is_staff,
            "is_superuser": user.is_superuser,
        }

    def test_create_duplicated(self, admin: User, rf: RequestFactory):
        view = UserViewSet()
        view.serializer_class = CreateUserSerializer
        view.action = "create"
        view.format_kwarg = None
        request = rf.get("/fake-url/")
        request.user = admin
        request.data = {
            "email": admin.email,
            "password": admin.password,
            "username": admin.username,
        }
        view.request = request
        response = view.create(request)
        assert response.status_code == 400

    def test_create_baseuser(self, user: User, rf: RequestFactory):
        view = UserViewSet()
        view.action = "create"
        view.format_kwarg = None

        request = rf.get("/fake-url/")
        request.user = user
        request.data = {
            "email": user.email,
            "password": user.password,
            "username": user.username,
        }
        view.request = request
        response = view.create(request)
        assert response.status_code == 400

    def test_create_success(self, admin: User, rf: RequestFactory):
        view = UserViewSet()
        view.action = "create"
        view.format_kwarg = None

        email = "test@example.com"
        password = "dummy1234$$"
        username = "test"

        request = rf.get("/fake-url/")
        request.data = {
            "email": email,
            "password": password,
            "username": username,
        }
        request.user = admin
        view.request = request

        response = view.create(request)

        assert response.data == {
            "username": username,
            "email": email,
            "url": f"http://testserver/api/users/{username}/",
            "is_active": True,
            "is_staff": False,
            "is_superuser": False,
        }