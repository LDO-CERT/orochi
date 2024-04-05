from typing import List

from allauth.account.models import EmailAddress
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.shortcuts import get_object_or_404
from ninja import Router
from ninja.pagination import paginate
from ninja.security import django_auth, django_auth_superuser

from orochi.api.models import ErrorsOut, SuccessResponse, UserInSchema, UserOutSchema

router = Router()


@router.post("/", response={201: UserOutSchema}, auth=django_auth_superuser)
def create_user(request, user_in: UserInSchema, is_readonly: bool = False):
    user = get_user_model().objects.create_user(**user_in.dict())
    email, _ = EmailAddress.objects.get_or_create(user=user, email=user.email)
    email.verified = True
    email.save()
    if is_readonly:
        readonly_group = Group.objects.get(name="ReadOnly")
        user.groups.add(readonly_group)
    return 201, user


@router.get("/", response={200: List[UserOutSchema]}, auth=django_auth)
@paginate
def list_users(request):
    return get_user_model().objects.all()


@router.get("/me", response={200: UserOutSchema, 403: ErrorsOut})
def me(request):
    if not request.user.is_authenticated:
        return 403, {"errors": "Please sign in first"}
    return request.user


@router.delete(
    "/{username}", auth=django_auth_superuser, response={200: SuccessResponse}
)
def delete_user(request, username: str):
    user = get_object_or_404(get_user_model(), username=username)
    user.delete()
    return 200, {"message": f"User {username} deleted"}
