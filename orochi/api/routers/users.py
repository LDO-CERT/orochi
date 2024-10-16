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
    """
    Summary:
    Create a new user with optional read-only access.

    Explanation:
    Creates a new user based on the provided UserInSchema data, and optionally assigns read-only permissions to the user. The user's email is verified during creation.

    Args:
    - request: The request object.
    - user_in: UserInSchema object containing the user details.
    - is_readonly: A boolean flag indicating whether the user should have read-only access (default is False).

    Returns:
    - HTTP status code 201 and the created UserOutSchema object representing the new user.
    """
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
    """
    Summary:
    Retrieve a list of users.

    Explanation:
    Returns a list of all users in the system.

    Args:
    - request: The request object.

    Returns:
    - List of UserOutSchema objects representing the users.
    """
    return get_user_model().objects.all()


@router.get("/me", response={200: UserOutSchema, 403: ErrorsOut})
def me(request):
    """
    Summary:
    Retrieve information about the authenticated user.

    Explanation:
    Returns details of the authenticated user if available; otherwise, returns a 403 Forbidden response with an error message prompting the user to sign in.

    Args:
    - request: The request object.

    Returns:
    - If the user is authenticated, returns the UserOutSchema object representing the authenticated user. If not authenticated, returns HTTP status code 403 and an ErrorsOut object with a sign-in prompt.
    """
    if not request.user.is_authenticated:
        return 403, {"errors": "Please sign in first"}
    return request.user


@router.delete(
    "/{str:username}",
    auth=django_auth_superuser,
    response={200: SuccessResponse, 400: ErrorsOut},
)
def delete_user(request, username: str):
    """
    Summary:
    Delete a user by username with error handling.

    Explanation:
    Attempts to delete the user with the specified username from the system. Returns a success message if the deletion is successful, or an error response with details if an exception occurs during deletion.

    Args:
    - request: The request object.
    - username: The username of the user to delete.

    Returns:
    - If successful, returns HTTP status code 200 and a success message dictionary. If an exception occurs, returns HTTP status code 400 and an ErrorsOut object with the exception details.
    """
    user = get_object_or_404(get_user_model(), username=username)
    try:
        user.delete()
        return 200, {"message": f"User {username} deleted"}
    except Exception as excp:
        return 400, {"errors": str(excp)}
