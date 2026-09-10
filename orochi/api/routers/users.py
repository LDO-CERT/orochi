from allauth.account.models import EmailAddress
from django.contrib.auth import get_user_model
from django.shortcuts import get_object_or_404
from ninja import Query, Router, Status
from ninja.pagination import paginate
from ninja.security import django_auth, django_auth_superuser

from orochi.api.models import ErrorsOut, SuccessResponse, UserInSchema, UserOutSchema
from orochi.website.roles import ROLE_ANALYST, ROLE_READONLY, set_user_role

router = Router()


@router.post("/", response={201: UserOutSchema}, auth=django_auth_superuser)
def create_user(
    request,
    user_in: UserInSchema,
    is_readonly: bool = False,
    role: str | None = Query(None),
):
    """
    Summary:
    Create a new user with optional role assignment or read-only access.
    """
    data = user_in.dict()
    selected_role = data.pop("role", None) or role
    if data.get("first_name") is None:
        data["first_name"] = ""
    if data.get("last_name") is None:
        data["last_name"] = ""
    user = get_user_model().objects.create_user(**data)
    email, _ = EmailAddress.objects.get_or_create(user=user, email=user.email)
    email.verified = True
    email.save()

    if selected_role:
        set_user_role(user, selected_role)
    elif is_readonly:
        set_user_role(user, ROLE_READONLY)
    else:
        set_user_role(user, ROLE_ANALYST)

    return Status(201, user)


@router.get("/", response={200: list[UserOutSchema]}, auth=django_auth)
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
        return Status(403, {"errors": "Please sign in first"})
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
        return Status(200, {"message": f"User {username} deleted"})
    except Exception as excp:
        return Status(400, {"errors": str(excp)})


@router.post(
    "/{str:username}/role",
    auth=django_auth_superuser,
    response={200: UserOutSchema, 400: ErrorsOut},
)
def update_user_role(request, username: str, role: str):
    """
    Summary:
    Update the assigned role for a user (Admin, Analyst, Reviewer, ReadOnly).
    """
    user = get_object_or_404(get_user_model(), username=username)
    try:
        set_user_role(user, role)
        return Status(200, user)
    except ValueError as excp:
        return Status(400, {"errors": str(excp)})
