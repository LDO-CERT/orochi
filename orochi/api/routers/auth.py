from django.conf import settings
from django.contrib.auth import authenticate, get_user_model, update_session_auth_hash
from django.contrib.auth import login as django_login
from django.contrib.auth import logout as django_logout
from django.contrib.auth.forms import (
    PasswordChangeForm,
    PasswordResetForm,
    SetPasswordForm,
)
from django.contrib.auth.tokens import default_token_generator
from ninja import Router, Status
from ninja.security import django_auth

from orochi.api.models import (
    APITokenCreatedOut,
    APITokenCreateIn,
    APITokenOut,
    ChangePasswordIn,
    ErrorsOut,
    LoginIn,
    RequestPasswordResetIn,
    SetPasswordIn,
    SuccessResponse,
    UserOutSchema,
)
from orochi.users.models import APIToken

router = Router()


@router.post("/", response={200: UserOutSchema, 403: None}, auth=None)
def login(request, data: LoginIn):
    # Authenticate against all configured backends (ModelBackend, LDAP, AllAuth)
    user = authenticate(request, username=data.username, password=data.password)
    if user is not None and user.is_active:
        django_login(request, user)
        return user
    return Status(403, None)


@router.delete("/", response={204: None}, auth=django_auth)
def logout(request):
    django_logout(request)
    return Status(204, None)


@router.get("/tokens/", response={200: list[APITokenOut]}, auth=django_auth)
def list_tokens(request):
    """List all active API tokens for the currently authenticated user."""
    return APIToken.objects.filter(user=request.user, is_active=True).order_by("-created_at")


@router.post("/tokens/", response={201: APITokenCreatedOut}, auth=django_auth)
def create_token(request, data: APITokenCreateIn):
    """Generate a new personal API Bearer token for the user.

    The raw token is returned once and cannot be retrieved again.
    """
    token_instance, raw_token = APIToken.generate_token(user=request.user, name=data.name)
    return Status(
        201,
        {
            "id": token_instance.pk,
            "name": token_instance.name,
            "token_prefix": token_instance.token_prefix,
            "created_at": token_instance.created_at,
            "last_used_at": token_instance.last_used_at,
            "is_active": token_instance.is_active,
            "token": raw_token,
        },
    )


@router.delete("/tokens/{int:token_id}/", response={200: SuccessResponse, 404: ErrorsOut}, auth=django_auth)
def revoke_token(request, token_id: int):
    """Revoke and delete an API token belonging to the current user."""
    token = APIToken.objects.filter(pk=token_id, user=request.user).first()
    if not token:
        return Status(404, {"errors": "Token not found"})
    token.delete()
    return Status(200, {"message": "Token revoked successfully"})


@router.post("/request_password_reset", response={204: None}, auth=None)
def request_password_reset(request, data: RequestPasswordResetIn):
    form = PasswordResetForm(data.dict())
    if form.is_valid():
        form.save(
            request=request,
            extra_email_context=(
                {"frontend_url": settings.FRONTEND_URL} if hasattr(settings, "FRONTEND_URL") else None
            ),
        )
    return Status(204, None)


@router.post(
    "/reset_password",
    response={200: UserOutSchema, 403: ErrorsOut, 422: None},
    auth=None,
)
def reset_password(request, data: SetPasswordIn):
    user_field = get_user_model().USERNAME_FIELD
    user_data = {user_field: getattr(data, user_field)}
    user = get_user_model().objects.filter(**user_data)

    if user.exists():
        user = user.get()
        if default_token_generator.check_token(user, data.token):
            form = SetPasswordForm(user, data.dict())
            if form.is_valid():
                form.save()
                backend = getattr(user, "backend", settings.AUTHENTICATION_BACKENDS[0])
                django_login(request, user, backend=backend)
                return user
            return Status(403, {"errors": dict(form.errors)})
    return Status(422, None)


@router.post("/change_password", response={200: None, 403: ErrorsOut}, auth=django_auth)
def change_password(request, data: ChangePasswordIn):
    form = PasswordChangeForm(request.user, data.dict())
    if form.is_valid():
        form.save()
        update_session_auth_hash(request, request.user)
        return 200
    return Status(403, {"errors": dict(form.errors)})
