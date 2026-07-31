from django.conf import settings
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth import login as django_login
from django.contrib.auth import logout as django_logout
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.forms import (
    PasswordChangeForm,
    PasswordResetForm,
    SetPasswordForm,
)
from django.contrib.auth.tokens import default_token_generator
from ninja import Router
from ninja.security import django_auth

from orochi.api.models import (
    ChangePasswordIn,
    ErrorsOut,
    LoginIn,
    RequestPasswordResetIn,
    SetPasswordIn,
    UserOutSchema,
)

router = Router()
_LOGIN_BACKEND = "django.contrib.auth.backends.ModelBackend"


@router.post("/", response={200: UserOutSchema, 403: None}, auth=None)
def login(request, data: LoginIn):
    user = authenticate(backend=_LOGIN_BACKEND, **data.dict())
    if user is not None and user.is_active:
        django_login(request, user, backend=_LOGIN_BACKEND)
        return user
    return 403, None


@router.delete("/", response={204: None}, auth=django_auth)
def logout(request):
    django_logout(request)
    return 204, None


@router.post("/request_password_reset", response={204: None}, auth=None)
def request_password_reset(request, data: RequestPasswordResetIn):
    form = PasswordResetForm(data.dict())
    if form.is_valid():
        form.save(
            request=request,
            extra_email_context=(
                {"frontend_url": settings.FRONTEND_URL}
                if hasattr(settings, "FRONTEND_URL")
                else None
            ),
        )
    return 204, None


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
                django_login(request, user, backend=_LOGIN_BACKEND)
                return user
            return 403, {"errors": dict(form.errors)}
    return 422, None


@router.post("/change_password", response={200: None, 403: ErrorsOut}, auth=django_auth)
def change_password(request, data: ChangePasswordIn):
    form = PasswordChangeForm(request.user, data.dict())
    if form.is_valid():
        form.save()
        update_session_auth_hash(request, request.user)
        return 200
    return 403, {"errors": dict(form.errors)}
