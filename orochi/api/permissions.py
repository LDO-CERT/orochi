from functools import wraps

from ninja.errors import HttpError

from orochi.website.roles import ROLE_READONLY, get_user_role, has_role


def ninja_permission_required(perm):
    def decorator(func):
        @wraps(func)
        def wrapper(request, *args, **kwargs):
            if request.user.has_perm(perm) is False:
                raise HttpError(status_code=403, message="Permission Denied")

            return func(request, *args, **kwargs)

        return wrapper

    return decorator


def ninja_role_required(min_role):
    """Decorator to require a minimum role for a ninja endpoint."""

    def decorator(func):
        @wraps(func)
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                raise HttpError(status_code=403, message="Authentication required")
            if not has_role(request.user, min_role):
                raise HttpError(
                    status_code=403,
                    message=f"Permission Denied: Requires at least {min_role} role",
                )
            return func(request, *args, **kwargs)

        return wrapper

    return decorator


def ninja_test_required(test):
    def decorator(func):
        @wraps(func)
        def wrapper(request, *args, **kwargs):
            if test == "is_not_readonly":
                if get_user_role(request.user) == ROLE_READONLY:
                    raise HttpError(status_code=403, message="Permission Denied")
            return func(request, *args, **kwargs)

        return wrapper

    return decorator
