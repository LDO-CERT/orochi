from functools import wraps

from ninja.errors import HttpError


def ninja_permission_required(perm):
    def decorator(func):
        @wraps(func)
        def wrapper(request, *args, **kwargs):
            if request.user.has_perm(perm) is False:
                raise HttpError(status_code=403, message="Permission Denied")

            return func(request, *args, **kwargs)

        return wrapper

    return decorator


def ninja_test_required(test):
    def decorator(func):
        @wraps(func)
        def wrapper(request, *args, **kwargs):
            if (
                test == "is_not_readonly"
                and request.user.groups.filter(name="ReadOnly").exists()
            ):
                raise HttpError(status_code=403, message="Permission Denied")
            return func(request, *args, **kwargs)

        return wrapper

    return decorator
