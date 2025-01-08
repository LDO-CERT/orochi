from django.contrib import messages
from django.core import management
from ninja import Router
from ninja.security import django_auth_superuser

from orochi.api.models import ErrorsOut, SuccessResponse

router = Router()


@router.get(
    "/rules/update",
    auth=django_auth_superuser,
    response={200: SuccessResponse, 400: ErrorsOut},
    url_name="update_rules",
)
def update_rules(request):
    """Update rules.

    This endpoint triggers the synchronization of rules using a management command.
    It returns a success message if the synchronization is successful, or an error message if it fails.

    Args:
        request: The request object.

    Returns:
        Tuple[int, dict]: A tuple containing the status code and a dictionary with a message.
            Returns 200 and a success message if the synchronization is successful.
            Returns 404 and an error message if the synchronization fails.

    Raises:
        Exception: If an error occurs during rule synchronization.
    """
    try:
        management.call_command("rules_sync", verbosity=0)
        messages.add_message(request, messages.INFO, "Sync Rules done")
        return 200, {"message": "Sync Symbols done"}
    except Exception as e:
        messages.add_message(request, messages.ERROR, f"Sync Plugin failed: {e}")
        return 404, {"errors": "Forbidden"}


@router.get(
    "/rules/generate",
    auth=django_auth_superuser,
    response={200: SuccessResponse, 400: ErrorsOut},
    url_name="generate_default_rule",
)
def generate_default_rule(request):
    """Generate a default rule.

    This endpoint triggers the generation of a default rule using a management command.
    It returns a success message if the rule creation is successful, or an error message if it fails.

    Args:
        request: The request object.

    Returns:
        Tuple[int, dict]: A tuple containing the status code and a dictionary with a message.
            Returns 200 and a success message if the rule creation is successful.
            Returns 404 and an error message if the rule creation fails.

    Raises:
        Exception: If an error occurs during rule generation.
    """
    try:
        management.call_command("generate_default_rule", verbosity=0)
        messages.add_message(request, messages.INFO, "Default Rule created")
        return 200, {"message": "Sync Symbols done"}
    except Exception as e:
        messages.add_message(request, messages.ERROR, f"Sync Plugin failed: {e}")
        return 404, {"errors": "Forbidden"}


@router.get(
    "/plugins/update",
    auth=django_auth_superuser,
    response={200: SuccessResponse, 400: ErrorsOut},
    url_name="update_plugins",
)
def update_plugins(request):
    """Update plugins for the application.

    This endpoint triggers a plugin synchronization process. It then redirects to the admin page, displaying a success or error message.

    Args:
        request: The incoming HTTP request.

    Returns:
        A redirect to /admin with a success message if the synchronization is successful, or a 404 error with an error message if it fails.

    Raises:
        Exception: If an error occurs during plugin synchronization.
    """

    try:
        management.call_command("plugins_sync", verbosity=0)
        messages.add_message(request, messages.INFO, "Sync Plugin done")
        return 200, {"message": "Sync Plugin done"}
    except Exception as e:
        messages.add_message(request, messages.ERROR, f"Sync Plugin failed: {e}")
        return 404, {"errors": "Forbidden"}


@router.get(
    "/symbols/update",
    auth=django_auth_superuser,
    response={200: SuccessResponse, 400: ErrorsOut},
    url_name="update_symbols",
)
def update_symbols(request):
    """Update symbols for the application.

    This endpoint triggers a symbol synchronization process. It then redirects to the admin page, displaying a success or error message.

    Args:
        request: The incoming HTTP request.

    Returns:
        A redirect to /admin with a success message if the synchronization is successful, or a 404 error with an error message if it fails.

    Raises:
        Exception: If an error occurs during symbol synchronization.
    """

    try:
        management.call_command("symbols_sync", verbosity=0)
        messages.add_message(request, messages.INFO, "Sync Symbols done")
        return 200, {"message": "Sync Symbols done"}
    except Exception as e:
        messages.add_message(request, messages.ERROR, f"Sync Symbols failed: {e}")
        return 404, {"errors": "Forbidden"}
