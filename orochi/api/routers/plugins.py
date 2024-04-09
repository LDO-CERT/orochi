from datetime import datetime
from tempfile import NamedTemporaryFile
from typing import List

import requests
from django.contrib.auth import get_user_model
from django.shortcuts import get_object_or_404
from ninja import Query, Router
from ninja.security import django_auth

from orochi.api.filters import OperatingSytemFilters
from orochi.api.models import (
    ErrorsOut,
    PluginInSchema,
    PluginInstallSchema,
    PluginOutSchema,
    SuccessResponse,
)
from orochi.utils.plugin_install import plugin_install
from orochi.website.defaults import RESULT_STATUS_NOT_STARTED
from orochi.website.models import Dump, Plugin, Result, UserPlugin

router = Router()


@router.get("/", response={200: List[PluginOutSchema]}, auth=django_auth)
def list_plugins(request, filters: Query[OperatingSytemFilters] = None):
    """
    Summary:
    Get a list of plugins based on optional operating system filters.

    Explanation:
    Retrieves a list of plugins filtered by the specified operating system if provided, otherwise returns all plugins.

    Args:
    - request: The request object.
    - filters: Optional Query object containing operating system filters.

    Returns:
    - List of PluginOutSchema objects.

    Examples:
    list_plugins(request)
    list_plugins(request, filters=Query(operating_system='Windows'))
    """
    if filters and filters.operating_system:
        return Plugin.objects.filter(operating_system=filters.operating_system)
    return Plugin.objects.all()


@router.post(
    "/install",
    auth=django_auth,
    url_name="install_plugin",
    response={200: SuccessResponse, 400: ErrorsOut},
)
def install_plugin(request, plugin_info: PluginInstallSchema):
    """
    Summary:
    Install a plugin from the provided PluginInstallSchema.

    Explanation:
    Downloads the plugin from the specified URL in the PluginInstallSchema, installs it for the specified operating system, and updates the database with the plugin information. UserPlugin and Result entries are created for all users and dumps respectively.

    Args:
    - request: The request object.
    - plugin_info: PluginInstallSchema object containing the plugin URL and operating system information.

    Returns:
    - If successful, returns HTTP status code 200 and a success message dictionary. If installation fails, returns HTTP status code 400 and an ErrorsOut object with the error details.
    """
    try:
        req = requests.get(plugin_info.plugin_url, allow_redirects=True)
        if req.ok:
            f = NamedTemporaryFile(mode="wb", suffix=".zip", delete=False)
            f.write(req.content)
            f.close()
            if plugin_names := plugin_install(f.name):
                for plugin_data in plugin_names:
                    plugin_name, plugin_class = list(plugin_data.items())[0]
                    plugin, _ = Plugin.objects.update_or_create(
                        name=plugin_name,
                        defaults={
                            "comment": plugin_class.__doc__,
                            "operating_system": plugin_info.operating_system,
                            "local": True,
                            "local_date": datetime.now(),
                        },
                    )
                    for user in get_user_model().objects.all():
                        UserPlugin.objects.get_or_create(user=user, plugin=plugin)
                    for dump in Dump.objects.all():
                        if plugin_info.operating_system in [
                            dump.operating_system,
                            "Other",
                        ]:
                            Result.objects.update_or_create(
                                dump=dump,
                                plugin=plugin,
                                defaults={"result": RESULT_STATUS_NOT_STARTED},
                            )
                return 200, {"message": "Plugin installed successfully"}
        return 400, {"errors": "Failed to install plugin"}
    except Exception as excp:
        return 400, {"errors": str(excp)}


@router.get("/{str:name}", response={200: PluginOutSchema}, auth=django_auth)
def get_plugin(request, name: str):
    """
    Summary:
    Retrieve a specific plugin by name.

    Explanation:
    Fetches a plugin from the database based on the provided name.

    Args:
    - request: The request object.
    - name: The name of the plugin to retrieve.

    Returns:
    - A single PluginOutSchema object representing the retrieved plugin.
    """
    return get_object_or_404(Plugin, name=name)


@router.put(
    "/{str:name}", response={200: PluginOutSchema, 400: ErrorsOut}, auth=django_auth
)
def update_plugin(request, name: str, data: PluginInSchema):
    """
    Summary:
    Update a plugin with new data based on the provided name.

    Explanation:
    Updates the attributes of a plugin specified by the name with the data provided in the PluginInSchema object.

    Args:
    - request: The request object.
    - name: The name of the plugin to update.
    - data: PluginInSchema object containing the new data for the plugin.

    Returns:
    - Updated PluginOutSchema object representing the modified plugin.
    """
    plugin = get_object_or_404(Plugin, name=name)
    try:
        for attr, value in data.dict().items():
            setattr(plugin, attr, value)
        plugin.save()
        return plugin
    except Exception as excp:
        return 400, {"errors": str(excp)}


@router.post(
    "/{str:name}/enable/{enable}",
    auth=django_auth,
    url_name="enable",
    response={200: SuccessResponse, 400: ErrorsOut},
)
def enable_plugin(request, name: str, enable: bool):
    """
    Summary:
    Enable or disable a plugin for the current user.

    Explanation:
    Updates the automatic attribute of a UserPlugin associated with the specified plugin name and the current user based on the enable flag.

    Args:
    - request: The request object.
    - name: The name of the plugin to enable or disable.
    - enable: A boolean flag indicating whether to enable (True) or disable (False) the plugin.

    Returns:
    - Tuple containing HTTP status code 200 and a success message dictionary.
    """
    try:
        plugin = get_object_or_404(UserPlugin, plugin__name=name, user=request.user)
        plugin.automatic = enable
        plugin.save()
        return 200, {
            "message": f"Plugin {name} enabled" if enable else f"Plugin {name} disabled"
        }
    except Exception as excp:
        return 400, {"errors": str(excp)}
