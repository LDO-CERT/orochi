import contextlib
import io
import logging
import os
import threading
import zipfile
from datetime import datetime
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any

import requests
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.conf import settings
from django.contrib.auth import get_user_model
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from extra_settings.models import Setting
from ninja import File, Form, Query, Router, Status, UploadedFile
from ninja.security import django_auth

from orochi.api.filters import OperatingSytemFilters
from orochi.api.models import (
    ErrorsOut,
    PluginInSchema,
    PluginInstallSchema,
    PluginOutSchema,
    PluginParametersOutSchema,
    PluginSourceOutSchema,
    PluginUploadOutSchema,
    SuccessResponse,
)
from orochi.api.permissions import ninja_role_required
from orochi.utils.plugin_install import plugin_install
from orochi.utils.volatility_dask_elk import get_parameters
from orochi.website.defaults import (
    DUMP_STATUS_MISSING_SYMBOLS,
    RESULT_STATUS_DISABLED,
    RESULT_STATUS_NOT_STARTED,
)
from orochi.website.models import Dump, Plugin, Result, UserPlugin
from orochi.website.roles import ROLE_ADMIN

logger = logging.getLogger(__name__)
router = Router()


def find_plugin_file(name: str) -> tuple[Path | None, str | None]:
    """
    Locates the source file for a plugin by name.
    Returns (Path, filename) or (None, None).
    """
    try:
        plugin_folder = Path(Setting.get("VOLATILITY_PLUGIN_PATH"))
        if plugin_folder.exists():
            stem = name.split(".")[-1].lower()
            for p in plugin_folder.rglob("*.py"):
                if p.stem.lower() == stem or stem in p.stem.lower():
                    return p, p.name
    except Exception as e:
        logger.debug(f"Error searching VOLATILITY_PLUGIN_PATH: {e}")

    try:
        import inspect

        import volatility3.plugins
        from volatility3 import framework
        from volatility3.framework import contexts

        _ = contexts.Context()
        _ = framework.import_files(volatility3.plugins, True)
        plugins = framework.list_plugins()
        plugin_cls = plugins.get(name)
        if plugin_cls:
            src_file = inspect.getsourcefile(plugin_cls)
            if src_file and os.path.exists(src_file):
                p = Path(src_file)
                return p, p.name
    except Exception as e:
        logger.debug(f"Error inspecting framework plugins: {e}")

    return None, None


def process_plugin_installation(
    file_path: str,
    operating_system: str,
    comment: str | None = None,
    disabled: bool = False,
    local_dump: bool = False,
    vt_check: bool = False,
    clamav_check: bool = False,
    regipy_check: bool = False,
    maxmind_check: bool = False,
) -> list[str]:
    """
    Extracts and installs custom Volatility plugins, and registers them in the database.
    Returns a list of successfully installed plugin names.
    """
    if plugin_names := plugin_install(file_path):
        installed_names = []
        for plugin_data in plugin_names:
            plugin_name, plugin_class = list(plugin_data.items())[0]
            plugin, _ = Plugin.objects.update_or_create(
                name=plugin_name,
                defaults={
                    "comment": comment or (plugin_class.__doc__ if plugin_class else None),
                    "operating_system": operating_system,
                    "local": True,
                    "local_date": datetime.now(),
                    "disabled": disabled,
                    "local_dump": local_dump,
                    "vt_check": vt_check,
                    "clamav_check": clamav_check,
                    "regipy_check": regipy_check,
                    "maxmind_check": maxmind_check,
                },
            )
            for user in get_user_model().objects.all():
                UserPlugin.objects.get_or_create(user=user, plugin=plugin)
            for dump in Dump.objects.all():
                if operating_system in [dump.operating_system, "Other"] or dump.operating_system in [
                    operating_system,
                    "Other",
                ]:
                    Result.objects.update_or_create(
                        dump=dump,
                        plugin=plugin,
                        defaults={
                            "result": (
                                RESULT_STATUS_NOT_STARTED
                                if dump.status != DUMP_STATUS_MISSING_SYMBOLS
                                else RESULT_STATUS_DISABLED
                            )
                        },
                    )
            installed_names.append(plugin_name)
        return installed_names
    return []


def background_install_plugin(
    file_path,
    plugin_info_os,
    user_pk,
    comment=None,
    disabled=False,
    local_dump=False,
    vt_check=False,
    clamav_check=False,
    regipy_check=False,
    maxmind_check=False,
):
    channel_layer = get_channel_layer()
    try:
        installed = process_plugin_installation(
            file_path,
            operating_system=plugin_info_os,
            comment=comment,
            disabled=disabled,
            local_dump=local_dump,
            vt_check=vt_check,
            clamav_check=clamav_check,
            regipy_check=regipy_check,
            maxmind_check=maxmind_check,
        )
        if installed:
            message = (
                f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')} || "
                f"Installed {len(installed)} plugin(s): {', '.join(installed)}.<br>"
                f"Status: <b style='color:green'>Success</b>"
            )
        else:
            message = (
                f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')} || "
                f"Failed to install plugin. Check server logs.<br>"
                f"Status: <b style='color:red'>Failed</b>"
            )
    except Exception as excp:
        message = (
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')} || "
            f"Failed to install plugin ({excp}).<br>"
            f"Status: <b style='color:red'>Failed</b>"
        )
    finally:
        if os.path.exists(file_path):
            os.remove(file_path)

    async_to_sync(channel_layer.group_send)(
        f"chat_{user_pk}",
        {
            "type": "chat_message",
            "message": message,
        },
    )


@router.get("/", response={200: list[PluginOutSchema]}, auth=django_auth)
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
    response={200: SuccessResponse, 400: ErrorsOut, 403: ErrorsOut},
)
@ninja_role_required(ROLE_ADMIN)
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
            threading.Thread(
                target=background_install_plugin,
                args=(f.name, plugin_info.operating_system, request.user.pk),
            ).start()
            return Status(200, {"message": "Plugin installation started in background"})
        return Status(400, {"errors": "Failed to download plugin"})
    except Exception as excp:
        return Status(400, {"errors": str(excp)})


@router.post(
    "/upload",
    auth=django_auth,
    url_name="upload_plugin",
    response={200: PluginUploadOutSchema, 400: ErrorsOut, 403: ErrorsOut},
)
@ninja_role_required(ROLE_ADMIN)
def upload_plugin(
    request,
    plugin_file: UploadedFile = File(...),
    operating_system: str = Form("Other"),
    comment: str | None = Form(None),
    disabled: bool = Form(False),
    local_dump: bool = Form(False),
    vt_check: bool = Form(False),
    clamav_check: bool = Form(False),
    regipy_check: bool = Form(False),
    maxmind_check: bool = Form(False),
    async_mode: bool = Form(False),
):
    """
    Summary:
    Upload a custom Volatility plugin archive (.zip) and install it.

    Explanation:
    Accepts a multipart file upload containing a ZIP archive with custom Volatility 3 plugin .py file(s),
    optional requirements.txt, and optional shell installation script. Validates the archive and installs
    the plugin across Orochi and connected Dask workers.
    """
    if not plugin_file.name.endswith(".zip"):
        return Status(400, {"errors": "Uploaded file must be a .zip archive."})

    f = NamedTemporaryFile(mode="wb", suffix=".zip", delete=False)
    try:
        for chunk in plugin_file.chunks():
            f.write(chunk)
        f.close()

        if not zipfile.is_zipfile(f.name):
            return Status(400, {"errors": "Uploaded file is not a valid zip archive."})

        with zipfile.ZipFile(f.name, "r") as z:
            py_files = [n for n in z.namelist() if n.endswith(".py") and not n.startswith("__MACOSX")]
            if not py_files:
                return Status(400, {"errors": "ZIP archive must contain at least one .py plugin file."})

        if async_mode:
            threading.Thread(
                target=background_install_plugin,
                args=(
                    f.name,
                    operating_system,
                    request.user.pk,
                    comment,
                    disabled,
                    local_dump,
                    vt_check,
                    clamav_check,
                    regipy_check,
                    maxmind_check,
                ),
            ).start()
            return Status(
                200,
                {
                    "message": "Plugin upload received. Installation started in background.",
                    "installed_plugins": [],
                },
            )

        installed = process_plugin_installation(
            f.name,
            operating_system=operating_system,
            comment=comment,
            disabled=disabled,
            local_dump=local_dump,
            vt_check=vt_check,
            clamav_check=clamav_check,
            regipy_check=regipy_check,
            maxmind_check=maxmind_check,
        )
        if installed:
            return Status(
                200,
                {
                    "message": f"Plugin(s) installed successfully: {', '.join(installed)}",
                    "installed_plugins": installed,
                },
            )
        return Status(
            400,
            {"errors": "Failed to install plugin from archive. Verify syntax and Volatility 3 compatibility."},
        )
    except Exception as excp:
        return Status(400, {"errors": str(excp)})
    finally:
        if not async_mode and os.path.exists(f.name):
            os.remove(f.name)


@router.post(
    "/sync",
    auth=django_auth,
    url_name="sync_plugins",
    response={200: SuccessResponse, 400: ErrorsOut, 403: ErrorsOut},
)
@ninja_role_required(ROLE_ADMIN)
def sync_plugins(request):
    """
    Summary:
    Trigger background synchronization of Volatility plugins.
    """
    try:
        from orochi.website.tasks import sync_volatility_plugins

        res = sync_volatility_plugins.enqueue()
        return Status(200, {"message": f"Plugin synchronization queued with task ID {res.id}"})
    except Exception as excp:
        return Status(400, {"errors": f"Failed to enqueue plugin sync: {excp}"})


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


@router.get(
    "/{str:name}/parameters",
    response={200: list[PluginParametersOutSchema], 400: ErrorsOut},
    auth=django_auth,
)
def get_plugin_parameters(request, name: str):
    """
    Summary:
    Retrieve parameters for a specific plugin.

    Explanation:
    Fetches the parameters associated with a plugin identified by its name. Returns the parameters if successful, otherwise returns an error response.

    Args:
    - request: The request object.
    - name: The name of the plugin.

    Returns:
    - List of PluginParametersOutSchema objects if successful, otherwise an ErrorsOut object with error details.
    """
    try:
        return Status(200, get_parameters(name))
    except Exception as excp:
        return Status(400, {"errors": str(excp)})


@router.put(
    "/{str:name}",
    response={200: PluginOutSchema, 400: ErrorsOut, 403: ErrorsOut},
    auth=django_auth,
)
@ninja_role_required(ROLE_ADMIN)
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
        return Status(400, {"errors": str(excp)})


@router.post(
    "/{str:name}/enable/{enable}",
    auth=django_auth,
    url_name="enable_plugin",
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
        return Status(
            200,
            {"message": (f"Plugin {name} enabled" if enable else f"Plugin {name} disabled")},
        )
    except Exception as excp:
        return Status(400, {"errors": str(excp)})


@router.get(
    "/{str:name}/source",
    auth=django_auth,
    url_name="get_plugin_source",
    response={200: PluginSourceOutSchema, 404: ErrorsOut},
)
def get_plugin_source(request, name: str):
    """
    Summary:
    Retrieve the Python source code of a plugin.
    """
    src_file, filename = find_plugin_file(name)
    if not src_file or not src_file.exists():
        return Status(404, {"errors": f"Source file for plugin '{name}' not found."})

    try:
        with open(src_file, encoding="utf-8", errors="replace") as f:
            content = f.read()
        return Status(200, {"name": name, "filename": filename or src_file.name, "source": content})
    except Exception as excp:
        return Status(404, {"errors": f"Failed to read source file: {excp}"})


@router.get(
    "/{str:name}/export",
    auth=django_auth,
    url_name="export_plugin",
    response={200: Any, 404: ErrorsOut},
)
def export_plugin(request, name: str):
    """
    Summary:
    Export and download the plugin Python source as a ZIP archive.
    """
    src_file, filename = find_plugin_file(name)
    if not src_file or not src_file.exists():
        return Status(404, {"errors": f"Source file for plugin '{name}' not found."})

    try:
        bio = io.BytesIO()
        with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.write(src_file, arcname=filename or src_file.name)
        bio.seek(0)
        safe_name = name.replace(".", "_")
        response = HttpResponse(bio.getvalue(), content_type="application/zip")
        response["Content-Disposition"] = f'attachment; filename="{safe_name}.zip"'
        return response
    except Exception as excp:
        return Status(404, {"errors": f"Failed to export plugin: {excp}"})


@router.delete(
    "/{str:name}",
    auth=django_auth,
    url_name="delete_plugin",
    response={200: SuccessResponse, 400: ErrorsOut, 403: ErrorsOut, 404: ErrorsOut},
)
@ninja_role_required(ROLE_ADMIN)
def delete_plugin(request, name: str):
    """
    Summary:
    Uninstall and delete a custom local plugin.

    Explanation:
    Removes the custom plugin Python source file from the server and connected Dask workers,
    and deletes its database records (Plugin, UserPlugin, Result).
    Built-in Volatility plugins cannot be deleted.
    """
    plugin = get_object_or_404(Plugin, name=name)
    if not plugin.local:
        return Status(
            400,
            {"errors": "Cannot delete built-in Volatility plugin. Only custom local plugins can be uninstalled."},
        )

    # Clean up local file(s)
    src_file, _ = find_plugin_file(name)
    if src_file and src_file.exists():
        try:
            src_file.unlink()
        except Exception as e:
            logger.warning(f"Failed to delete local plugin file {src_file}: {e}")

    # Clean up on Dask workers
    try:
        from distributed import Client

        def _worker_delete(p_name):
            from extra_settings.models import Setting

            folder = Path(Setting.get("VOLATILITY_PLUGIN_PATH"))
            stem = p_name.split(".")[-1].lower()
            for p in folder.rglob("*.py"):
                if p.stem.lower() == stem:
                    with contextlib.suppress(Exception):
                        p.unlink()

        client = Client(settings.DASK_SCHEDULER_URL, timeout="2s")
        client.run(_worker_delete, name)
        client.close()
    except Exception as e:
        logger.debug(f"Could not delete plugin on Dask workers: {e}")

    # Delete database records
    Result.objects.filter(plugin=plugin).delete()
    UserPlugin.objects.filter(plugin=plugin).delete()
    plugin.delete()

    return Status(200, {"message": f"Plugin '{name}' was uninstalled successfully."})
