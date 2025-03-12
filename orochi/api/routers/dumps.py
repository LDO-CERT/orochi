import json
import shlex
import shutil
from pathlib import Path
from typing import List, Optional
from urllib.request import pathname2url
from uuid import UUID, uuid1

from distributed import Client, fire_and_forget
from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import transaction
from django.shortcuts import get_object_or_404
from guardian.shortcuts import assign_perm, get_objects_for_user, get_perms, remove_perm
from ninja import File, PatchDict, Query, Router, UploadedFile
from ninja.security import django_auth

from orochi.api.filters import DumpFilters, OperatingSytemFilters
from orochi.api.models import (
    DumpEditIn,
    DumpIn,
    DumpInfoSchema,
    DumpSchema,
    ErrorsOut,
    ResultSmallOutSchema,
    SuccessResponse,
)
from orochi.utils.volatility_dask_elk import (
    check_runnable,
    get_banner,
    get_parameters,
    run_plugin,
)
from orochi.website.defaults import (
    DUMP_STATUS_COMPLETED,
    RESULT_STATUS_NOT_STARTED,
    RESULT_STATUS_RUNNING,
)
from orochi.website.models import Dump, Folder, Plugin, Result, UserPlugin, Value
from orochi.website.views import index_f_and_f

router = Router()


## UTILS
def plugin_f_and_f(dump, plugin, params, user_pk=None):
    """
    Summary:
    Asynchronously executes a plugin on a dump with specified parameters.

    Explanation:
    Submits a task to the Dask scheduler to run the specified plugin on the given dump with the provided parameters, without waiting for the result.

    Args:
    - dump: The dump object.
    - plugin: The plugin object.
    - params: A dictionary of parameters for the plugin.
    - user_pk: Optional primary key of the user initiating the execution.

    Returns:
    - None
    """
    dask_client = Client(settings.DASK_SCHEDULER_URL)
    fire_and_forget(dask_client.submit(run_plugin, dump, plugin, params, user_pk))


def handle_uploaded_file(index, plugin, f):
    """
    Summary:
    Handles the upload and storage of a file associated with a specific plugin and dump index.

    Explanation:
    Creates a directory for the plugin under the specified index within the media root if it doesn't exist, then saves the uploaded file to that directory.

    Args:
    - index: The index of the dump.
    - plugin: The name of the plugin.
    - f: The uploaded file object.

    Returns:
    - The full path to the saved file.
    """
    path = Path(f"{settings.MEDIA_ROOT}/{index}/{plugin}")
    if not path.exists():
        path.mkdir(parents=True, exist_ok=True)
    with open(f"{path}/{f}", "wb+") as destination:
        for chunk in f.chunks():
            destination.write(chunk)
    return f"{path}/{f}"


## UTILS FINE


@router.get("/", auth=django_auth, response=List[DumpSchema])
def list_dumps(request, filters: Query[OperatingSytemFilters]):
    """
    Summary:
    Retrieve a list of dumps based on optional operating system filters.

    Explanation:
    Returns a list of dumps accessible to the user, filtered by the specified operating system if provided and the user's permissions.

    Args:
    - request: The request object.
    - filters: Query object containing operating system filters.

    Returns:
    - List of DumpSchema objects representing the dumps that match the criteria.
    """
    dumps = (
        Dump.objects.all()
        if request.user.is_superuser
        else get_objects_for_user(request.user, "website.can_see")
    )
    if filters and filters.operating_system:
        dumps = [x for x in dumps if x.operating_system == filters.operating_system]
    return dumps


@router.delete(
    "/{pk}",
    auth=django_auth,
    url_name="delete_dump",
    response={200: SuccessResponse, 400: ErrorsOut},
)
def delete_dump(request, pk: UUID):
    """
    Deletes a dump identified by its primary key (pk). This function ensures that the user has permission to delete the dump before proceeding with the deletion.

    Args:
        request: The HTTP request object.
        pk (UUID): The primary key of the dump to be deleted.

    Returns:
        SuccessResponse: A response indicating the successful deletion of the dump.

    Raises:
        Http404: If the dump with the specified primary key does not exist.
        ErrorsOut: If the user does not have permission to delete the dump.

    Examples:
        DELETE /dumps/{pk}
    """
    try:
        dump = get_object_or_404(Dump, index=pk)
        name = dump.name
        if dump not in get_objects_for_user(request.user, "website.can_see"):
            return 400, {"errors": "Error during index deletion."}
        dump.delete()
        shutil.rmtree(f"{settings.MEDIA_ROOT}/{dump.index}")
        return 200, {"message": f"Index {name} has been deleted successfully."}
    except Exception as excp:
        return 400, {
            "errors": str(excp) if excp else "Generic error during dump deletion"
        }


@router.get("/{pk}", response={200: DumpInfoSchema, 400: ErrorsOut}, auth=django_auth)
def get_dump_info(request, pk: UUID):
    """
    Summary:
    Retrieve detailed information about a specific dump by its index.

    Explanation:
    Fetches the dump with the specified index and returns its information if the user has permission to view it; otherwise, returns a 403 Forbidden response.

    Args:
    - request: The request object.
    - pk: The UUID index of the dump to retrieve information for.

    Returns:
    - DumpInfoSchema object representing the detailed information of the dump.
    """
    dump = get_object_or_404(Dump, index=pk)
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return 400, {"errors": "Forbidden"}
    return 200, dump


@router.post(
    "/",
    url_name="create_index",
    response={200: DumpSchema, 400: ErrorsOut},
    auth=django_auth,
)
def create_dump(request, payload: DumpIn, upload: Optional[UploadedFile] = File(None)):
    """
    Creates a new dump index and handles the associated file uploads. This function processes the provided payload to create a dump entry in the database and manages file storage based on the input parameters.

    Args:
        request: The HTTP request object.
        payload (DumpIn): The data containing information about the dump to be created.
        upload (Optional[UploadedFile]): An optional file to be uploaded.

    Returns:
        DumpSchema: The created dump object.

    Raises:
        HttpResponse: Returns a 400 Bad Request response if an error occurs during the process.
    """

    try:
        if payload.folder:
            folder, _ = Folder.objects.get_or_create(
                name=payload.folder.name, user=request.user
            )
        else:
            folder = None
        dump_index = str(uuid1())
        Path(f"{settings.MEDIA_ROOT}/{dump_index}").mkdir()
        dump = Dump.objects.create(
            name=payload.name,
            color=payload.color,
            comment=payload.comment,
            operating_system=payload.operating_system,
            folder=folder,
            author=request.user,
            index=dump_index,
        )
        if payload.local_folder:
            start = payload.local_folder
            start = start.replace("/upload/upload", "/media/uploads")
            filename = payload.original_name or Path(start).name
            shutil.move(start, f"{settings.MEDIA_ROOT}/{dump_index}/{filename}")
            dump.upload.name = f"{settings.MEDIA_URL}{dump_index}/{filename}"
            move = False
        elif upload:
            dump.upload.save(Path(upload.name).name, upload)
            move = True
        else:
            return 400, {"errors": "Bad Request"}
        dump.save()
        Result.objects.bulk_create(
            [
                Result(
                    plugin=up.plugin,
                    dump=dump,
                    result=(
                        RESULT_STATUS_RUNNING
                        if up.automatic
                        else RESULT_STATUS_NOT_STARTED
                    ),
                )
                for up in UserPlugin.objects.filter(
                    plugin__operating_system__in=[
                        dump.operating_system,
                        "Other",
                    ],
                    user=request.user,
                    plugin__disabled=False,
                )
            ]
        )

        transaction.on_commit(
            lambda: index_f_and_f(
                dump.pk,
                request.user.pk,
                password=payload.password,
                restart=None,
                move=move,
            )
        )
        return dump
    except Exception as excp:
        return 400, {"errors": f"Bad Request ({excp})"}


@router.patch(
    "/{pk}",
    url_name="edit_index",
    response={200: DumpSchema, 400: ErrorsOut},
    auth=django_auth,
)
def edit_dump(request, pk: UUID, payload: PatchDict[DumpEditIn]):
    """
    Edits an existing dump based on the provided payload. This function updates the dump's attributes and manages user permissions for accessing the dump.

    Args:
        request: The HTTP request object.
        payload (PatchDict[DumpEditIn]): The data containing the updates to be applied to the dump.

    Returns:
        DumpSchema: The updated dump object.

    Raises:
        Http404: If the dump with the specified index does not exist.
        HttpResponse: If there is an error during the update process.

    Examples:
        PATCH /dumps/{pk}
    """

    try:
        dump = get_object_or_404(Dump, index=pk)
        if dump not in get_objects_for_user(request.user, "website.can_see"):
            return 403, {"message": "Unauthorized"}

        auth_users = [
            user.pk
            for user in get_user_model().objects.all()
            if "can_see" in get_perms(user, dump) and user != request.user
        ]

        if payload.get("folder"):
            folder, _ = Folder.objects.get_or_create(
                name=payload["folder"]["name"], user=request.user
            )
            dump.folder = folder

        for attr, value in payload.items():
            if attr not in ["authorized_users", "folder"]:
                setattr(dump, attr, value)
            else:
                for user_pk in payload.get("authorized_users", []):
                    user = get_user_model().objects.get(pk=user_pk)
                    if user.pk not in auth_users:
                        assign_perm("can_see", user, dump)
                for user_pk in auth_users:
                    if user_pk not in payload.get("authorized_users", []):
                        user = get_user_model().objects.get(pk=user_pk)
                        remove_perm("can_see", user, dump)
        dump.save()
        return dump
    except Exception as excp:
        return 400, {"errors": f"Bad Request ({excp})"}


@router.get(
    "/{idxs:pks}/plugins",
    url_name="dumps_plugins",
    response=List[ResultSmallOutSchema],
    auth=django_auth,
)
def get_dump_plugins(request, pks: List[UUID], filters: Query[DumpFilters] = None):
    """
    Summary:
    Retrieve a list of plugins associated with specified dumps.

    Explanation:
    Fetches the plugins related to the dumps identified by the provided list of UUIDs, considering user permissions, and optionally filters the results based on DumpFilters.

    Args:
    - request: The request object.
    - pks: List of UUIDs representing the indexes of the dumps to retrieve plugins for.
    - filters: Optional Query object containing dump filters.

    Returns:
    - List of ResultSmallOutSchema objects representing the plugins associated with the specified dumps.
    """
    dumps_ok = get_objects_for_user(request.user, "website.can_see")
    dumps = [
        dump.index for dump in Dump.objects.filter(index__in=pks) if dump in dumps_ok
    ]
    res = (
        Result.objects.select_related("dump", "plugin")
        .filter(dump__index__in=dumps)
        .order_by("plugin__name")
        .distinct()
        .values("plugin__name", "plugin__comment", "plugin__id")
    )
    if filters and filters.result:
        res = res.filter(result=filters.result)
    return res


@router.post(
    "/{idxs:pks}/plugin/{str:plugin_name}/execute",
    url_name="dumps_plugin_execute",
    response={200: SuccessResponse, 400: ErrorsOut},
    auth=django_auth,
)
def dumps_plugin_execute(request, pks: List[UUID], plugin_name: str):
    try:
        dumps_ok = get_objects_for_user(request.user, "website.can_see")
        dumps = [
            dump for dump in Dump.objects.filter(index__in=pks) if dump in dumps_ok
        ]
        plugin = get_object_or_404(Plugin, name=plugin_name)
        get_object_or_404(UserPlugin, plugin=plugin, user=request.user)
        for dump in dumps:
            result = get_object_or_404(Result, dump=dump, plugin=plugin)
            params = {}

            parameters = get_parameters(plugin.name)
            payload = json.loads(request.POST["payload"])
            for parameter in parameters:
                if parameter["name"] in payload.keys():
                    name = parameter["name"]
                    name_value = payload.get(name)
                    if parameter["mode"] == "list":
                        value = shlex.shlex(name_value, posix=True)
                        value.whitespace += ","
                        value.whitespace_split = True
                        value = list(value)
                        if parameter["type"] == "int":
                            value = [int(x) for x in value]
                        params[name] = value

                    elif parameter["type"] == "bool":
                        params[name] = name_value in ["true", "on"]

                    else:
                        params[name] = name_value
            for filename in request.FILES:
                filepath = handle_uploaded_file(
                    dump.index, plugin.name, request.FILES.get(filename)
                )
                params[filename] = f"file:{pathname2url(filepath)}"

            # REMOVE OLD DATA
            result.result = RESULT_STATUS_RUNNING
            result.description = None
            result.parameter = params
            result.save()
            Value.objects.filter(result=result).delete()

            plugin_f_and_f(dump, plugin, params, request.user.pk)
        return 200, {
            "message": f"Plugin {plugin.name} resubmitted on {', '.join([x.name for x in dumps])}."
        }
    except Exception as excp:
        return 400, {"errors": f"Bad Request ({excp})"}


@router.get(
    "/{idxs:pks}/plugin/{str:plugin_name}",
    url_name="dumps_plugin_status",
    auth=django_auth,
)
def get_dump_plugin_status(request, pks: List[UUID], plugin_name: str):
    """
    Retrieve the status of a specific plugin for a list of dumps. This function checks the user's permissions and returns the relevant results based on the provided dump indices and plugin name.

    Args:
        request: The HTTP request object.
        pks (List[UUID]): A list of UUIDs representing the dump indices.
        plugin_name (str): The name of the plugin to filter results by.

    Returns:
        QuerySet: A queryset containing the results related to the specified dumps and plugin.

    Raises:
        PermissionDenied: If the user does not have permission to view the dumps.
    """
    dumps_ok = get_objects_for_user(request.user, "website.can_see")
    dumps = [
        dump.index for dump in Dump.objects.filter(index__in=pks) if dump in dumps_ok
    ]
    return Result.objects.select_related("dump", "plugin").filter(
        dump__index__in=dumps, plugin__name=plugin_name
    )


@router.get(
    "/{pk}/reload_symbols",
    url_name="reload_symbols",
    auth=django_auth,
    response={200: SuccessResponse, 400: ErrorsOut},
)
def reload_symbols(request, pk: UUID):
    """
    Reload the symbols for a specific dump identified by its primary key. This function checks user permissions, attempts to reload the banner if necessary, and updates the dump's status accordingly.

    Args:
        request: The HTTP request object.
        pk (UUID): The primary key of the dump to reload symbols for.

    Returns:
        Tuple[int, dict]: A tuple containing the HTTP status code and a message indicating the result of the operation.

    Raises:
        Http404: If the dump with the specified primary key does not exist.
    """
    try:
        dump = get_object_or_404(Dump, index=pk)
        if dump not in get_objects_for_user(request.user, "website.can_see"):
            return 403, {"message": "Unauthorized"}

        # Try to reload banner from elastic if first time was not successful
        if not dump.banner:
            banner = dump.result_set.get(plugin__name="banners.Banners")
            if banner_result := get_banner(banner):
                dump.banner = banner_result.strip("\"'")
                dump.save()

        if check_runnable(dump.pk, dump.operating_system, dump.banner):
            dump.status = DUMP_STATUS_COMPLETED
            dump.save()
        return 200, {"message": f"Symbol for index {dump.name} has been reloaded."}
    except Exception as excp:
        return 400, {"errors": f"Bad Request ({excp})"}
