import json
import shlex
import shutil
from pathlib import Path
from urllib.request import pathname2url
from uuid import UUID, uuid1

from distributed import Client, fire_and_forget
from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import transaction
from django.db.models import Exists, OuterRef, Q
from django.shortcuts import get_object_or_404
from guardian.shortcuts import assign_perm, get_objects_for_user, get_perms, remove_perm
from ninja import File, PatchDict, Query, Router, Status, UploadedFile
from ninja.security import django_auth

from orochi.api.filters import DumpFilters, OperatingSytemFilters
from orochi.api.models import (
    DumpEditIn,
    DumpIn,
    DumpInfoSchema,
    DumpNarrativeOut,
    DumpSchema,
    DumpSecretOut,
    ErrorsOut,
    PromoteFindingIn,
    ResultSmallOutSchema,
    SuccessResponse,
    TimelineReportOut,
    TriageReportOut,
    ValueAnnotationIn,
    ValueAnnotationOut,
)
from orochi.utils.timeliner import build_timeline_feed, extract_timeline_entries
from orochi.utils.volatility_dask_elk import (
    check_runnable,
    get_banner,
    get_parameters,
    run_plugin,
)
from orochi.website.ai_narrative import generate_dump_narrative
from orochi.website.defaults import (
    DUMP_STATUS_COMPLETED,
    RESULT_STATUS_NOT_STARTED,
    RESULT_STATUS_RUNNING,
    RESULT_STATUS_SUCCESS,
)
from orochi.website.detection.engine import evaluate_dump_triage
from orochi.website.models import (
    Bookmark,
    Case,
    Dump,
    DumpSecret,
    Evidence,
    Finding,
    Folder,
    Plugin,
    Result,
    TriageFinding,
    UserPlugin,
    Value,
    ValueAnnotation,
)
from orochi.website.roles import (
    ROLE_ANALYST,
    ROLE_HIERARCHY,
    ROLE_READONLY,
    can_execute_plugin,
    get_user_role,
    has_role,
)
from orochi.website.secrets_scanner import scan_dump_for_secrets
from orochi.website.views import index_f_and_f, is_not_readonly

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


@router.get("/", auth=django_auth, response=list[DumpSchema])
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
    dumps = Dump.objects.all() if request.user.is_superuser else get_objects_for_user(request.user, "website.can_see")

    if filters and filters.operating_system:
        # get_objects_for_user returns a QuerySet which we can filter directly
        dumps = dumps.filter(operating_system=filters.operating_system)

    has_auto_plugins = UserPlugin.objects.filter(
        user=request.user,
        automatic=True,
        plugin__operating_system__in=[OuterRef("operating_system"), "Other"],
        plugin__disabled=False,
    )
    dumps = dumps.annotate(has_auto=Exists(has_auto_plugins))

    return dumps


@router.post(
    "/promote_finding",
    response={201: SuccessResponse, 400: ErrorsOut, 403: ErrorsOut, 404: ErrorsOut},
    auth=django_auth,
    url_name="api_promote_finding",
)
def api_promote_finding(request, payload: PromoteFindingIn):
    """
    Promote a DumpSecret or TriageFinding to a Case Finding.
    """
    if not is_not_readonly(request.user):
        return Status(403, {"errors": "Read-only users cannot promote findings."})

    if payload.new_case_name and payload.new_case_name.strip():
        case, _ = Case.objects.get_or_create(
            name=payload.new_case_name.strip(),
            user=request.user,
        )
    elif payload.case_id:
        try:
            case = Case.objects.get(
                Q(user=request.user) | Q(collaborators=request.user),
                pk=payload.case_id,
            )
        except Case.DoesNotExist:
            return Status(404, {"errors": "Case not found or access denied."})
    else:
        return Status(400, {"errors": "Either case_id or new_case_name must be provided."})

    evidence = None
    if payload.item_type == "secret":
        try:
            secret = DumpSecret.objects.get(pk=payload.item_id)
        except DumpSecret.DoesNotExist:
            return Status(404, {"errors": "Secret not found."})
        if secret.dump not in get_objects_for_user(request.user, "website.can_see"):
            return Status(403, {"errors": "Unauthorized to access this dump."})
        evidence = Evidence.objects.create(
            case=case,
            dump=secret.dump,
            plugin="secrets_scanner",
            name=f"Secret: {secret.rule_name}"[:250],
            description=secret.masked_data,
        )
    elif payload.item_type == "triage":
        try:
            tf = TriageFinding.objects.get(pk=payload.item_id)
        except TriageFinding.DoesNotExist:
            return Status(404, {"errors": "Triage finding not found."})
        if tf.dump not in get_objects_for_user(request.user, "website.can_see"):
            return Status(403, {"errors": "Unauthorized to access this dump."})
        evidence = Evidence.objects.create(
            case=case,
            dump=tf.dump,
            plugin=tf.category,
            result_row=tf.raw_data,
            name=f"Triage: {tf.rule_name}"[:250],
            description=tf.description,
        )
    else:
        return Status(
            400,
            {"errors": f"Invalid item_type '{payload.item_type}'. Must be 'secret' or 'triage'."},
        )

    finding = Finding.objects.create(
        case=case,
        evidence=evidence,
        severity=payload.severity or "Medium",
        mitre_attack_technique=payload.mitre_technique or "",
        note=payload.note or "",
        tags=payload.tags or [],
    )
    return Status(
        201,
        {"message": f"Successfully promoted to finding #{finding.id} in case '{case.name}'."},
    )


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
        if not has_role(request.user, ROLE_ANALYST):
            return Status(
                400,
                {"errors": "Permission Denied: Only Analysts and Admins can delete dumps."},
            )
        dump = get_object_or_404(Dump, index=pk)
        name = dump.name
        if dump not in get_objects_for_user(request.user, "website.can_see"):
            return Status(400, {"errors": "Error during index deletion."})
        Bookmark.objects.filter(indexes=dump).delete()
        dump.result_set.all().delete()
        dump.delete()
        shutil.rmtree(f"{settings.MEDIA_ROOT}/{dump.index}", ignore_errors=True)
        return Status(200, {"message": f"Index {name} has been deleted successfully."})
    except Exception as excp:
        return Status(
            400,
            {"errors": str(excp) if excp else "Generic error during dump deletion"},
        )


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
        return Status(400, {"errors": "Forbidden"})
    return Status(200, dump)


@router.post(
    "/",
    url_name="create_index",
    response={200: DumpSchema, 400: ErrorsOut},
    auth=django_auth,
)
def create_dump(request, payload: DumpIn, upload: UploadedFile | None = File(None)):
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
        if not has_role(request.user, ROLE_ANALYST):
            return Status(
                400,
                {"errors": "Permission Denied: Only Analysts and Admins can upload dumps."},
            )
        if getattr(payload, "folder", None):
            folder_val = str(payload.folder).strip()
            folder = Folder.objects.filter(name=folder_val, user=request.user).first()
            if not folder and folder_val.isdigit():
                folder = Folder.objects.filter(id=int(folder_val), user=request.user).first()
            if not folder:
                folder, _ = Folder.objects.get_or_create(name=folder_val, user=request.user)
        else:
            folder = None

        if getattr(payload, "host", None):
            from orochi.website.models import Host

            host_val = str(payload.host).strip()
            host_obj = Host.objects.filter(name=host_val).first()
            if not host_obj and host_val.isdigit():
                host_obj = Host.objects.filter(id=int(host_val)).first()
            if not host_obj:
                host_obj, _ = Host.objects.get_or_create(name=host_val)
        else:
            host_obj = None
        dump_index = str(uuid1())
        Path(f"{settings.MEDIA_ROOT}/{dump_index}").mkdir()
        dump = Dump.objects.create(
            name=payload.name,
            color=payload.color,
            comment=payload.comment,
            operating_system=payload.operating_system,
            folder=folder,
            host=host_obj,
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
            return Status(400, {"errors": "Bad Request"})
        dump.save()
        Result.objects.bulk_create(
            [
                Result(
                    plugin=up.plugin,
                    dump=dump,
                    result=(
                        RESULT_STATUS_RUNNING
                        if up.automatic and can_execute_plugin(request.user, up.plugin)
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
        return Status(400, {"errors": f"Bad Request ({excp})"})


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
            return Status(403, {"message": "Unauthorized"})

        auth_users = [
            user.pk
            for user in get_user_model().objects.all()
            if "can_see" in get_perms(user, dump) and user != request.user
        ]

        if "folder" in payload:
            if folder_val := payload.get("folder"):
                folder_val = str(folder_val).strip()
                folder = Folder.objects.filter(name=folder_val, user=request.user).first()
                if not folder and folder_val.isdigit():
                    folder = Folder.objects.filter(id=int(folder_val), user=request.user).first()
                if not folder:
                    folder, _ = Folder.objects.get_or_create(name=folder_val, user=request.user)
                dump.folder = folder
            else:
                dump.folder = None

        if "host" in payload:
            if host_val := payload.get("host"):
                from orochi.website.models import Host

                host_val = str(host_val).strip()
                host_obj = Host.objects.filter(name=host_val).first()
                if not host_obj and host_val.isdigit():
                    host_obj = Host.objects.filter(id=int(host_val)).first()
                if not host_obj:
                    host_obj, _ = Host.objects.get_or_create(name=host_val)
                dump.host = host_obj
            else:
                dump.host = None

        for attr, value in payload.items():
            if attr not in ["authorized_users", "folder", "host"]:
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
        return Status(400, {"errors": f"Bad Request ({excp})"})


@router.get(
    "/{idxs:pks}/plugins",
    url_name="dumps_plugins",
    response=list[ResultSmallOutSchema],
    auth=django_auth,
)
def get_dump_plugins(request, pks: list[UUID], filters: Query[DumpFilters] = None):
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
    dumps = [dump.index for dump in Dump.objects.filter(index__in=pks) if dump in dumps_ok]
    res = (
        Result.objects.select_related("dump", "plugin")
        .filter(dump__index__in=dumps)
        .order_by("plugin__name")
        .distinct()
        .values(
            "plugin__name",
            "plugin__comment",
            "plugin__id",
            "plugin__min_role",
            "plugin__disabled",
        )
    )
    if filters and filters.result:
        res = res.filter(result=filters.result)

    plugin_pks = [item["plugin__id"] for item in res]
    user_plugins = {
        up.plugin_id: up.can_execute for up in UserPlugin.objects.filter(user=request.user, plugin_id__in=plugin_pks)
    }
    user_role = get_user_role(request.user)
    is_super = getattr(request.user, "is_superuser", False)
    user_level = ROLE_HIERARCHY.get(user_role, 0)

    output = []
    for item in res:
        min_role = item.get("plugin__min_role") or ROLE_ANALYST
        plugin_id = item["plugin__id"]
        override = user_plugins.get(plugin_id)
        if item.get("plugin__disabled", False):
            can_exec = False
        elif is_super:
            can_exec = True
        elif user_role == ROLE_READONLY:
            can_exec = False
        elif override is not None:
            can_exec = bool(override)
        else:
            can_exec = user_level >= ROLE_HIERARCHY.get(min_role, 30)

        output.append(
            {
                "plugin__name": item["plugin__name"],
                "plugin__comment": item["plugin__comment"],
                "plugin__id": item["plugin__id"],
                "min_role": min_role,
                "can_execute": can_exec,
            }
        )
    return output


@router.post(
    "/{idxs:pks}/plugin/{str:plugin_name}/execute",
    url_name="dumps_plugin_execute",
    response={200: SuccessResponse, 400: ErrorsOut, 403: ErrorsOut},
    auth=django_auth,
)
def dumps_plugin_execute(request, pks: list[UUID], plugin_name: str):
    try:
        plugin = get_object_or_404(Plugin, name=plugin_name)
        if not can_execute_plugin(request.user, plugin):
            return Status(
                403,
                {"errors": f"Permission Denied: You do not have permission to execute plugin '{plugin.name}'."},
            )
        dumps_ok = get_objects_for_user(request.user, "website.can_see")
        dumps = [dump for dump in Dump.objects.filter(index__in=pks) if dump in dumps_ok]
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
                filepath = handle_uploaded_file(dump.index, plugin.name, request.FILES.get(filename))
                params[filename] = f"file:{pathname2url(filepath)}"

            # REMOVE OLD DATA
            result.result = RESULT_STATUS_RUNNING
            result.description = None
            result.parameter = params
            result.save()
            Value.objects.filter(result=result).delete()

            plugin_f_and_f(dump, plugin, params, request.user.pk)
        return Status(
            200,
            {"message": f"Plugin {plugin.name} resubmitted on {', '.join([x.name for x in dumps])}."},
        )
    except Exception as excp:
        return Status(400, {"errors": f"Bad Request ({excp})"})


@router.get(
    "/{idxs:pks}/plugin/{str:plugin_name}",
    url_name="dumps_plugin_status",
    auth=django_auth,
)
def get_dump_plugin_status(request, pks: list[UUID], plugin_name: str):
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
    dumps = [dump.index for dump in Dump.objects.filter(index__in=pks) if dump in dumps_ok]
    return Result.objects.select_related("dump", "plugin").filter(dump__index__in=dumps, plugin__name=plugin_name)


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
            return Status(403, {"message": "Unauthorized"})

        # Try to reload banner from elastic if first time was not successful
        if not dump.banner:
            banner = dump.result_set.get(plugin__name="banners.Banners")
            if banner_result := get_banner(banner):
                dump.banner = banner_result.strip("\"'")
                dump.save()

        if check_runnable(dump.pk, dump.operating_system, dump.banner):
            dump.status = DUMP_STATUS_COMPLETED
            dump.save()
        return Status(200, {"message": f"Symbol for index {dump.name} has been reloaded."})
    except Exception as excp:
        return Status(400, {"errors": f"Bad Request ({excp})"})


@router.get(
    "/temporal_diff/{index_a}/{index_b}",
    url_name="dump_temporal_diff",
    auth=django_auth,
    response={200: dict, 403: dict, 404: dict},
)
def dump_temporal_diff(request, index_a: str, index_b: str, reverse: bool = False):
    """
    Summary:
    Compute temporal delta (processes, injected regions, connections, common plugins)
    between two memory dumps (same host T1 vs T2).
    """
    dump_a = Dump.objects.filter(index=index_a).first()
    dump_b = Dump.objects.filter(index=index_b).first()
    if not dump_a or not dump_b:
        return Status(404, {"message": "Dump not found"})

    user_dumps = get_objects_for_user(request.user, "website.can_see")
    if dump_a not in user_dumps or dump_b not in user_dumps:
        return Status(403, {"message": "Unauthorized"})

    from orochi.website.temporal import compute_temporal_diff

    diff_data = compute_temporal_diff(dump_a, dump_b, reverse=reverse)

    t1 = diff_data["t1"]
    t2 = diff_data["t2"]
    meta = diff_data["meta"]

    response_data = {
        "meta": {
            "is_same_host": meta["is_same_host"],
            "host_name": meta["host_name"],
            "time_delta_display": meta["time_delta_display"],
            "delta_seconds": meta["delta_seconds"],
            "is_reversed": meta["is_reversed"],
        },
        "t1": {
            "name": t1.name,
            "index": t1.index,
            "created_at": t1.created_at.isoformat() if t1.created_at else None,
            "operating_system": t1.operating_system,
            "color": t1.color,
            "host": t1.host.name if t1.host else None,
        },
        "t2": {
            "name": t2.name,
            "index": t2.index,
            "created_at": t2.created_at.isoformat() if t2.created_at else None,
            "operating_system": t2.operating_system,
            "color": t2.color,
            "host": t2.host.name if t2.host else None,
        },
        "summary": diff_data["summary"],
        "processes": {
            "available": diff_data["processes"]["available"],
            "plugin_t1": diff_data["processes"]["plugin_t1"],
            "plugin_t2": diff_data["processes"]["plugin_t2"],
            "total_t1": diff_data["processes"]["total_t1"],
            "total_t2": diff_data["processes"]["total_t2"],
            "new_count": diff_data["processes"]["new_count"],
            "terminated_count": diff_data["processes"]["terminated_count"],
            "persisted_count": diff_data["processes"]["persisted_count"],
            "new": diff_data["processes"]["new"],
            "terminated": diff_data["processes"]["terminated"],
            "persisted": diff_data["processes"]["persisted"],
        },
        "injected": {
            "available": diff_data["injected"]["available"],
            "plugin_t1": diff_data["injected"]["plugin_t1"],
            "plugin_t2": diff_data["injected"]["plugin_t2"],
            "total_t1": diff_data["injected"]["total_t1"],
            "total_t2": diff_data["injected"]["total_t2"],
            "new_count": diff_data["injected"]["new_count"],
            "terminated_count": diff_data["injected"]["terminated_count"],
            "persisted_count": diff_data["injected"]["persisted_count"],
            "new": diff_data["injected"]["new"],
            "terminated": diff_data["injected"]["terminated"],
            "persisted": diff_data["injected"]["persisted"],
        },
        "network": {
            "available": diff_data["network"]["available"],
            "plugin_t1": diff_data["network"]["plugin_t1"],
            "plugin_t2": diff_data["network"]["plugin_t2"],
            "total_t1": diff_data["network"]["total_t1"],
            "total_t2": diff_data["network"]["total_t2"],
            "new_count": diff_data["network"]["new_count"],
            "closed_count": diff_data["network"]["closed_count"],
            "persisted_count": diff_data["network"]["persisted_count"],
            "new": diff_data["network"]["new"],
            "closed": diff_data["network"]["closed"],
            "persisted": diff_data["network"]["persisted"],
        },
        "common_plugins": diff_data["common_plugins"],
    }
    return Status(200, response_data)


@router.get(
    "/values/{int:value_id}/annotations",
    response={200: list[ValueAnnotationOut], 403: ErrorsOut, 404: ErrorsOut},
    auth=django_auth,
    url_name="get_value_annotations",
)
def get_value_annotations(request, value_id: int):
    """
    Get all annotations for a specific Value row.
    """
    try:
        val = Value.objects.select_related("result__dump").get(pk=value_id)
    except Value.DoesNotExist:
        return Status(404, {"errors": "Value not found."})

    dump = val.result.dump
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return Status(403, {"errors": "Unauthorized to view annotations for this dump."})

    annotations = val.annotations.select_related("user").all()
    return Status(
        200,
        [
            {
                "id": a.id,
                "value_id": a.value_id,
                "user": a.user.username,
                "status": a.status,
                "comment": a.comment,
                "created_at": a.created_at.isoformat(),
            }
            for a in annotations
        ],
    )


@router.post(
    "/values/{int:value_id}/annotations",
    response={201: ValueAnnotationOut, 400: ErrorsOut, 403: ErrorsOut, 404: ErrorsOut},
    auth=django_auth,
    url_name="create_value_annotation",
)
def create_value_annotation(request, value_id: int, payload: ValueAnnotationIn):
    """
    Create a new annotation for a specific Value row.
    """
    if not is_not_readonly(request.user):
        return Status(403, {"errors": "Read-only users cannot add annotations."})

    try:
        val = Value.objects.select_related("result__dump").get(pk=value_id)
    except Value.DoesNotExist:
        return Status(404, {"errors": "Value not found."})

    dump = val.result.dump
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return Status(403, {"errors": "Unauthorized to view annotations for this dump."})

    if not payload.comment or not payload.comment.strip():
        return Status(400, {"errors": "Comment cannot be empty."})

    valid_statuses = [choice[0] for choice in ValueAnnotation.STATUS_CHOICES]
    if payload.status not in valid_statuses:
        return Status(
            400,
            {"errors": f"Invalid status '{payload.status}'. Valid choices: {valid_statuses}."},
        )

    annotation = ValueAnnotation.objects.create(
        value=val,
        user=request.user,
        status=payload.status,
        comment=payload.comment.strip(),
    )
    return Status(
        201,
        {
            "id": annotation.id,
            "value_id": annotation.value_id,
            "user": annotation.user.username,
            "status": annotation.status,
            "comment": annotation.comment,
            "created_at": annotation.created_at.isoformat(),
        },
    )


@router.delete(
    "/annotations/{int:annotation_id}",
    response={200: SuccessResponse, 403: ErrorsOut, 404: ErrorsOut},
    auth=django_auth,
    url_name="delete_value_annotation",
)
def delete_value_annotation_api(request, annotation_id: int):
    """
    Delete an annotation by ID (author or superuser only).
    """
    if not is_not_readonly(request.user):
        return Status(403, {"errors": "Read-only users cannot delete annotations."})

    try:
        annotation = ValueAnnotation.objects.get(pk=annotation_id)
    except ValueAnnotation.DoesNotExist:
        return Status(404, {"errors": "Annotation not found."})

    if annotation.user != request.user and not request.user.is_superuser:
        return Status(403, {"errors": "Cannot delete another user's annotation."})

    annotation.delete()
    return Status(200, {"message": f"Annotation {annotation_id} deleted successfully."})


###################################################
# Secrets & Detection Triage Endpoints
###################################################
def _serialize_secrets(secrets):
    return [
        {
            "id": s.id,
            "category": s.category,
            "category_display": s.get_category_display(),
            "rule_name": s.rule_name,
            "masked_data": s.masked_data,
            "offset": s.offset,
            "pid": s.pid,
            "process_name": s.process_name,
            "created_at": s.created_at.isoformat() if s.created_at else "",
        }
        for s in secrets
    ]


def _build_triage_report(dump):
    findings = dump.triage_findings.all()
    severity_counts = {
        "Critical": findings.filter(severity="Critical").count(),
        "High": findings.filter(severity="High").count(),
        "Medium": findings.filter(severity="Medium").count(),
        "Low": findings.filter(severity="Low").count(),
        "Info": findings.filter(severity="Info").count(),
    }
    if dump.risk_score >= 75:
        risk_level = "Critical"
    elif dump.risk_score >= 50:
        risk_level = "High"
    elif dump.risk_score >= 25:
        risk_level = "Medium"
    elif dump.risk_score > 0:
        risk_level = "Low"
    else:
        risk_level = "Clean"

    mitre_techniques = sorted({f.mitre_technique for f in findings if f.mitre_technique})
    return {
        "dump_index": str(dump.index),
        "dump_name": dump.name,
        "risk_score": dump.risk_score,
        "risk_level": risk_level,
        "total_findings": findings.count(),
        "severity_counts": severity_counts,
        "mitre_techniques": mitre_techniques,
        "findings": [
            {
                "id": f.id,
                "rule_id": f.rule_id,
                "rule_name": f.rule_name,
                "category": f.category,
                "severity": f.severity,
                "score": f.score,
                "mitre_technique": f.mitre_technique,
                "description": f.description,
                "evidence_snippet": f.evidence_snippet,
                "entity": f.entity,
                "created_at": f.created_at.isoformat() if f.created_at else "",
            }
            for f in findings
        ],
    }


@router.get(
    "/{str:index}/secrets",
    response={200: list[DumpSecretOut], 403: ErrorsOut, 404: ErrorsOut},
    auth=django_auth,
    url_name="get_dump_secrets",
)
def get_dump_secrets(request, index: str):
    """
    Get all detected secrets for a specific memory dump.
    """
    dump = get_object_or_404(Dump, index=index)
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return Status(403, {"errors": "Unauthorized to view this dump."})

    secrets = dump.secrets.all()
    return Status(200, _serialize_secrets(secrets))


@router.post(
    "/{str:index}/secrets/scan",
    response={200: list[DumpSecretOut], 403: ErrorsOut, 404: ErrorsOut},
    auth=django_auth,
    url_name="scan_dump_secrets",
)
def scan_dump_secrets(request, index: str):
    """
    Trigger a fresh YARA-X secrets scan over the dump's memory and parsed values.
    """
    dump = get_object_or_404(Dump, index=index)
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return Status(403, {"errors": "Unauthorized to view this dump."})
    if not is_not_readonly(request.user):
        return Status(403, {"errors": "Read-only users cannot run secrets scanner."})

    scan_dump_for_secrets(dump)
    secrets = dump.secrets.all()
    return Status(200, _serialize_secrets(secrets))


@router.get(
    "/{str:index}/triage",
    response={200: TriageReportOut, 403: ErrorsOut, 404: ErrorsOut},
    auth=django_auth,
    url_name="get_dump_triage",
)
def get_dump_triage(request, index: str):
    """
    Get the forensic behavioral triage report and findings for a memory dump.
    """
    dump = get_object_or_404(Dump, index=index)
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return Status(403, {"errors": "Unauthorized to view this dump."})

    report = _build_triage_report(dump)
    return Status(200, report)


@router.post(
    "/{str:index}/triage/evaluate",
    response={200: TriageReportOut, 403: ErrorsOut, 404: ErrorsOut},
    auth=django_auth,
    url_name="evaluate_dump_triage",
)
def evaluate_dump_triage_api(request, index: str):
    """
    Re-evaluate behavioral forensic detection rules over structured plugin outputs.
    """
    dump = get_object_or_404(Dump, index=index)
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return Status(403, {"errors": "Unauthorized to view this dump."})
    if not is_not_readonly(request.user):
        return Status(403, {"errors": "Read-only users cannot run triage evaluation."})

    evaluate_dump_triage(dump)
    dump.refresh_from_db()
    report = _build_triage_report(dump)
    return Status(200, report)


@router.get(
    "/{str:index}/timeline",
    response={200: TimelineReportOut, 403: ErrorsOut, 404: ErrorsOut},
    auth=django_auth,
    url_name="get_dump_timeline",
)
def get_dump_timeline(request, index: str, limit: int = 5000):
    """
    Get structured forensic timeline feed, activity histogram, and category metrics for a memory dump.
    """
    dump = get_object_or_404(Dump, index=index)
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return Status(403, {"errors": "Unauthorized to view this dump."})

    res = Result.objects.filter(dump=dump, plugin__name="timeliner.Timeliner", result=RESULT_STATUS_SUCCESS).first()

    timeline_entries = []
    if res:
        dump_bodyfile_path = Path(res.dump.upload.path).parent / "timeliner.Timeliner/volatility.body"
        if dump_bodyfile_path.exists():
            timeline_entries = extract_timeline_entries(
                file_path=dump_bodyfile_path,
                dump_name=dump.name,
                dump_index=dump.index,
                dump_color=dump.color or "#3b82f6",
            )
        elif db_vals := list(Value.objects.filter(result=res)):
            timeline_entries = extract_timeline_entries(
                values=db_vals,
                dump_name=dump.name,
                dump_index=dump.index,
                dump_color=dump.color or "#3b82f6",
            )

    triage_findings = list(dump.triage_findings.all())
    dump_secrets = list(dump.secrets.all())
    feed = build_timeline_feed(
        timeline_entries,
        limit=limit,
        threat_findings=triage_findings,
        secrets=dump_secrets,
    )
    return Status(
        200,
        {
            "dump_index": dump.index,
            "dump_name": dump.name,
            "stats": feed["stats"],
            "categories": feed["categories"],
            "histogram": feed["histogram"],
            "events": feed["events"],
        },
    )


@router.get(
    "/{str:index}/narrative",
    response={200: DumpNarrativeOut, 403: ErrorsOut, 404: ErrorsOut},
    auth=django_auth,
    url_name="get_dump_narrative",
)
def get_dump_narrative(request, index: str):
    """
    Retrieve the latest AI first-pass forensic triage narrative for a memory dump.
    """
    dump = get_object_or_404(Dump, index=index)
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return Status(403, {"errors": "Unauthorized to view this dump."})

    if narrative := dump.narratives.first():
        return Status(
            200,
            {
                "id": narrative.pk,
                "dump_index": dump.index,
                "dump_name": dump.name,
                "model_name": narrative.model_name,
                "created_at": narrative.created_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
                "evidence_hash": narrative.evidence_hash,
                "raw_narrative": narrative.raw_narrative,
                "formatted_narrative": narrative.formatted_narrative,
                "hallucination_check": narrative.hallucination_check,
                "citations": narrative.citations,
            },
        )
    else:
        return Status(404, {"errors": "No AI narrative generated yet for this dump."})


@router.post(
    "/{str:index}/narrative/generate",
    response={201: DumpNarrativeOut, 400: ErrorsOut, 403: ErrorsOut, 404: ErrorsOut},
    auth=django_auth,
    url_name="generate_dump_narrative",
)
def api_generate_dump_narrative(request, index: str, model_name: str | None = Query(None)):
    """
    Generate a new natural-language first-pass triage narrative with local Ollama inference and forensic guardrail verification.
    """
    dump = get_object_or_404(Dump, index=index)
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return Status(403, {"errors": "Unauthorized to view this dump."})

    from orochi.website.roles import ROLE_READONLY, get_user_role

    if get_user_role(request.user) == ROLE_READONLY:
        return Status(403, {"errors": "Read-only users cannot generate AI narratives."})

    try:
        narrative = generate_dump_narrative(dump, author=request.user, model_name=model_name)
    except Exception as e:
        return Status(400, {"errors": f"Failed to generate narrative: {str(e)}"})

    return Status(
        201,
        {
            "id": narrative.pk,
            "dump_index": dump.index,
            "dump_name": dump.name,
            "model_name": narrative.model_name,
            "created_at": narrative.created_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "evidence_hash": narrative.evidence_hash,
            "raw_narrative": narrative.raw_narrative,
            "formatted_narrative": narrative.formatted_narrative,
            "hallucination_check": narrative.hallucination_check,
            "citations": narrative.citations,
        },
    )
