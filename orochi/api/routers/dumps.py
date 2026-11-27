import json
import logging
import shlex
import shutil
from pathlib import Path
from urllib.request import pathname2url
from uuid import uuid1

from distributed import fire_and_forget
from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import transaction
from django.db.models import Count, Exists, OuterRef
from django.http import Http404
from django.shortcuts import get_object_or_404
from guardian.shortcuts import assign_perm, get_objects_for_user, get_perms, remove_perm
from ninja import File, PatchDict, Query, Router, Status, UploadedFile

from orochi.api.filters import DumpFilters, OperatingSytemFilters
from orochi.api.models import (
    DumpEditIn,
    DumpIn,
    DumpInfoSchema,
    DumpPluginStatusSchema,
    DumpSchema,
    ErrorsOut,
    IntegrityCheckOut,
    PromoteFindingIn,
    RecycledDumpOut,
    ResultRunOut,
    ResultSmallOutSchema,
    SuccessResponse,
    SymbolsBannerIn,
)
from orochi.api.permissions import ninja_test_required
from orochi.api.security import dual_auth
from orochi.backends.dask_client import get_dask_client
from orochi.utils.volatility_dask_elk import (
    check_runnable,
    get_banner,
    get_parameters,
    run_plugin,
)
from orochi.website.defaults import (
    DUMP_STATUS_COMPLETED,
    RESULT_STATUS_DISABLED,
    RESULT_STATUS_NOT_STARTED,
    RESULT_STATUS_RUNNING,
    SymbolStatus,
)
from orochi.website.models import (
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
)
from orochi.website.recycle_bin import deleted_dumps, purge, purge_at, retention_days, schedule_purge
from orochi.website.roles import (
    ROLE_ANALYST,
    ROLE_HIERARCHY,
    ROLE_READONLY,
    can_execute_plugin,
    get_user_role,
    has_role,
)
from orochi.website.storage import allowed_upload_source_roots, resolve_path_within, sanitize_filename
from orochi.website.views import index_f_and_f, is_not_readonly

router = Router()


## UTILS
def plugin_f_and_f(dump, plugin, params, user_pk=None, priority: int = 0, dask_client=None):
    """
    Summary:
    Asynchronously executes a plugin on a dump with specified parameters and optional Dask priority.

    Explanation:
    Submits a task to the Dask scheduler to run the specified plugin on the given dump with the provided parameters, without waiting for the result.

    Args:
    - dump: The dump object.
    - plugin: The plugin object.
    - params: A dictionary of parameters for the plugin.
    - user_pk: Optional primary key of the user initiating the execution.
    - priority: Optional integer priority for the Dask scheduler queue (higher runs first).
    - dask_client: Optional pre-connected Dask client for batch submissions.

    Returns:
    - None
    """
    from orochi.backends.dask_client import wait_for_scheduler

    client = dask_client or get_dask_client()
    submit_kwargs = {"priority": int(priority)} if priority else {}
    future = client.submit(run_plugin, dump, plugin, params, user_pk, pure=False, **submit_kwargs)
    fire_and_forget(future)
    # Fire-and-forget futures are lost when the submitting process exits before the scheduler has them
    if not wait_for_scheduler(future.key, timeout=15, client=client):
        logging.getLogger(__name__).error(f"Dask scheduler did not receive plugin {plugin.name} on dump {dump.name}")


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
    safe_index = sanitize_filename(str(index))
    safe_plugin = sanitize_filename(str(plugin))
    safe_name = sanitize_filename(getattr(f, "name", None) or str(f))
    media_root = Path(settings.MEDIA_ROOT)
    plugin_dir = resolve_path_within(media_root / safe_index / safe_plugin, [media_root])
    plugin_dir.mkdir(parents=True, exist_ok=True)
    target = resolve_path_within(plugin_dir / safe_name, [plugin_dir])
    with open(target, "wb+") as destination:
        for chunk in f.chunks():
            destination.write(chunk)
    return str(target)


## UTILS FINE


@router.get("/", auth=dual_auth, response=list[DumpSchema])
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
    auth=dual_auth,
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
            case = Case.objects.visible_to(request.user).get(pk=payload.case_id)
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


def _dump_for_lifecycle(request, pk: str, *, deleted: bool):
    """Dump the user may delete/restore/purge, or an error ``Status`` (Analysts and Admins with ``can_see``).

    403 below the Analyst role, 404 when the dump is not visible to the user (or not in the requested state).
    """
    if not has_role(request.user, ROLE_ANALYST):
        return None, Status(403, {"errors": "Permission Denied: Only Analysts and Admins can delete dumps."})
    queryset = deleted_dumps() if deleted else Dump.objects.all()
    dump = get_objects_for_user(request.user, "website.can_see", klass=queryset).filter(index=pk).first()
    if dump is None:
        where = "in the recycle bin" if deleted else ""
        return None, Status(404, {"errors": f"Dump not found {where}".strip() + "."})
    return dump, None


@router.get(
    "/recycle_bin",
    auth=dual_auth,
    url_name="recycle_bin",
    response=list[RecycledDumpOut],
)
def list_recycle_bin(request):
    """Dumps in the recycle bin that the user can see, most recently deleted first."""
    dumps = get_objects_for_user(request.user, "website.can_see", klass=deleted_dumps()).select_related("deleted_by")
    return [
        {
            "index": dump.index,
            "name": dump.name,
            "operating_system": dump.operating_system,
            "deleted_at": dump.deleted_at,
            "deleted_by": dump.deleted_by.username if dump.deleted_by else None,
            "purge_at": purge_at(dump),
            "status_before_delete": dump.status_before_delete,
        }
        for dump in dumps
    ]


@router.delete(
    "/{pk}",
    auth=dual_auth,
    url_name="delete_dump",
    response={200: SuccessResponse, 400: ErrorsOut, 403: ErrorsOut, 404: ErrorsOut},
)
def delete_dump(request, pk: str, permanent: bool = False):
    """
    Move a dump to the recycle bin, or delete it for good.

    The dump keeps its files and results and can be restored for ``DUMP_RETENTION_DAYS`` days; with
    ``permanent=true`` or a retention of 0 it is deleted immediately with its files. Only Analysts and Admins who can
    see the dump may delete it.

    Examples:
        DELETE /dumps/{pk}
        DELETE /dumps/{pk}?permanent=true
    """
    try:
        dump, error = _dump_for_lifecycle(request, pk, deleted=False)
        if error:
            return error
        name = dump.name
        days = retention_days()
        if permanent or days == 0:
            purge(dump)
            return Status(200, {"message": f"Index {name} has been deleted permanently."})
        dump.soft_delete(request.user)
        schedule_purge()
        return Status(
            200,
            {"message": f"Index {name} moved to the recycle bin: it can be restored for {days} day(s)."},
        )
    except Exception as excp:
        return Status(
            400,
            {"errors": str(excp) if excp else "Generic error during dump deletion"},
        )


@router.post(
    "/{pk}/restore",
    auth=dual_auth,
    url_name="restore_dump",
    response={200: SuccessResponse, 400: ErrorsOut, 403: ErrorsOut, 404: ErrorsOut},
)
def restore_dump(request, pk: str):
    """Take a dump out of the recycle bin with the status it had (or reached while deleted)."""
    dump, error = _dump_for_lifecycle(request, pk, deleted=True)
    if error:
        return error
    dump.restore()
    return Status(200, {"message": f"Index {dump.name} has been restored."})


@router.delete(
    "/{pk}/purge",
    auth=dual_auth,
    url_name="purge_dump",
    response={200: SuccessResponse, 400: ErrorsOut, 403: ErrorsOut, 404: ErrorsOut},
)
def purge_dump(request, pk: str):
    """Delete a dump of the recycle bin for good, with its files and results."""
    dump, error = _dump_for_lifecycle(request, pk, deleted=True)
    if error:
        return error
    name = dump.name
    purge(dump)
    return Status(200, {"message": f"Index {name} has been deleted permanently."})


@router.get("/{pk}", response={200: DumpInfoSchema, 400: ErrorsOut, 403: ErrorsOut}, auth=dual_auth)
def get_dump_info(request, pk: str):
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
        return Status(403, {"errors": "Forbidden"})
    return Status(200, dump)


@router.post(
    "/",
    url_name="create_index",
    response={200: DumpSchema, 400: ErrorsOut, 403: ErrorsOut},
    auth=dual_auth,
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
                403,
                {"errors": "Permission Denied: Only Analysts and Admins can upload dumps."},
            )
        if not (payload.name or "").strip():
            return Status(400, {"errors": "Dump name cannot be empty."})
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
        if not payload.local_folder and not upload:
            return Status(400, {"errors": "Upload a file or choose one from the server folder."})
        if payload.local_folder and upload:
            return Status(400, {"errors": "Choose either an uploaded file or a server file, not both."})
        if deleted_dumps().filter(name=payload.name, author=request.user).exists():
            return Status(
                400,
                {
                    "errors": f"A dump named '{payload.name}' is in the recycle bin: "
                    "restore it or delete it permanently first."
                },
            )

        source_path = None
        safe_filename = None
        if payload.local_folder:
            start = payload.local_folder.replace(
                "/upload/upload",
                str(Path(settings.MEDIA_ROOT) / "uploads"),
            )
            source_path = resolve_path_within(
                start,
                allowed_upload_source_roots(),
                must_exist_file=True,
            )
            safe_filename = sanitize_filename(payload.original_name or source_path.name)
        else:
            safe_filename = sanitize_filename(getattr(upload, "name", None))

        dump_index = str(uuid1())
        dump_dir = Path(settings.MEDIA_ROOT) / dump_index
        dump_dir.mkdir(parents=True, exist_ok=True)

        with transaction.atomic():
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
            assign_perm("website.can_see", request.user, dump)

            if source_path is not None:
                dest_path = resolve_path_within(dump_dir / safe_filename, [dump_dir])
                shutil.move(str(source_path), str(dest_path))
                dump.upload.name = f"{dump_index}/{safe_filename}"
                move = False
            else:
                dump.upload.save(safe_filename, upload)
                move = True
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
    response={200: DumpSchema, 400: ErrorsOut, 403: ErrorsOut},
    auth=dual_auth,
)
def edit_dump(request, pk: str, payload: PatchDict[DumpEditIn]):
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
            return Status(403, {"errors": "Unauthorized"})

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
    auth=dual_auth,
)
def get_dump_plugins(request, pks: list[str], filters: Query[DumpFilters] = None):
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
    result_qs = Result.objects.select_related("dump", "plugin").filter(dump__index__in=dumps)
    if filters and filters.result:
        result_qs = result_qs.filter(result=filters.result)

    # Aggregate per-plugin result state and stored row count across the selected dumps
    status_by_plugin: dict[int, tuple[int, str, int]] = {}
    for r in result_qs.annotate(row_count=Count("value")):
        prev = status_by_plugin.get(r.plugin_id)
        if prev is None:
            status_by_plugin[r.plugin_id] = (r.result, r.get_result_display(), r.row_count)
        else:
            status_by_plugin[r.plugin_id] = (r.result, r.get_result_display(), prev[2] + r.row_count)

    res = (
        result_qs.order_by("plugin__name")
        .distinct()
        .values(
            "plugin__name",
            "plugin__comment",
            "plugin__id",
            "plugin__min_role",
            "plugin__disabled",
        )
    )

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

        res_code, res_display, row_count = status_by_plugin.get(plugin_id, (None, None, 0))
        output.append(
            {
                "plugin__name": item["plugin__name"],
                "plugin__comment": item["plugin__comment"],
                "plugin__id": item["plugin__id"],
                "min_role": min_role,
                "can_execute": can_exec,
                "result": res_code,
                "result_display": res_display,
                "row_count": row_count,
            }
        )
    return output


@router.post(
    "/{idxs:pks}/plugin/{str:plugin_name}/execute",
    url_name="dumps_plugin_execute",
    response={200: SuccessResponse, 400: ErrorsOut, 403: ErrorsOut},
    auth=dual_auth,
)
def dumps_plugin_execute(request, pks: list[str], plugin_name: str):
    """Run a plugin on the selected dumps, honouring per-plugin execution rights and optional parameters."""
    try:
        plugin = get_object_or_404(Plugin, name=plugin_name)
        if not can_execute_plugin(request.user, plugin):
            return Status(
                403,
                {"errors": f"Permission Denied: You do not have permission to execute plugin '{plugin.name}'."},
            )
        dumps_ok = get_objects_for_user(request.user, "website.can_see")
        dumps = [dump for dump in Dump.objects.filter(index__in=pks) if dump in dumps_ok]
        if not UserPlugin.objects.filter(plugin=plugin, user=request.user).exists():
            raise Http404("No UserPlugin matches the given query.")
        for dump in dumps:
            result = get_object_or_404(Result, dump=dump, plugin=plugin)
            params = {}

            parameters = get_parameters(plugin.name)
            raw_payload = request.POST.get("payload")
            if raw_payload:
                payload = json.loads(raw_payload)
            elif request.content_type == "application/json" and request.body:
                payload = json.loads(request.body.decode("utf-8"))
            else:
                payload = {}
            for parameter in parameters:
                if parameter["name"] in payload:
                    name = parameter["name"]
                    name_value = payload.get(name)
                    if parameter["mode"] == "list":
                        if isinstance(name_value, list):
                            value = [
                                (int(x, 0) if isinstance(x, str) else int(x)) if parameter["type"] == "int" else x
                                for x in name_value
                            ]
                        else:
                            value = shlex.shlex(str(name_value), posix=True)
                            value.whitespace += ","
                            value.whitespace_split = True
                            value = list(value)
                            if parameter["type"] == "int":
                                value = [int(x, 0) for x in value]
                        params[name] = value

                    elif parameter["type"] == "bool":
                        params[name] = (
                            name_value
                            if isinstance(name_value, bool)
                            else str(name_value).lower() in ["true", "on", "1"]
                        )

                    elif parameter["type"] == "int" and name_value not in (None, ""):
                        params[name] = int(name_value, 0) if isinstance(name_value, str) else int(name_value)

                    else:
                        params[name] = name_value
            for filename in request.FILES:
                filepath = handle_uploaded_file(dump.index, plugin.name, request.FILES.get(filename))
                params[filename] = f"file:{pathname2url(filepath)}"

            # Previous rows are archived as a snapshot of their run, then removed (#1674)
            from orochi.website.result_history import archive_and_clear

            archive_and_clear(result, user_pk=request.user.pk, reason="re-run")
            result.result = RESULT_STATUS_RUNNING
            result.description = None
            result.parameter = params
            result.save()

            priority = int(payload.get("priority", 0)) if isinstance(payload, dict) and "priority" in payload else 0
            if priority:
                plugin_f_and_f(dump, plugin, params, request.user.pk, priority=priority)
            else:
                plugin_f_and_f(dump, plugin, params, request.user.pk)
        return Status(
            200,
            {"message": f"Plugin {plugin.name} resubmitted on {', '.join([x.name for x in dumps])}."},
        )
    except Exception as excp:
        return Status(400, {"errors": f"Bad Request ({excp})"})


@router.get(
    "/{pk}/integrity",
    url_name="dump_integrity_checks",
    auth=dual_auth,
    response={200: list[IntegrityCheckOut], 404: ErrorsOut},
)
def list_integrity_checks(request, pk: str):
    """Hashes recorded for the dump: as received, after extraction and every later verification (#1674)."""
    dump = get_objects_for_user(request.user, "website.can_see").filter(index=pk).first()
    if dump is None:
        return Status(404, {"errors": "Dump not found."})
    return [
        {
            **{
                f: getattr(c, f)
                for f in ("kind", "checked_at", "target", "expected_sha256", "actual_sha256", "ok", "detail")
            },
            "user": c.user.username if c.user else None,
        }
        for c in dump.integrity_checks.select_related("user")
    ]


@router.post(
    "/{pk}/verify",
    url_name="dump_verify_integrity",
    auth=dual_auth,
    response={200: SuccessResponse, 404: ErrorsOut},
)
@ninja_test_required("is_not_readonly")
def verify_dump_integrity(request, pk: str):
    """Re-hash the memory image and the kept original in the background; the result is notified and recorded."""
    from orochi.website.tasks import verify_dump_integrity_task

    dump = get_objects_for_user(request.user, "website.can_see").filter(index=pk).first()
    if dump is None:
        return Status(404, {"errors": "Dump not found."})
    verify_dump_integrity_task.enqueue(dump_pk=dump.pk, user_pk=request.user.pk)
    return Status(200, {"message": f"Integrity check of {dump.name} started: you will be notified of the result."})


def _visible_result(request, pk: str, plugin_name: str):
    dump = get_objects_for_user(request.user, "website.can_see").filter(index=pk).first()
    if dump is None:
        return None
    return Result.objects.filter(dump=dump, plugin__name=plugin_name).first()


@router.get(
    "/{pk}/plugin/{str:plugin_name}/runs",
    url_name="dump_plugin_runs",
    auth=dual_auth,
    response={200: list[ResultRunOut], 404: ErrorsOut},
)
def list_plugin_runs(request, pk: str, plugin_name: str):
    """Runs of a plugin on a dump, newest first: who, when, tools, symbols, parameters, archived rows (#1674)."""
    result = _visible_result(request, pk, plugin_name)
    if result is None:
        return Status(404, {"errors": "Result not found."})
    return [
        {
            **{
                f: getattr(run, f)
                for f in (
                    "number",
                    "reason",
                    "started_at",
                    "finished_at",
                    "parameters",
                    "volatility_version",
                    "plugin_version",
                    "symbols",
                    "row_count",
                    "rows_sha256",
                    "has_snapshot",
                    "snapshot_sha256",
                    "snapshot_size",
                    "snapshot_deleted_at",
                )
            },
            "status": run.get_status_display(),
            "user": run.user.username if run.user else None,
        }
        for run in result.runs.select_related("user")
    ]


@router.get(
    "/{pk}/plugin/{str:plugin_name}/runs/{int:number}/snapshot",
    url_name="dump_plugin_run_snapshot",
    auth=dual_auth,
    response={200: None, 404: ErrorsOut},
)
def download_plugin_run_snapshot(request, pk: str, plugin_name: str, number: int):
    """Archived rows of a run as gzipped JSON lines; ``X-Rows-SHA256`` lets the client check them."""
    from django.http import FileResponse

    result = _visible_result(request, pk, plugin_name)
    run = result.runs.filter(number=number).first() if result else None
    if run is None or not run.has_snapshot or not Path(run.snapshot_path).is_file():
        return Status(404, {"errors": "No archived rows for this run."})
    response = FileResponse(
        open(run.snapshot_path, "rb"),
        as_attachment=True,
        filename=f"{result.dump.name}_{plugin_name}_run{number}.jsonl.gz",
    )
    response["X-Rows-SHA256"] = run.rows_sha256
    return response


@router.delete(
    "/{pk}/plugin/{str:plugin_name}/runs/{int:number}/snapshot",
    url_name="dump_plugin_run_snapshot_delete",
    auth=dual_auth,
    response={200: SuccessResponse, 404: ErrorsOut},
)
@ninja_test_required("is_not_readonly")
def delete_plugin_run_snapshot(request, pk: str, plugin_name: str, number: int):
    """Delete the archived rows of a run; the run record stays for custody."""
    from orochi.website.result_history import delete_snapshot

    result = _visible_result(request, pk, plugin_name)
    run = result.runs.filter(number=number).first() if result else None
    if run is None or not run.has_snapshot:
        return Status(404, {"errors": "No archived rows for this run."})
    delete_snapshot(run, request.user)
    return Status(200, {"message": f"Archived rows of run {number} deleted."})


@router.get(
    "/{idxs:pks}/plugin/{str:plugin_name}",
    url_name="dumps_plugin_status",
    response=list[DumpPluginStatusSchema],
    auth=dual_auth,
)
def get_dump_plugin_status(request, pks: list[str], plugin_name: str):
    """Retrieve the status and stored row count of a specific plugin for visible dumps (Issue #1661)."""
    dumps_ok = get_objects_for_user(request.user, "website.can_see")
    dumps = [dump.index for dump in Dump.objects.filter(index__in=pks) if dump in dumps_ok]
    results = (
        Result.objects.select_related("dump", "plugin")
        .filter(dump__index__in=dumps, plugin__name=plugin_name)
        .annotate(row_count=Count("value"))
    )
    return [
        {
            "dump_index": str(r.dump.index),
            "dump_name": r.dump.name,
            "plugin": r.plugin.name,
            "result": r.result,
            "status": r.get_result_display(),
            "description": r.description,
            "row_count": r.row_count,
            "updated_at": r.updated_at,
        }
        for r in results
    ]


@router.get(
    "/{pk}/reload_symbols",
    url_name="reload_symbols",
    auth=dual_auth,
    response={200: SuccessResponse, 400: ErrorsOut, 403: ErrorsOut},
)
def reload_symbols(request, pk: str):
    """
    Reload the symbols for a specific dump identified by its primary key. This function checks user permissions, attempts to reload the banner if necessary, and updates the dump's status accordingly.
    """
    try:
        dump = get_object_or_404(Dump, index=pk)
        if dump not in get_objects_for_user(request.user, "website.can_see"):
            return Status(403, {"errors": "Unauthorized"})

        from orochi.utils.volatility_dask_elk import invalidate_vol3_config_cache
        from orochi.website.symbols_assistant import (
            diagnose_symbols,
            ensure_symbol_environment,
        )

        invalidate_vol3_config_cache(dump.index)
        ensure_symbol_environment()

        # Try to reload banner if first time was not successful
        if not dump.banner:
            try:
                banner = dump.result_set.get(plugin__name="banners.Banners")
                if banner_result := get_banner(banner):
                    dump.banner = banner_result.strip("\"'")
                    dump.save(update_fields=["banner"])
            except Exception:
                pass

        if check_runnable(dump.pk, dump.operating_system, dump.banner):
            dump.status = DUMP_STATUS_COMPLETED
            dump.symbol_status = SymbolStatus.OK
            dump.result_set.filter(result=RESULT_STATUS_DISABLED).update(result=RESULT_STATUS_NOT_STARTED)
            dump.save()
        else:
            diagnose_symbols(dump)

        return Status(200, {"message": f"Symbol for index {dump.name} has been reloaded."})
    except Exception as excp:
        return Status(400, {"errors": f"Bad Request ({excp})"})


@router.get(
    "/{pk}/symbols/diagnosis",
    url_name="dump_symbols_diagnosis",
    auth=dual_auth,
    response={200: dict, 400: ErrorsOut, 403: dict},
)
def dump_symbols_diagnosis(request, pk: str):
    """
    Run Smart Symbol Assistant diagnosis for a dump and return structured report.
    """
    try:
        dump = get_object_or_404(Dump, index=pk)
        if dump not in get_objects_for_user(request.user, "website.can_see"):
            return Status(403, {"message": "Unauthorized"})

        from orochi.website.symbols_assistant import diagnose_symbols

        report = diagnose_symbols(dump)
        return Status(200, report)
    except Exception as excp:
        return Status(400, {"errors": f"Diagnostic error: {excp}"})


@router.post(
    "/{pk}/symbols/auto-resolve",
    url_name="dump_symbols_auto_resolve",
    auth=dual_auth,
    response={200: SuccessResponse, 400: ErrorsOut, 403: dict},
)
def dump_symbols_auto_resolve(request, pk: str, payload: SymbolsBannerIn | None = None):
    """
    1-Click auto-resolve symbols for a dump via Smart Symbol Assistant.
    """
    try:
        dump = get_object_or_404(Dump, index=pk)
        if dump not in get_objects_for_user(request.user, "website.can_see"):
            return Status(403, {"message": "Unauthorized"})

        from orochi.utils.volatility_dask_elk import invalidate_vol3_config_cache
        from orochi.website.symbols_assistant import auto_resolve_symbols

        invalidate_vol3_config_cache(dump.index)
        custom_path = payload.path if payload else None
        res = auto_resolve_symbols(dump, custom_path=custom_path, user=request.user)
        if res.get("success"):
            return Status(200, {"message": res.get("message", "Symbols auto-resolved successfully.")})
        return Status(400, {"errors": res.get("errors", "Could not auto-resolve symbols.")})
    except Exception as excp:
        return Status(400, {"errors": f"Auto-resolve error: {excp}"})


@router.post(
    "/{pk}/symbols/retry",
    url_name="dump_symbols_retry",
    auth=dual_auth,
    response={200: SuccessResponse, 400: ErrorsOut, 403: ErrorsOut},
)
@ninja_test_required("is_not_readonly")
def dump_symbols_retry(request, pk: str):
    """Re-run the plugins of a dump that ended Unsatisfied or Disabled for missing symbols (Issue #1553)."""
    dump = get_object_or_404(Dump, index=pk)
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return Status(403, {"errors": "Unauthorized"})
    from orochi.utils.volatility_dask_elk import invalidate_vol3_config_cache
    from orochi.website.symbols_assistant import retry_unsatisfied_plugins

    invalidate_vol3_config_cache(dump.index)
    names = retry_unsatisfied_plugins(dump, user=request.user)
    if not names:
        return Status(200, {"message": "No unsatisfied plugins to retry."})
    shown = ", ".join(names[:5]) + (f" and {len(names) - 5} more" if len(names) > 5 else "")
    return Status(200, {"message": f"Retrying {len(names)} plugin(s): {shown}."})


# Analysis hubs (temporal diff, annotations, secrets, triage, narrative, network, IOCs, sandbox) live in
# dump_analysis.py and register on this router; imported last so every helper above already exists.
from orochi.api.routers import dump_analysis  # noqa: E402, F401
